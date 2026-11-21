#!/usr/bin/env bash
# kura.sh: one script for setting up and running Kura on the Ubuntu Server VM.
#     ./kura.sh help                 list every subcommand
#     sudo ./kura.sh setup           first setup on a fresh VM
#     sudo ./kura.sh preflight       read-only production checks
# Options (anywhere on the command line):
# --dry-run   print what each step would do and change nothing --force     answer YES to the confirmation of a destructive step
# Every step is safe to run twice: work that is already done is skipped, and the script says so.
# Destructive steps ask you to type YES first.
# The script never runs "docker compose down -v" and never deletes a volume.
# On Linux, private keys and secret files belong to the container user that reads them (see certs/README.md and secrets/README.md), so the commands that write or read them must run as root.
set -eu

# Work from the project folder so "docker compose" finds docker-compose.yml.
cd "$(dirname "$0")"

CERT_DIR="certs/internal"
SECRETS_DIR="secrets"

# Secrets Kura generates itself with a cryptographic random generator.
GENERATED_SECRETS="db_password backup_encryption_key django_secret_key crowdsec_bouncer_key grafana_admin_password grafana_viewer_password"
# Secrets that come from outside services or from Vault.
# We cannot generate these, so setup creates an empty file and says where the value comes from.
EXTERNAL_SECRETS="telegram_bot_token telegram_chat_id vault_role_id vault_secret_id"
# Host-only secrets written by vault-init (never mounted into a container).
HOST_ONLY_SECRETS="vault_issuer_role_id vault_issuer_secret_id"

# Private keys and the container user (UID) that reads each one.
KEY_OWNERS="db:26 web:10001 migrator:0:10002 waf:101 nginx:0 vault:100 alloy:473"
# Internal certificates issued by Vault (and by the bootstrap CA before it).
INTERNAL_CERTS="nginx waf web db vault alloy migrator"

DRY_RUN=0
FORCE=0
RESET_PASSWORD=0

# Small helpers

# Print a step, a skipped step, or an error in one consistent format.
say() { echo "[*] $*"; }
skip() { echo "[skip] $*"; }
die() { echo "[-] $*" >&2; exit 1; }

# In --dry-run mode, print the planned action and return success so the caller skips the real work.
# Otherwise return failure so the caller does the work.
planned() {
    if [ "$DRY_RUN" = 1 ]; then
        echo "[dry-run] would $*"
        return 0
    fi
    return 1
}

# Ask before a destructive step. --force answers for you.
# Anything other than exactly YES stops the script without changing anything.
confirm() {
    echo "[!] $1"
    if [ "$FORCE" = 1 ]; then
        echo "[!] --force given: continuing."
        return 0
    fi
    if [ ! -t 0 ]; then
        die "This step needs confirmation. Run it in a terminal or pass --force."
    fi
    printf 'Type YES to continue: '
    read -r answer
    [ "$answer" = "YES" ] || die "Not confirmed. Nothing was changed."
}

is_linux() { [ "$(uname -s)" = "Linux" ]; }

# On Linux the key and secret files belong to container users, so commands that write or read them must run as root. A dry run changes nothing, so it may run as anyone.
need_root() {
    if [ "$DRY_RUN" = 0 ] && is_linux && [ "$(id -u)" != "0" ]; then
        die "Run this as root on Linux:  sudo ./kura.sh $1"
    fi
}

# True when the named Compose service is running.
is_running() {
    docker compose ps --status running --services 2>/dev/null | grep -qx "$1"
}

# Set a secret file to mode 600 and give it to the one container user that reads it.
# Host-only files belong to root.
# Docker Desktop on macOS ignores owners, so the owner is only set on Linux.
secret_owner() {
    case "$1" in
        db_password|backup_encryption_key) echo 26 ;;          # "postgres" in the pgEdge image
        django_secret_key|vault_role_id|vault_secret_id) echo 10001 ;;  # "kura" in our Dockerfile
        grafana_admin_password) echo 472 ;;                    # "grafana" in the Grafana image
        telegram_bot_token|telegram_chat_id) echo 65534 ;;     # "nobody" in the Alertmanager image
        *) echo 0 ;;  # crowdsec_bouncer_key (read as root), host-only files
    esac
}

fix_secret_file() {
    name=$1
    file="$SECRETS_DIR/$name.txt"
    want_owner=$(secret_owner "$name")
    if ! is_linux; then
        chmod 600 "$file"
        return
    fi
    current=$(stat -c '%a %u' "$file")
    if [ "$current" = "600 $want_owner" ]; then
        return
    fi
    if planned "set $file to mode 600, owner $want_owner"; then
        return
    fi
    chmod 600 "$file"
    chown "$want_owner" "$file"
    echo "fixed     $file (mode 600, owner $want_owner)"
}

# Read a secret file without printing it.
# Only used inside $(...).
read_secret() {
    tr -d '\r\n' < "$SECRETS_DIR/$1.txt"
}

# The "vault" command line tool inside the Vault container.
vault_cli() {
    docker compose exec -T vault vault "$@"
}

# True when Vault answers and reports that it has been initialised.
vault_initialised() {
    is_running vault || return 1
    status=$(vault_cli status -format=json 2>/dev/null || true)
    echo "$status" | grep -q '"initialized": true'
}

# Give the folder a service mounts at TARGET (a named volume or a host folder, as written in docker-compose.yml) to OWNER, mode 700. Uses the database image as a throwaway root container with no network; the service itself is untouched.
fix_volume_owner() {
    service=$1
    target=$2
    owner=$3
    # Ask Compose which volume or host folder is mounted at TARGET. A named volume is reported by its short name, so look up its real Docker name.
    source=$(docker compose config --format json | python3 -c '
import json, sys
config = json.load(sys.stdin)
for mount in config["services"][sys.argv[1]]["volumes"]:
    if mount["target"] == sys.argv[2]:
        name = mount["source"]
        volume = config.get("volumes", {}).get(name)
        print(volume["name"] if volume else name)
' "$service" "$target")
    [ -n "$source" ] || die "No mount at $target for service $service in docker-compose.yml."
    image=$(docker compose config --images db | head -1)
    docker run --rm --user 0 --network none --entrypoint sh -v "$source:/fix" "$image" \
        -c 'chown "$1" /fix && chmod 700 /fix' sh "$owner"
    say "$source now belongs to $owner"
}

# help

# Print every subcommand with one line about what it does.
cmd_help() {
    cat <<'EOF'
Usage: ./kura.sh <command> [--dry-run] [--force]

Setup
  setup              First setup on a fresh VM: prerequisites, secrets, certificates,
                     database migration, Vault, static files, stack, Grafana users, health
  secrets            Create missing secret files (mode 600, container owner); never overwrites
  certs              Create the public self-signed certificate certs/kura.crt and kura.key
  mtls-bootstrap     Create the temporary openssl CA and first internal mTLS certificates
  vault-init         One-time Vault setup (unseal key, Transit, database users, PKI, AppRoles),
                     then switch every service to Vault-issued certificates
  vault-add-name N   Add service name N to Vault's kura-service certificate role
  renew-certs        Renew internal certificates from Vault and reload services (weekly cron)
  grafana-users      Check the Grafana admin login and create the read-only "viewer" account
                     (--reset-password resets both passwords to the secret files)

Checks
  preflight          Read-only production checks; ends with PASS or FAIL
  health             Container health, the HTTPS site and Grafana's health endpoint

Operations
  firewall-bouncer   Install the CrowdSec nftables bouncer config (key from secrets/) and enable it
  app-metrics        Write Kura's application counts for Alloy (every-minute cron)
  egress-refresh     Resolve Gmail SMTP and HaveIBeenPwned to IP addresses and refresh
                     the host firewall egress allowlists (every-10-minutes cron)
  restore-drill [T]  Restore the backup (latest, or time T) into a throwaway database
                     and compare row counts with the live one; the live database is untouched
  help               This list

Destructive steps (ask for YES, or pass --force):
  mtls-bootstrap after Vault exists (replaces the trusted CA),
  certs when a certificate exists (replaces it),
  grafana-users --reset-password.
EOF
}

# secrets

# Create every missing secret file. A file that already exists is NEVER overwritten, so running it again cannot break a database or Vault that is already set up.
# Values are never printed to the screen.
cmd_secrets() {
    need_root secrets
    # The secrets/ folder is locked to its owner (700), so other users on the host cannot open any file inside it.
    if ! planned "set $SECRETS_DIR/ to mode 700"; then
        chmod 700 "$SECRETS_DIR"
    fi

    # 1. Secrets we generate. "openssl rand -base64 48" gives 48 random bytes (384 bits) as text; tr removes characters that cause trouble in connection strings. umask 077 creates the file as owner-only.
    for name in $GENERATED_SECRETS; do
        file="$SECRETS_DIR/$name.txt"
        if [ -f "$file" ]; then
            skip "$file already exists"
        elif planned "generate $file"; then
            continue
        else
            (umask 077; openssl rand -base64 48 | tr -d '\n/+=' > "$file")
            echo "generated $file"
        fi
        [ -f "$file" ] && fix_secret_file "$name"
    done

    # 2. Secrets from outside services.
    # Compose refuses to start if a file is missing, so an empty file is created and we say where the value comes from.
    for name in $EXTERNAL_SECRETS; do
        file="$SECRETS_DIR/$name.txt"
        case "$name" in
            telegram_bot_token) source="Telegram @BotFather" ;;
            telegram_chat_id) source="the Telegram chat that receives alerts" ;;
            *) source="Vault. ./kura.sh vault-init writes it for you" ;;
        esac
        if [ -s "$file" ]; then
            skip "$file already filled in"
        elif [ -f "$file" ]; then
            echo "TODO      $file is empty: paste the value from $source"
        elif planned "create empty $file"; then
            continue
        else
            (umask 077; touch "$file")
            echo "TODO      $file is empty: paste the value from $source"
        fi
        [ -f "$file" ] && fix_secret_file "$name"
    done

    # 3. Host-only files from vault-init: only fix their mode and owner.
    for name in $HOST_ONLY_SECRETS; do
        [ -f "$SECRETS_DIR/$name.txt" ] && fix_secret_file "$name"
    done
    return 0
}

# certs

# Create the self-signed public certificate Nginx serves on port 443. Browsers warn about it; a real deployment replaces certs/kura.crt and kura.key with a CA-issued certificate (certs/README.md).
# Skipped when it already exists.
cmd_certs() {
    need_root certs
    if [ -f certs/kura.crt ] && [ -f certs/kura.key ]; then
        if [ "$FORCE" = 0 ]; then
            skip "certs/kura.crt already exists (use --force to replace it)"
            return 0
        fi
        if planned "replace certs/kura.crt and certs/kura.key"; then
            return 0
        fi
        confirm "This replaces the public certificate certs/kura.crt."
    elif planned "create certs/kura.crt and certs/kura.key"; then
        return 0
    fi

    # Remove the old key first (on Linux it belongs to root after the last run).
    rm -f certs/kura.key certs/kura.crt
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/kura.key \
        -out certs/kura.crt \
        -subj "/C=EG/ST=Cairo/L=Cairo/O=Kura/OU=Security/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:web,DNS:nginx,IP:127.0.0.1"

    # On Linux the key must belong to root: Nginx reads it as root at start-up and has no permission to read files owned by other users (see docker-compose.yml).
    chmod 0600 certs/kura.key
    if is_linux; then
        chown 0 certs/kura.key
    fi
    say "TLS certificate generated in certs/"
}

# mtls-bootstrap

# BOOTSTRAP ONLY: first internal mTLS certificates.
# PostgreSQL and Vault need TLS certificates before Vault can issue any, so on a new server this makes a temporary openssl CA and the first certificates.
# vault-init then switches every service to certificates issued by Vault's own CA (renew-certs) and deletes this bootstrap CA's key.
# After that this step would replace the trusted CA, so it asks for YES.
# Each container mounts only its own .crt/.key plus ca.crt (docker-compose.yml).
# The CA private key is kept in certs/ca/, which is never mounted.
cmd_mtls_bootstrap() {
    need_root mtls-bootstrap
    if [ -f "$CERT_DIR/ca.crt" ]; then
        if [ -f certs/ca/ca.key ]; then
            skip "bootstrap certificates already exist (certs/ca/ca.key present)"
            return 0
        fi
        # ca.crt exists but the bootstrap key is gone: Vault's CA is in use.
        if planned "ask for YES, then replace Vault's CA with a new bootstrap CA"; then
            return 0
        fi
        confirm "Vault's CA is in use. A new bootstrap CA breaks every service until vault-init or renew-certs runs again."
    elif planned "create the bootstrap CA and certificates for: $INTERNAL_CERTS"; then
        return 0
    fi

    # Requires OpenSSL 3: the CA must carry a Subject Key Identifier so leaf certificates can reference it. macOS ships LibreSSL, which omits it, so a modern binary is preferred when installed (e.g. Homebrew's openssl@3).
    if command -v /opt/homebrew/opt/openssl@3/bin/openssl >/dev/null 2>&1; then
        OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
    elif command -v openssl >/dev/null 2>&1; then
        OPENSSL=$(command -v openssl)
        if [ "$($OPENSSL version | cut -d' ' -f1)" != "OpenSSL" ] || \
           [ "$($OPENSSL version | cut -d' ' -f2 | cut -d. -f1)" -lt 3 ]; then
            die "OpenSSL 3 is required (found $($OPENSSL version))."
        fi
    else
        die "openssl not found in PATH."
    fi

    # internal/: certificates and private keys that containers mount (one file at a time).
    # ca/: the CA private key and serial number. NO container mounts this folder:
    # anyone holding ca.key could sign a "kura_app" certificate and log in to PostgreSQL.
    mkdir -p "$CERT_DIR" certs/ca
    chmod 700 certs/ca

    # Remove old keys first.
    # On Linux they belong to container users after the last run, so we could not overwrite them, but we can delete them because we own the folder.
    rm -f "$CERT_DIR"/*.key "$CERT_DIR"/*.crt certs/ca/ca.key certs/ca/ca.srl

    say "Generating Internal Root CA..."
    $OPENSSL req -x509 -new -nodes -newkey rsa:4096 -days 3650 \
        -sha256 \
        -keyout certs/ca/ca.key \
        -out "$CERT_DIR/ca.crt" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign" \
        -addext "subjectKeyIdentifier=hash" \
        -subj "/C=EG/O=Kura/OU=Security/CN=Kura Internal Root CA"

    # Nginx: CLIENT certificate when it connects to the WAF (CN "nginx").
    bootstrap_cert nginx nginx "DNS:nginx,DNS:nginx.kura.internal"
    # Coraza WAF: SERVER for Nginx (name "waf") and CLIENT to Django.
    bootstrap_cert waf waf "DNS:waf,DNS:waf.kura.internal"
    # Django: serves TLS to the WAF and is the database CLIENT.
    # PostgreSQL certificate login requires CN = database user, so the CN is kura_app.
    bootstrap_cert web kura_app "DNS:web,DNS:web.kura.internal,DNS:localhost,IP:127.0.0.1"
    # PostgreSQL client/server certificate.
    bootstrap_cert db db "DNS:db,DNS:db.kura.internal,DNS:localhost,IP:127.0.0.1"
    # Vault: Django checks "vault"; the vault tool inside the container checks 127.0.0.1.
    bootstrap_cert vault vault "DNS:vault,DNS:vault.kura.internal,DNS:localhost,IP:127.0.0.1"
    # Alloy (client certificate for its PostgreSQL login as role "alloy").
    bootstrap_cert alloy alloy "DNS:alloy"
    # Migration role (client certificate for migrations as role "kura_migrator").
    bootstrap_cert migrator kura_migrator "DNS:kura_migrator"

    chmod 0600 "$CERT_DIR"/*.key certs/ca/ca.key
    chmod 0644 "$CERT_DIR"/*.crt
    set_key_owners
    say "Internal mTLS certificates generated in $CERT_DIR"
}

# Make one key and certificate signed by the bootstrap CA.
bootstrap_cert() {
    name=$1
    cn=$2
    san=$3
    say "Generating certificate for $name ($cn)..."
    $OPENSSL req -new -nodes -newkey rsa:2048 \
        -keyout "$CERT_DIR/$name.key" \
        -out "$CERT_DIR/$name.csr" \
        -subj "/C=EG/O=Kura/OU=Internal/CN=$cn"
    cat <<EOF > "$CERT_DIR/$name.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $san
EOF
    $OPENSSL x509 -req -in "$CERT_DIR/$name.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey certs/ca/ca.key \
        -CAserial certs/ca/ca.srl \
        -CAcreateserial \
        -out "$CERT_DIR/$name.crt" \
        -days 365 \
        -extfile "$CERT_DIR/$name.ext"
    rm -f "$CERT_DIR/$name.csr" "$CERT_DIR/$name.ext"
}

# On Linux, a 0600 key can only be read by its owner.
# Each container runs as a different user, so give every key to the one container user that needs it.
# PostgreSQL also refuses to start unless it owns its key. (Docker Desktop on macOS ignores file owners, so this is only needed on Linux.)
set_key_owners() {
    is_linux || return 0
    for entry in $KEY_OWNERS; do
        chown "${entry#*:}" "$CERT_DIR/${entry%%:*}.key"
    done
    # The migration key is readable only by root and group 10002; Gunicorn runs without that group.
    chown 0:10002 "$CERT_DIR/migrator.key"
    chmod 0440 "$CERT_DIR/migrator.key"
}

# vault-init

# One-time Vault setup.
# Needs the database up and migrated, and Vault started (setup does both).
# Refuses to run twice: initialising again would throw away every key.
# Steps:
# 1. Initialise Vault and show the unseal key ONCE.
# Nothing is saved to disk.
# 2. Unseal.
# 3. Audit log (every request, secrets hashed) to the container output.
# 4. Transit keys kura-mfa (AES-256-GCM) and kura-files (RSA-4096).
# 5. Temporary database users (database engine).
# 6. The "kura-web" policy and Django's AppRole login, written to secrets/.
# 7. Kura's CA inside Vault: a root CA that only signs an intermediate CA.
# 8. The "kura-cert-issuer" AppRole for renew-certs (host-only login).
# 9. Revoke the root token, so no all-powerful token is left anywhere.
# 10. renew-certs: every service switches to certificates issued by Vault.
cmd_vault_init() {
    need_root vault-init

    # 0. Never initialise twice. "vault status" exits with 2 while sealed, so its exit code is ignored and only the "initialized" line is checked.
    STATUS=$(vault_cli status -format=json 2>/dev/null || true)
    if echo "$STATUS" | grep -q '"initialized": true'; then
        skip "Vault is already initialised"
        if echo "$STATUS" | grep -q '"sealed": true'; then
            echo "      Vault is sealed. Unseal it:  docker compose exec vault vault operator unseal"
        fi
        return 0
    fi
    if ! echo "$STATUS" | grep -q '"initialized"'; then
        if planned "initialise Vault once it is running"; then
            return 0
        fi
        die "Cannot reach Vault. Start it first:  docker compose up -d vault"
    fi
    if planned "initialise, unseal and configure Vault, then run renew-certs"; then
        return 0
    fi

    # 1. Initialise with one unseal key.
    # Vault returns JSON; we pick out the unseal key and the root token with grep (no extra tools needed on the host).
    say "[1/9] Initialising Vault..."
    INIT_JSON=$(vault_cli operator init -key-shares=1 -key-threshold=1 -format=json)
    UNSEAL_KEY=$(echo "$INIT_JSON" | grep -A1 '"unseal_keys_b64"' | tail -n 1 | tr -d ' ",')
    ROOT_TOKEN=$(echo "$INIT_JSON" | grep '"root_token"' | cut -d'"' -f4)
    if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
        echo "Could not read the unseal key or root token from Vault's answer." >&2
        echo "Vault's answer was:" >&2
        echo "$INIT_JSON" >&2
        exit 1
    fi

    # Show the unseal key straight away.
    # If any later step fails, the key is already on screen: without it, this Vault could never be opened again.
    echo ""
    echo "=============================================================================="
    echo " UNSEAL KEY (shown only this once, NOT saved anywhere). Store it in your"
    echo " password manager now:"
    echo ""
    echo "     $UNSEAL_KEY"
    echo "=============================================================================="
    echo ""

    # If a later step fails, also show the root token, so the remaining steps can be finished by hand.
    # On success the token is revoked and never shown.
    trap show_root_token_on_failure EXIT

    # 2. Unseal by writing the key to Vault's unseal endpoint. "key=-" makes the vault tool read the key from standard input instead of the command line, so the key does not appear in the container's process list.
    say "[2/9] Unsealing Vault..."
    printf '%s' "$UNSEAL_KEY" | vault_cli write sys/unseal key=- > /dev/null

    # 3. Audit log: one JSON line per request on the container output.
    # Vault replaces secret values with HMAC hashes before writing them.
    say "[3/9] Turning on the audit log..."
    vault_root audit enable file file_path=stdout > /dev/null

    # 4. Transit engine and the key that encrypts authenticator seeds.
    # Vault keeps the key inside; Django can only ask Vault to use it.
    say "[4/9] Creating the kura-mfa and kura-files encryption keys..."
    vault_root secrets enable transit > /dev/null
    vault_root write -f transit/keys/kura-mfa type=aes256-gcm96 > /dev/null
    # An RSA-4096 key used to wrap per-file AES-256-GCM data keys (FileContent.wrapped_key).
    vault_root write -f transit/keys/kura-files type=rsa-4096 > /dev/null
    # Rotate Transit keys every 30 days (720h).
    # Vault Transit keeps old key versions, so previously encrypted seeds and file keys still decrypt (LOG-05).
    vault_root write transit/keys/kura-mfa/config auto_rotate_period=720h > /dev/null
    vault_root write transit/keys/kura-files/config auto_rotate_period=720h > /dev/null

    # 5. Temporary database users.
    say "[5/9] Setting up temporary database users..."

    # a) In PostgreSQL (as kura-admin through the container's local socket):
    # make kura_app NOLOGIN and create vault_admin (docker/postgres/vault-roles.sql).
    docker compose exec -T db sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" exec psql -q -U kura-admin -d kura -v ON_ERROR_STOP=1' < docker/postgres/vault-roles.sql > /dev/null

    # b) Give vault_admin a random first password.
    # It only lives for a moment:
    # step d) replaces it with one that only Vault knows.
    FIRST_PASSWORD=$(openssl rand -hex 24)
    printf "ALTER ROLE vault_admin WITH PASSWORD '%s';\n" "$FIRST_PASSWORD" | \
        docker compose exec -T db sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" exec psql -q -U kura-admin -d kura -v ON_ERROR_STOP=1'

    # c) Connect Vault's database engine to PostgreSQL:
    # - TLS with the database certificate checked (verify-full) and Vault's own certificate as the client certificate (pg_hba.conf requires it).
    # - password_authentication=scram-sha-256: Vault sends PostgreSQL a hash, never the plain password, so the pgAudit log of "CREATE ROLE" never contains a usable password.
    # - Temporary users are named kura_dyn_<20 random characters>.
    # The first password is read from standard input ("password=-").
    vault_root secrets enable database > /dev/null
    printf '%s' "$FIRST_PASSWORD" | vault_root write database/config/kura-postgresql \
        plugin_name=postgresql-database-plugin \
        connection_url="postgresql://{{username}}:{{password}}@db:5432/kura?sslmode=verify-full&sslrootcert=/vault/tls/ca.crt&sslcert=/vault/tls/vault.crt&sslkey=/vault/tls/vault.key" \
        username=vault_admin \
        password=- \
        password_authentication=scram-sha-256 \
        username_template='kura_dyn_{{random 20 | lowercase}}' \
        allowed_roles=kura-app > /dev/null

    # d) "rotate-root": Vault changes vault_admin's password to a new random one that it never shows to anyone.
    vault_root write -f database/rotate-root/kura-postgresql > /dev/null

    # e) The "kura-app" role: each request makes a new user that can log in for 15 minutes and gets kura_app's permissions (IN ROLE kura_app).
    # When the 15 minutes are up, Vault drops the user.
    vault_root write database/roles/kura-app \
        db_name=kura-postgresql \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE kura_app;" \
        revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
        default_ttl=15m \
        max_ttl=15m > /dev/null

    # 6. Policy and AppRole for Django.
    #    token_type=batch: login tokens are not stored by Vault, so logging in for
    # every request does not fill up Vault's storage.
    #    token_ttl=15m: a stolen token stops working after 15 minutes.
    say "[6/9] Creating Django's policy and AppRole login..."
    vault_root policy write kura-web /vault/policies/kura-web.hcl > /dev/null
    vault_root auth enable approle > /dev/null
    vault_root write auth/approle/role/kura-web \
        token_policies=kura-web \
        token_type=batch \
        token_ttl=15m \
        token_max_ttl=15m > /dev/null

    # Write Django's two login values into Docker secret files, then give them to the Django user (mode 600, UID 10001).
    vault_root read -field=role_id auth/approle/role/kura-web/role-id > "$SECRETS_DIR/vault_role_id.txt"
    vault_root write -f -field=secret_id auth/approle/role/kura-web/secret-id > "$SECRETS_DIR/vault_secret_id.txt"
    fix_secret_file vault_role_id
    fix_secret_file vault_secret_id

    # 7. Kura's certificate authority (PKI engine), in two levels:
    # - "pki": the ROOT CA, valid 10 years.
    # Its only job is to sign the intermediate CA below, so it is almost never used.
    # - "pki_int": the INTERMEDIATE CA, valid 5 years.
    # It signs every service certificate.
    # If it were ever compromised it could be replaced without changing ca.crt (the root) in every service.
    # "generate/internal" means the private key is created inside Vault and can never be exported. certs/ca/ca.key (the openssl bootstrap CA) is no longer needed after step 10.
    say "[7/9] Creating Kura's certificate authority (root + intermediate)..."
    vault_root secrets enable -path=pki pki > /dev/null
    vault_root secrets tune -max-lease-ttl=87600h pki > /dev/null
    vault_root write -field=certificate pki/root/generate/internal \
        common_name="Kura Internal Root CA" key_type=ec key_bits=384 ttl=87600h > /dev/null

    vault_root secrets enable -path=pki_int pki > /dev/null
    vault_root secrets tune -max-lease-ttl=43800h pki_int > /dev/null
    # The intermediate makes a signing request (CSR), the root signs it, and the signed certificate is loaded back into the intermediate.
    # Each step reads the previous step's output on standard input ("=-").
    INTERMEDIATE_CSR=$(vault_root write -field=csr pki_int/intermediate/generate/internal \
        common_name="Kura Internal Intermediate CA" key_type=ec key_bits=384)
    INTERMEDIATE_CERT=$(echo "$INTERMEDIATE_CSR" | vault_root write -field=certificate pki/root/sign-intermediate \
        csr=- format=pem_bundle ttl=43800h)
    echo "$INTERMEDIATE_CERT" | vault_root write pki_int/intermediate/set-signed certificate=- > /dev/null

    # The only kind of certificate the intermediate may issue: one of Kura's service names (alloy = the metrics collector's PostgreSQL login) (plus localhost / 127.0.0.1 for health checks inside a container), for at most 1 year, usable as both server and client certificate.
    # cn_validations=disabled lets the common name be "kura_migrator", a PostgreSQL
    # user name that is not a valid host name. allowed_domains still limits the names.
    vault_root write pki_int/roles/kura-service \
        allowed_domains="nginx,waf,web,db,vault,alloy,kura_migrator,localhost" \
        allow_bare_domains=true \
        allow_subdomains=false \
        allow_wildcard_certificates=false \
        cn_validations=disabled \
        allow_ip_sans=true \
        server_flag=true \
        client_flag=true \
        key_type=ec \
        key_bits=256 \
        max_ttl=8760h > /dev/null

    # 8. The renewal step's own login.
    # Its policy may ONLY issue certificates with the kura-service role (docker/vault/policies/kura-cert-issuer.hcl).
    # The login stays on the host in secrets/ with mode 600 (owner only).
    say "[8/9] Creating the certificate renewal AppRole..."
    vault_root policy write kura-cert-issuer /vault/policies/kura-cert-issuer.hcl > /dev/null
    vault_root write auth/approle/role/kura-cert-issuer \
        token_policies=kura-cert-issuer \
        token_type=batch \
        token_ttl=10m \
        token_max_ttl=10m > /dev/null
    (
        umask 077
        vault_root read -field=role_id auth/approle/role/kura-cert-issuer/role-id > "$SECRETS_DIR/vault_issuer_role_id.txt"
        vault_root write -f -field=secret_id auth/approle/role/kura-cert-issuer/secret-id > "$SECRETS_DIR/vault_issuer_secret_id.txt"
    )
    fix_secret_file vault_issuer_role_id
    fix_secret_file vault_issuer_secret_id

    # 9. Revoke the root token.
    # If full admin access is ever needed again, a new root token can be made with the unseal key ("vault operator generate-root").
    say "[9/9] Revoking the root token..."
    vault_root token revoke -self > /dev/null
    trap - EXIT

    # 10. Switch every service to certificates issued by Vault.
    echo ""
    say "Switching all services to certificates issued by Vault..."
    cmd_renew_certs

    echo ""
    echo "=============================================================================="
    echo " Vault is set up. Keep the unseal key shown above in your password manager."
    echo ""
    echo " Vault locks itself (seals) every time it restarts. Until you unseal it,"
    echo " Django cannot get a database login, so the site shows an error page:"
    echo ""
    echo "     docker compose exec vault vault operator unseal"
    echo ""
    echo " Then restart Django so it picks up its new login:  docker compose restart web"
    echo "=============================================================================="
}

# The vault tool, logged in with the temporary root token from vault-init or vault-add-name.
vault_root() {
    docker compose exec -T -e VAULT_TOKEN="$ROOT_TOKEN" vault vault "$@"
}

# Called on exit while vault-init still holds the root token.
show_root_token_on_failure() {
    if [ $? -ne 0 ]; then
        echo "" >&2
        echo "Setup stopped early. The ROOT TOKEN is needed to finish by hand:" >&2
        echo "     $ROOT_TOKEN" >&2
        echo "Revoke it afterwards:  vault token revoke <root token>" >&2
    fi
}

# vault-add-name

# Add a service name to Vault's "kura-service" certificate role on a Vault that is already set up.
# The root token was revoked at setup, so this:
# 1. asks for the UNSEAL KEY (typed, not shown, never saved),
# 2. makes a short-lived root token with "vault operator generate-root",
# 3. adds the name to pki_int/roles/kura-service (keeping all other settings),
# 4. revokes that root token again.
# Afterwards add the name to INTERNAL_CERTS and KEY_OWNERS above and run renew-certs.
cmd_vault_add_name() {
    NEW_NAME=${1:-}
    if [ -z "$NEW_NAME" ]; then
        die "Usage: ./kura.sh vault-add-name <service-name>"
    fi
    if planned "add '$NEW_NAME' to Vault's kura-service role (asks for the unseal key)"; then
        return 0
    fi

    # 1. Ask for the unseal key without showing it on screen.
    printf "Unseal key (input hidden): "
    stty -echo 2>/dev/null || true
    read -r UNSEAL_KEY
    stty echo 2>/dev/null || true
    echo ""
    # Remove spaces, tabs and line breaks that often come along when pasting.
    UNSEAL_KEY=$(printf '%s' "$UNSEAL_KEY" | tr -d ' \t\r\n')

    # 2. Make a temporary root token.
    # Vault returns it encoded with a one-time password (OTP); only someone holding both can decode it.
    # Cancel any earlier attempt that was left unfinished (e.g. a wrong key).
    vault_cli operator generate-root -cancel > /dev/null 2>&1 || true
    OTP=$(vault_cli operator generate-root -generate-otp)
    NONCE=$(vault_cli operator generate-root -init -otp="$OTP" -format=json | grep '"nonce"' | cut -d'"' -f4)
    ENCODED=$(printf '%s' "$UNSEAL_KEY" | vault_cli write -field=encoded_root_token sys/generate-root/update key=- nonce="$NONCE")
    ROOT_TOKEN=$(vault_cli operator generate-root -decode="$ENCODED" -otp="$OTP")
    UNSEAL_KEY=""

    # Always revoke the temporary root token at the end, even if a step fails.
    trap revoke_root_token EXIT

    # 3. Read the current allowed names and add the new one (if not there yet).
    # "patch" changes ONLY allowed_domains; "write" would reset the role's other settings (lifetimes, key type, flags) to their defaults.
    CURRENT=$(vault_root read -field=allowed_domains pki_int/roles/kura-service | tr -d '[]' | tr ' ' ',')
    case ",$CURRENT," in
        *",$NEW_NAME,"*)
            skip "kura-service already allows '$NEW_NAME'"
            return 0
            ;;
    esac
    vault_root patch pki_int/roles/kura-service allowed_domains="$CURRENT,$NEW_NAME" > /dev/null
    say "kura-service now allows: $CURRENT,$NEW_NAME"
}

# Revoke the temporary root token made by vault-add-name.
revoke_root_token() {
    vault_root token revoke -self > /dev/null 2>&1 || true
    echo "Temporary root token revoked."
}

# renew-certs

# Renew the internal mTLS certificates from Vault's CA.
# Runs weekly from root's crontab (docker/cron/kura.crontab) and at the end of vault-init.
# 1. Log in to Vault with the "kura-cert-issuer" AppRole (secrets/, host only).
# 2. Ask the intermediate CA for a new certificate and key for each service:
# 30 days for most, 1 year for Vault itself (so Vault's own certificate cannot expire during a long sealed period).
# 3. Only when ALL of them were issued, write them over the old files IN PLACE. (docker-compose.yml mounts single files; replacing a file with a new one would leave the container looking at the old one.)
# 4. Reload each running service so it picks up its new certificate without downtime.
# 5. Delete the openssl bootstrap CA key (certs/ca/), which nothing trusts any more: ca.crt is now Vault's root CA.
# Vault must be unsealed.
# Nothing is changed if any step before 3 fails.
# Renewing twice is safe: each run issues a fresh set.
cmd_renew_certs() {
    need_root renew-certs
    if planned "issue new certificates from Vault for: $INTERNAL_CERTS, write them in place and reload services"; then
        return 0
    fi

    # New certificates and keys are first written to a private temporary folder (umask 077: owner only) that is always deleted at the end.
    old_umask=$(umask)
    umask 077
    WORK_DIR=$(mktemp -d)
    trap 'rm -rf "$WORK_DIR"' EXIT

    # 1. Log in.
    # The secret ID goes in on standard input, so it is not visible in the process list.
    # The returned token lives for 10 minutes.
    say "[1/5] Logging in to Vault as kura-cert-issuer..."
    ROLE_ID=$(read_secret vault_issuer_role_id)
    ISSUER_TOKEN=$(docker compose exec -T vault vault write -field=token auth/approle/login \
        role_id="$ROLE_ID" secret_id=- < "$SECRETS_DIR/vault_issuer_secret_id.txt")

    # 2. Issue them all. "localhost" and 127.0.0.1 are for health checks that run inside the container itself.
    say "[2/5] Issuing new certificates..."
    issue_certificate nginx "nginx" 720h
    issue_certificate waf "waf" 720h
    issue_certificate web "web,localhost" 720h
    issue_certificate db "db,localhost" 720h
    issue_certificate vault "vault,localhost" 8760h
    issue_certificate alloy "alloy" 720h
    issue_certificate migrator "kura_migrator" 720h
    # The root CA certificate becomes ca.crt: the one thing every service trusts.
    # (Reading it needs no login: it is public.)
    docker compose exec -T vault vault read -field=certificate pki/cert/ca > "$WORK_DIR/ca.crt"

    # Stop here, before touching anything, unless every file looks right.
    grep -q "BEGIN CERTIFICATE" "$WORK_DIR/ca.crt" || die "Vault returned a bad ca.crt"
    for NAME in $INTERNAL_CERTS; do
        grep -q "BEGIN CERTIFICATE" "$WORK_DIR/$NAME.crt" || die "Vault returned a bad $NAME.crt"
        grep -q "PRIVATE KEY" "$WORK_DIR/$NAME.key" || die "Vault returned a bad $NAME.key"
    done

    # 3. Write the new files over the old ones IN PLACE ("cat new > old" keeps the same file, so the containers' single-file mounts see the new content).
    say "[3/5] Installing the new certificates..."
    for NAME in ca $INTERNAL_CERTS; do
        for FILE in "$NAME.crt" "$NAME.key"; do
            [ -f "$WORK_DIR/$FILE" ] || continue
            if [ ! -f "$CERT_DIR/$FILE" ]; then
                touch "$CERT_DIR/$FILE"
            fi
            cat "$WORK_DIR/$FILE" > "$CERT_DIR/$FILE"
        done
    done
    chmod 0644 "$CERT_DIR"/*.crt
    chmod 0600 "$CERT_DIR"/*.key
    # On Linux, each key must belong to the container user that reads it.
    set_key_owners

    # 4. Tell each running service to load its new certificate. A service that is not running simply reads the new files when it next starts.
    say "[4/5] Reloading services..."
    if is_running db; then
        docker compose exec -T db sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" psql -q -U kura-admin -d kura -c "SELECT pg_reload_conf();"' > /dev/null
        echo "      db: configuration reloaded"
    fi
    if is_running vault; then
        docker compose kill -s SIGHUP vault > /dev/null 2>&1
        echo "      vault: sent SIGHUP (reloads its HTTPS certificate)"
    fi
    if is_running waf; then
        docker compose exec -T waf nginx -c /etc/coraza/nginx.conf -s reload
        echo "      waf: nginx reloaded"
    fi
    if is_running nginx; then
        docker compose exec -T nginx nginx -s reload
        echo "      nginx: reloaded"
    fi
    if is_running web; then
        docker compose kill -s SIGHUP web > /dev/null 2>&1
        echo "      web: sent SIGHUP (Gunicorn starts new workers with the new certificate)"
    fi

    # 5. The openssl bootstrap CA is no longer trusted by anything (ca.crt is now Vault's root), so its private key is deleted.
    say "[5/5] Removing the openssl bootstrap CA key..."
    rm -f certs/ca/ca.key certs/ca/ca.srl

    write_cert_metrics
    rm -rf "$WORK_DIR"
    trap - EXIT
    umask "$old_umask"

    echo ""
    echo "Done. Certificates now expire on:"
    for NAME in $INTERNAL_CERTS; do
        printf '  %-8s %s\n' "$NAME" "$(openssl x509 -noout -enddate -in "$CERT_DIR/$NAME.crt" | cut -d= -f2)"
    done
}

# Ask the intermediate CA for one certificate.
# Vault answers in JSON; python3 (standard library only) picks out the parts:
#   <name>.crt = the certificate followed by the intermediate CA certificate
# (the "chain", so others can link it back to the root CA)
#   <name>.key = the private key, created by Vault and shown only this once
issue_certificate() {
    NAME=$1
    DNS_NAMES=$2
    LIFETIME=$3
    # kura_migrator is a PostgreSQL user name, not a DNS name ("_" is not allowed in DNS names), so Vault refuses it as a DNS name.
    # PostgreSQL only checks the common name, so the migrator certificate gets the common name and no DNS names.
    if [ "$NAME" = "migrator" ]; then
        NAME_ARGS="common_name=$DNS_NAMES exclude_cn_from_sans=true"
    else
        NAME_ARGS="common_name=${DNS_NAMES%%,*} alt_names=$DNS_NAMES"
    fi
    # NAME_ARGS is left unquoted on purpose, so it splits into separate settings.
    # shellcheck disable=SC2086
    docker compose exec -T -e VAULT_TOKEN="$ISSUER_TOKEN" vault vault write -format=json \
        pki_int/issue/kura-service \
        $NAME_ARGS ip_sans=127.0.0.1 ttl="$LIFETIME" > "$WORK_DIR/$NAME.json"
    python3 -c 'import json, sys; data = json.load(open(sys.argv[1]))["data"]; print(data["certificate"]); print(data["issuing_ca"])' \
        "$WORK_DIR/$NAME.json" > "$WORK_DIR/$NAME.crt"
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["data"]["private_key"])' \
        "$WORK_DIR/$NAME.json" > "$WORK_DIR/$NAME.key"
    rm "$WORK_DIR/$NAME.json"
}

# Record each certificate's expiry time for Prometheus (InternalCertExpiring alert).
# Same folder and write-then-rename pattern as the other metric files.
# A missing metrics folder must not make the renewal itself look failed: the certificates are already installed at this point, so only warn.
write_cert_metrics() {
    metrics_directory=${KURA_METRICS_DIR:-/var/lib/kura-metrics}
    if ! mkdir -p "$metrics_directory" 2>/dev/null; then
        echo "WARNING: cannot write metrics to $metrics_directory (set KURA_METRICS_DIR); certificate expiry metrics skipped." >&2
        return 0
    fi
    {
        echo "# HELP kura_cert_expiry_timestamp_seconds When each internal certificate expires (Unix time)."
        echo "# TYPE kura_cert_expiry_timestamp_seconds gauge"
        for NAME in nginx waf web db vault alloy; do
            EXPIRY_TEXT=$(openssl x509 -noout -enddate -in "$CERT_DIR/$NAME.crt" | cut -d= -f2)
            EXPIRY_SECONDS=$(python3 -c 'import sys, datetime; print(int(datetime.datetime.strptime(sys.argv[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()))' "$EXPIRY_TEXT")
            echo "kura_cert_expiry_timestamp_seconds{service=\"$NAME\"} $EXPIRY_SECONDS"
        done
    } > "$metrics_directory/kura_certs.prom.tmp"
    # Renewal runs with umask 077 (for the keys); the metrics file holds only expiry dates, and Alloy (another user) must be able to read it.
    chmod 0644 "$metrics_directory/kura_certs.prom.tmp"
    mv -f "$metrics_directory/kura_certs.prom.tmp" "$metrics_directory/kura_certs.prom"
}

# grafana-users

# Keep the built-in "admin" account for setup and recovery, and make sure one personal read-only account "viewer" exists with the Viewer role.
# Uses the Grafana HTTP API on 127.0.0.1:3000. Basic auth is off (docker-compose.yml), so the script logs in through the login form like a browser and keeps the session cookie in a private folder.
# Passwords go from the secret files into that folder and to Grafana, never onto the command line or the screen.
# Safe to rerun: an existing viewer is kept; only a wrong role is corrected.
# --reset-password (asks for YES) sets both passwords back to the secret files.
cmd_grafana_users() {
    need_root grafana-users
    if planned "check the admin login and create or check the 'viewer' account through http://127.0.0.1:3000"; then
        if [ "$RESET_PASSWORD" = 1 ]; then
            planned "ask for YES, then reset the admin and viewer passwords to the secret files"
        fi
        return 0
    fi
    curl -fsS -o /dev/null http://127.0.0.1:3000/api/health || die "Grafana is not answering on 127.0.0.1:3000."
    [ -s "$SECRETS_DIR/grafana_viewer_password.txt" ] || die "secrets/grafana_viewer_password.txt is missing. Run ./kura.sh secrets."

    # Private working folder for the session cookies and API answers.
    GRAFANA_WORK=$(mktemp -d)
    chmod 700 "$GRAFANA_WORK"
    trap 'rm -rf "$GRAFANA_WORK"' EXIT

    if [ "$RESET_PASSWORD" = 1 ]; then
        confirm "This resets the Grafana admin and viewer passwords to the values in secrets/."
        # The admin password is reset inside the container, read from standard input.
        read_secret grafana_admin_password | docker compose exec -T grafana grafana cli admin reset-admin-password --password-from-stdin > /dev/null
        say "admin password reset to secrets/grafana_admin_password.txt"
    fi

    # 1. The admin login must work, or nothing else can be checked.
    code=$(grafana_login admin grafana_admin_password)
    if [ "$code" != "200" ]; then
        die "The admin password in secrets/grafana_admin_password.txt does not log in (HTTP $code). Run: sudo ./kura.sh grafana-users --reset-password"
    fi
    skip "admin account works (kept for setup and recovery)"

    # 2. Create "viewer" if it does not exist yet.
    # The JSON body (with the password) is built from the secret file inside the private folder.
    code=$(grafana_api admin GET "/api/users/lookup?loginOrEmail=viewer")
    if [ "$code" = "404" ]; then
        python3 -c 'import json, sys; print(json.dumps({"name": "Viewer", "login": "viewer", "email": "viewer@localhost", "password": sys.stdin.read().strip(), "OrgId": 1}))' \
            < "$SECRETS_DIR/grafana_viewer_password.txt" > "$GRAFANA_WORK/body.json"
        code=$(grafana_api admin POST /api/admin/users "$GRAFANA_WORK/body.json")
        rm -f "$GRAFANA_WORK/body.json"
        [ "$code" = "200" ] || die "Could not create the viewer account (HTTP $code)."
        say "created the 'viewer' account"
        grafana_api admin GET "/api/users/lookup?loginOrEmail=viewer" > /dev/null
    elif [ "$code" = "200" ]; then
        skip "'viewer' account already exists"
    else
        die "Could not look up the viewer account (HTTP $code)."
    fi
    viewer_id=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["id"])' "$GRAFANA_WORK/answer.json")

    # 3. The viewer's role in the main organisation must be Viewer.
    grafana_api admin GET /api/org/users > /dev/null
    role=$(python3 -c 'import json, sys; print(next((u["role"] for u in json.load(open(sys.argv[1])) if u["login"] == "viewer"), ""))' "$GRAFANA_WORK/answer.json")
    if [ "$role" = "Viewer" ]; then
        skip "'viewer' already has the Viewer role"
    else
        echo '{"role": "Viewer"}' > "$GRAFANA_WORK/role.json"
        code=$(grafana_api admin PATCH "/api/org/users/$viewer_id" "$GRAFANA_WORK/role.json")
        [ "$code" = "200" ] || die "Could not set the viewer role (HTTP $code)."
        say "set the 'viewer' role to Viewer (was: ${role:-none})"
    fi

    # 4. Reset the viewer password only when asked (already confirmed above).
    if [ "$RESET_PASSWORD" = 1 ]; then
        python3 -c 'import json, sys; print(json.dumps({"password": sys.stdin.read().strip()}))' \
            < "$SECRETS_DIR/grafana_viewer_password.txt" > "$GRAFANA_WORK/body.json"
        code=$(grafana_api admin PUT "/api/admin/users/$viewer_id/password" "$GRAFANA_WORK/body.json")
        rm -f "$GRAFANA_WORK/body.json"
        [ "$code" = "200" ] || die "Could not reset the viewer password (HTTP $code)."
        say "viewer password reset to secrets/grafana_viewer_password.txt"
    fi

    # 5. The viewer password in the secret file must log in.
    code=$(grafana_login viewer grafana_viewer_password)
    if [ "$code" = "200" ]; then
        skip "viewer login works"
    else
        die "The viewer password in secrets/ does not log in (HTTP $code). Run: sudo ./kura.sh grafana-users --reset-password"
    fi
    rm -rf "$GRAFANA_WORK"
    trap - EXIT
}

# Log in to Grafana through the login form as "admin" or "viewer", with the password from the named secret file.
# Keeps the session cookie in $GRAFANA_WORK/<login>.cookies and prints only the HTTP status.
grafana_login() {
    login=$1
    secret=$2
    python3 -c 'import json, sys; print(json.dumps({"user": sys.argv[1], "password": sys.stdin.read().strip()}))' "$login" \
        < "$SECRETS_DIR/$secret.txt" > "$GRAFANA_WORK/login.json"
    curl -sS -c "$GRAFANA_WORK/$login.cookies" -X POST -H "Content-Type: application/json" \
        --data-binary "@$GRAFANA_WORK/login.json" -o /dev/null -w '%{http_code}' http://localhost:3000/login
    rm -f "$GRAFANA_WORK/login.json"
}

# Call the Grafana API with the session of "admin" or "viewer".
# Prints only the HTTP status; the answer body goes to $GRAFANA_WORK/answer.json.
# An optional fourth argument is a JSON file sent as the request body.
grafana_api() {
    login=$1
    method=$2
    path=$3
    body=${4:-}
    if [ -n "$body" ]; then
        curl -sS -b "$GRAFANA_WORK/$login.cookies" -X "$method" -H "Content-Type: application/json" \
            --data-binary "@$body" -o "$GRAFANA_WORK/answer.json" -w '%{http_code}' "http://localhost:3000$path"
    else
        curl -sS -b "$GRAFANA_WORK/$login.cookies" -X "$method" \
            -o "$GRAFANA_WORK/answer.json" -w '%{http_code}' "http://localhost:3000$path"
    fi
}

# preflight

PASSED=0
FAILED=0

# Record one check result.
# Messages never contain secret values.
pass() { echo "[PASS] $*"; PASSED=$((PASSED + 1)); }
fail() { echo "[FAIL] $*"; FAILED=$((FAILED + 1)); }

# Read-only production checks.
# Ends with PASS or FAIL and exits non-zero when any check fails.
# Nothing is changed, so --dry-run makes no difference.
# Run it as root on the VM: secret files belong to container users, and sshd -T needs root.
# As another user, unreadable files are reported as failures.
cmd_preflight() {
    check_compose_config
    check_django_deploy
    check_debug_off
    check_secret_values
    check_file_modes
    check_cert_expiry
    check_published_ports
    check_sshd
    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo "PREFLIGHT PASS ($PASSED checks)"
    else
        echo "PREFLIGHT FAIL ($FAILED failed, $PASSED passed)"
        exit 1
    fi
}

# The Compose file must be valid.
check_compose_config() {
    if docker compose config --quiet 2>/dev/null; then
        pass "docker compose config is valid"
    else
        fail "docker compose config reports an error (run: docker compose config --quiet)"
    fi
}

# Django's deployment checklist, inside the web image in a throwaway container (removed afterwards).
# Only the check output is shown, never the environment.
check_django_deploy() {
    if docker compose run --rm --no-deps -T -u 10001:10001 --entrypoint python web manage.py check --deploy --fail-level WARNING > /tmp/kura-check-deploy.$$ 2>&1; then
        pass "manage.py check --deploy"
    else
        fail "manage.py check --deploy reported problems:"
        grep -E '^(System check|\?:|kura|SystemCheckError|CommandError|.*\(security\.)' /tmp/kura-check-deploy.$$ | head -20 | sed 's/^/       /'
    fi
    rm -f /tmp/kura-check-deploy.$$
}

# DEBUG must not be true in .env.
# Only that one key is read; no value is printed.
check_debug_off() {
    if [ ! -f .env ]; then
        pass ".env not present (Compose sets DEBUG=False for every Django container)"
        return
    fi
    debug=$(grep -E '^[[:space:]]*DEBUG[[:space:]]*=' .env | tail -n 1 | cut -d= -f2- | tr -d ' "'"'" | tr '[:upper:]' '[:lower:]')
    case "$debug" in
        true|1|yes|on) fail "DEBUG is true in .env" ;;
        *) pass "DEBUG is not true in .env" ;;
    esac
}

# No secret file may be missing, empty, a known placeholder, or (for keys and passwords Kura generates) shorter than 32 characters.
check_secret_values() {
    for name in $GENERATED_SECRETS $EXTERNAL_SECRETS $HOST_ONLY_SECRETS; do
        file="$SECRETS_DIR/$name.txt"
        if [ ! -f "$file" ]; then
            fail "$file is missing"
            continue
        fi
        if [ ! -r "$file" ]; then
            fail "$file is not readable by this user (run preflight as root)"
            continue
        fi
        value=$(read_secret "$name")
        length=${#value}
        lower=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
        value=""
        case "$lower" in
            "") fail "$file is empty"; continue ;;
            *your-*-here*|*changeme*|*change-me*|*placeholder*|*example*|todo|xxx*)
                fail "$file holds a placeholder value"; continue ;;
        esac
        case " $GENERATED_SECRETS " in
            *" $name "*)
                if [ "$length" -lt 32 ]; then
                    fail "$file is shorter than 32 characters"
                    continue
                fi
                ;;
        esac
        pass "$file is set"
    done
}

# Secret files and private keys must be mode 600 and belong to the expected user; the secrets folder must be 700.
check_file_modes() {
    if ! is_linux; then
        pass "file owners not checked (not Linux)"
        return
    fi
    check_mode "$SECRETS_DIR" 700 "$(stat -c %u "$SECRETS_DIR")"
    for name in $GENERATED_SECRETS $EXTERNAL_SECRETS $HOST_ONLY_SECRETS; do
        [ -f "$SECRETS_DIR/$name.txt" ] && check_mode "$SECRETS_DIR/$name.txt" 600 "$(secret_owner "$name")"
    done
    check_mode certs/kura.key 600 0
    for entry in $KEY_OWNERS; do
        check_mode "$CERT_DIR/${entry%%:*}.key" 600 "${entry#*:}"
    done
}

# Compare one file's mode and owner with the expected values.
check_mode() {
    if [ ! -e "$1" ]; then
        fail "$1 is missing"
        return
    fi
    actual=$(stat -c '%a %u' "$1")
    if [ "$actual" = "$2 $3" ]; then
        pass "$1 is mode $2, owner $3"
    else
        fail "$1 is mode/owner $actual, expected $2 $3"
    fi
}

# Every certificate must be valid for more than 7 more days.
check_cert_expiry() {
    for cert in certs/kura.crt "$CERT_DIR/ca.crt" $(for n in $INTERNAL_CERTS; do echo "$CERT_DIR/$n.crt"; done); do
        if [ ! -f "$cert" ]; then
            fail "$cert is missing"
        elif openssl x509 -checkend 604800 -noout -in "$cert" > /dev/null; then
            pass "$cert is valid for more than 7 days"
        else
            fail "$cert expires within 7 days"
        fi
    done
}

# Only nginx may publish ports on all interfaces, and only 80 (redirect) and
# 443. Grafana must be exactly 127.0.0.1:3000 and the CrowdSec API stays on loopback; Prometheus, Loki and Alertmanager must publish no port.
check_published_ports() {
    ports=$(docker compose --profile tools config --format json 2>/dev/null | python3 -c '
import json, sys
config = json.load(sys.stdin)
for name, service in config["services"].items():
    for port in service.get("ports", []):
        print(name, port.get("host_ip") or "0.0.0.0", port.get("published", ""), port.get("target"))
')
    if [ -z "$ports" ]; then
        fail "could not read the published ports"
        return
    fi
    bad=0
    while read -r service host_ip published target; do
        case "$service:$host_ip:$published" in
            grafana:127.0.0.1:3000|nginx:0.0.0.0:80|nginx:0.0.0.0:443|crowdsec:127.0.0.1:8085) ;;
            *) fail "$service publishes $host_ip:$published -> $target (not allowed)"; bad=1 ;;
        esac
    done <<EOF
$ports
EOF
    if ! echo "$ports" | grep -q '^grafana 127.0.0.1 3000 3000$'; then
        fail "grafana must publish 127.0.0.1:3000"
        bad=1
    fi
    [ "$bad" = 0 ] && pass "published ports: only nginx 80 and 443 on all interfaces; Grafana 127.0.0.1:3000; CrowdSec API on loopback"
    return 0
}

# On the VM, the live sshd settings must match docker/ssh/kura-sshd.conf.
# Skipped where sshd is not installed (for example a development machine).
check_sshd() {
    if ! command -v sshd > /dev/null 2>&1 || ! sshd -T > /tmp/kura-sshd.$$ 2>/dev/null; then
        echo "[note] sshd not found or not readable here: SSH settings not checked (run preflight on the VM)"
        rm -f /tmp/kura-sshd.$$
        return
    fi
    for setting in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no" \
                   "pubkeyauthentication yes" "maxauthtries 3" "logingracetime 30" \
                   "x11forwarding no" "allowagentforwarding no" "gatewayports no" "permittunnel no" \
                   "allowtcpforwarding no" "permitopen none" "pubkeyacceptedalgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com"; do
        if grep -qx "$setting" /tmp/kura-sshd.$$; then
            pass "sshd: $setting"
        else
            fail "sshd: expected '$setting'"
        fi
    done
    if grep -q '^allowusers ' /tmp/kura-sshd.$$; then
        pass "sshd: AllowUsers is set"
    else
        fail "sshd: AllowUsers is not set"
    fi
    rm -f /tmp/kura-sshd.$$
}

# health

# Container health states, the HTTPS site through nginx, and Grafana's health endpoint.
# Read-only.
# Exits non-zero when anything is unhealthy.
cmd_health() {
    PASSED=0
    FAILED=0
    # Every running container must be healthy (or have no health check).
    # "|" separates the fields because Health is empty without a health check.
    docker compose ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' > /tmp/kura-health.$$
    while IFS='|' read -r service state health exit_code; do
        if [ "$state" = "running" ] && { [ "$health" = "healthy" ] || [ -z "$health" ]; }; then
            pass "$service is running${health:+ ($health)}"
        else
            fail "$service is $state${health:+ ($health)}"
        fi
    done < /tmp/kura-health.$$
    rm -f /tmp/kura-health.$$

    # The site through nginx on port 443 (self-signed certificate, so -k).
    code=$(curl -k -s -o /dev/null -w '%{http_code}' https://127.0.0.1/login/ || true)
    case "$code" in
        200|301|302) pass "https://127.0.0.1/login/ answers ($code)" ;;
        *) fail "https://127.0.0.1/login/ answered ${code:-nothing}" ;;
    esac

    # Grafana's health endpoint on loopback (the SSH tunnel's target).
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health || true)
    if [ "$code" = "200" ]; then
        pass "http://127.0.0.1:3000/api/health answers (200)"
    else
        fail "http://127.0.0.1:3000/api/health answered ${code:-nothing}"
    fi

    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo "HEALTH OK ($PASSED checks)"
    else
        echo "HEALTH FAIL ($FAILED failed)"
        exit 1
    fi
}

# setup

# One-command first setup on a fresh VM.
# Each step skips what is already done, so it is safe to run again after fixing a problem.
cmd_setup() {
    need_root setup

    # Prerequisites: Docker, Compose v2 or newer, OpenSSL, python3 and curl.
    say "Checking prerequisites..."
    command -v docker > /dev/null || die "docker is not installed."
    compose_version=$(docker compose version --short 2>/dev/null || true)
    case "$compose_version" in
        ""|1.*) die "Docker Compose v2 or newer is required (docker compose version)." ;;
    esac
    command -v openssl > /dev/null || die "openssl is not installed."
    command -v python3 > /dev/null || die "python3 is not installed."
    command -v curl > /dev/null || die "curl is not installed."
    skip "prerequisites present (Compose $compose_version)"

    cmd_secrets
    cmd_certs
    # Setup never replaces an existing CA; only a fresh VM gets bootstrap certificates.
    if [ -f "$CERT_DIR/ca.crt" ]; then
        skip "internal certificates already exist ($CERT_DIR/ca.crt)"
    else
        cmd_mtls_bootstrap
    fi

    # Build the images Kura builds itself (web and nginx).
    if ! planned "build the local images"; then
        docker compose build
    fi

    # The database must be up before Vault can create its roles.
    if ! planned "start db and wait until healthy"; then
        docker compose up -d --wait db
    fi

    # Migrate as kura_migrator through the web entrypoint before Vault exists.
    if ! planned "run migrations as kura_migrator"; then
        docker compose run --rm --no-deps web migrate-only
    fi

    # A new, empty Docker volume belongs to root.
    # Loki (UID 10001) and the second pgBackRest repository (postgres, UID 26) cannot write to it, so Loki would crash on start and stanza-create would fail.
    # Give each its owner.
    if ! planned "give the Loki volume to UID 10001 and the second backup repository to UID 26"; then
        docker compose up --no-start loki
        fix_volume_owner loki /var/loki 10001:10001
        fix_volume_owner db /var/lib/pgbackrest-offsite 26:26
    fi

    # Create the pgBackRest stanza in both repositories (safe to repeat), so WAL archiving works from the start, then check archiving end to end.
    if ! planned "create the pgBackRest stanza and run pgbackrest check"; then
        docker compose exec -T db pgbackrest --stanza=kura stanza-create
        docker compose exec -T db pgbackrest --stanza=kura check
    fi

    # Vault, then its one-time setup (which issues the certificates from Vault).
    if ! planned "start vault"; then
        docker compose up -d vault
        # Give Vault up to 20 seconds to answer before asking for its status.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if vault_cli status -format=json 2>/dev/null | grep -q '"initialized"'; then
                break
            fi
            sleep 2
        done
    fi
    cmd_vault_init
    if [ "$DRY_RUN" = 0 ] && vault_cli status -format=json 2>/dev/null | grep -q '"sealed": true'; then
        die "Vault is sealed. Unseal it, then run setup again:  docker compose exec vault vault operator unseal"
    fi

    # Start the whole stack and wait until healthy.
    if ! planned "start the stack and wait until healthy"; then
        docker compose up -d --wait
    fi

    cmd_grafana_users
    # The bouncer is a host package; setup skips it when the package is not installed.
    if command -v crowdsec-firewall-bouncer > /dev/null 2>&1; then
        cmd_firewall_bouncer
    else
        skip "crowdsec-firewall-bouncer-nftables not installed (see docker/nftables/README.md, then run: sudo ./kura.sh firewall-bouncer)"
    fi
    if ! planned "run the health checks"; then
        cmd_health
    fi
}

# firewall-bouncer

# Install the CrowdSec nftables firewall bouncer's configuration and enable its service.
# It copies bans from CrowdSec's Local API (127.0.0.1:8085) into the kura_host nftables sets.
# The API key comes from secrets/crowdsec_bouncer_key.txt and is never printed.
# Needs the crowdsec-firewall-bouncer-nftables package (apt) and the rules from docker/nftables/kura.nft loaded.
# Safe to repeat: the file is rewritten only when its content would change.
cmd_firewall_bouncer() {
    need_root firewall-bouncer
    template="docker/crowdsec/crowdsec-firewall-bouncer.yaml"
    target="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    [ -f "$SECRETS_DIR/crowdsec_bouncer_key.txt" ] || die "Missing $SECRETS_DIR/crowdsec_bouncer_key.txt (run: sudo ./kura.sh secrets)."
    if ! command -v crowdsec-firewall-bouncer > /dev/null 2>&1; then
        die "Package crowdsec-firewall-bouncer-nftables is not installed (see docker/nftables/README.md)."
    fi
    if planned "write $target (mode 600, root) and enable crowdsec-firewall-bouncer"; then
        return 0
    fi
    # Put the key into a copy of the template; awk reads it from the environment so it never appears in a command line.
    new_file=$(mktemp)
    chmod 600 "$new_file"
    BOUNCER_KEY=$(read_secret crowdsec_bouncer_key) awk '
        /^api_key:/ { print "api_key: \"" ENVIRON["BOUNCER_KEY"] "\""; next }
        { print }' "$template" > "$new_file"
    if [ -f "$target" ] && cmp -s "$new_file" "$target"; then
        skip "$target is up to date"
    else
        install -d -m 755 "$(dirname "$target")"
        install -o root -g root -m 600 "$new_file" "$target"
        say "Wrote $target"
    fi
    rm -f "$new_file"
    # The bouncer only fills sets that already exist, so start it only once the Kura rules are loaded.
    if nft list table inet kura_host > /dev/null 2>&1; then
        systemctl enable --now crowdsec-firewall-bouncer
        systemctl restart crowdsec-firewall-bouncer
        say "crowdsec-firewall-bouncer enabled and running"
    else
        systemctl enable crowdsec-firewall-bouncer
        say "Enabled crowdsec-firewall-bouncer but did not start it: table inet kura_host is not loaded (apply docker/nftables/kura.nft, then run this again)."
    fi
}

# app-metrics

# Save Kura's application counts (manage.py write_app_metrics) as a metrics file for Alloy's textfile collector.
# Writes to a temporary file first and then renames it, so Alloy never reads half a file.
cmd_app_metrics() {
    if planned "write \${KURA_METRICS_DIR:-/var/lib/kura-metrics}/kura_app.prom"; then
        return 0
    fi
    metrics_directory=${KURA_METRICS_DIR:-/var/lib/kura-metrics}
    mkdir -p "$metrics_directory"
    docker compose exec -T -u 10001:10001 web python manage.py write_app_metrics > "$metrics_directory/kura_app.prom.tmp"
    chmod 0644 "$metrics_directory/kura_app.prom.tmp"
    mv -f "$metrics_directory/kura_app.prom.tmp" "$metrics_directory/kura_app.prom"
}

# egress-refresh

# Resolve Gmail SMTP and HaveIBeenPwned to IP addresses and add them to the host firewall
# egress allowlists, with a 2-hour timeout so stale entries expire. Safe to run while the
# stack is up: adding elements never replaces the table.
# Needs root on Linux (nftables) and the kura_host table already loaded.
cmd_egress_refresh() {
    need_root egress-refresh
    is_linux || die "egress-refresh is Linux only (nftables)."
    for name in smtp.gmail.com api.pwnedpasswords.com; do
        case "$name" in
            smtp.gmail.com) set="egress_smtp" ;;
            api.pwnedpasswords.com) set="egress_hibp" ;;
        esac
        for ip in $(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u); do
            [ -n "$ip" ] || continue
            if planned "add $ip to inet kura_host $set (timeout 2h)"; then
                continue
            fi
            nft add element inet kura_host "$set" "{ $ip timeout 2h }" 2>/dev/null || true
        done
    done
    say "Egress allowlists refreshed"
}

# restore-drill

# SAFE restore drill: restores the backups into a THROWAWAY database and compares it with the live one.
# The live database is never touched.
# - the restore runs in a separate container with NO network (--network none)
# - into its own new, empty volume (kura_restore_drill_<time>)
# - with WAL archiving OFF, so the drill can never write into the backup repo
# - the backup repository volume is mounted READ-ONLY At the end it prints row counts from the live and the restored database and how long the restore took (the "RTO").
# Remove the drill volume afterwards with the command it prints.
cmd_restore_drill() {
    need_root restore-drill
    TARGET_TIME=${1:-latest}
    if planned "restore backup ($TARGET_TIME) into a new throwaway volume and compare row counts"; then
        return 0
    fi
    IMAGE=$(docker compose config --images db | head -1)
    DRILL_VOLUME="kura_restore_drill_$(date +%Y%m%d%H%M%S)"
    DRILL_CONTAINER="kura-restore-drill"
    if docker container inspect "$DRILL_CONTAINER" > /dev/null 2>&1; then
        die "$DRILL_CONTAINER already exists. Inspect it, then rename or remove it before another drill."
    fi
    START_SECONDS=$(date +%s)

    # The tables compared between live and restored databases (counts only).
    TABLES="users courses enrollments assessments grades outgoing_emails"

    # 1. A new empty volume for the restored data, owned by the image's postgres user (UID 26).
    docker volume create "$DRILL_VOLUME" > /dev/null
    docker run --rm -v "$DRILL_VOLUME":/restore --entrypoint sh "$IMAGE" -c 'chown 26:26 /restore && chmod 700 /restore' > /dev/null 2>&1 || \
        docker run --rm --user 0 -v "$DRILL_VOLUME":/restore --entrypoint sh "$IMAGE" -c 'chown 26:26 /restore && chmod 700 /restore'

    # 2. Restore with pgBackRest into that volume. "--type=time" stops replaying WAL at TARGET_TIME (point-in-time recovery); "latest" replays everything.
    # The options are kept as separate, quoted arguments ("set --"), because the target time contains a space and must stay one argument.
    if [ "$TARGET_TIME" = "latest" ]; then
        set -- --type=default
    else
        set -- --type=time "--target=$TARGET_TIME" --target-action=promote
    fi
    say "[1/3] Restoring backup ($TARGET_TIME) into $DRILL_VOLUME (no network)..."
    docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /var/run/postgresql --tmpfs /var/log/pgbackrest \
        -v "$DRILL_VOLUME":/restore \
        -v kura_postgres_backups:/var/lib/pgbackrest:ro \
        -v "$PWD/docker/postgres/pgbackrest.conf":/etc/pgbackrest/pgbackrest.conf:ro \
        -v "$PWD/docker/postgres/pgbackrest-wrapper.sh":/usr/local/bin/pgbackrest:ro \
        -v "$PWD/secrets/backup_encryption_key.txt":/run/secrets/backup_encryption_key:ro \
        --entrypoint /usr/local/bin/pgbackrest "$IMAGE" \
        --stanza=kura --pg1-path=/restore --lock-path=/tmp "$@" restore > /dev/null

    # Use the key-loading wrapper for WAL recovery; pgBackRest otherwise writes /usr/bin/pgbackrest into the restored config.
    # Send startup errors to Docker logs instead of hiding them inside the restored data folder.
    # The restored copy has no network and cannot write to the read-only backup repository.
    say "[2/3] Starting the restored copy and replaying WAL..."
    docker run -d --name "$DRILL_CONTAINER" --network none --tmpfs /tmp --tmpfs /var/run/postgresql:mode=1777 --tmpfs /var/log/pgbackrest:mode=1777 \
        -v "$DRILL_VOLUME":/restore \
        -v kura_postgres_backups:/var/lib/pgbackrest:ro \
        -v "$PWD/docker/postgres/pgbackrest.conf":/etc/pgbackrest/pgbackrest.conf:ro \
        -v "$PWD/docker/postgres/pgbackrest-wrapper.sh":/usr/local/bin/pgbackrest:ro \
        -v "$PWD/secrets/backup_encryption_key.txt":/run/secrets/backup_encryption_key:ro \
        -v "$PWD/secrets/db_password.txt":/run/secrets/db_password:ro \
        --entrypoint postgres "$IMAGE" \
        -D /restore -c listen_addresses='' -c archive_mode=off -c shared_preload_libraries='' \
        -c 'restore_command=/usr/local/bin/pgbackrest --repo=1 --lock-path=/tmp --pg1-path=/restore --stanza=kura archive-get %f "%p"' \
        -c logging_collector=off \
        -c unix_socket_directories=/var/run/postgresql > /dev/null

    # Wait until recovery is finished and the copy accepts queries (at most 2 minutes).
    RECOVERED=0
    for _ in $(seq 1 60); do
        if docker exec "$DRILL_CONTAINER" sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" psql -h /var/run/postgresql -U kura-admin -d kura -X -q -t -A -c "SELECT pg_is_in_recovery();"' 2>/dev/null | grep -q '^f$'; then
            RECOVERED=1
            break
        fi
        if [ "$(docker inspect --format '{{.State.Running}}' "$DRILL_CONTAINER")" != "true" ]; then
            die "Restored database exited before recovery finished. Inspect: docker logs $DRILL_CONTAINER"
        fi
        sleep 2
    done
    [ "$RECOVERED" = 1 ] || die "Restored database did not finish recovery within 120 seconds. Inspect: docker logs $DRILL_CONTAINER"
    END_SECONDS=$(date +%s)

    # 4. Compare row counts, live vs restored.
    COUNTS_MATCH=1
    say "[3/3] Comparing row counts (live -> restored):"
    for TABLE in $TABLES; do
        LIVE=$(docker compose exec -T db sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" psql -v ON_ERROR_STOP=1 -U kura-admin -d kura -X -q -t -A -c "SELECT count(*) FROM '"$TABLE"';"') || die "Could not query $TABLE in the source database."
        RESTORED=$(docker exec "$DRILL_CONTAINER" sh -c 'PGPASSWORD="$(tr -d "\r\n" < /run/secrets/db_password)" psql -v ON_ERROR_STOP=1 -h /var/run/postgresql -U kura-admin -d kura -X -q -t -A -c "SELECT count(*) FROM '"$TABLE"';"') || die "Could not query $TABLE in the restored database."
        printf '  %-16s %6s -> %s\n' "$TABLE" "$LIVE" "$RESTORED"
        [ "$LIVE" = "$RESTORED" ] || COUNTS_MATCH=0
    done
    if [ "$TARGET_TIME" = "latest" ] && [ "$COUNTS_MATCH" != 1 ]; then
        die "Row counts differ. Recovery completed, but latest-restore verification failed. Source writes or unarchived WAL may explain the difference."
    fi
    echo "Restore + recovery completed in $((END_SECONDS - START_SECONDS)) seconds for this database size."
    if [ "$TARGET_TIME" = "latest" ]; then
        echo "PASS: restored database accepts queries and all compared row counts match."
    else
        echo "Recovery completed; verify the intended historical records separately. Current row counts may differ."
    fi
    echo ""
    echo "The restored copy is still running for inspection:"
    echo "  docker exec -it $DRILL_CONTAINER psql -h /var/run/postgresql -U kura-admin -d kura"
    echo "Remove it when done:"
    echo "  docker rm -f $DRILL_CONTAINER && docker volume rm $DRILL_VOLUME"
}

# Command line

# Options may appear anywhere; the first other word is the command and the rest are its arguments.
COMMAND=""
ARGUMENT=""
for word in "$@"; do
    case "$word" in
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        --reset-password) RESET_PASSWORD=1 ;;
        -h|--help) COMMAND=help ;;
        -*) die "Unknown option: $word (see ./kura.sh help)" ;;
        *)
            if [ -z "$COMMAND" ]; then
                COMMAND=$word
            else
                ARGUMENT=$word
            fi
            ;;
    esac
done

case "$COMMAND" in
    ""|help) cmd_help ;;
    setup) cmd_setup ;;
    secrets) cmd_secrets ;;
    certs) cmd_certs ;;
    mtls-bootstrap) cmd_mtls_bootstrap ;;
    vault-init) cmd_vault_init ;;
    vault-add-name) cmd_vault_add_name "$ARGUMENT" ;;
    renew-certs) cmd_renew_certs ;;
    grafana-users) cmd_grafana_users ;;
    preflight) cmd_preflight ;;
    health) cmd_health ;;
    firewall-bouncer) cmd_firewall_bouncer ;;
    app-metrics) cmd_app_metrics ;;
    egress-refresh) cmd_egress_refresh ;;
    restore-drill) cmd_restore_drill "$ARGUMENT" ;;
    *) die "Unknown command: $COMMAND (see ./kura.sh help)" ;;
esac

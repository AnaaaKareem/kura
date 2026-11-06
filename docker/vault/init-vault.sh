#!/bin/sh
# ==============================================================================
# One-time Vault setup for Kura. Run it ON THE HOST from the project folder,
# after the database is up and migrated and Vault is started:
#     docker compose up -d db && docker compose run --rm migrate
#     docker compose up -d vault
#
#     sh docker/vault/init-vault.sh
#
# What it does:
#   1. Initialises Vault and shows the unseal key ONCE, straight away. Nothing
#      is saved to disk.
#   2. Unseals Vault.
#   3. Turns on the audit log (every request, with secrets hashed) to the
#      container output, so it can be collected with the other logs.
#   4. Creates the "kura-mfa" encryption key (Transit engine, AES-256-GCM).
#   5. Sets up temporary database users (database engine): prepares the
#      PostgreSQL roles, connects Vault as vault_admin, then changes
#      vault_admin's password so only Vault knows it.
#   6. Creates the "kura-web" policy and an AppRole login for Django, and writes
#      Django's role ID and secret ID to secrets/ (Docker secrets).
#   7. Creates Kura's certificate authority inside Vault: a root CA that only
#      signs an intermediate CA, which signs the service certificates. Neither
#      private key can ever leave Vault.
#   8. Creates the "kura-cert-issuer" AppRole for certs/renew-certs-from-vault.sh
#      and writes its login to secrets/ (host only, never mounted in a container).
#   9. Revokes the root token, so no all-powerful token is left anywhere.
#  10. Runs certs/renew-certs-from-vault.sh: every service switches from the
#      bootstrap openssl certificates to certificates issued by Vault.
#
# It refuses to run twice: initialising again would throw away every key.
# ==============================================================================
set -e

# Work from the project folder so "docker compose" finds docker-compose.yml.
cd "$(dirname "$0")/../.."

# Run the vault command line tool inside the Vault container.
vault_cli() {
    docker compose exec -T vault vault "$@"
}

# The same, but logged in with the temporary root token (set in step 1).
vault_root() {
    docker compose exec -T -e VAULT_TOKEN="$ROOT_TOKEN" vault vault "$@"
}

# 0. Never initialise twice. "vault status" exits with 2 while sealed, so its
#    exit code is ignored and only the "initialized" line is checked.
STATUS=$(vault_cli status -format=json || true)
if echo "$STATUS" | grep -q '"initialized": true'; then
    echo "Vault is already initialised. Nothing to do."
    echo "After a restart, unseal it with:  docker compose exec vault vault operator unseal"
    exit 0
fi
if ! echo "$STATUS" | grep -q '"initialized"'; then
    echo "Cannot reach Vault. Start it first:  docker compose up -d vault" >&2
    exit 1
fi

# 1. Initialise with one unseal key. Vault returns JSON; we pick out the unseal
#    key and the root token with grep (no extra tools needed on the host).
echo "[1/9] Initialising Vault..."
INIT_JSON=$(vault_cli operator init -key-shares=1 -key-threshold=1 -format=json)
UNSEAL_KEY=$(echo "$INIT_JSON" | grep -A1 '"unseal_keys_b64"' | tail -n 1 | tr -d ' ",')
ROOT_TOKEN=$(echo "$INIT_JSON" | grep '"root_token"' | cut -d'"' -f4)
if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
    echo "Could not read the unseal key or root token from Vault's answer." >&2
    echo "Vault's answer was:" >&2
    echo "$INIT_JSON" >&2
    exit 1
fi

# Show the unseal key straight away. If any later step fails, the key is
# already on screen: without it, this Vault could never be opened again.
echo ""
echo "=============================================================================="
echo " UNSEAL KEY (shown only this once, NOT saved anywhere). Store it in your"
echo " password manager now:"
echo ""
echo "     $UNSEAL_KEY"
echo "=============================================================================="
echo ""

# If a later step fails, also show the root token, so the remaining steps can
# be finished by hand. On success the token is revoked and never shown.
show_root_token_on_failure() {
    if [ $? -ne 0 ]; then
        echo "" >&2
        echo "Setup stopped early. The ROOT TOKEN is needed to finish by hand:" >&2
        echo "     $ROOT_TOKEN" >&2
        echo "Revoke it afterwards:  vault token revoke <root token>" >&2
    fi
}
trap show_root_token_on_failure EXIT

# 2. Unseal by writing the key to Vault's unseal endpoint. "key=-" makes the
#    vault tool read the key from standard input instead of the command line,
#    so the key does not appear in the container's process list.
echo "[2/9] Unsealing Vault..."
printf '%s' "$UNSEAL_KEY" | vault_cli write sys/unseal key=- > /dev/null

# 3. Audit log: one JSON line per request on the container output. Vault
#    replaces secret values with HMAC hashes before writing them.
echo "[3/9] Turning on the audit log..."
vault_root audit enable file file_path=stdout > /dev/null

# 4. Transit engine and the key that encrypts authenticator seeds. Vault keeps
#    the key inside; Django can only ask Vault to use it.
echo "[4/9] Creating the kura-mfa encryption key..."
vault_root secrets enable transit > /dev/null
vault_root write -f transit/keys/kura-mfa type=aes256-gcm96 > /dev/null

# 5. Temporary database users.
echo "[5/9] Setting up temporary database users..."

#    a) In PostgreSQL (as kura-admin through the container's local socket):
#       make kura_app NOLOGIN and create vault_admin (docker/postgres/vault-roles.sql).
docker compose exec -T db psql -q -U kura-admin -d kura -v ON_ERROR_STOP=1 < docker/postgres/vault-roles.sql > /dev/null

#    b) Give vault_admin a random first password. It only lives for a moment:
#       step d) replaces it with one that only Vault knows.
FIRST_PASSWORD=$(openssl rand -hex 24)
printf "ALTER ROLE vault_admin WITH PASSWORD '%s';\n" "$FIRST_PASSWORD" | \
    docker compose exec -T db psql -q -U kura-admin -d kura -v ON_ERROR_STOP=1

#    c) Connect Vault's database engine to PostgreSQL:
#       - TLS with the database certificate checked (verify-full) and Vault's
#         own certificate as the client certificate (pg_hba.conf requires it).
#       - password_authentication=scram-sha-256: Vault sends PostgreSQL a
#         hash, never the plain password, so the pgAudit log of "CREATE ROLE"
#         never contains a usable password.
#       - Temporary users are named kura_dyn_<20 random characters>.
#       The first password is read from standard input ("password=-").
vault_root secrets enable database > /dev/null
printf '%s' "$FIRST_PASSWORD" | vault_root write database/config/kura-postgresql \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@db:5432/kura?sslmode=verify-full&sslrootcert=/vault/tls/ca.crt&sslcert=/vault/tls/vault.crt&sslkey=/vault/tls/vault.key" \
    username=vault_admin \
    password=- \
    password_authentication=scram-sha-256 \
    username_template='kura_dyn_{{random 20 | lowercase}}' \
    allowed_roles=kura-app > /dev/null

#    d) "rotate-root": Vault changes vault_admin's password to a new random one
#       that it never shows to anyone.
vault_root write -f database/rotate-root/kura-postgresql > /dev/null

#    e) The "kura-app" role: each request makes a new user that can log in for
#       15 minutes and gets kura_app's permissions (IN ROLE kura_app). When the
#       15 minutes are up, Vault drops the user.
vault_root write database/roles/kura-app \
    db_name=kura-postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE kura_app;" \
    revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl=15m \
    max_ttl=15m > /dev/null

# 6. Policy and AppRole for Django.
#    token_type=batch: login tokens are not stored by Vault, so logging in for
#    every request does not fill up Vault's storage.
#    token_ttl=15m: a stolen token stops working after 15 minutes.
echo "[6/9] Creating Django's policy and AppRole login..."
vault_root policy write kura-web /vault/policies/kura-web.hcl > /dev/null
vault_root auth enable approle > /dev/null
vault_root write auth/approle/role/kura-web \
    token_policies=kura-web \
    token_type=batch \
    token_ttl=15m \
    token_max_ttl=15m > /dev/null

# Write Django's two login values into Docker secret files (folder is 700,
# files 644 so the non-root Django user can read its mounted copy).
umask 022
vault_root read -field=role_id auth/approle/role/kura-web/role-id > secrets/vault_role_id.txt
vault_root write -f -field=secret_id auth/approle/role/kura-web/secret-id > secrets/vault_secret_id.txt

# 7. Kura's certificate authority (PKI engine), in two levels:
#    - "pki": the ROOT CA, valid 10 years. Its only job is to sign the
#      intermediate CA below, so it is almost never used.
#    - "pki_int": the INTERMEDIATE CA, valid 5 years. It signs every service
#      certificate. If it were ever compromised it could be replaced without
#      changing ca.crt (the root) in every service.
#    "generate/internal" means the private key is created inside Vault and can
#    never be exported. certs/ca/ca.key (the openssl bootstrap CA) is no longer
#    needed after step 10.
echo "[7/9] Creating Kura's certificate authority (root + intermediate)..."
vault_root secrets enable -path=pki pki > /dev/null
vault_root secrets tune -max-lease-ttl=87600h pki > /dev/null
vault_root write -field=certificate pki/root/generate/internal \
    common_name="Kura Internal Root CA" key_type=ec key_bits=384 ttl=87600h > /dev/null

vault_root secrets enable -path=pki_int pki > /dev/null
vault_root secrets tune -max-lease-ttl=43800h pki_int > /dev/null
# The intermediate makes a signing request (CSR), the root signs it, and the
# signed certificate is loaded back into the intermediate. Each step reads the
# previous step's output on standard input ("=-").
INTERMEDIATE_CSR=$(vault_root write -field=csr pki_int/intermediate/generate/internal \
    common_name="Kura Internal Intermediate CA" key_type=ec key_bits=384)
INTERMEDIATE_CERT=$(echo "$INTERMEDIATE_CSR" | vault_root write -field=certificate pki/root/sign-intermediate \
    csr=- format=pem_bundle ttl=43800h)
echo "$INTERMEDIATE_CERT" | vault_root write pki_int/intermediate/set-signed certificate=- > /dev/null

# The only kind of certificate the intermediate may issue: one of Kura's seven
# service names (alloy = the metrics collector's PostgreSQL login) (plus localhost / 127.0.0.1 for health checks inside a
# container), for at most 1 year, usable as both server and client certificate.
vault_root write pki_int/roles/kura-service \
    allowed_domains="nginx,waf,web,db,vault,relay,alloy,netbird.kura.lan,localhost" \
    allow_bare_domains=true \
    allow_subdomains=false \
    allow_wildcard_certificates=false \
    allow_ip_sans=true \
    server_flag=true \
    client_flag=true \
    key_type=ec \
    key_bits=256 \
    max_ttl=8760h > /dev/null

# 8. The renewal script's own login. Its policy may ONLY issue certificates
#    with the kura-service role (docker/vault/policies/kura-cert-issuer.hcl).
#    The login stays on the host in secrets/ with mode 600 (owner only).
echo "[8/9] Creating the certificate renewal AppRole..."
vault_root policy write kura-cert-issuer /vault/policies/kura-cert-issuer.hcl > /dev/null
vault_root write auth/approle/role/kura-cert-issuer \
    token_policies=kura-cert-issuer \
    token_type=batch \
    token_ttl=10m \
    token_max_ttl=10m > /dev/null
umask 077
vault_root read -field=role_id auth/approle/role/kura-cert-issuer/role-id > secrets/vault_issuer_role_id.txt
vault_root write -f -field=secret_id auth/approle/role/kura-cert-issuer/secret-id > secrets/vault_issuer_secret_id.txt
umask 022

# 9. Revoke the root token. If full admin access is ever needed again, a new
#    root token can be made with the unseal key ("vault operator generate-root").
echo "[9/9] Revoking the root token..."
vault_root token revoke -self > /dev/null
trap - EXIT

# 10. Switch every service to certificates issued by Vault.
echo ""
echo "Switching all services to certificates issued by Vault..."
sh certs/renew-certs-from-vault.sh

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

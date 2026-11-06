#!/bin/sh
# ==============================================================================
# Renews Kura's internal mTLS certificates from Vault's certificate authority.
#
# Run it on the host from the project folder (on the Linux VM as root, because
# each private key belongs to the container user that reads it):
#
#     sudo sh certs/renew-certs-from-vault.sh
#
# Schedule it weekly (root crontab), e.g. every Monday at 03:30:
#     30 3 * * 1  cd /path/to/kura && sh certs/renew-certs-from-vault.sh
#
# What it does:
#   1. Logs in to Vault with the "kura-cert-issuer" AppRole (secrets/, host only).
#   2. Asks Vault's intermediate CA for a new certificate and key for each
#      service: 30 days for nginx, waf, web, db and relay; 1 year for Vault itself (so
#      Vault's own certificate cannot expire during a long sealed period).
#   3. Only when ALL of them were issued, writes them over the old files IN
#      PLACE. (docker-compose.yml mounts single files; replacing a file with a
#      new one would leave the container looking at the old one.)
#   4. Reloads each running service so it picks up its new certificate without
#      downtime.
#   5. Deletes the openssl bootstrap CA key (certs/ca/), which nothing trusts
#      any more: ca.crt is now Vault's root CA.
# Vault must be unsealed. Nothing is changed if any step before 3 fails.
# ==============================================================================
set -e

# Work from the project folder so "docker compose" finds docker-compose.yml.
cd "$(dirname "$0")/.."
CERT_DIR="certs/internal"

# On Linux the key files belong to container users (see the chown list below),
# so only root can overwrite them.
if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" != "0" ]; then
    echo "Run this as root on Linux:  sudo sh certs/renew-certs-from-vault.sh" >&2
    exit 1
fi

# New certificates and keys are first written to a private temporary folder
# (umask 077: owner only) that is always deleted at the end.
umask 077
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# 1. Log in. The secret ID goes in on standard input, so it is not visible in
#    the process list. The returned token lives for 10 minutes.
echo "[1/5] Logging in to Vault as kura-cert-issuer..."
ROLE_ID=$(cat secrets/vault_issuer_role_id.txt)
ISSUER_TOKEN=$(docker compose exec -T vault vault write -field=token auth/approle/login \
    role_id="$ROLE_ID" secret_id=- < secrets/vault_issuer_secret_id.txt)

# Ask the intermediate CA for one certificate. Vault answers in JSON; python3
# (standard library only) picks out the parts:
#   <name>.crt = the certificate followed by the intermediate CA certificate
#                (the "chain", so others can link it back to the root CA)
#   <name>.key = the private key, created by Vault and shown only this once
issue_certificate() {
    NAME=$1
    DNS_NAMES=$2
    LIFETIME=$3
    docker compose exec -T -e VAULT_TOKEN="$ISSUER_TOKEN" vault vault write -format=json \
        pki_int/issue/kura-service \
        common_name="${DNS_NAMES%%,*}" alt_names="$DNS_NAMES" ip_sans=127.0.0.1 ttl="$LIFETIME" > "$WORK_DIR/$NAME.json"
    python3 -c 'import json, sys; data = json.load(open(sys.argv[1]))["data"]; print(data["certificate"]); print(data["issuing_ca"])' \
        "$WORK_DIR/$NAME.json" > "$WORK_DIR/$NAME.crt"
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["data"]["private_key"])' \
        "$WORK_DIR/$NAME.json" > "$WORK_DIR/$NAME.key"
    rm "$WORK_DIR/$NAME.json"
}

# 2. Issue all five. "localhost" and 127.0.0.1 are for health checks that run
#    inside the container itself.
echo "[2/5] Issuing new certificates..."
issue_certificate nginx "nginx" 720h
issue_certificate waf "waf" 720h
issue_certificate web "web,localhost" 720h
issue_certificate db "db,localhost" 720h
issue_certificate vault "vault,localhost" 8760h
issue_certificate relay "relay" 720h
issue_certificate alloy "alloy" 720h
# The NetBird VPN server's public name on the LAN (file: netbird.crt / netbird.key).
issue_certificate netbird "netbird.kura.lan" 720h
# The root CA certificate becomes ca.crt: the one thing every service trusts.
# (Reading it needs no login: it is public.)
docker compose exec -T vault vault read -field=certificate pki/cert/ca > "$WORK_DIR/ca.crt"

# Stop here, before touching anything, unless every file looks right.
for FILE in ca.crt nginx.crt waf.crt web.crt db.crt vault.crt relay.crt alloy.crt netbird.crt; do
    grep -q "BEGIN CERTIFICATE" "$WORK_DIR/$FILE" || { echo "Vault returned a bad $FILE" >&2; exit 1; }
done
for FILE in nginx.key waf.key web.key db.key vault.key relay.key alloy.key netbird.key; do
    grep -q "PRIVATE KEY" "$WORK_DIR/$FILE" || { echo "Vault returned a bad $FILE" >&2; exit 1; }
done

# 3. Write the new files over the old ones IN PLACE ("cat new > old" keeps the
#    same file, so the containers' single-file mounts see the new content).
echo "[3/5] Installing the new certificates..."
for FILE in ca.crt nginx.crt waf.crt web.crt db.crt vault.crt relay.crt alloy.crt netbird.crt nginx.key waf.key web.key db.key vault.key relay.key alloy.key netbird.key; do
    if [ ! -f "$CERT_DIR/$FILE" ]; then
        touch "$CERT_DIR/$FILE"
    fi
    cat "$WORK_DIR/$FILE" > "$CERT_DIR/$FILE"
done
chmod 0644 "$CERT_DIR"/*.crt
chmod 0600 "$CERT_DIR"/*.key

# On Linux, each key must belong to the container user that reads it (same
# list as certs/generate_internal_mtls_certs.sh).
if [ "$(uname -s)" = "Linux" ]; then
    chown 26 "$CERT_DIR/db.key"       # "postgres" in the pgEdge image
    chown 10001 "$CERT_DIR/web.key"   # "kura" in our Dockerfile
    chown 101 "$CERT_DIR/waf.key"     # "nginx" in the Coraza WAF image
    chown 0 "$CERT_DIR/nginx.key"     # Nginx reads its keys as root
    chown 100 "$CERT_DIR/vault.key"   # "vault" in the HashiCorp Vault image
    chown 0 "$CERT_DIR/relay.key"     # Postfix reads its key as root
    chown 473 "$CERT_DIR/alloy.key"   # "alloy" user in the Grafana Alloy image
    chown 0 "$CERT_DIR/netbird.key"   # NetBird's nginx reads its key as root
fi

# 4. Tell each running service to load its new certificate. A service that is
#    not running simply reads the new files when it next starts.
echo "[4/5] Reloading services..."
is_running() {
    docker compose ps --status running --services | grep -qx "$1"
}
if is_running db; then
    docker compose exec -T db psql -q -U kura-admin -d kura -c "SELECT pg_reload_conf();" > /dev/null
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
if is_running relay; then
    docker compose exec -T relay postfix reload
    echo "      relay: postfix reloaded"
fi
if is_running netbird-proxy; then
    docker compose exec -T netbird-proxy nginx -s reload
    echo "      netbird-proxy: reloaded"
fi
if is_running web; then
    docker compose kill -s SIGHUP web > /dev/null 2>&1
    echo "      web: sent SIGHUP (Gunicorn starts new workers with the new certificate)"
fi

# 5. The openssl bootstrap CA is no longer trusted by anything (ca.crt is now
#    Vault's root), so its private key is deleted.
echo "[5/5] Removing the openssl bootstrap CA key..."
rm -f certs/ca/ca.key certs/ca/ca.srl

# Record each certificate's expiry time for Prometheus (InternalCertExpiring
# alert). Same folder and write-then-rename pattern as the other metric files.
# A missing metrics folder must not make the renewal itself look failed: the
# certificates are already installed at this point, so only warn.
metrics_directory=${KURA_METRICS_DIR:-/var/lib/kura-metrics}
if ! mkdir -p "$metrics_directory" 2>/dev/null; then
    echo "WARNING: cannot write metrics to $metrics_directory (set KURA_METRICS_DIR); certificate expiry metrics skipped." >&2
else
{
    echo "# HELP kura_cert_expiry_timestamp_seconds When each internal certificate expires (Unix time)."
    echo "# TYPE kura_cert_expiry_timestamp_seconds gauge"
    for NAME in nginx waf web db vault relay alloy netbird; do
        EXPIRY_TEXT=$(openssl x509 -noout -enddate -in "$CERT_DIR/$NAME.crt" | cut -d= -f2)
        EXPIRY_SECONDS=$(python3 -c 'import sys, email.utils, datetime; print(int(datetime.datetime.strptime(sys.argv[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()))' "$EXPIRY_TEXT")
        echo "kura_cert_expiry_timestamp_seconds{service=\"$NAME\"} $EXPIRY_SECONDS"
    done
} > "$metrics_directory/kura_certs.prom.tmp"
# This script runs with umask 077 (for the keys); the metrics file holds only
# expiry dates, and Alloy (another user) must be able to read it.
chmod 0644 "$metrics_directory/kura_certs.prom.tmp"
mv -f "$metrics_directory/kura_certs.prom.tmp" "$metrics_directory/kura_certs.prom"
fi

echo ""
echo "Done. Certificates now expire on:"
for NAME in nginx waf web db vault relay alloy netbird; do
    printf '  %-6s %s\n' "$NAME" "$(openssl x509 -noout -enddate -in "$CERT_DIR/$NAME.crt" | cut -d= -f2)"
done

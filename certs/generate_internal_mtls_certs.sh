#!/bin/sh
set -e

# ==============================================================================
# BOOTSTRAP ONLY: first internal mTLS certificates for Kura LMS
#
# PostgreSQL and Vault need TLS certificates before Vault can issue any, so on
# a new server this script makes a temporary openssl CA and the first
# certificates. docker/vault/init-vault.sh then switches every service to
# certificates issued by Vault's own CA (certs/renew-certs-from-vault.sh) and
# deletes this bootstrap CA's key. After that, never run this script again:
# renew with  sh certs/renew-certs-from-vault.sh  instead.
#
# Generates a temporary Root CA and service certificates for:
# 1. Nginx (client to the WAF)
# 1b. WAF (server for Nginx, client to Django)
# 2. Web (server for the WAF, client to PostgreSQL)
# 3. PostgreSQL (server for Django)
# 4. Vault (server for Django)
#
# Each container mounts only its own .crt/.key plus ca.crt (docker-compose.yml).
# The CA private key is kept in certs/ca/, which is never mounted.
#
# Requires OpenSSL 3: the CA must carry a Subject Key Identifier so leaf
# certificates can reference it. macOS ships LibreSSL, which omits it, so a
# modern binary is preferred when installed (e.g. Homebrew's openssl@3).
# ==============================================================================

if command -v /opt/homebrew/opt/openssl@3/bin/openssl >/dev/null 2>&1; then
  OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
elif command -v openssl >/dev/null 2>&1; then
  OPENSSL=$(command -v openssl)
  if [ "$($OPENSSL version | cut -d' ' -f1)" != "OpenSSL" ] || \
     [ "$($OPENSSL version | cut -d' ' -f2 | cut -d. -f1)" -lt 3 ]; then
    echo "[-] ERROR: OpenSSL 3 is required (found $($OPENSSL version))." >&2
    echo "    Install e.g. Homebrew openssl@3 and re-run this script." >&2
    exit 1
  fi
else
  echo "[-] ERROR: openssl not found in PATH." >&2
  exit 1
fi

# internal/: certificates and private keys that containers mount (one file at a time).
DIR="$(cd "$(dirname "$0")" && pwd)/internal"
# ca/: the CA private key and serial number. NO container mounts this folder:
# anyone holding ca.key could sign a "kura_app" certificate and log in to PostgreSQL.
CA_DIR="$(cd "$(dirname "$0")" && pwd)/ca"
mkdir -p "$DIR" "$CA_DIR"
chmod 700 "$CA_DIR"

# Remove old keys first. On Linux they belong to container users after the
# last run, so we could not overwrite them, but we can delete them because we
# own the folder.
rm -f "$DIR"/*.key "$DIR"/*.crt "$CA_DIR"/ca.key "$CA_DIR"/ca.srl

echo "[*] Generating Internal Root CA..."
$OPENSSL req -x509 -new -nodes -newkey rsa:4096 -days 3650 \
  -sha256 \
  -keyout "$CA_DIR/ca.key" \
  -out "$DIR/ca.crt" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "subjectKeyIdentifier=hash" \
  -subj "/C=EG/O=Kura/OU=Security/CN=Kura Internal Root CA"

generate_cert() {
  NAME=$1
  CN=$2
  SAN=$3

  echo "[*] Generating certificate for $NAME ($CN)..."
  $OPENSSL req -new -nodes -newkey rsa:2048 \
    -keyout "$DIR/$NAME.key" \
    -out "$DIR/$NAME.csr" \
    -subj "/C=EG/O=Kura/OU=Internal/CN=$CN"

  cat <<EOF > "$DIR/$NAME.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $SAN
EOF

  $OPENSSL x509 -req -in "$DIR/$NAME.csr" \
    -CA "$DIR/ca.crt" \
    -CAkey "$CA_DIR/ca.key" \
    -CAserial "$CA_DIR/ca.srl" \
    -CAcreateserial \
    -out "$DIR/$NAME.crt" \
    -days 365 \
    -extfile "$DIR/$NAME.ext"

  rm -f "$DIR/$NAME.csr" "$DIR/$NAME.ext"
}

# 2. Nginx client/server certificate. Nginx uses it as a CLIENT certificate
# when it connects to the WAF. The WAF only accepts the CN "nginx".
generate_cert "nginx" "nginx" "DNS:nginx,DNS:nginx.kura.internal"

# 2b. Coraza WAF certificate. The WAF uses it as a SERVER certificate (Nginx
# checks the name "waf") and as a CLIENT certificate when it connects to Django.
generate_cert "waf" "waf" "DNS:waf,DNS:waf.kura.internal"

# 3. Web (Django Gunicorn) certificate. It serves TLS to Nginx and acts as the
# database CLIENT certificate. PostgreSQL certificate authentication requires
# the CN to equal the database username, so the CN is kura_app. The SANs keep
# the server names Nginx verifies when proxying to Gunicorn.
generate_cert "web" "kura_app" "DNS:web,DNS:web.kura.internal,DNS:localhost,IP:127.0.0.1"

# 4. Database (PostgreSQL) client/server certificate
generate_cert "db" "db" "DNS:db,DNS:db.kura.internal,DNS:localhost,IP:127.0.0.1"
# 5. Vault server certificate. Django checks the name "vault"; the Vault command
# line tool inside the container checks "127.0.0.1".
generate_cert "vault" "vault" "DNS:vault,DNS:vault.kura.internal,DNS:localhost,IP:127.0.0.1"
# 6. Mail relay (server for Django's email).
generate_cert "relay" "relay" "DNS:relay"
# 7. Alloy (client certificate for its PostgreSQL login as role "alloy").
generate_cert "alloy" "alloy" "DNS:alloy"
# 8. The self-hosted NetBird VPN server (admins reach https://netbird.kura.lan).
generate_cert "netbird" "netbird.kura.lan" "DNS:netbird.kura.lan"

# Fix permissions on private keys
chmod 0600 "$DIR"/*.key "$CA_DIR"/ca.key
chmod 0644 "$DIR"/*.crt

# On Linux, a 0600 key can only be read by its owner. Each container runs as a
# different user, so give every key to the one container user that needs it.
# PostgreSQL also refuses to start unless it owns its key. Other containers
# cannot read keys that are not theirs. (Docker Desktop on macOS ignores file
# owners, so this is only needed on Linux.)
if [ "$(uname -s)" = "Linux" ]; then
  echo "[*] Linux: giving each private key to its container user (needs sudo)..."
  sudo chown 26 "$DIR/db.key"       # "postgres" user in the pgEdge image
  sudo chown 10001 "$DIR/web.key"   # "kura" user in our Dockerfile
  sudo chown 101 "$DIR/waf.key"     # "nginx" user in the Coraza WAF image
  sudo chown 0 "$DIR/nginx.key"     # Nginx reads its keys as root at start-up
  sudo chown 100 "$DIR/vault.key"   # "vault" user in the HashiCorp Vault image
  sudo chown 0 "$DIR/relay.key"     # Postfix reads its key as root
  sudo chown 473 "$DIR/alloy.key"   # "alloy" user in the Grafana Alloy image
  sudo chown 0 "$DIR/netbird.key"   # NetBird's nginx reads its key as root
fi

echo "[+] Internal mTLS certificates generated successfully in $DIR"


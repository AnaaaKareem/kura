#!/bin/sh
# Generate self-signed TLS certificates for local Kura development
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR"

# Remove the old key first (on Linux it belongs to root after the last run).
rm -f "$DIR/kura.key" "$DIR/kura.crt"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$DIR/kura.key" \
  -out "$DIR/kura.crt" \
  -subj "/C=EG/ST=Cairo/L=Cairo/O=Kura/OU=Security/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:web,DNS:nginx,IP:127.0.0.1"

# On Linux the key must belong to root: Nginx reads it as root at start-up and
# has no permission to read files owned by other users (see docker-compose.yml).
chmod 0600 "$DIR/kura.key"
if [ "$(uname -s)" = "Linux" ]; then
  sudo chown 0 "$DIR/kura.key"
fi

echo "TLS certificates generated in $DIR"


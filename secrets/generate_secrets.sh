#!/bin/sh
# Creates the secret files that docker-compose.yml reads from this folder.
#
# Safe to run more than once: a file that already exists is NEVER overwritten,
# so running it again cannot break a database or Vault that is already set up.
# Values are never printed to the screen.
set -e

# Work inside the folder this script lives in (secrets/).
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Permissions:
# - The secrets/ folder is locked to its owner (700), so other users on the
#   host cannot open any file inside it.
# - Each file is 644. Compose mounts the file into the container with the same
#   permissions, and our containers run as non-root users (Django is UID 10001)
#   that are not the file's owner, so they need "read for others" to use it.
chmod 700 "$DIR"
umask 022

# 1. Secrets we can generate ourselves with a cryptographic random generator.
#    "openssl rand -base64 48" gives 48 random bytes (384 bits) as text.
for name in db_password backup_encryption_key django_secret_key \
            crowdsec_bouncer_key grafana_admin_password; do
    file="$name.txt"
    if [ -f "$file" ]; then
        echo "kept      $file (already exists)"
    else
        # tr removes characters that cause trouble in connection strings.
        openssl rand -base64 48 | tr -d '\n/+=' > "$file"
        echo "generated $file"
    fi
done

# 2. Secrets that come from outside services. We cannot generate these, so we
#    create an empty file (Compose refuses to start if the file is missing) and
#    tell the user where the real value comes from.
for entry in \
    "cloudflare_tunnel_token:Cloudflare Zero Trust dashboard > Tunnels" \
    "telegram_bot_token:Telegram @BotFather" \
    "telegram_chat_id:the Telegram chat that receives alerts" \
    "netbird_setup_key:NetBird dashboard > Setup Keys" \
    "smtp_relay_credentials:your mail provider. One line: [smtp.example.com]:587 username:password" \
    "vault_role_id:Vault. docker/vault/init-vault.sh writes it for you" \
    "vault_secret_id:Vault. docker/vault/init-vault.sh writes it for you"; do
    name="${entry%%:*}"
    source="${entry#*:}"
    file="$name.txt"
    if [ -s "$file" ]; then
        echo "kept      $file (already filled in)"
    else
        touch "$file"
        echo "TODO      $file is empty: paste the value from $source"
    fi
done

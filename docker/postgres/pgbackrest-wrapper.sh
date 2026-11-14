#!/bin/sh
# Wrapper placed at /usr/local/bin/pgbackrest ahead of /usr/bin/pgbackrest (W2).
# Loads PGBACKREST_REPO1_CIPHER_PASS from the Docker secret when unset so
# `docker compose exec db pgbackrest ...` and cron jobs use the real secret.
set -eu

KEY_FILE="/run/secrets/backup_encryption_key"
if [ -z "${PGBACKREST_REPO1_CIPHER_PASS:-}" ]; then
    if [ ! -r "$KEY_FILE" ]; then
        echo "ERROR: backup encryption secret not readable at $KEY_FILE" >&2
        exit 1
    fi
    PGBACKREST_REPO1_CIPHER_PASS="$(tr -d '\r\n' < "$KEY_FILE")"
    if [ -z "$PGBACKREST_REPO1_CIPHER_PASS" ]; then
        echo "ERROR: backup encryption secret at $KEY_FILE is empty" >&2
        exit 1
    fi
    export PGBACKREST_REPO1_CIPHER_PASS
fi

exec /usr/bin/pgbackrest "$@"

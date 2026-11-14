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

if [ -z "${PGBACKREST_REPO2_CIPHER_PASS:-}" ] && [ -n "${PGBACKREST_REPO1_CIPHER_PASS:-}" ]; then
    PGBACKREST_REPO2_CIPHER_PASS="$PGBACKREST_REPO1_CIPHER_PASS"
    export PGBACKREST_REPO2_CIPHER_PASS
fi

DB_PASS_FILE="/run/secrets/db_password"
if [ -z "${PGPASSWORD:-}" ] && [ -r "$DB_PASS_FILE" ]; then
    PGPASSWORD="$(tr -d '\r\n' < "$DB_PASS_FILE")"
    export PGPASSWORD
fi

exec /usr/bin/pgbackrest "$@"

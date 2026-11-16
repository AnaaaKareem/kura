#!/bin/sh
# Entrypoint wrapper for the PostgreSQL container (W2).
# Reads the backup encryption passphrase from the Docker secret into PGBACKREST_REPO1_CIPHER_PASS so PostgreSQL's archive_command and restore_command inherit it without putting secrets in pgbackrest.conf.
set -eu

KEY_FILE="/run/secrets/backup_encryption_key"
if [ -r "$KEY_FILE" ]; then
    PGBACKREST_REPO1_CIPHER_PASS="$(tr -d '\r\n' < "$KEY_FILE")"
    PGBACKREST_REPO2_CIPHER_PASS="$PGBACKREST_REPO1_CIPHER_PASS"
    export PGBACKREST_REPO1_CIPHER_PASS PGBACKREST_REPO2_CIPHER_PASS
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"

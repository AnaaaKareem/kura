#!/bin/sh
# Web container start-up: apply database migrations as kura_migrator, then run Gunicorn as the unprivileged kura user.
# This script runs as root with only SETUID and SETGID. The migrator key is readable only by root and group 10002,
# so Gunicorn (which runs without that group) can never read it.
set -eu

KURA_UID=10001
KURA_GID=10001
MIGRATE_GID=10002

# Run one command as kura (with or without the migrator group) and with every capability removed.
as_kura() {
    groups=$1; shift
    exec setpriv --reuid="$KURA_UID" --regid="$KURA_GID" --groups="$groups" \
        --inh-caps=-all --no-new-privs "$@"
}

if [ "${KURA_RUN_MIGRATIONS:-True}" = "True" ]; then
    # Migrations use the migrator login only for this command. Vault and Vault-issued logins are switched off for it.
    ( env DATABASE_USER=kura_migrator VAULT_DATABASE_CREDENTIALS=False VAULT_ENABLED=False \
          DB_SSL_CERT=/certs/internal/migrator.crt DB_SSL_KEY=/certs/internal/migrator.key \
          setpriv --reuid="$KURA_UID" --regid="$KURA_GID" --groups="$MIGRATE_GID" \
              --inh-caps=-all --no-new-privs \
              python manage.py migrate --noinput )
fi

# "migrate-only" lets ./kura.sh setup run migrations before Vault exists (see section 6).
[ "${1:-}" = "migrate-only" ] && exit 0

# Gunicorn: kura only, no migrator group, normal runtime settings from the container environment.
as_kura "$KURA_GID" "$@"

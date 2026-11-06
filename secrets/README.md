# Container Secrets Directory

This directory holds plaintext secret files for local Docker Compose development.
In production or Docker Compose, these files are mounted into containers as read-only files at `/run/secrets/<secret_name>`.

Files matching `*.txt` in this directory are ignored by `.gitignore` and must never be committed to source control.

To create any missing secret files, run `sh secrets/generate_secrets.sh`. It generates
random values for the secrets Kura owns, creates empty placeholders for values that come
from outside services (Cloudflare, Telegram, NetBird, Vault), and never overwrites a file
that already exists. It sets this folder to `700` and the files to `644`: Compose mounts
each file into its container with the host permissions, and the non-root containers
(Django runs as UID 10001) must be able to read their own copy.

- `db_password.txt`: password of the database superuser `kura-admin`. Used by the
  database container on first start and by the one-off `migrate` service
  (`docker compose run --rm migrate`, see docker/postgres/README.md). The
  long-running `web` container does not get it.
  The runtime role `kura_app` does not use this password: it authenticates with
  its client certificate (CN=kura_app), so its password is not required here.
- `backup_encryption_key.txt`: pgBackRest repository encryption passphrase,
  referenced safely from `pgbackrest.conf` as `repo1-cipher-pass=file:/run/secrets/backup_encryption_key`.
- Other Compose secret source files are `django_secret_key.txt`,
  `crowdsec_bouncer_key.txt`, `cloudflare_tunnel_token.txt`,
  `grafana_admin_password.txt`, `telegram_bot_token.txt`, `telegram_chat_id.txt`,
  `netbird_setup_key.txt`, `smtp_relay_credentials.txt` (the mail provider login,
  read only by the Postfix relay), `vault_role_id.txt` and `vault_secret_id.txt`
  (Django's AppRole login for Vault, written by `docker/vault/init-vault.sh`). Their use is defined in the
  top-level `docker-compose.yml`; create only the credentials needed by enabled
  services and keep every secret file out of Git.

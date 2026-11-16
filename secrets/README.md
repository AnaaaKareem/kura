# Container Secrets Directory

This directory holds plaintext secret files for local Docker Compose development.
In production or Docker Compose, these files are mounted into containers as read-only files at `/run/secrets/<secret_name>`.

Files matching `*.txt` in this directory are ignored by `.gitignore` and must never be committed to source control.

To create any missing secret files, run `sudo ./kura.sh secrets` from the project folder
(`./kura.sh setup` runs it for you). It generates random values for the secrets Kura owns,
creates empty placeholders for values that come from outside services (Cloudflare,
Telegram, the mail provider, Vault), and never overwrites a file that already exists.
`--dry-run` shows what it would do.

It sets this folder to `700` and every file to `600`. Compose mounts each file into its
container with the host owner and mode, so on Linux each file belongs to the one
container user that reads it. Root runs the host-side commands that read a secret.

| File | Owner (UID) | Read by |
|---|---|---|
| `db_password.txt`, `backup_encryption_key.txt` | 26 | PostgreSQL (`postgres` in the pgEdge image) |
| `django_secret_key.txt`, `vault_role_id.txt`, `vault_secret_id.txt` | 10001 | Django, migrate and collectstatic (`kura`) |
| `grafana_admin_password.txt` | 472 | Grafana |
| `telegram_bot_token.txt`, `telegram_chat_id.txt` | 65534 | Alertmanager (`nobody`) |
| `cloudflare_tunnel_token.txt` | 65532 | cloudflared (`nonroot`) |
| `crowdsec_bouncer_key.txt`, `smtp_relay_credentials.txt` | 0 | CrowdSec and Postfix (read as root) |
| `grafana_viewer_password.txt` | 0 | Only `./kura.sh grafana-users` on the host |
| `vault_issuer_role_id.txt`, `vault_issuer_secret_id.txt` | 0 | Only `./kura.sh renew-certs` on the host |

`./kura.sh preflight` checks that no file is missing, empty or a placeholder, that the
generated keys and passwords are at least 32 characters, and that every file has the
mode and owner above.

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
  `smtp_relay_credentials.txt` (the mail provider login,
  read only by the Postfix relay), `vault_role_id.txt` and `vault_secret_id.txt`
  (Django's AppRole login for Vault, written by `./kura.sh vault-init`).
- `grafana_viewer_password.txt` is the password of Grafana's read-only `viewer`
  account. It is not mounted into any container: `./kura.sh grafana-users` sends it
  to Grafana's API. Their use is defined in the
  top-level `docker-compose.yml`; create only the credentials needed by enabled
  services and keep every secret file out of Git.

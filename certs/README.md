# TLS Certificates Directory

The public-facing Nginx listener uses `kura.crt` and `kura.key`
(`./kura.sh certs`). The internal mTLS certificates (nginx, waf, web, db,
vault) are in `internal/` and are **issued by Vault's certificate authority**.

```
Kura Internal Root CA        (inside Vault, mount "pki", 10 years, key never leaves Vault)
  └─ Kura Internal Intermediate CA   (inside Vault, mount "pki_int", 5 years, key never leaves Vault)
       ├─ nginx  (30 days)     ├─ web (30 days)     ├─ vault (1 year)
       ├─ waf    (30 days)     └─ db  (30 days)
       └─ relay  (30 days, the Postfix mail relay)
```

| File | Contents | Mounted into |
|---|---|---|
| `internal/ca.crt` | The **root** CA certificate: the only thing every service trusts | every container that uses mTLS |
| `internal/<name>.crt` | The service certificate **followed by** the intermediate CA certificate (the chain) | only that service |
| `internal/<name>.key` | The service's private key, created by Vault and shown once | only that service |

There's **no CA private key on disk**. Both CA keys were generated inside Vault
(`generate/internal`) and can't be exported.

## Commands

All certificate steps are subcommands of `kura.sh` in the project folder. On
Linux they run as root (`sudo ./kura.sh <command>`), because each key belongs
to a container user. `./kura.sh setup` runs them in the right order on a new VM.

| Command | When | What it does |
|---|---|---|
| `./kura.sh mtls-bootstrap` | **Once, on a new server, before Vault exists** | Makes a temporary openssl CA and the first certificates, so PostgreSQL and Vault can start over TLS. Its CA key (`certs/ca/ca.key`) is deleted by the first renewal. Afterwards it asks you to type YES, because it would replace the trusted CA. Skipped when the bootstrap certificates already exist. |
| `./kura.sh renew-certs` | At the end of `./kura.sh vault-init`, then **weekly** | Issues new certificates from Vault and writes them **in place** (the containers mount single files). Sets key owners on Linux, then reloads every running service without downtime. |
| `./kura.sh certs` | Once | The public Nginx certificate `kura.crt` / `kura.key` (self-signed; Cloudflare trusts it as the origin certificate). Skipped when it exists; `--force` replaces it. |

The renewal is scheduled every Monday at 03:30 in `docker/cron/kura.crontab`,
which is installed into **root's** crontab on the VM, because the renewal must
overwrite keys owned by container users:

```cron
30 3 * * 1 /bin/sh $KURA_DIR/docker/cron/run-job.sh cert-renewal ./kura.sh renew-certs >> /var/log/kura/cert-renewal.log 2>&1
```

Vault must be **unsealed** when it runs. Certificates last 30 days, so a few
failed weekly runs don't break anything. Vault's own certificate lasts 1 year
for the same reason: a long sealed period can't let it expire.

The renewal logs in with the `kura-cert-issuer` AppRole. Its login is in
`secrets/vault_issuer_role_id.txt` and `secrets/vault_issuer_secret_id.txt`,
with mode `600`, on the host only and never mounted into a container. Its policy
(`docker/vault/policies/kura-cert-issuer.hcl`) only allows
`pki_int/issue/kura-service`. That role only accepts the names `nginx`, `waf`,
`web`, `db`, `vault`, `relay`, `alloy`, `kura_migrator` and `localhost` (no wildcards, no other domains), and caps
lifetimes at 1 year.

## Key file owners (Linux)

Both `mtls-bootstrap` and `renew-certs` give each private key to the user inside the
container that reads it (mode `0600`):

| Key | Owner (UID) | Why |
|---|---|---|
| `internal/db.key` | 26 (`postgres` in the pgEdge image) | PostgreSQL refuses a key it does not own |
| `internal/web.key` | 10001 (`kura` in our Dockerfile) | Gunicorn and the database client run as `kura` |
| `internal/waf.key` | 101 (`nginx` in the Coraza image) | The WAF runs as `nginx` |
| `internal/vault.key` | 100 (`vault` in the Vault image) | Vault runs as `vault` |
| `internal/migrator.key` | 10001 (`kura` in our Dockerfile) | The one-off migrate job runs as `kura` |
| `internal/alloy.key` | 473 (`alloy` in the Alloy image) | Alloy logs in to PostgreSQL as role `alloy` |
| `internal/nginx.key`, `kura.key`, `internal/relay.key` | 0 (root) | Nginx and Postfix read their keys as root before starting workers |

Docker Desktop on macOS ignores file owners, so this step only runs on Linux.
Certificate and key files are ignored by Git.

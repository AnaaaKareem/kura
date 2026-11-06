# TLS Certificates Directory

The public-facing Nginx listener uses `kura.crt` and `kura.key`
(`generate_certs.sh`). The internal mTLS certificates (nginx, waf, web, db,
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

## Scripts

| Script | When | What it does |
|---|---|---|
| `generate_internal_mtls_certs.sh` | **Once, on a new server, before Vault exists** | Makes a temporary openssl CA and the first certificates, so PostgreSQL and Vault can start over TLS. Its CA key (`certs/ca/ca.key`) is deleted by the first renewal. Never run it again afterwards: it would replace the trusted CA. |
| `renew-certs-from-vault.sh` | At the end of `docker/vault/init-vault.sh`, then **weekly** | Issues new certificates from Vault and writes them **in place** (the containers mount single files). Sets key owners on Linux, then reloads every running service without downtime. |
| `generate_certs.sh` | Once | The public Nginx certificate `kura.crt` / `kura.key` (self-signed; Cloudflare trusts it as the origin certificate). |

Schedule the renewal on the VM in **root's** crontab, because it must overwrite
keys owned by container users:

```cron
# Renew Kura's internal certificates every Monday at 03:30 (they last 30 days).
30 3 * * 1  cd /path/to/kura && sh certs/renew-certs-from-vault.sh >> /var/log/kura-certs.log 2>&1
```

Vault must be **unsealed** when it runs. Certificates last 30 days, so a few
failed weekly runs don't break anything. Vault's own certificate lasts 1 year
for the same reason: a long sealed period can't let it expire.

The script logs in with the `kura-cert-issuer` AppRole. Its login is in
`secrets/vault_issuer_role_id.txt` and `secrets/vault_issuer_secret_id.txt`,
with mode `600`, on the host only and never mounted into a container. Its policy
(`docker/vault/policies/kura-cert-issuer.hcl`) only allows
`pki_int/issue/kura-service`. That role only accepts the names `nginx`, `waf`,
`web`, `db`, `vault` and `localhost` (no wildcards, no other domains), and caps
lifetimes at 1 year.

## Key file owners (Linux)

Both certificate scripts give each private key to the user inside the
container that reads it (mode `0600`):

| Key | Owner (UID) | Why |
|---|---|---|
| `internal/db.key` | 26 (`postgres` in the pgEdge image) | PostgreSQL refuses a key it does not own |
| `internal/web.key` | 10001 (`kura` in our Dockerfile) | Gunicorn and the database client run as `kura` |
| `internal/waf.key` | 101 (`nginx` in the Coraza image) | The WAF runs as `nginx` |
| `internal/vault.key` | 100 (`vault` in the Vault image) | Vault runs as `vault` |
| `internal/nginx.key`, `kura.key`, `internal/relay.key` | 0 (root) | Nginx and Postfix read their keys as root before starting workers |

Docker Desktop on macOS ignores file owners, so this step only runs on Linux.
Certificate and key files are ignored by Git.

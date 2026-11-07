# HashiCorp Vault for Kura

Vault does two jobs for Kura:

1. It **encrypts every user's authenticator-app (TOTP) seed** (Transit engine).
   The seed is what an authenticator app uses to make 6-digit codes; anyone who
   has it can make valid codes forever, so it must never sit in the database in
   plain text.
2. It **gives Django temporary database users** (database engine). Each one
   lives for 15 minutes, then Vault drops it. Nobody can log in as `kura_app`
   any more, so a stolen certificate or an old password is useless.
3. It is **Kura's internal certificate authority** (PKI engines `pki` and
   `pki_int`). It issues the mTLS certificates for nginx, the WAF, Django,
   PostgreSQL and Vault itself. See `certs/README.md`.

See the "Temporary database users" section below for job 2.

```
Django ──HTTPS (cert checked with ca.crt)──► Vault :8200
  │  logs in with AppRole (role ID + secret ID, Docker secrets)
  │  gets a 15-minute batch token, policy "kura-web"
  │  "encrypt this seed" / "decrypt this ciphertext" with key kura-mfa
  ▼
PostgreSQL users.mfa_secret = "vault:v1:..."   (ciphertext only)
```

## Where the seed lives

| Place | What it holds |
|---|---|
| `users.mfa_secret` | The seed, encrypted by Vault (`vault:v1:...`). The only copy. |
| `otp_totp_totpdevice.key` | A **random placeholder**. django-otp still uses this row for the "confirmed" flag, throttling and replay protection. |
| Django's memory | The decrypted seed, only while a code is being checked or the setup QR code is drawn. |

`kura.views.verify_totp_code()` checks every authenticator code (login, MFA
setup, grade release). It asks Vault to decrypt the seed, then checks the code
the same way django-otp does: ±1 time window, a code can't be used twice, and
there's a delay after wrong codes.

If Vault is down or sealed, authenticator codes are **refused** (fail closed)
and the setup page answers 503. Recovery codes still work, because they don't
need Vault. With `VAULT_ENABLED=True`, a plain-text value in `mfa_secret` is
also refused.

## Files

| File | What it does |
|---|---|
| `config/vault.hcl` | Server settings: file storage, HTTPS only (TLS 1.3), no web UI |
| `policies/kura-web.hcl` | Django's policy: **only** encrypt and decrypt with `kura-mfa` and `kura-answer-keys`, and `database/creds/kura-app` (read) |
| `policies/kura-cert-issuer.hcl` | The renewal script's policy: **only** `pki_int/issue/kura-service` |
| `init-vault.sh` | One-time setup, run on the host (see below) |

The container is read-only, runs as the image's `vault` user with no Linux
capabilities, and mounts only `ca.crt`, `vault.crt` and `vault.key`.

## One-time setup

```bash
docker compose up -d vault
sh docker/vault/init-vault.sh
docker compose restart web
```

`init-vault.sh` does the following:

1. Initialises Vault with one unseal key and **shows the key straight away, once**. It's never written to disk. Keep it in a password manager.
2. Unseals Vault. The key goes in on standard input, so it isn't visible in the process list.
3. Turns on the audit log, which writes JSON to the container output. Secret values are replaced by `hmac-sha256:` hashes.
4. Creates the Transit keys `kura-mfa` (authenticator seeds) and `kura-answer-keys` (exam answer keys), both AES-256-GCM. They can't be exported.
5. Sets up temporary database users:
   - runs `docker/postgres/vault-roles.sql`, which makes `kura_app` NOLOGIN and creates `vault_admin`
   - gives `vault_admin` a random first password
   - connects the database engine (TLS `verify-full` plus Vault's client certificate)
   - runs `rotate-root`, so only Vault knows `vault_admin`'s password
   - creates the `kura-app` role (15 minutes, `IN ROLE kura_app`)
6. Creates the `kura-web` policy and AppRole (batch tokens, 15 minutes), and writes `secrets/vault_role_id.txt` and `secrets/vault_secret_id.txt`.
7. Creates the certificate authority:
   - root CA `pki`: EC P-384, 10 years
   - intermediate CA `pki_int`: 5 years, signed by the root
   - role `kura-service`: names `nginx`, `waf`, `web`, `db`, `vault`, `relay`, `localhost`; no wildcards; at most 1 year

   Both private keys are created inside Vault and can't be exported.
8. Creates the `kura-cert-issuer` AppRole (10-minute batch tokens) and writes its login to `secrets/vault_issuer_role_id.txt` and `secrets/vault_issuer_secret_id.txt` (mode `600`, host only).
9. Revokes the root token. If you need an admin token later, make a new one with the unseal key (`vault operator generate-root`).
10. Runs `certs/renew-certs-from-vault.sh`. Every service switches from the bootstrap openssl certificates to Vault-issued ones, and the bootstrap CA key is deleted.

The PKI step prints a harmless warning about "authority information access
(AIA)". That's where a public CA would publish its certificate and revocation
list. Kura's CA is internal and every service already has `ca.crt`, so it
isn't needed.

The database must be running and migrated first:
`docker compose up -d db && docker compose run --rm migrate`.

If a step after initialising fails, the script prints the root token so you
can finish the remaining steps by hand. Running the script again on an
already-initialised Vault does nothing.

Users who enrolled before Vault was set up have their seed in
`TOTPDevice.key`. Move it into Vault once:

```bash
docker compose exec web python manage.py encrypt_totp_seeds
```

Until this runs, their authenticator codes are refused, though recovery codes
still work. Their app keeps working afterwards, because the seed itself
doesn't change.

## After every restart: unseal

Vault keeps its encryption keys only in memory, so every restart **seals** it:

```bash
docker compose exec vault vault operator unseal
```

Paste the unseal key when asked; it's hidden as you type. `docker compose ps`
shows Vault as healthy while sealed, because the server itself is running.
An alert for "Vault is sealed" comes in the observability stage.

**While Vault is sealed the whole site shows an error page.** Every Gunicorn
worker needs a database login from Vault, and a worker that has none yet
can't get one. Django logs `Failed to get a temporary database login from
Vault: Vault is sealed`. The site works again as soon as Vault is unsealed.

## Checked live (4 November 2026)

| Check | Result |
|---|---|
| Encrypt then decrypt a seed through real Vault | ciphertext starts `vault:v1:`, decrypts to the same seed |
| Django's token: read, export or rotate the key, list engines, write a policy, create a secret ID | all `403 Forbidden` |
| Django's token | `batch`, 900 seconds |
| Plain HTTP to Vault | `400 Client sent an HTTP request to an HTTPS server` |
| HTTPS trusting public CAs only (a fake Vault would pass this) | `SSLError`: Vault's certificate is only trusted through `ca.crt` |
| AppRole login with a wrong secret ID | refused |
| `users.mfa_secret` in the database | ciphertext, does not contain the seed |
| Correct code / same code again | accepted / refused (replay) |
| Old-style user after `encrypt_totp_seeds` | same authenticator app code accepted |
| Vault restarted (sealed) | code refused, setup page 503, Django logs "Vault is sealed" |
| Audit log entry for `transit/encrypt/kura-mfa` | `plaintext` shown as `hmac-sha256:...` |

Stage 3a, checked live on 6 November 2026:

| Check | Result |
|---|---|
| `SELECT current_user` from Django | `kura_dyn_<random>` (new backend in use) |
| Failed login through nginx → WAF → Django | `200`, written to `axes_accessattempt` by the temporary user |
| Temporary user in `pg_roles` | `VALID UNTIL` 15 minutes ahead, member of `kura_app` with inherit |
| `kura_app` / `vault_admin` flags | `kura_app` cannot log in; `vault_admin` not superuser, no bypass RLS |
| Temporary user without a client certificate / with a wrong password | both rejected |
| `kura_app` with `web.crt` (the old way) | rejected |
| `CREATE ROLE` / `ALTER ROLE` in the pgAudit log | password shown as `<REDACTED>` |
| Vault sealed, then Django restarted | login request `500`, Django logs "Vault is sealed" |
| Vault unsealed again | login request `200` |

Stage 3b, checked live on 6 November 2026 (fresh install: bootstrap certificates, `init-vault.sh`, then the rest of the stack):

| Check | Result |
|---|---|
| Issuers | `ca.crt` = Kura Internal Root CA (self-signed); nginx, waf, web, db and vault all issued by Kura Internal Intermediate CA |
| `openssl verify` of each service certificate against `ca.crt` | all `OK` |
| Lifetimes | 30 days (nginx, waf, web, db), 1 year (vault) |
| `certs/ca/` after the switch | empty: no CA private key on disk |
| Full chain nginx → WAF → Django / Django → PostgreSQL (TLS, temporary user) / Django → Vault | `200` / `ssl = true` / works |
| Second renewal while sending requests for 25 seconds | 2,241 requests, no errors (`200`, or `429` from nginx's rate limit); new web serial served by Gunicorn |
| Issuer AppRole: `evil.example.com`, wildcard `*.web` | `400 not allowed by this role` |
| Issuer AppRole: root CA, sign intermediate, edit role, database login, MFA decrypt | all `403` |
| Django's AppRole: issue a certificate | `403` |
| Ask for a 2-year certificate | capped at 1 year by the role |

## Temporary database users (stage 3a)

```
Django worker ──► kura/vault_postgres/base.py (before each new connection)
                    └─► kura.vault.get_dynamic_database_credentials()
                          cached login still has > 5 minutes left? reuse it
                          otherwise: Vault database/creds/kura-app
                                       └─► vault_admin runs in PostgreSQL:
                                           CREATE ROLE "kura_dyn_<random>" LOGIN
                                             PASSWORD '<SCRAM hash>'
                                             VALID UNTIL '<now + 15 minutes>'
                                             IN ROLE kura_app;
Django ──TLS + web.crt + temporary password──► PostgreSQL as kura_dyn_<random>
After 15 minutes Vault runs: DROP ROLE IF EXISTS "kura_dyn_<random>";
```

- Each Gunicorn worker has its own login and asks for a new one 5 minutes
  before it expires, so a running site holds a few users at a time. Each new
  process (for example a `manage.py` command) also gets its own.
- The temporary user's lease is tied to Django's 15-minute Vault token. That's
  one reason the users last 15 minutes and not longer.
- If Vault can't give a login, the backend raises a database
  `OperationalError`. Users see the generic error page, and the details go
  only to the log.
- Turned on by `VAULT_DATABASE_CREDENTIALS=True` (Docker `web` service only).
  Local development and tests use the normal backend.

## Internal certificates (stage 3b)

Vault's intermediate CA issues every internal mTLS certificate:
- nginx, WAF, Django and PostgreSQL: 30 days
- Vault's own certificate: 1 year, so a long sealed period can't let it expire

`certs/renew-certs-from-vault.sh` renews them weekly and reloads each service
without downtime. On `SIGHUP`, Vault reloads its own HTTPS certificate without
sealing. Django never issues certificates: its token gets `403` on
`pki_int/issue/kura-service`. Details: `certs/README.md`.

## Metrics for Alloy

Vault exposes Prometheus metrics at `/v1/sys/metrics`. The metrics endpoint is
enabled without a Vault token only for the private backend network, so Alloy
can collect health information without receiving a Vault credential. Alloy
still validates Vault's HTTPS certificate with the mounted internal CA.

Configuration follows HashiCorp's [Vault telemetry documentation for the 2.x
configuration](https://developer.hashicorp.com/vault/docs/configuration/telemetry)
and its [TCP listener telemetry settings](https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#telemetry-parameters),
checked 6 November 2026 against the pinned Vault image `2.2.1`.

# PostgreSQL Mutual TLS (mTLS) Configuration for Kura LMS

This directory configures PostgreSQL to enforce Mutual TLS (mTLS) for all incoming client connections (Hop 2: Django ➔ PostgreSQL).

## Database Roles (Least Privilege)

| Role | Purpose | How it logs in |
|---|---|---|
| `kura_app` | Holds the runtime permissions: read/write on tables and sequences only. | **It doesn't.** `NOLOGIN`: it is a group role. |
| `kura_dyn_<random>` | Django's temporary users, created by Vault as members of `kura_app`. Each one lives for **15 minutes**, then Vault drops it. | Password from Vault **and** a client certificate signed by our CA (`web.crt`). |
| `vault_admin` | Used only by Vault's database engine to create and drop the temporary users. `CREATEROLE`, not a superuser; may hand out only `kura_app`, and cannot use its permissions (`INHERIT FALSE, SET FALSE`). | Password that **only Vault knows** (Vault replaced it with `rotate-root`), plus Vault's client certificate. |
| `kura-admin` | Migrations and administrative maintenance (superuser created by `POSTGRES_USER`). | Password from the `db_password` Docker secret, sent only inside TLS. |

`docker/postgres/vault-roles.sql` makes `kura_app` NOLOGIN and creates
`vault_admin`. `docker/vault/init-vault.sh` runs it. The login rules are in
`pg_hba.conf`: the first matching line wins, and any user without a line
(for example `kura_app`) can't log in at all.

Django gets its temporary user through `kura/vault_postgres/base.py`. This is
Django's PostgreSQL backend plus one change: before each new connection, it
asks Vault (`kura.vault.get_dynamic_database_credentials`) for the username
and password. Each Gunicorn worker reuses its login until 5 minutes before it
expires.

Schema migrations run as `kura-admin`, never as the runtime role, in a separate one-off container:

```bash
docker compose run --rm migrate
```

The `migrate` service (profile `tools` in `docker-compose.yml`) is the **only** Kura container given the `db_password` secret. The long-running `web` container does not have it, so an attacker who breaks into Django gets at most a 15-minute `kura_app` member and nothing more. `migrate` uses password authentication inside TLS, checks the database certificate against `ca.crt` (`verify-full`), and exits when the migrations finish.

### What `kura_app` cannot do (checked live)

Checked as `kura_app` on 4 November 2026, before it became NOLOGIN. To repeat a check now, use a current temporary user, which has the same permissions (`docker exec kura-db psql -U <kura_dyn_name> -d kura -c "..."`; list the users with `SELECT rolname FROM pg_roles WHERE rolname LIKE 'kura_dyn_%';`):

| Attempt | Result |
|---|---|
| Role flags: superuser, bypass RLS, create role, create database | all `false` |
| `CREATE TABLE hacked (id int);` | `permission denied for schema public` |
| `DROP TABLE grades;` | `must be owner of table grades` |
| `ALTER TABLE grades DISABLE ROW LEVEL SECURITY;` | `must be owner of table grades` (tables are owned by `kura-admin`) |
| `SELECT rolpassword FROM pg_authid;` | `permission denied` |
| `SET ROLE "kura-admin";` | `permission denied to set role` |
| `SELECT pg_read_file('/etc/passwd');` | `permission denied for function pg_read_file` |
| `COPY (SELECT 1) TO PROGRAM 'id';` | `permission denied to COPY to or from an external program` |

The same checks hold for a temporary `kura_dyn_` user, which gets exactly
`kura_app`'s permissions. In addition, a temporary user can't `SET ROLE
vault_admin` or create roles. `vault_admin` can't read `users`, can't
`SET ROLE kura_app`, can't make itself superuser, and can't grant itself
`kura-admin` (all checked live on 6 November 2026).

Network logins tried from inside the `web` container (checked live):

| Attempt | Result |
|---|---|
| Temporary user + its password + `web.crt` | accepted |
| Temporary user + its password, no certificate | rejected: `connection requires a valid client certificate` |
| Temporary user + wrong password + `web.crt` | rejected |
| `kura_app` with `web.crt` (the old way) | rejected: no `pg_hba.conf` line, and NOLOGIN |
| `vault_admin` with a guessed password + `web.crt` | rejected |
| Made-up `kura_dyn_` user | rejected |
| `kura-admin` with a guessed password | rejected |
| Any user with `sslmode=disable` | rejected by `hostnossl ... reject` |

### Passwords in the audit log

pgAudit logs every `CREATE ROLE` and `ALTER ROLE` (class `role`), and replaces
the password with `<REDACTED>`. Vault also sends passwords as SCRAM hashes
(`password_authentication=scram-sha-256`), so even without that redaction a
log line would never contain a usable password. `log_line_prefix` includes
`%u@%d`, so each audit line shows which user ran it, for example
`vault_admin@kura` for `CREATE ROLE "kura_dyn_..."`.

### Certificate files

Each container mounts only `ca.crt` plus its own `.crt` and `.key` (PostgreSQL: `db.*`, Django: `web.*`). The certificates come from Vault's intermediate CA and last 30 days (`certs/renew-certs-from-vault.sh`); the CA keys exist only inside Vault, so nobody can sign client certificates that PostgreSQL trusts without going through Vault. `ca.crt` is the root CA; each `.crt` file carries the intermediate CA too, so PostgreSQL and libpq can build the chain. The renewal script reloads PostgreSQL (`pg_reload_conf()`), which re-reads the certificate files without dropping connections. On Linux both certificate scripts make `db.key` belong to the image's `postgres` user (UID 26) with mode `0600`, which PostgreSQL requires before it will start.

`ALTER DEFAULT PRIVILEGES` in `init-roles.sql` automatically grants future tables
(created by that migration) to `kura_app`, including `kura_search_cache`.

## How PostgreSQL mTLS Works

1. **Server Verification:**
   PostgreSQL serves its certificate (`db.crt`) signed by the internal Root CA. Django validates this certificate using `ca.crt` to prevent man-in-the-middle (MITM) attacks.

2. **Client Verification (`clientcert=verify-ca`) plus a password:**
   Every TCP login needs **both** a client certificate signed by `ca.crt` **and** the right password (`scram-sha-256`). Django presents `web.crt` and the temporary password from Vault; Vault presents `vault.crt` and the password only it knows. The certificate's name isn't compared to the username (`verify-ca`, not `verify-full`), because the temporary usernames change every 15 minutes. If the certificate is missing, self-signed by an untrusted CA, or expired, PostgreSQL ends the connection immediately.

3. **Plaintext Rejection:**
   In `pg_hba.conf`, the directive `hostnossl all all all reject` ensures that any unencrypted connection attempt is blocked.

## Data Migration & Rollback (image cutover)

The current live database runs on the standalone `kura-postgres` container
_pgdata volume_ (`kura_pgdata`). To move its data onto the new pgEdge stack
(whose data lives in the new `kura_pgedge_postgres_data` Compose volume —
**not** the old `kura_postgres_data` volume, which holds only a stale 31 Oct
snapshot and must not be reused):

1. **Forward path (verified as an isolated rehearsal on 2026-11-03):**
   ```bash
   # 1. Dump the live database (read-only operation).
   docker exec kura-postgres pg_dump -U kura-admin -d kura > kura-live-dump.sql
   # 2. Start the new stack (fresh postgres_data volume).
   docker compose up -d
   # 3. Restore the dump (roles are created first by init-roles.sql).
   docker compose exec -T db psql -U kura-admin -d kura < kura-live-dump.sql
   # 4. Run migrations as kura-admin, then verify row counts against step 1 source.
   docker compose run --rm migrate python manage.py migrate --check
   ```
2. **Rollback before the new database accepts writes:** freeze application
   writes during the cutover and keep the old container and `kura_pgdata`
   volume unchanged. If validation fails before writes resume, route the
   application back to the old database. Never attach the stale
   `kura_postgres_data` volume to pgEdge.
3. **Rollback after the new database accepts writes:** stop the application
   first so neither database changes during recovery. Dump the pgEdge database
   to a protected file, excluding pgAudit because the old PostgreSQL image may
   not include that extension:
   ```bash
   docker compose stop web
   umask 077
   docker compose exec -T db pg_dump -U kura-admin -d kura \
       --no-owner --no-acl --exclude-extension=pgaudit > kura-rollback.sql
   ```
   Restore that dump into a **fresh** PostgreSQL 17 rollback volume running the
   previous PostgreSQL image. Recreate or verify `kura_app` and its table,
   sequence and future-table grants; then verify row counts and application
   connectivity before routing the application back. Keep the original
   `kura_pgdata` volume untouched until recovery has been validated. Do not
   simply restart the old database after new writes have occurred: that would
   discard those writes.
4. The forward and reverse data-copy rehearsal was run only with isolated
   volumes. It verified matching user/course/file counts, a simulated write
   made after cutover surviving the reverse dump, `kura_app` reads, and denied
   DDL on the rollback copy. It did not switch production traffic or modify
   either live volume.

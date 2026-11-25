# Kura Agent Guidelines & Test Harness

## How to test

Tests require PostgreSQL 17 because migrations enforce PostgreSQL Row-Level Security (RLS), triggers, and constraints.

### 1. Start a disposable PostgreSQL 17 test container (never touch the Compose `db` volume)

```bash
docker run -d --name kura-test-db \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_USER=kura-admin \
  -e POSTGRES_DB=kura \
  -p 127.0.0.1:55432:5432 \
  postgres:17-alpine
```

### 2. Run the full Django test suite

```bash
DEBUG=True VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False \
DATABASE_HOST=127.0.0.1 DATABASE_PORT=55432 DATABASE_NAME=kura \
DATABASE_USER=kura-admin DATABASE_PASSWORD=testpass DB_SSL_MODE= \
SECRET_KEY=local-test-secret-key-not-for-production-min-50-chars-long \
.venv/bin/python manage.py test \
  kura \
  kura.tests_security_leads_part1 \
  kura.tests_security_leads_part2 \
  kura.tests_security_routes \
  kura.tests_security_gaps \
  kura.tests_signatures \
  --noinput
```

### 3. Re-run a single test while iterating

```bash
DEBUG=True VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False \
DATABASE_HOST=127.0.0.1 DATABASE_PORT=55432 DATABASE_NAME=kura \
DATABASE_USER=kura-admin DATABASE_PASSWORD=testpass DB_SSL_MODE= \
SECRET_KEY=local-test-secret-key-not-for-production-min-50-chars-long \
.venv/bin/python manage.py test kura.tests_security_gaps.TestClass.test_name --noinput
```

### 4. Pre-commit static and deployment checks

```bash
.venv/bin/ruff check .
DEBUG=False VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False \
SECURE_SSL_REDIRECT=True ALLOWED_HOSTS=localhost,127.0.0.1 \
SECRET_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
.venv/bin/python manage.py check --deploy
```

## Non-negotiable safety rules

- Never run `docker compose down -v`, `docker volume rm` on persistent `kura_*` volumes, or `DROP DATABASE`.
- Never commit `secrets/`, `certs/`, `.env`, or literal tokens, passwords, role IDs, or secret IDs.
- Never weaken, delete, or skip existing tests to pass checks.
- Keep plain-English security rationale comments above security checks and `"Who can use it:"` / `"Security:"` lines in view and helper docstrings.

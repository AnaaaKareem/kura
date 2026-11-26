# STRIDE Threat Model

Based on the data-flow diagram in `architecture.py` and `docs/coursework/pdf/kuras_secure_architecture_v2.png`.

## Trust Boundaries

| Boundary | Description | Controls |
|----------|-------------|----------|
| TB1 | Browser <-> Internet | TLS 1.3, HSTS, CSP, rate limiting (nginx) |
| TB2 | Internet <-> nginx (DMZ) | nftables default-drop, CrowdSec, Coraza WAF |
| TB3 | nginx <-> Coraza WAF | mTLS, internal Docker network (`frontend`) |
| TB4 | Coraza WAF <-> Gunicorn (App) | mTLS, internal Docker network (`app`) |
| TB5 | App <-> PostgreSQL | mTLS, RLS policies, Vault dynamic creds, internal network (`backend`) |
| TB6 | App <-> Vault | mTLS, AppRole auth via Docker secrets, internal network (`backend`) |
| TB7 | App <-> ClamAV | TCP (`INSTREAM`), internal network (`clamav`) |
| TB8 | App <-> Loki/Alloy | TLS 1.3, internal network (`observability`) |
| TB9 | Admin SSH <-> Host | Key-only auth, nftables allowlist, CrowdSec bouncer |
| TB10 | Offsite Backup <-> Host | Encrypted pgBackRest repository, dedicated network (`egress`) |

## Elements and STRIDE Analysis

### 1. Browser (Client)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Credential theft via phishing | Spoofing | User enters credentials on a spoofed site | Mandatory MFA (TOTP/WebAuthn), Passkeys, HIBP check | `kura/views.py:177`, `kura/views.py:1128`, `kura/views.py:1423` |
| Session hijacking | Spoofing | Attacker steals session cookie via XSS or MitM | HttpOnly/Secure/SameSite, `__Host-` prefix, HMAC binding | `config/settings.py:337-370`, `kura/middleware.py:123` |
| CSRF | Tampering | Malicious site triggers state-changing requests | Django CSRF middleware, Origin and pre-MFA check on passkey completion | `config/settings.py:365-370`, `kura/views.py:1423` |
| XSS | Injection | Attacker injects script via filenames or text inputs | NFKC normalization, bidi rejection, CSP, template auto-escape | `kura/text_safety.py:9-33`, `docker/nginx/conf.d/kura.conf:57` |
| Malicious file download | Injection | Malicious upload executes in browser on download | Forced `Content-Disposition: attachment`, MIME/extension match, ClamAV scan | `kura/views.py:537-555`, `kura/views.py:590-615` |

### 2. nginx (Reverse Proxy and TLS Termination)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| TLS downgrade | Spoofing | Attacker forces older TLS version or weak cipher | TLS 1.3 only, HSTS with `includeSubDomains; preload` | `docker/nginx/conf.d/kura.conf:37-46` |
| Application DDoS | DoS | High request volume exhausts app workers | `limit_req_zone` and `limit_req`, nftables default-drop | `docker/nginx/nginx.conf:43-44`, `docker/nginx/conf.d/kura.conf:109,128` |
| Header spoofing or duplication | Injection | Client injects proxy headers or breaks HSTS semantics | `server_tokens off`, `charset utf-8`, `proxy_hide_header` | `docker/nginx/conf.d/kura.conf:30-31,59` |
| Certificate expiry | Information / DoS | Expired certificate interrupts HTTPS availability | `CertRenewalFailing` alert and automated host renewal | `docker/prometheus/alerts.yml:92` |

### 3. Coraza WAF (OWASP CRS)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Rule bypass | Tampering | Encoded payloads evade CRS rules | OWASP CRS ruleset plus app-layer NFKC and parameterized ORM | `docker-compose.yml` (`waf` service), `kura/text_safety.py:33` |
| False-positive blocking | DoS | Valid LMS traffic blocked by strict rules | Scoped exclusion rules before CRS | `docker/coraza/rules.d/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |
| WAF log tampering | Repudiation | Attacker modifies local log files | Alloy shipping to Loki, host FIM | `kura.sh:1645`, `docker-compose.yml` (`alloy` service) |

### 4. Gunicorn / Django App (Web)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Authentication bypass | Spoofing | Forged session or inactive user retains access | Mandatory MFA, active-user check, `SessionValidationMiddleware` | `kura/middleware.py:60-123`, `kura/permissions.py:222` |
| Privilege escalation / IDOR | Elevation | Student accesses another student or instructor route | RBAC, course ownership checks, separation of duties, PostgreSQL RLS | `kura/permissions.py:53-192`, `kura/migrations/0026_rls_and_readonly_revokes.py` |
| SQL injection | Injection | Untrusted query parameters alter SQL execution | Parameterized ORM with `server_side_binding`, zero raw SQL, Coraza WAF | `config/settings.py:189`, `docs/evidence/2026-12/db-boundary-validation.txt` |
| Malicious upload | Injection | Malware, polyglots, or oversized archives uploaded | 25 MiB cap, ClamAV fail-closed, python-magic MIME check, AES-256-GCM | `kura/views.py:239-248`, `kura/views.py:355-575` |
| Grade tampering | Tampering | Instructor or DBA alters finalized/released grades | Insert-only `GradeHistory`, PostgreSQL RLS, Vault Transit ECDSA signatures | `kura/migrations/0016_grade_history_insert_only.py`, `kura/signing.py:99` |
| Submission repudiation | Repudiation | Student denies submission or timestamp | Vault Transit ECDSA-P256 receipt signed on submit, immutable hash trigger | `kura/views.py:5446`, `kura/signing.py:80`, `kura/migrations/0025_submission_hash_immutability_trigger.py` |
| Error leakage | Information | HTTP 500 stack traces leak internals | Generic error pages, HTTP 503 on dependency outage | `kura/middleware.py:22`, `kura/views.py:717,786` |
| Log tampering / injection | Tampering | Fake or deleted log entries hide activity | Structured logfmt, redaction, HMAC-SHA256 sequence chain | `kura/logging_utils.py:45,106,206` |

### 5. PostgreSQL (Database)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Direct network access | Spoofing | Remote client connects directly to port 5432 | No published port, `pg_hba.conf` rejects `kura-admin` TCP and requires mTLS cert | `docker-compose.yml` (`db` service), `docker/postgres/pg_hba.conf:22-36` |
| Static credential theft | Information | Stolen static DB password grants long-lived access | Vault dynamic DB credentials (15-minute TTL) | `kura/base.py:1`, `config/settings.py:196` |
| Direct DBA data tampering | Tampering | Superuser edits submissions or grades directly | Immutability triggers, Vault Transit ECDSA signatures, `verify_signatures` | `kura/migrations/0025`, `0030`, `0031`; `kura/signing.py:154` |
| Backup theft | Information | Stolen backup files expose database contents | pgBackRest AES-256-CBC encryption on local and offsite repos | `docker/postgres/pgbackrest.conf:10,20` |
| Ransomware | Destruction | Attacker encrypts live DB volume | Separate encrypted offsite backup volume and tested restore drill | `kura.sh:1516`, `docker-compose.yml:991-992` |

### 6. Vault (Secrets Management)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Unseal key compromise | Spoofing | Unauthorized actor unseals Vault | Threshold unseal shares held by operators | `kura.sh:427` |
| AppRole credential theft | Information | Attacker reads `role_id`/`secret_id` from compose or env | Stored in Docker secrets only, preflight inline-secret check, rotation command | `docker-compose.yml:1012-1015`, `kura.sh:719,1094` |
| Cryptographic key misuse | Tampering | App exports keys or accesses unrelated secrets | Least-privilege Transit and KV policy (`kura-web.hcl`) | `docker/vault/policies/kura-web.hcl:10-52` |
| Audit trail suppression | Repudiation | Secret access goes unrecorded | Vault file audit device shipped into Loki | `kura.sh:427` |

### 7. ClamAV (Antivirus)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Scanner bypass | Tampering | Upload passes through when ClamAV is unreachable | Fail-closed scanner handling and clamd limits | `kura/views.py:392-396`, `docker/clamav/clamd.conf` |
| Scanner DoS via huge upload | DoS | Oversized stream stalls ClamAV | 25 MiB cap and socket timeout | `kura/views.py:359,488` |
| Stale virus signatures | Information | Outdated definitions miss new malware | `check_signature_age` warns after 3 days | `kura/views.py:436` |

### 8. Observability Stack (Loki, Alloy, Prometheus, Alertmanager)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Loki outage silences alerts | DoS | Logging downtime hides active attacks | Loki healthcheck, `LokiDown` and `SecurityLogsStopped` alerts | `docker-compose.yml` (`loki` service), `docker/prometheus/alerts.yml:51,61` |
| Log deletion or editing | Repudiation | Attacker deletes or modifies security events | HMAC-SHA256 sequence chain, `verify_log_chain`, host FIM | `kura/logging_utils.py:197-206`, `kura/management/commands/verify_log_chain.py` |
| Alert fatigue | DoS | High noise causes real incidents to be missed | Severity labels and grouped alert routing | `docker/prometheus/alerts.yml` |

### 9. Admin SSH (Host Access)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| SSH brute force | Spoofing | Automated login attempts against host SSH | Key-only authentication, nftables allowlist, CrowdSec bouncer | `docker/nftables/kura.nft`, `docker/crowdsec/` |
| Container breakout / lateral movement | Elevation | Compromised app process escalates to host | Read-only containers, `cap_drop: ALL`, `no-new-privileges`, non-root user | `docker-compose.yml`, `Dockerfile:98` |
| Host config persistence | Tampering | Attacker modifies compose, nginx, nftables, or sshd config | Host FIM baseline and periodic check | `kura.sh:1645,1659` |

## Cross-Boundary Threat Summary

| From -> To | Primary Threats | Key Controls |
|------------|-----------------|--------------|
| Internet -> nginx | DDoS, TLS downgrade, header spoofing | nftables, `limit_req`, TLS 1.3 only, HSTS |
| nginx -> WAF | Request smuggling, WAF evasion | mTLS, Coraza CRS |
| WAF -> App | Injection, auth bypass, IDOR | mTLS, RLS, MFA, parameterized ORM, NFKC validation |
| App -> DB | Credential theft, data tampering | Vault dynamic creds, RLS, immutability triggers, ECDSA signatures |
| App -> Vault | Secret theft, policy bypass | AppRole via Docker secrets, scoped `kura-web.hcl` |
| App -> ClamAV | Scanner evasion, large-upload DoS | 25 MiB limit, timeout, fail-closed scan |
| App -> Loki | Log loss, log tampering | HMAC-SHA256 chain, healthcheck, `LokiDown` alert |
| Admin -> Host | Brute force, config tampering | Key-only SSH, nftables allowlist, CrowdSec, host FIM |

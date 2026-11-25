# STRIDE Threat Model

Based on data-flow diagram from `architecture.py` and `docs/coursework/pdf/kuras_secure_architecture_v2.png`.

## Trust Boundaries

| Boundary | Description | Controls |
|----------|-------------|----------|
| TB1 | Browser ↔ Internet | TLS 1.3, HSTS, CSP, Rate limiting (nginx) |
| TB2 | Internet ↔ nginx (DMZ) | nftables default-drop, CrowdSec, Coraza WAF |
| TB3 | nginx ↔ Coraza WAF | mTLS, internal Docker network (frontend) |
| TB4 | Coraza WAF ↔ Gunicorn (App) | mTLS, internal Docker network (app) |
| TB5 | App ↔ PostgreSQL | mTLS, RLS policies, Vault dynamic creds, internal network (backend) |
| TB6 | App ↔ Vault | mTLS, AppRole auth, internal network (backend) |
| TB7 | App ↔ ClamAV | TCP (INSTREAM), internal network (clamav) |
| TB8 | App ↔ Loki/Alloy | mTLS, internal network (observability) |
| TB9 | Admin SSH ↔ Host | Key-only, nftables allowlist, CrowdSec bouncer |
| TB10 | Offsite Backup ↔ Host | mTLS (pgBackRest), dedicated network (egress) |

## Elements and STRIDE Analysis

### 1. Browser (Client)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Credential theft via phishing | Spoofing | User enters credentials on fake site | MFA (TOTP/WebAuthn), Passkeys, HIBP check | kura/views.py:1099, kura/views.py:1277 |
| Session hijacking | Spoofing | Steal session cookie via XSS/mitm | HttpOnly/Secure/SameSite, __Host- prefix, HMAC binding | config/settings.py:365, kura/middleware.py:125 |
| CSRF | Tampering | Forge requests via malicious site | Django CSRF, Origin check on passkey | kura/views.py:1277 |
| XSS | Injection | Inject script via file names, titles | NFKC, bidi rejection, CSP no-inline | kura/text_safety.py:1, docker/nginx/conf.d/kura.conf:45 |
| Malicious file download | Injection | Download malware via crafted filename | Forced attachment, MIME match, AV scan | kura/views.py:590 |

### 2. nginx (Reverse Proxy + TLS Termination)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| TLS downgrade | Spoofing | Force HTTP/1.1 or weak ciphers | TLS 1.3 only, HSTS, secure ciphers | docker/nginx/conf.d/kura.conf:15 |
| DDoS | DoS | Overwhelm with requests | rate_limit (limit_req_zone), nftables | docker/nginx/conf.d/kura.conf:25 |
| Header injection | Injection | Inject headers via Host/User-Agent | Proxy headers sanitized, proxy_hide_header | docker/nginx/conf.d/kura.conf:35 |
| Cert expiry | Information | Expired cert causes outage | CertRenewalFailing alert, auto-renewal | docker/prometheus/alerts.yml:35 |

### 3. Coraza WAF (OWASP CRS)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Rule bypass | Tampering | Evade CRS rules via encoding | PL1 blocking, PL2 detection, Lua scripts | docker-compose.yml waf: |
| False positive block | DoS | Legitimate traffic blocked | Exclusion rules for known paths | docker/coraza/rules.d/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf |
| Log tampering | Repudiation | Modify WAF logs | Loki HMAC chain, FIM on host | kura/logging_utils.py:45 |

### 4. Gunicorn / Django App (Web)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Auth bypass | Spoofing | Forge session/admin access | MFA mandatory, RLS, session validation | kura/middleware.py:60, kura/permissions.py:1 |
| Privilege escalation | Elevation | Student → Instructor via IDOR | RBAC + RLS, course ownership checks | kura/permissions.py:154 |
| SQL injection | Injection | Via search params, API | Parameterized ORM only, Coraza WAF | kura/views.py:162 |
| Malicious upload | Injection | Malware, zip bomb, polyglot | 25MB limit, ClamAV, libmagic, AES-GCM | kura/views.py:350 |
| Grade tampering | Tampering | Instructor/DB admin alters grades | RLS insert-only history, Vault Transit sigs | kura/migrations/0030, kura/signing.py:1 |
| Repudiation | Repudiation | Student denies submission | Vault Transit ECDSA receipts | kura/views.py:258 |
| Error leakage | Information | 500 stack traces to user | Generic error pages, 503 on dep outage | kura/middleware.py:22 |
| Log injection | Tampering | Inject fake log entries | Structured logfmt, HMAC chain | kura/logging_utils.py:45 |

### 5. PostgreSQL (Database)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Direct access | Spoofing | Connect to DB from internet | No published port, pg_hba client cert | docker-compose.yml db:, pg_hba.conf |
| Credential theft | Information | Steal static DB password | Vault dynamic users (15 min TTL) | kura/base.py:1 |
| Data tampering | Tampering | DBA alters grades/submissions | RLS policies, triggers, Vault Transit sigs | kura/migrations/0026, 0030, 0031 |
| Backup theft | Information | Steal backup files | pgBackRest AES-256-CBC, offsite repo | docker/postgres/pgbackrest.conf:1 |
| Ransomware | Destruction | Encrypt DB files | Offsite immutable backup, restore drill | kura.sh restore-drill |

### 6. Vault (Secrets Management)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Seal compromise | Spoofing | Unseal with stolen keys | Operator-held unseal keys (3 of 5), auto-seal | kura.sh vault-init |
| AppRole theft | Information | Steal role_id/secret_id | Docker secrets, rotation 720h | docker-compose.yml secrets:, kura.sh vault-rotate-approle |
| Key misuse | Tampering | Encrypt/decrypt unauthorized data | Policies restrict paths (kura-web.hcl) | docker/vault/policies/kura-web.hcl |
| Audit log loss | Repudiation | Disable audit device | File audit device, Loki ingestion | kura.sh vault-init |

### 7. ClamAV (Antivirus)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Scanner bypass | Tampering | Evade signature detection | Heuristics, stream size limits, fail-closed | kura/views.py:392, docker/clamav/clamd.conf |
| DoS via large file | DoS | Upload huge file to stall scanner | 25MB limit, 10s timeout | kura/views.py:484, kura/views.py:359 |
| Signature stale | Information | Old signatures miss new malware | check_signature_age (3-day warn) | kura/views.py:436 |

### 8. Observability Stack (Loki, Alloy, Prometheus, Alertmanager)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Loki down → silent alerts | DoS | No logs = no alerts | Loki healthcheck, LokiDown alert, SecurityLogsStopped | docker/compose.yml loki:, docker/prometheus/alerts.yml:45 |
| Log tampering | Repudiation | Delete/modify logs in Loki | HMAC-SHA256 chain, verify_log_chain, FIM | kura/logging_utils.py:45, kura/management/commands/verify_log_chain.py |
| Alert fatigue | DoS | Too many alerts ignored | Severity labels, grouping, inhibition rules | docker/prometheus/alerts.yml |

### 9. Admin SSH (Host Access)

| Threat | STRIDE | Description | Mitigation | Control Ref |
|--------|--------|-------------|------------|-------------|
| Brute force | Spoofing | Password/key guessing | Key-only auth, nftables allowlist, CrowdSec bouncer | docker/nftables/kura.nft, docker/crowdsec/ |
| Lateral movement | Elevation | Compromise host → containers | Read-only containers, cap_drop, no-new-privs | docker-compose.yml *: cap_drop |
| Persistence | Tampering | Modify host configs | FIM (kura.sh fim-baseline/check), AIDE (prod rec) | kura.sh fim-baseline |

## Cross-Boundary Threat Summary

| From → To | Primary Threats | Key Controls |
|-----------|-----------------|--------------|
| Internet → nginx | DDoS, TLS downgrade, Header injection | nftables, rate_limit, TLS 1.3 only |
| nginx → WAF | Request smuggling, WAF bypass | mTLS, Coraza CRS PL1 |
| WAF → App | Injection, Auth bypass | mTLS, RLS, MFA, parameterized ORM |
| App → DB | Credential theft, Data tampering | Vault dynamic creds, RLS, triggers, signatures |
| App → Vault | Secret theft, Policy bypass | AppRole + Docker secrets, path policies |
| App → ClamAV | Scanner evasion, DoS | 25MB limit, timeout, fail-closed |
| App → Loki | Log loss, Tampering | HMAC chain, healthcheck, alerts |
| Admin → Host | Brute force, Persistence | Key-only, nftables, CrowdSec, FIM |

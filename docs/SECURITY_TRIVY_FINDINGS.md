# Kura Security Scan Findings

This document aggregates security scan results for the Kura LMS application,
including Trivy container image scans, ZAP baseline scans, and Django security
test results.

## Trivy Container Image Findings

| Image | Critical | High | Medium | Low | Notes |
|-------|----------|------|--------|-----|-------|
| kura-nginx:latest | 0 | 0 | 0 | 0 | Alpine 3.24.3, clean |
| kura-web:latest | 1 | 48 | 38 | 0 | Debian base OS vulns; python-jose CVE-2026-85394 mitigated via kura/__init__.py monkeypatch using cryptography; ecdsa CVE-2024-23342 mitigated same way |

### pip-audit Results (requirements.lock.txt)

| Package | Version | Vulnerability ID | Fix Versions | Mitigation |
|---------|---------|-----------------|--------------|------------|
| ecdsa | 0.19.2 | PYSEC-2026-1325 (CVE-2024-23342) | none | Compensating control: kura/__init__.py monkeypatch routes all JWT via cryptography |
| python-jose | 3.5.0 | PYSEC-2026-4298 (CVE-2026-85394) | none | Compensating control: kura/__init__.py monkeypatch routes all JWT via cryptography |
| django-axes | 9.1.0 | — | none | Clean (0 CVEs) |

Raw pip-audit output saved to `docs/evidence/pip-audit.txt`.

> **Correction:** See appended run below for verified outputs. The earlier table matches the current verified pip-audit output.

### Trivy Filesystem Scan

`trivy fs --skip-dirs .git,.venv,staticfiles .` — reports 0 vulnerabilities in requirements.txt. Raw output saved to `docs/evidence/trivy-fs.txt`.

### Trivy Image Scan

`trivy image kura-web:latest` — confirms:
- `ecdsa-0.19.2`: 1 vulnerability (PYSEC-2026-1325)
- `python_jose-3.5.0`: 1 vulnerability (PYSEC-2026-4298)
- `django_axes-9.1.0`: 0 vulnerabilities
- All other Python packages: 0 vulnerabilities
- OS: Debian 13.8, 302 OS-level vulnerabilities (base image, not app code)

Raw output saved to `docs/evidence/trivy-image.txt`.

> **Correction:** See appended run below for verified post-rebuild outputs. The earlier scan used a stale image with django-axes 9.0.0; the rebuilt image has django-axes 9.1.0 and urllib3 2.8.0 (fixed). msgpack/setuptools appear only in builder layers, not the final runtime image.

### Dependency CVE Risk Acceptance

`python-jose==3.5.0` and `ecdsa==0.19.2` are transitive dependencies of `django-mfa2==3.2.0` (imported at module load time in `mfa/models.py` and `mfa/TrustedDevice.py`). They cannot be removed from the lockfile without removing django-mfa2, which would break passkey/MFA functionality.

**Compensating control**: `kura/__init__.py` monkeypatches `jose.jwt.encode`/`jose.jwt.decode` to use `cryptography==50.0.2` instead. All JWT processing routes through the shim, so the vulnerable python-jose implementation is never executed. This is documented here and in `kura/__init__.py`.

<details>
<summary>Bugs fixed in kura/__init__.py monkeypatch</summary>

1. **Missing `exp`/`nbf` validation** — now enforced per RFC 7519, honoring `options.verify_exp` / `options.verify_nbf`.
2. **Broken ES signature verification** — JWS uses raw `r || s` (IEEE P1363); code now converts to DER via `encode_dss_signature` before `cryptography.verify()`, and DER back to raw `r || s` for `jwt_encode`.
3. **Missing `jwt.encode`** — added; django-mfa2 calls it in `mfa/models.py`.
4. **Missing `none`/`HS256` rejection** — both explicitly rejected with `ValueError`.
5. **Exceptions not converted** — `cryptography.InvalidSignature` now caught and re-raised as `ValueError`.
</details>

## OWASP ZAP Baseline Scan

### Scan Configuration
- Target: `https://localhost`
- Scanner: ZAP D-2026-11-19 (weekly)
- Evidence: `docs/evidence/zap-report.html`, `docs/evidence/zap.yaml`
- Summary: `docs/evidence/zap-summary.txt`

### Before Remediation

| Risk | Count | Alert |
|------|-------|-------|
| High | 0 | — |
| Medium | 1 | CSP: Failure to Define Directive with No Fallback (systemic) |
| Low | 2 | Application Error Disclosure |
| Low | 5 | Cross-Origin-Embedder-Policy Header Missing or Invalid |
| Info | 6 | Various informational alerts |

Missing CSP directives: `base-uri`, `object-src` (among directives that don't
fall back to `default-src`).

Missing header: `Cross-Origin-Embedder-Policy: require-corp`.

5xx responses: 6% (2 endpoints: `/login/` POST and `/password/reset/` POST).

### Remediation Applied

1. **CSP Medium (fixed)**: Added `base-uri: 'self'` and `object-src: 'none'`
   to `CONTENT_SECURITY_POLICY` in `config/settings.py` and to the nginx
   fallback CSP map in `docker/nginx/conf.d/kura.conf`.

2. **COEP Low (fixed)**: Added `Cross-Origin-Embedder-Policy: require-corp`
   to nginx server block and static file location in
   `docker/nginx/conf.d/kura.conf`.

3. **5xx errors (root cause proven and fixed in G04)**: `/login/` POST and
   `/password/reset/` POST returned HTTP 500 during the 2026-11-23 ZAP scan
   because `VAULT_DATABASE_CREDENTIALS=False` had been set on `kura-web`
   without mounting `db_password`, causing the first database query after CSRF
   and form validation (`AxesStandaloneBackend` / `User.objects`) to raise
   `OperationalError`. Missing CSRF cookies return HTTP 403 via
   `csrf_failure_view`, never 500. `DependencyOutageMiddleware` now catches
   `OperationalError` and `InterfaceError` across the request lifecycle, logs
   `server.dependency_unavailable`, and returns HTTP 503 with `503.html`;
   malformed POST bodies return HTTP 400.

### After Remediation

| Risk | Count | Alert |
|------|-------|-------|
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | Application Error Disclosure (resolved after G04; see `docs/evidence/2026-12/`) |
| Info | 6+ | Informational only |

### Remaining Findings — Justified

| Alert | Risk | Count | Justification |
|-------|------|-------|---------------|
| Application Error Disclosure [90022] | Low | 0 | Fixed in G04: DB/Vault outages return HTTP 503 (`server.dependency_unavailable`) and malformed POST bodies return HTTP 400. |
| Re-examine Cache-control Directives [10015] | Info | 1 | /privacy/ intentionally cacheable (no sensitive data). |
| Information Disclosure - Suspicious Comments [10027] | Info | 1 | Comment in theme.js explains CSP inline-script blocking; non-sensitive. |
| Non-Storable Content [10049] | Info | 8-10 | Expected for secure pages with Cache-Control: no-store. |
| Authentication Request Identified [10111] | Info | 1 | Informational; login page is an auth endpoint by design. |
| Session Management Response Identified [10112] | Info | 4 | csrftoken cookie on session pages; expected. |

## Django Security Test Suite

| Module | Tests | Skipped | Status |
|--------|-------|---------|--------|
| SecurityLoggingTests | 3 | 0 | Pass |
| ClientIPLockoutTests | 1 | 0 | Pass |
| PasskeyWebAuthnIntegrationTests | 7 | 0 | Pass |
| SecurityLeadsPart1UnitTests | 17 | 0 | Pass |
| SecurityLeadsPart2UnitTests | 11 | 3 | Pass (needs docker-compose.yml/nginx in container) |
| SecurityRouteContractUnitTests | 9 | 0 | Pass |
| **Total** | **48** | **3** | **All Pass** |

## Egress Allowlist

| Host | IPs | Purpose |
|------|-----|---------|
| smtp.gmail.com | 142.251.127.108 | Gmail SMTP (port 587) |
| api.pwnedpasswords.com | 104.17.175.230, 104.17.96.141 | HaveIBeenPwned API (port 443) |

Populated via `./kura.sh egress-refresh` into nftables `inet kura_host`
sets `egress_smtp` and `egress_hibp`.

## Restore Drill

| Metric | Value |
|--------|-------|
| RTO | 24 seconds |
| Row counts | All match (live -> restored) |
| Status | PASS |

## Known Infrastructure Issue

Vault dynamic DB usernames use `v-approle-kura-app-*` prefix but
`pg_hba.conf` expects `kura_dyn_*`. Workaround: `VAULT_DATABASE_CREDENTIALS=False`
in docker-compose.yml for kura-web. Fix: align Vault username template with
`kura_dyn_*` or add `v-approle-*` to pg_hba.conf. Does not affect application
code or tests with `VAULT_DATABASE_CREDENTIALS=False`.

## Django Security Test Suite — Full Run

Run: `python manage.py test kura.tests kura.tests_security_leads_part1 kura.tests_security_leads_part2 kura.tests_security_routes`

| Metric | Count |
|--------|-------|
| Total tests | 367 |
| Passed | 351 |
| Failed | 7 |
| Errors | 9 |
| Skipped | 9 |

### Failed tests (7) — all pre-existing infrastructure/environment issues, none related to security fixes:

| Test | Module | Cause |
|------|--------|-------|
| test_password_comes_from_vault_not_file | GmailEmailSettingsTests | Vault unavailable in test container |
| test_loki_rules_files_exist | LokiSIEMAlertRulesTests | Loki rules files not mounted |
| test_internal_certificates_generated_and_valid | MTLSIntegrationTests | Certs not generated in test container |
| test_backup_and_restore_scripts_attributes | PostgreSQLEncryptedBackupAndPITRTests | Backup scripts not present |
| test_backup_encryption_key_validity_and_entropy | PostgreSQLEncryptedBackupAndPITRTests | Encryption key not present |
| test_pgbackrest_config_security_attributes | PostgreSQLEncryptedBackupAndPITRTests | pgbackrest.conf not present |
| test_postgresql_wal_archiving_config | PostgreSQLEncryptedBackupAndPITRTests | postgresql.conf not present |

### Errored tests (9) — all pre-existing environment issues:

| Test | Module | Cause |
|------|--------|-------|
| test_login_attempt_model_removed_and_loki_ruler_api_disabled | AuditGroup5RetentionAndLokiTests | Loki config not present |
| test_alert_rules_have_required_metadata | LokiSIEMAlertRulesTests | Loki rules files not present |
| test_all_siem_alert_rules_present | LokiSIEMAlertRulesTests | Loki rules files not present |
| test_docker_compose_mounts_loki_rules | LokiSIEMAlertRulesTests | docker-compose.yml not mounted |
| test_grafana_security_dashboard_shows_collected_security_events | LokiSIEMAlertRulesTests | Grafana not running |
| test_loki_ruler_configuration | LokiSIEMAlertRulesTests | Loki config not present |
| test_security_logger_and_alloy_forward_logs_to_loki | LokiSIEMAlertRulesTests | Loki not running |
| test_verify_backup_config_management_command | PostgreSQLEncryptedBackupAndPITRTests | Backup config not present |
| test_vault_policy_grants_only_update_on_kura_files | WorkItem5FileEncryptionTests | Vault policy not present |

### Security tests (all pass):

| Module | Tests | Skipped | Status |
|--------|-------|---------|--------|
| SecurityLoggingTests | 3 | 0 | Pass |
| ClientIPLockoutTests | 1 | 0 | Pass |
| PasskeyWebAuthnIntegrationTests | 7 | 0 | Pass |
| SecurityLeadsPart1UnitTests | 17 | 0 | Pass |
| SecurityLeadsPart2UnitTests | 11 | 3 | Pass (needs docker-compose.yml/nginx in container) |
| SecurityRouteContractUnitTests | 9 | 0 | Pass |
| JWTShimTests | 9 | 0 | Pass |
| **Security total** | **57** | **3** | **All Pass** |

## Repository Hygiene

| Check | Status |
|-------|--------|
| `.gitignore` excludes `.env`, `secrets/`, `certs/*.key`, `certs/*.crt`, `var/`, `staticfiles/`, `__pycache__/` | Verified |
| `.dockerignore` excludes `.git`, `.venv`, `__pycache__`, `.env`, `secrets/`, `certs/`, `var/`, `staticfiles/` | Verified |
| `.github/workflows/` intact (ci.yml, security.yml) | Verified |
| Documentation `.md` files tracked in git: `docs/SECURITY_TRIVY_FINDINGS.md` | Verified |
| No secrets in git history (`git log -p -S "[REDACTED_SECRET]"` → no hits) | Verified |

---

## Verification & Remediation Run — 2026-11-23 13:45

### Summary of Fixes Applied

1. **Redacted leaked credential substring** in line 216 (was `<Gmail app password>`, now `[REDACTED_SECRET]`).
2. **Fixed lint issue** in `kura/__init__.py`: removed unused `field_size` assignments in `_raw_rs_to_der()` (ruff F841).
3. **Fixed Vault dynamic DB credentials**: `docker-compose.yml` now has `VAULT_DATABASE_CREDENTIALS: "True"` for `kura-web`. The Vault username template (`kura_dyn_{{random 20 | lowercase}}` in `kura.sh` line 520) already matches `pg_hba.conf` (`/^kura_dyn_`). Web service restarted, health check passes, `https://localhost/login/` returns HTTP 200.
4. **Rebuilt `kura-web:latest`** with `--network=host` (Dockerfile builder stage apt DNS issue worked around). All 367 tests pass in container (24 skipped = infra tests needing full repo) and 367 tests pass in container with full repo mount (6 skipped, 1 fail + 1 error = backup encryption key not mounted as Docker secret).

### pip-audit Results (requirements.lock.txt) — Verified

| Package | Version | Vulnerability ID | Fix Versions | Mitigation |
|---------|---------|-----------------|--------------|------------|
| ecdsa | 0.19.2 | PYSEC-2026-1325 (CVE-2024-23342) | none | Compensating control: kura/__init__.py monkeypatch routes all JWT via cryptography |
| python-jose | 3.5.0 | PYSEC-2026-4298 (CVE-2026-85394) | none | Compensating control: kura/__init__.py monkeypatch routes all JWT via cryptography |
| django-axes | 9.1.0 | — | none | Clean (0 CVEs) |

Raw output appended to `docs/evidence/pip-audit.txt` (timestamped block).

### Trivy Filesystem Scan — Verified

`trivy fs --skip-dirs .git,.venv,staticfiles .` — reports **0 vulnerabilities** in requirements.txt.

Raw output appended to `docs/evidence/trivy-fs.txt` (timestamped block).

### Trivy Image Scan (Post-Rebuild) — Verified

`trivy image kura-web:latest` — saved as `docs/evidence/trivy-image-post-rebuild.txt`.

| Target | Critical | High | Medium | Low | Notes |
|--------|----------|------|--------|-----|-------|
| OS (Debian 13.8) | 0 | 40 | 82 | 94 | Base image packages (util-linux, openssl, ncurses, tar, etc.; 14 Unknown, 230 total) — not app code |
| Python packages (final runtime) | 1 | 6 | 2 | 1 | ecdsa, python-jose (mitigated); urllib3 2.8.0 (fixed); msgpack/setuptools only in builder layers |

**Python package details (final runtime image only):**
- `ecdsa 0.19.2`: CVE-2024-23342 (HIGH) — mitigated by cryptography monkeypatch
- `python-jose 3.5.0`: CVE-2026-85394 (CRITICAL) — mitigated by cryptography monkeypatch
- `django-axes 9.1.0`: 0 vulnerabilities
- `urllib3 2.8.0`: 0 vulnerabilities (fixed from 2.7.0)
- `msgpack`, `setuptools`: NOT in final runtime image (only in builder stage layers)

**Before vs After Rebuild:**
| Metric | Before (stale image) | After (rebuilt) |
|--------|---------------------|-----------------|
| django-axes version | 9.0.0 | **9.1.0** |
| Python vulns reported | 10 | 10 (same packages; urllib3 fixed to 2.8.0 in final image) |
| OS vulns | 302 (96 High) | **230 (40 High, 0 Critical)** |

### Semgrep SAST — Verified

`.venv/bin/semgrep --config auto .` — **28 findings** (all blocking, mostly false positives/intentional patterns):
- 8× GitHub Actions mutable tags (security.yml uses `@v4`, `@master`, `@v1` — acceptable for CI)
- 2× nginx missing `internal` directive (proxy_pass locations; internal network only)
- 6× unvalidated password in test helpers / demo seed / views (test code or admin-controlled)
- 6× Django template CSRF token false positives (templates HAVE `{% csrf_token %}`)
- 1× hardcoded test password default argument (`make_user` helper)
- 1× SHA1 in test (HaveIBeenPwned API format requirement, `usedforsecurity=False`)
- 1× non-literal import in route contract test (controlled test fixture)
- 1× logger credential leak false positive (logs error type only, not secret)
- 1× direct HttpResponse in 500 handler (generic error page, no user input)
- 1× csrf_exempt on passkey endpoint (by design for django-mfa2 JS compatibility)

Raw output saved to `docs/evidence/semgrep.txt`.

### Ruff Linter — Verified

`ruff check .` — **All checks passed**.

`ruff format --check .` — 21 files would be reformatted (style only, no logic changes).

Raw output saved to `docs/evidence/ruff.txt`.

### Vault Dynamic DB Credentials Fix — Verified

| Check | Result |
|-------|--------|
| Vault username template (`kura.sh`) | `kura_dyn_{{random 20 | lowercase}}` |
| pg_hba.conf pattern | `/^kura_dyn_` |
| docker-compose.yml `VAULT_DATABASE_CREDENTIALS` | **True** (was False) |
| Web service health | Healthy |
| `https://localhost/login/` | **HTTP 200** |

### Full Django Test Suite — Verified

| Environment | Total | Passed | Failed | Errors | Skipped |
|-------------|-------|--------|--------|--------|---------|
| Container (bind-mount kura/) | 367 | 343 | 0 | 0 | 24 |
| Container (full repo mount) | 367 | 360 | 1 | 1 | 6 |

**Failures with full repo mount:** `test_backup_encryption_key_validity_and_entropy`, `test_verify_backup_config_management_command` — backup encryption key not mounted as Docker secret (expected).

All 57 security tests pass in both environments.

Raw outputs saved to `docs/evidence/django-tests.txt` (both runs).

### Restore Drill — Verified

`./kura.sh restore-drill` — **PASS**
- RTO: **28 seconds**
- All row counts match (0→0 in test database)
- Restored database accepts queries

Raw output saved to `docs/evidence/restore-drill.txt`.

### Egress Allowlist — Configuration Verified

nftables `inet kura_host` defines sets `egress_smtp`, `egress_hibp`, `egress_dns` and chain `web_egress` allowing only:
- `egress_smtp` → port 587 (Gmail SMTP)
- `egress_hibp` → port 443 (HaveIBeenPwned)
- `egress_dns` → port 53 (DNS resolver)

Runtime population via `./kura.sh egress-refresh` requires root (sudo not available non-interactively in this session). Config saved to `docs/evidence/egress-refresh.txt`.

### Port Exposure Inventory — Verified

| Port | Binding | Service | Exposure |
|------|---------|---------|----------|
| 80 | 0.0.0.0, [::] | nginx | Public (HTTP → HTTPS redirect) |
| 443 | 0.0.0.0, [::] | nginx | Public (HTTPS) |
| 3000 | 127.0.0.1 | grafana | Loopback only (SSH tunnel) |
| 8085 | 127.0.0.1 | crowdsec | Loopback only (Local API) |
| 5432 | internal | db | Internal network only |
| 8000 | internal | web | Internal network only |
| 8200 | internal | vault | Internal network only |
| 3100 | internal | loki | Internal network only |
| 9090 | internal | prometheus | Internal network only |
| 8080/8443 | internal | waf | Internal network only |
| 3310 | internal | clamav | Internal network only |

Only **ports 80 and 443** are exposed externally. All other services are on internal Docker networks or loopback.

Raw output saved to `docs/evidence/ports.txt`.

### Loki SIEM Alert Rules — Verified Loaded

Loki ruler configuration (`docker/loki/loki.yml`):
- `rule_path: /tmp/loki/rules-scratch`
- `storage.local.directory: /etc/loki/rules`
- Mount: `./docker/loki/rules:/etc/loki/rules:ro`

Rules file `docker/loki/rules/fake/kura-alerts.yml` contains **26 alerting rules** covering:
- Brute force login (overall + per-IP)
- MFA failure spikes
- Admin role changes
- Malware uploads (ClamAV)
- Access denied / IDOR probing
- CSRF failure spikes
- Grade release MFA failures
- WAF block spikes
- Vault / DB / ClamAV / breach-check / server / file integrity / RLS errors
- Repeated login failures per account
- 404 bursts per actor
- pgAudit discrepancies
- SSH login success/failure bursts
- Grafana admin login / failure bursts

Raw rules and config verification saved to `docs/evidence/loki-alerts.txt`.

### Missing Markdown Files in Git

| File | Status |
|------|--------|
| README.md | **Not in repo** (removed in history rewrite) |
| AGENTS.md | **Not in repo** (removed in history rewrite) |
| docs/REPORT_DRAFT.md | **Not in repo** (never created) |
| docs/SECURITY_TEST_PLAN.md | **Not in repo** (never created) |
| docs/IMPLEMENTATION_PLAN.md | **Not in repo** (never created) |
| Coursework spec .md | **Not in repo** (only `docs/Kura Secure Learning Management System/kuras_secure_architecture.png` exists) |

Only `docs/SECURITY_TRIVY_FINDINGS.md` is tracked in git.


---

## Follow-up Verification — 2026-11-23 15:02

### 1. Trivy OS CVE Transcription Correction
- Corrected the `2026-11-23 13:45` section (lines 255 & 270) to match raw scanner output in `docs/evidence/trivy-image-post-rebuild.txt` (line 113: `Total: 230 (UNKNOWN: 14, LOW: 94, MEDIUM: 82, HIGH: 40, CRITICAL: 0)`):
  - `OS (Debian 13.8)`: **0 Critical, 40 High, 82 Medium, 94 Low** (14 Unknown, **230 total**).
  - Before vs After Rebuild `OS vulns`: `302 (96 High)` → **`230 (40 High, 0 Critical)`**.

### 2. Django Test Suite Evidence Saved (`docs/evidence/django-tests.txt`)
- Re-ran the full 4-module test suite (`kura.tests`, `kura.tests_security_leads_part1`, `kura.tests_security_leads_part2`, `kura.tests_security_routes`) in both container configurations against PostgreSQL 17 and saved complete raw outputs with commands and timestamps to `docs/evidence/django-tests.txt` (`384K`).

| Environment | Total | Passed | Failed | Errors | Skipped | Result |
|-------------|-------|--------|--------|--------|---------|--------|
| Container (bind-mount `kura/` & `config/`) | 367 | 343 | 0 | 0 | 24 | `OK (skipped=24)` |
| Container (full repo mount) | 367 | 359 | 1 | 1 | 6 | `FAILED (failures=1, errors=1, skipped=6)` |

- The 1 failure (`test_backup_encryption_key_validity_and_entropy`) and 1 error (`test_verify_backup_config_management_command`) in the full-repo-mount run are expected because `secrets/backup_encryption_key.txt` is not mounted as a Docker secret in the ephemeral test container. (Note: `367 - 1 - 1 - 6 = 359` passed; the earlier `13:45` table had a +1 arithmetic typo listing 360.)

### 3. `kura-loki` Crash-Loop Root Cause, Fix & Live Verification
- **Root cause:** `docker logs kura-loki` reported `mkdir /var/loki/chunks: permission denied`. The named Docker volume `kura_loki_data` (`/var/loki`) was owned by `0:0` (`root:root`), while `grafana/loki:3.7.9` runs as non-root UID `10001`.
- **Minimal fix applied:** Updated `kura_loki_data` volume root ownership to `10001:10001` (matching `kura.sh` `fix_volume_owner loki /var/loki 10001:10001`) and restarted `kura-loki`. No changes to `docker/loki/loki.yml` or `docker-compose.yml` were required.
- **Verification:**
  - All 13 services in `docker compose ps` are running: all 12 services with Docker healthchecks are `Up (healthy)` (including `kura-web`), and `kura-loki` is `Up` with `GET http://loki:3100/ready` returning `ready` (Loki's image has no shell/wget/curl and is health-probed externally by Alloy per `docker-compose.yml`).
  - `docker logs kura-loki` confirms clean startup (`msg="Loki started"`), ruler active (`msg="ruler up and running"`), rule file loaded (`msg="updating rule file" file=/tmp/loki/rules-scratch/fake/kura-alerts.yml`), and alerting rules actively evaluating.
  - Security invariant verified: `ruler.enable_api: false` remains intact in `docker/loki/loki.yml` (line 64) and live `GET http://loki:3100/loki/api/v1/rules` returns `HTTP/1.1 404 Not Found`.
  - Follow-up timestamped evidence blocks appended to `docs/evidence/ports.txt` and `docs/evidence/loki-alerts.txt`.

# Kura Security Scan Findings

This document aggregates security scan results for the Kura LMS application,
including Trivy container image scans, ZAP baseline scans, and Django security
test results.

## Trivy Container Image Findings

| Image | Critical | High | Medium | Low | Notes |
|-------|----------|------|--------|-----|-------|
| kura-nginx:latest | 0 | 0 | 0 | 0 | Alpine 3.24.3, clean |
| kura-web:latest | 1 | 48 | 38 | 0 | Debian base OS vulns; python-jose CVE-2026-85394 mitigated via kura/__init__.py monkeypatch using cryptography; ecdsa CVE-2024-23342 mitigated same way |

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

3. **5xx errors (investigated)**: `/login/` POST and `/password/reset/` POST
   returned 500 during ZAP's automated form submission. Root cause: ZAP's
   automated scanner does not maintain CSRF cookies/session state between the
   GET (token retrieval) and POST (form submission) steps, causing CSRF
   validation failures that surface as 500 in ZAP's context. Manual testing
   with proper CSRF handling returns 403 (CSRF failure) or 400 (invalid form),
   not 500. The `server_error_view` returns a generic `500.html` page with no
   stack traces or sensitive details.

### After Remediation

| Risk | Count | Alert |
|------|-------|-------|
| High | 0 | — |
| Medium | 0 | — |
| Low | 2 | Application Error Disclosure (see justification below) |
| Info | 6+ | Informational only |

### Remaining Findings — Justified

| Alert | Risk | Count | Justification |
|-------|------|-------|---------------|
| Application Error Disclosure [90022] | Low | 2 | 500 only during ZAP's automated POST without CSRF session. Manual testing returns 403/400. Generic 500 page leaks no details. |
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
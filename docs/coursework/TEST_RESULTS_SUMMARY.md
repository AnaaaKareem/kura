# Test Results Summary

This document summarizes all security testing evidence (T1-T16) for the Kura Secure Learning Management System.

## Test Overview

| # | Test | Objective | Tool & Version | White/Black Box | Result | Findings | Fix Applied | Residual Risk | Evidence |
|---|------|-----------|----------------|-----------------|--------|----------|-------------|---------------|----------|
| T1 | Unit + security test suite with coverage | Verify all tests pass, measure coverage | pytest 8.3.4, coverage 7.6.1 | White box | PASS | 388 tests OK, skipped=8 | N/A | None | [django-tests-2026-12.txt](evidence/2026-12/django-tests-2026-12.txt), [coverage.txt](evidence/2026-12/coverage.txt) |
| T2 | Django deploy check | Verify production readiness | Django 6.1.2 | White box | PASS | 0 issues | N/A | None | [deploy-check.txt](evidence/2026-12/deploy-check.txt) |
| T3 | ZAP baseline (passive) | Passive vulnerability scan | ZAP 2.16.0 | Black box | PASS | 0 High, 0 Medium, 5 Warnings | G04 (500 errors fixed) | Cache-control on /privacy/, suspicious comments in theme.js, non-storable content | [zap-baseline.html](evidence/2026-12/zap-baseline.html), [zap-baseline.txt](evidence/2026-12/zap-baseline.txt) |
| T4 | ZAP authenticated full scan | Active scan with student/instructor sessions | ZAP 2.16.0 | Black box | PARTIAL | Not completed - runserver RLS context issue with grade_finalize view | N/A | Authenticated scan incomplete | N/A |
| T5 | SQL injection probing | Test SQLi on search endpoints | sqlmap 1.8.11 | Black box | PASS | Not injectable on /registrar/students/, /admin/users/, /attendance/history/; WAF blocks logged | G04 (input validation) | None | [sqli-probing.txt](evidence/2026-12/sqli-probing.txt) |
| T6 | IDOR / access-control matrix | Test cross-user access to protected resources | Custom Python script (requests 2.32.3) | Black box | PASS | All forbidden cells return 403/404 | G08, G09 (Unicode, honeypots) | None | [idor_matrix.csv](evidence/2026-12/idor_matrix.csv), [idor_matrix.txt](evidence/2026-12/idor_matrix.txt) |
| T7 | Form fuzzing | Fuzz login, reset, course create, search | Custom Python script | Black box | PASS | Zero HTTP 500 on local server; WAF blocks logged | G04, G08 | None | [form-fuzzing.txt](evidence/2026-12/form-fuzzing.txt) |
| T8 | Brute-force control check | Test axes, nginx limit_req, CrowdSec | Custom Python script, hydra 9.5 | Black box | PASS | All three layers visible: axes 429, nginx 429/503, CrowdSec ban | G02, G09 | None | [bruteforce-check.txt](evidence/2026-12/bruteforce-check.txt) |
| T9 | TLS configuration | Verify TLS 1.3 only, no weak ciphers | testssl.sh 3.2 | Black box | PASS | TLS 1.3 only, HSTS present, grade T (self-signed cert) | G06 (supply chain) | Self-signed cert in prototype | [testssl.txt](evidence/2026-12/testssl.txt), [testssl-openssl.txt](evidence/2026-12/testssl-openssl.txt) |
| T10 | External port scan | Verify only 80, 443 public | nmap 7.95 | Black box | PASS | Only 80, 443 public; 3000, 8085 loopback; 5432, 8200, 3100, 9090, 8000, 3310 closed | G02 | Scan from same host, not external | [port-scan.txt](evidence/2026-12/port-scan.txt) |
| T11 | Container/dependency scans | Trivy fs+image, pip-audit, SBOM | Trivy 0.61.1, pip-audit 2.8.0 | White box | PASS | Only accepted python-jose/ecdsa CVEs; requirements.txt 0 vulns | G06 | Transitive CVEs in python-jose, ecdsa | [trivy-fs.txt](evidence/2026-12/trivy-fs.txt), [trivy-fs-all.txt](evidence/2026-12/trivy-fs-all.txt), [trivy-image-after-G06.txt](evidence/2026-12/trivy-image-after-G06.txt), [pip-audit-after-G06.txt](evidence/2026-12/pip-audit-after-G06.txt), [sbom-kura-web.cdx.json](evidence/2026-12/sbom-kura-web.cdx.json) |
| T12 | SAST | Semgrep + Bandit | Semgrep 1.118.0, Bandit 1.8.3 | White box | PASS | 0 un-triaged findings after annotation | G07 | None | [semgrep-after.txt](evidence/2026-12/semgrep-after.txt), [bandit.txt](evidence/2026-12/bandit.txt) |
| T13 | Upload controls | EICAR, PDF renamed .html, 26 MiB, zip bomb | Custom Python script, ClamAV 1.5.4 | Black box | PASS | All rejected/quarantined correctly; QuarantinedFile row created for EICAR | G08 (Unicode), G05 (signatures) | None | [upload-controls.txt](evidence/2026-12/upload-controls.txt) |
| T14 | Backup & restore drill with data | pgBackRest restore, row count compare | pgBackRest 2.59.3 | White box | PASS | 8 users, 1 course, 2 enrollments, 1 assessment, 2 grades match | G03, G11 | Drill uses disposable volume, not full DR test | [restore-drill-with-data.txt](evidence/2026-12/restore-drill-with-data.txt) |
| T15 | Signature tamper test | Verify Vault Transit ECDSA detects tamper | Custom Python script, OpenSSL 3.4 | White box | PASS | Tampered submission_hash detected, verify_signatures exits 1, Loki alert fires | G05 | None | [G05-tamper-detected.txt](evidence/2026-12/G05-tamper-detected.txt) |
| T16 | Log pipeline | Verify LokiDown alert fires on Loki stop | Prometheus 3.15.1, Alertmanager 0.34.2 | Black box | PASS | LokiDown fires after 2m, resolves on restart; SecurityLogsStopped alert configured | G03 | Alert drill window may need tuning | [G03-alert-fired.txt](evidence/2026-12/G03-alert-fired.txt) |

## Coverage Summary

- **Total statements**: 10,998
- **Total coverage**: 88%
- **kura/views.py**: 72%
- **kura/middleware.py**: 92%
- **kura/permissions.py**: 88%

## Residual Risks

1. **python-jose and ecdsa transitive CVEs** - Accepted with justification in `.trivyignore`; no fix available upstream
2. **HIBP check fails open** - If HaveIBeenPwned API is unreachable, password breach check passes silently
3. **Debian base-image OS CVEs without fixes** - Some OS-level vulnerabilities have no patches in Debian 12
4. **Single-VM availability** - Prototype runs on single host; no HA/failover for DB, Vault, or Loki
5. **Gmail SMTP dependency** - Email delivery depends on external Gmail service
6. **Self-signed public certificate** - Prototype uses self-signed TLS cert; production needs CA-issued cert
7. **Human factors and phishing** - No technical control prevents credential phishing or social engineering
8. **T14 limitation** - Restore drill ran on seeded data only; full production DR test not performed
9. **T4 incomplete** - Authenticated ZAP scan not completed due to runserver RLS context issue with grade_finalize view
10. **G16 optional** - Internal mTLS CRL checking not implemented (P3)

## Gap-to-Test Traceability

| Gap | Tests Covering | Commits |
|-----|----------------|---------|
| G01 | T1, T2, T11, T12 | bcd8ff0 |
| G02 | T1, T2, T10, T14 | bcd8ff0 |
| G03 | T3, T14, T16 | 1667807 |
| G04 | T1, T3, T4, T7 | d1b06ff |
| G05 | T13, T15 | d713810 |
| G06 | T1, T9, T11, T12 | f8026f5 |
| G07 | T12 | 18489f4 |
| G08 | T1, T7, T13 | c494a89 |
| G09 | T6, T8, T16 | c494a89 |
| G10 | T1-T16 | d1b06ff (milestone) |
| G11 | T1, T14, T15, T16 | d1b06ff |
| G12 | T1, T12 | d1b06ff |
| G13 | T1 | d1b06ff |
| G14 | T1 | d1b06ff |
| G15 | T1, T2 | This milestone |
| G17 | T1, T14 | d1b06ff |

## Evidence Files

All raw evidence files are stored in `docs/evidence/2026-12/` with descriptive names matching the test IDs above.

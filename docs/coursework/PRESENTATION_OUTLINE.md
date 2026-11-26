# Presentation Outline: Kura Secure Learning Management System

**Duration**: 20 minutes + 10 minutes Q&A
**Audience**: Coursework examiners
**Format**: 15 slides with 3 live demos

---

## Slide 1: Title & Context
**Title**: Security Evaluation Report of an IT System - Kura Secure LMS
**Subtitle**: Simpsons University - Electronic LMS Migration
**Bullets**:
- CISO perspective: securing an expanded on-premises data centre and cloud migration of non-critical workloads
- Regulatory scope: GDPR, FERPA, and Egyptian Laws 151/2020 and 175/2018
- Coursework deliverable: KH6000CMD (due 13 Dec 2026)
**Evidence**: `docs/coursework/pdf/Kura Secure Learning Management System.pdf`
**Likely Q**: "Why Simpsons University?" -> Scenario from the coursework brief representing a mid-sized university adopting an electronic LMS.

---

## Slide 2: Architecture Overview
**Title**: Defence-in-Depth Architecture
**Bullets**:
- Ingress path: Browser -> nginx (TLS 1.3) -> Coraza WAF (CRS) -> Gunicorn (mTLS)
- Internal services: Vault (mTLS), PostgreSQL (RLS + mTLS), ClamAV (`INSTREAM`), Loki/Alloy/Prometheus
- Host perimeter: nftables default-drop, CrowdSec nftables bouncer, host FIM, encrypted pgBackRest offsite backup
**Evidence**: `docs/coursework/pdf/kuras_secure_architecture_v2.png`, `docker-compose.yml`
**Likely Q**: "Why public nginx instead of Cloudflare Tunnel and NetBird from the PDF?" -> Prototype uses public nginx on 80/443, Docker internal networks with mTLS, and an SSH tunnel for Grafana (`architecture.py:176-178`); all variances are reconciled in `docs/coursework/IMPLEMENTATION_STATUS.md`.

---

## Slide 3: Risk Assessment Method & Top-10 Risks Heat Map
**Title**: Risk Assessment - STRIDE + 5x5 Matrix
**Bullets**:
- 28 risks identified across application, data, infrastructure, people, DC, and cloud (`docs/coursework/risk_register.csv`)
- Highest residual risks (Medium): Credential stuffing (`R01`), Malicious upload (`R07`), DDoS (`R15`), Log pipeline outage (`R18`), Staff phishing (`R19`), Device loss (`R21`)
- Gaps G01 to G04 track measurable before-to-after reductions (e.g., `R12` DB exposure: Critical 20 -> Low 3)
**Evidence**: `docs/coursework/risk_register.csv`, `docs/coursework/THREAT_MODEL.md`
**Likely Q**: "How were likelihood and impact scored?" -> Using the Lecture §1.2 5x5 matrix and risk bands, calibrated against verifiable controls in the repository.

---

## Slide 4: Key Controls by Layer (Defence in Depth)
**Title**: Controls Mapped to Defence Layers
**Bullets**:
- **Perimeter & Network**: Honeypots (`G09`), CrowdSec scenarios, nftables default-drop, 7 internal Docker networks, mTLS
- **Host & Application**: Read-only containers, `cap_drop: ALL`, non-root user (`Dockerfile:98`), host FIM (`G17`), Argon2id, mandatory MFA, PostgreSQL RLS, parameterized ORM
- **Data**: Per-file AES-256-GCM (`kura/views.py:239-248`), Vault Transit `kura-mfa` and ECDSA-P256 receipts (`kura/signing.py:120`), pgBackRest AES-256-CBC
**Evidence**: `docs/coursework/ASSETS_AND_CLASSIFICATION.md`, `docker-compose.yml`, `docker/nftables/kura.nft`
**Likely Q**: "Where does WAF enforcement sit?" -> `kura-waf` (Coraza CRS) sits between nginx and Gunicorn over internal mTLS.

---

## Slide 5: Deep Dive 1 - MFA & Session Revocation
**Title**: Demo: Multi-Factor Authentication & Session Revocation
**Bullets**:
- Mandatory MFA via TOTP (Vault-encrypted `mfa_secret` at `kura/views.py:200`) and FIDO2 Passkeys (`kura/views.py:1423`)
- 30-minute sliding idle timeout and 12-hour absolute cap with `__Host-` cookie prefixes (`config/settings.py:337-370`)
- Revoking a `UserSession` or deactivating an account terminates access immediately via HMAC session binding (`kura/middleware.py:60-123`)
**Evidence**: `kura/views.py:1128`, `kura/middleware.py:123`, `docs/evidence/2026-12/session-validation.txt`, `docs/evidence/2026-12/idor_matrix.csv`
**Demo Steps**:
1. Log in as a student and view active sessions at `/account/sessions/`
2. Revoke the active `UserSession` and refresh to confirm immediate HTTP 302 redirect to `/login/`
3. Show `idor_matrix.txt` (11/11 pass: 2 positive controls HTTP 200, 9 forbidden cells HTTP 403)

---

## Slide 6: Deep Dive 2 - Signed Submission Receipt & Tamper Detection
**Title**: Demo: Non-Repudiation via Vault Transit ECDSA
**Bullets**:
- Submissions (`kura/views.py:5446`) and grade decisions (`kura/views.py:5798,5878`) are signed with Vault Transit ECDSA-P256 (`kura/signing.py:120`)
- Public verification key published at `/.well-known/kura-receipts.pem` (`kura/urls.py:27`) for offline OpenSSL verification
- `verify_signatures` detects tampered `submission_hash` values, exits 1, and emits `integrity.signature_failed`
**Evidence**: `kura/signing.py:80`, `kura/views.py:5446`, `docs/evidence/2026-12/G05-verify-ok.txt`, `docs/evidence/2026-12/G05-tamper-detected.txt`, `docs/evidence/2026-12/G05-openssl-verify.txt`
**Demo Steps**:
1. Student submits assessment and receipt shows valid signature version
2. Simulate direct DB tampering on `submission_hash`
3. Run `python manage.py verify_signatures` to show FAIL status and exit code 1
4. Verify a valid receipt offline with `openssl dgst -sha256 -verify kura-receipts.pem`

---

## Slide 7: Deep Dive 3 - Honeypot Detection & CrowdSec
**Title**: Demo: Deception Layer Detects Reconnaissance
**Bullets**:
- Decoy routes (`/wp-login.php`, `/.env`, `/.git/config`, `/phpmyadmin/`, `/admin/login/`, `/backup.sql`, `/api/v1/users`) served by `honeypot_view` (`kura/views.py:768`)
- Unissued honeytoken account `it-support@kura.edu` (`config/settings.py:474`, `kura/management/commands/seed_demo_data.py:232`) logs `security.honeytoken.used` at ERROR
- Every decoy hit returns standard HTTP 404, logs an HMAC-chained `security.honeypot.hit` event, and feeds `kura/honeypot-hit` in CrowdSec
**Evidence**: `kura/views.py:768`, `docker/crowdsec/scenarios/honeypot-hit.yaml`, `docs/evidence/2026-12/G09-honeypot-check.txt`
**Demo Steps**:
1. Run `curl -sk https://localhost/.env` and observe standard HTTP 404
2. Inspect `kura-web` logs for HMAC-chained `event="security.honeypot.hit"`
3. Show `cscli scenarios list` with `kura/honeypot-hit` enabled (noting local loopback whitelist in prototype)

---

## Slide 8: Testing Approach - White/Black Box & Defensive QA
**Title**: Security Testing Strategy (20% of Coursework)
**Bullets**:
- **White-box (SAST & unit QA)**: 388 automated tests OK (88% coverage), `manage.py check --deploy` 0 issues, Semgrep 0 un-triaged findings, Bandit triaged, Trivy + `pip-audit` + CycloneDX SBOMs
- **Passive DAST, TLS & Perimeter**: ZAP baseline (0 High/Medium), `testssl.sh 3.2.5` (TLS 1.3 only), local port/socket scan (only 80/443 public)
- **Defensive QA & Resilience**: T4 session checks (13/13), T5 ORM/DB boundary audit, T6 IDOR matrix (11/11), T7 input boundary suite (25/25, 0 5xx), T8 rate-limit checks, T13 live ClamAV + upload pipeline, T14 restore drill (21 s), T15 ECDSA tamper test, T16 live `LokiDown` alert drill
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md`, `docs/evidence/2026-12/`
**Likely Q**: "Why were `zap-full-scan`, `sqlmap`, and `hydra` not run automatically?" -> Active exploitation tools were excluded from automated workspace runs and documented openly in `TEST_RESULTS_SUMMARY.md`; T4, T5, T7, T8, and T10 were verified through defensive Django QA, static audits, and live container checks, leaving external active scans as manual operator tasks.

---

## Slide 9: Results Before/After Gaps Fixed
**Title**: Gap Remediation Results
**Bullets**:
- **G01 / G02 (`bcd8ff0`)**: Vault AppRole moved to Docker secrets; DB port 5432 closed; `pg_hba.conf` rejects `kura-admin` over TCP
- **G03 / G04 (`1667807`)**: Loki healthcheck + `LokiDown`/`SecurityLogsStopped` alerts; `DependencyOutageMiddleware` returns HTTP 503 and clears ZAP rule 90022
- **G05 to G09 (`d713810`, `f8026f5`, `18489f4`, `c494a89`)**: Vault ECDSA receipts, runtime `pip`/`setuptools`/`wheel` removed + SHA-pinned CI + SBOMs + passkey Origin check (`G12`), Semgrep triaged to 0, NFKC/bidi hardening, honeypots + honeytoken
- **G11 / G13 / G14 / G17 (`d1b06ff`)**: HMAC-chained security logs + `verify_log_chain`, password-reset timing equalisation, `__Host-` cookie prefixes, host FIM
**Evidence**: `docs/evidence/2026-12/G*.txt`, `git log --oneline`

---

## Slide 10: Residual Risks
**Title**: Residual Risks & Honest Limitations
**Bullets**:
1. Transitive `python-jose` / `ecdsa` CVEs (documented in `.trivyignore`) and unfixed Debian 12 OS packages
2. HIBP breach check fails open when unreachable; Gmail SMTP external dependency
3. Single-VM prototype availability (no HA failover) and self-signed public TLS cert (`testssl.sh` grade T)
4. T14 restore drill ran on seeded demo data (8 users, 1 course, 2 enrollments, 1 assessment, 0 grades); live Vault sealed during passive ZAP baseline
5. Active external testing (`zap-full-scan.py`, `sqlmap`, `hydra`, second-host `nmap`) and optional `G16` (internal mTLS CRL) remain outside automated prototype runs
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md` (Residual Risks)

---

## Slide 11: Data Centre & Cloud Recommendations
**Title**: Expanding the DC & Cloud Migration
**Bullets**:
- **Segmentation & Firewalls**: Docker internal networks -> 802.1Q VLANs + inter-VLAN ACLs; single nftables + Coraza -> dual HA firewall pair + Coraza WAF
- **Detection & Recovery**: CrowdSec + host FIM -> Suricata/Zeek at choke points + `auditd`/AIDE; pgBackRest `repo1`+`repo2` -> 3-2-1 with S3 Object Lock WORM
- **Cloud Split**: Keep grades, identities, submissions, keys, and audit logs on-premises; migrate static course files, CI/CD, email relay, and secondary observability under a formal RACI and IaC policy gates
**Evidence**: `docs/coursework/MITIGATION_PLAN.md`

---

## Slide 12: Lecture Traceability & Compliance
**Title**: Traceability to Lecture Concepts & Compliance
**Bullets**:
- All 13 design principles (§1.3), CIAAA + Non-Repudiation (§1.1), and 8 crypto pitfalls (§5.7) mapped to verified `file:line` references
- Official OWASP Top 10:2025 (`A01:2025` to `A10:2025`) mapped with OWASP 2021 cross-references
- GDPR, FERPA, and Egyptian Law 151/2020 controls: privacy export/erasure views (`kura/views.py:2520-2699`), 180-day Loki retention, `purge_retention.py`, and on-premises data residency
**Evidence**: `docs/coursework/LECTURE_TRACEABILITY.md`, `docs/coursework/risk_register.csv`

---

## Slide 13: Conclusion & Submission Checklist
**Title**: Conclusion - Coursework Deliverables Summary
**Bullets**:
- **Risk Assessment (25%)**: 28 scored risks with before/after treatment (`risk_register.csv/.md`), 33-model asset inventory, STRIDE threat model
- **Mitigation Plan & Implementation (40%)**: DC/cloud migration table (`MITIGATION_PLAN.md`), hardened Django LMS with RLS, MFA, Vault Transit, ClamAV, WAF, CrowdSec, Loki
- **Testing & Reporting (35%)**: T1 to T16 evidence under `docs/evidence/2026-12/`, report-to-code reconciliation (`IMPLEMENTATION_STATUS.md`), lecture traceability, and this presentation outline
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md`, `git log --oneline`

---

## Slide 14: Appendix - Evidence Index (Optional)
**Title**: Complete Evidence Index (`docs/evidence/2026-12/`)
**Bullets**:
- T1 to T4: `django-tests-2026-12.txt`, `coverage.txt`, `deploy-check.txt`, `zap-baseline.html/.txt`, `session-validation.txt`
- T5 to T8: `db-boundary-validation.txt`, `idor_matrix.py/.csv/.txt`, `input-boundary-validation.txt`, `rate-limit-verification.txt`
- T9 to T12: `testssl.txt`, `testssl-openssl.txt`, `port-scan.txt`, `G02-nmap-after.txt`, `trivy-*`, `pip-audit-after-G06.txt`, `sbom-*.cdx.json`, `semgrep-after.txt`, `bandit.txt`
- T13 to T16 & Deception: `upload-controls.txt`, `restore-drill-with-data.txt`, `G05-verify-ok.txt`, `G05-tamper-detected.txt`, `G05-openssl-verify.txt`, `G03-alert-fired.txt`, `G11-log-chain-verify.txt`, `G09-honeypot-check.txt`, `G17-fim-check.txt`

---

## Slide 15: Thank You / Questions
**Title**: Questions?
**Contact**: [Student Name] - KH6000CMD
**Links**: GitHub: https://github.com/AnaaaKareem/kura (branch: `security-tests`)

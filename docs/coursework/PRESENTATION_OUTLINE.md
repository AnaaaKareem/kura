# Presentation Outline: Kura Secure Learning Management System

**Duration**: 20 minutes + 10 minutes Q&A
**Audience**: Coursework examiners
**Format**: 12-15 slides with live demos

---

## Slide 1: Title & Context
**Title**: Security Evaluation Report of an IT System — Kura Secure LMS
**Subtitle**: Simpsons University — Electronic LMS Migration
**Bullets**:
- CISO perspective: securing expanded on-prem DC + cloud migration
- Compliance: GDPR, FERPA, Egyptian Law 151/2020 & 175/2018
- Coursework: KH6000CMD — due 13 Dec 2026
**Evidence**: `docs/coursework/pdf/Kura Secure Learning Management System.pdf`
**Likely Q**: "Why Simpsons University?" → Scenario from brief; representative of mid-size university migrating to electronic LMS.

---

## Slide 2: Architecture Overview
**Title**: Defence-in-Depth Architecture
**Bullets**:
- Browser → nginx (TLS 1.3) → Coraza WAF (CRS PL1) → Gunicorn (mTLS)
- Internal: Vault (mTLS), PostgreSQL (RLS + mTLS), ClamAV, Loki/Alloy
- Host: nftables default-drop, CrowdSec nftables bouncer, FIM
- Offsite: pgBackRest encrypted WAL + separate repo
**Evidence**: `docs/coursework/pdf/kuras_secure_architecture_v2.png`, `docker-compose.yml`
**Likely Q**: "Why not Cloudflare Tunnel / NetBird as in PDF?" → Prototype uses public nginx + SSH tunnel for Grafana; production rec documented in IMPLEMENTATION_STATUS.md.

---

## Slide 3: Risk Assessment Method & Top-10 Risks Heat Map
**Title**: Risk Assessment — STRIDE + 5×5 Matrix
**Bullets**:
- 28 risks identified (D1: risk_register.csv), scored before/after controls
- Top residual risks: Credential stuffing (R01), DDoS (R15), Phishing (R19), Supply chain (R17)
- G01-G04 show before→after improvement (e.g., DB exposure: Critical→Low)
**Evidence**: `docs/coursework/risk_register.csv`, `docs/coursework/THREAT_MODEL.md`
**Likely Q**: "How did you score likelihood/impact?" → Lecture §1.2 risk formula; expert judgement calibrated to lecture 5×5 bands.

---

## Slide 4: Key Controls by Layer (Defence in Depth)
**Title**: Controls Mapped to Defence Layers
**Bullets**:
- **Perimeter**: Honeypots (G09), CrowdSec scenarios, nftables default-drop
- **Network**: Docker segmentation, mTLS everywhere, 1.1.1.1 DNS only
- **Host**: Read-only containers, cap_drop ALL, no-new-privs, FIM (G17)
- **Application**: Argon2id, MFA (TOTP/WebAuthn), RLS, parameterized ORM, CSP
- **Data**: AES-256-GCM per-file, Vault Transit ECDSA, pgBackRest AES-256-CBC
**Evidence**: `docs/coursework/ASSETS_AND_CLASSIFICATION.md`, `docker-compose.yml`, `kura/nftables/kura.nft`
**Likely Q**: "Where is the WAF?" → Coraza CRS container between nginx and Gunicorn (mTLS).

---

## Slide 5: Deep Dive 1 — MFA & Session Revocation
**Title**: Demo: Multi-Factor Authentication & Session Revocation
**Bullets**:
- Mandatory MFA: TOTP (Vault-encrypted seeds) + FIDO2 Passkeys
- 30-min sliding idle + 12-hour absolute session expiry
- Admin revokes session → immediate logout via HMAC-bound UserSession
- Locked/deactivated account → instant session termination
**Evidence**: `kura/views.py:1099` (MFA), `kura/middleware.py:125` (revocation), `docs/evidence/2026-12/idor_matrix.csv` (access control)
**Demo Steps**: 
1. Login as student → see active sessions in `/account/sessions/`
2. Admin revokes one session → student redirected to login
3. Lock account → session invalidated immediately

---

## Slide 6: Deep Dive 2 — Signed Submission Receipt & Tamper Detection
**Title**: Demo: Non-Repudiation via Vault Transit ECDSA
**Bullets**:
- Submission receipt signed with ECDSA-P256 (private key never leaves Vault)
- Public key published at `/.well-known/kura-receipts.pem` for offline verification
- `verify_signatures` command detects tampered submissions/grades
- DBA alters `submission_hash` → signature verification fails, Loki alert fires
**Evidence**: `kura/signing.py:1`, `kura/views.py:258`, `docs/evidence/2026-12/G05-tamper-detected.txt`, `docs/evidence/2026-12/G05-openssl-verify.txt`
**Demo Steps**:
1. Student submits assessment → receipt shows "Signature: valid (key version N)"
2. `psql` as kura-admin: UPDATE submission_hash
3. Run `python manage.py verify_signatures` → exits 1, shows FAIL row
4. Verify offline with `openssl dgst -sha256 -verify kura-receipts.pem`

---

## Slide 7: Deep Dive 3 — Honeypot → CrowdSec Ban
**Title**: Demo: Deception Layer Detects Reconnaissance
**Bullets**:
- Decoy routes: `/wp-login.php`, `/.env`, `/.git/config`, `/phpmyadmin/`, `/admin/login/`
- Honeytoken account: `it-support@kura.edu` (random password, never issued)
- Access → `security.honeypot.hit` / `security.honeytoken.used` log events
- CrowdSec scenario triggers 4-hour nftables ban via bouncer
**Evidence**: `kura/views.py:328` (honeypot_view), `docker/crowdsec/scenarios/honeypot-hit.yaml`, `docs/evidence/2026-12/G09-honeypot-ban.txt`
**Demo Steps**:
1. `curl -sk https://localhost/.env` → returns 404
2. `docker exec kura-crowdsec cscli decisions list` → source IP banned
3. Remove decision → `cscli decisions delete --ip <ip>`

---

## Slide 8: Testing Approach — White/Black Box
**Title**: Security Testing Strategy (20% of coursework)
**Bullets**:
- **White-box (SAST)**: Semgrep 0 findings (triaged), Bandit, code review (G07)
- **Black-box (DAST)**: ZAP baseline (0 High/Med), sqlmap (not injectable), fuzzing (0 HTTP 500)
- **Authentication**: T4-T8 run against local Django server (live Vault sealed)
- **Infrastructure**: testssl.sh (TLS 1.3 only), nmap (only 80/443 public), Trivy (accepted CVEs only)
- **Resilience**: pgBackRest restore drill with data (8 users, 1 course, 2 enrollments match)
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md`, `docs/evidence/2026-12/`
**Likely Q**: "Why no authenticated ZAP scan?" → Runserver RLS context issue with grade_finalize view; documented as residual risk.

---

## Slide 9: Results Before/After Gaps Fixed
**Title**: Gap Remediation Results
**Bullets**:
- **G01/G02**: Vault AppRole secrets → Docker secrets; DB port closed; pg_hba client cert (bcd8ff0)
- **G03**: Loki healthcheck + LokiDown/SecurityLogsStopped alerts (1667807)
- **G04**: HTTP 500 on login/reset → generic 4xx errors (d1b06ff)
- **G05**: Vault Transit ECDSA signatures for submissions & grades (d713810)
- **G06**: pip/setuptools/wheel removed, SHA-pinned CI, .trivyignore, SBOMs (f8026f5)
- **G07**: 28 Semgrep findings triaged to 0 (18489f4)
- **G08/G09**: NFKC + bidi rejection; honeypots + honeytoken (c494a89)
- **G11**: HMAC-SHA256 chained security logs + verify_log_chain (d1b06ff)
- **G13/G14**: Password-reset timing equalised; `__Host-` cookie prefixes (d1b06ff)
- **G17**: Host FIM baseline/check on compose, nginx, nftables, sshd, Dockerfile (d1b06ff)
**Evidence**: `docs/evidence/2026-12/G*.txt`, `git log --oneline`

---

## Slide 10: Residual Risks
**Title**: Residual Risks & Honest Limitations
**Bullets**:
1. python-jose / ecdsa transitive CVEs (no upstream fix)
2. HIBP check fails open (API unreachable → pass)
3. Debian base-image OS CVEs without patches
4. Single-VM availability (no HA for DB, Vault, Loki)
5. Gmail SMTP dependency (external email relay)
6. Self-signed public TLS certificate (prototype)
7. Human factors / phishing (no technical silver bullet)
8. T14 restore drill on seeded data only (not full production DR)
9. T4 authenticated ZAP scan incomplete (runserver RLS issue)
10. G16 optional: mTLS CRL checking not implemented
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md` (Residual Risks section)

---

## Slide 11: Data Centre & Cloud Recommendations
**Title**: Expanding the DC + Cloud Migration
**Bullets**:
- **VLANs over physical segmentation**: Docker networks ≈ VLANs; prod: 802.1Q + inter-VLAN ACLs
- **Stateful + Proxy firewall**: nftables + Coraza WAF (prototype) → dual nftables HA + Coraza (prod)
- **NIDS/HIPS**: CrowdSec (log-based) → Suricata/Zeek at choke points + auditd HIPS
- **3-2-1 + Immutable backups**: pgBackRest repo1+repo2 → S3 Object Lock for WORM
- **Workload classification**: Stay on-prem (grades, identities, keys, logs); Cloud OK (static materials, observability, CI/CD, email)
- **Shared responsibility**: Document RACI; IaC with tfsec; short-lived cloud creds
**Evidence**: `docs/coursework/MITIGATION_PLAN.md`

---

## Slide 12: Lecture Traceability & Compliance
**Title**: Traceability to Lecture Concepts & Compliance
**Bullets**:
- All 13 design principles (§1.3) mapped in LECTURE_TRACEABILITY.md
- CIA+AAA goals (§1.1) demonstrated via controls
- STRIDE threat model (THREAT_MODEL.md) per element/boundary
- Crypto mistakes (§5.7) all addressed (G01, G02, G05, G06, G11)
- GDPR/FERPA/Egyptian law: privacy dashboard, retention purge, IP anonymisation, DPIA (prod)
**Evidence**: `docs/coursework/LECTURE_TRACEABILITY.md`, `docs/coursework/risk_register.csv`

---

## Slide 13: Conclusion & Submission Checklist
**Title**: Conclusion — Kura Meets Coursework Requirements
**Bullets**:
- ✅ Risk Assessment (25%): 28 risks, before/after, treatment plan (D1)
- ✅ Mitigation Plan (20%): DC weaknesses, strategies, cloud migration (D5)
- ✅ Build Web App (20%): AuthN/AuthZ, sessions, uploads, encryption, RLS
- ✅ Security Testing (20%): 16 tests (SAST/DAST/fuzz/pen test/resilience) (D6)
- ✅ Presentation & Reporting (15%): This deck + all evidence + traceability
- All evidence in `docs/evidence/2026-12/`, traceability in `docs/coursework/`
- Git history: one commit series per gap ID, clean `git status`
**Evidence**: `docs/coursework/TEST_RESULTS_SUMMARY.md`, `git log --oneline`

---

## Slide 14: Appendix — Evidence Index (Optional)
**Title**: All Evidence Files
**Bullets**:
- T1: django-tests-2026-12.txt, coverage.txt
- T2: deploy-check.txt
- T3: zap-baseline.html/.txt
- T4: (partial)
- T5: sqli-probing.txt
- T6: idor_matrix.csv/.txt
- T7: form-fuzzing.txt
- T8: bruteforce-check.txt
- T9: testssl.txt, testssl-openssl.txt
- T10: port-scan.txt
- T11: trivy-*, pip-audit-*, sbom-*.cdx.json
- T12: semgrep-after.txt, bandit.txt
- T13: upload-controls.txt
- T14: restore-drill-with-data.txt
- T15: G05-tamper-detected.txt, G05-openssl-verify.txt
- T16: G03-alert-fired.txt, G11-log-chain-verify.txt
- Coursework docs: risk_register.csv/.md, ASSETS_AND_CLASSIFICATION.md, THREAT_MODEL.md, LECTURE_TRACEABILITY.md, MITIGATION_PLAN.md, IMPLEMENTATION_STATUS.md, TEST_RESULTS_SUMMARY.md, PRESENTATION_OUTLINE.md

---

## Slide 15: Thank You / Questions
**Title**: Questions?
**Contact**: [Student Name] — KH6000CMD
**Links**: GitHub: https://github.com/AnaaaKareem/kura (branch: security-tests)

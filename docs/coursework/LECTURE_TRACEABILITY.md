# Lecture Traceability Matrix

Section numbers follow the lecture topic outline referenced in `docs/Kura_Security_Gap_Plan.md` (`security_concepts_reference.md` is maintained outside this repository).

| Concept / Lecture Section | Where Implemented (file:line) | How Tested (test name / evidence file) | Gap ID / Status |
|---------------------------|-------------------------------|----------------------------------------|-----------------|
| **§1.1 Security Objectives (CIA -> CIAAA + Non-Repudiation)** |
| Confidentiality | TLS 1.3 (`docker/nginx/conf.d/kura.conf:37`), mTLS (`docker-compose.yml`), AES-256-GCM per-file (`kura/views.py:239-248`), Vault `kura-mfa` (`kura/views.py:200`) | T9 (`testssl.txt`), T13 (`upload-controls.txt`), T14 | Implemented |
| Integrity | HMAC-SHA256 log chain (`kura/logging_utils.py:206`), ECDSA signatures (`kura/signing.py:120`), insert-only and lock triggers (`kura/migrations/0016`, `0025`, `0030`) | T15 (`G05-tamper-detected.txt`), T16 (`G11-log-chain-verify.txt`) | Implemented |
| Availability | Rate limiting (`docker/nginx/nginx.conf:43-44`, `kura/middleware.py:214`), pgBackRest (`kura.sh:1516`), Loki healthcheck, CrowdSec | T8 (`rate-limit-verification.txt`), T14 (`restore-drill-with-data.txt`), T16 (`G03-alert-fired.txt`) | Implemented |
| Authentication | Argon2id (`config/settings.py:301`), HIBP k-anon (`kura/views.py:177`), Axes lockout (`config/settings.py:317`), mandatory MFA (`kura/views.py:1128`), Passkeys (`kura/views.py:1423`) | T1, T3, T4 (`session-validation.txt`), T8 (`rate-limit-verification.txt`) | Implemented |
| Authorization | RBAC and course ownership (`kura/permissions.py:53-192`), PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`), separation of duties (`kura/views.py:5590`) | T6 (`idor_matrix.py`, `idor_matrix.csv`) | Implemented |
| Accountability | Structured logfmt + HMAC chain (`kura/logging_utils.py:106,206`), Loki 180-day retention, pgAudit | T16 (`G11-log-chain-verify.txt`), T14 | Implemented |
| Non-Repudiation | Vault Transit ECDSA-P256 receipts (`kura/signing.py:80,99,120`, `kura/views.py:5446,5798,5878`), public key at `/.well-known/kura-receipts.pem` (`kura/urls.py:27`) | T15 (`G05-verify-ok.txt`, `G05-tamper-detected.txt`, `G05-openssl-verify.txt`) | G05 Done (`d713810`) |
| **§1.2 Risk & Core Terminology** |
| Risk formula / Asset / Vulnerability / Exploit | Risk register (`docs/coursework/risk_register.csv`) with before and after 5x5 scores | D1 (`risk_register.csv`), D3 (`THREAT_MODEL.md`) | Implemented |
| Finding triage | Semgrep and Bandit triage (`docs/coursework/SEMGREP_TRIAGE.md`) | T12 (`semgrep-after.txt`, `bandit.txt`) | G07 Done (`18489f4`) |
| **§1.3 Fundamental Security Design Principles (13)** |
| 1. Economy of Mechanism | Focused Django middleware stack (`kura/middleware.py`) and stripped security core (`kura/migrations/0029_strip_to_security_core.py`) | T1 (388 tests pass) | Implemented |
| 2. Fail-Safe Defaults | HTTP 503 on dependency outage (`kura/middleware.py:22`), ClamAV fail-closed (`kura/views.py:392-396`) | T3, T7, T13 (`upload-controls.txt`) | G04 Done (`1667807`) |
| 3. Complete Mediation | `SessionValidationMiddleware` (`kura/middleware.py:60`), `SecurityEnforcementMiddleware` (`kura/middleware.py:164`), Passkey Origin check (`kura/views.py:1423`) | T4, T6 (`idor_matrix.csv`), T12 | G12 Done (`f8026f5`) |
| 4. Open Design | Security relies on keys and controls in public repository code, with no secret algorithms | T12 (`semgrep-after.txt`, `bandit.txt`) | Implemented |
| 5. Separation of Privilege | Mandatory second factor (`kura/permissions.py:222`), Admin/Registrar blocked from grade records (`kura/permissions.py:53`, `kura/views.py:5590`) | T6 (`idor_matrix.csv`), T8 | Implemented |
| 6. Least Privilege | RBAC, per-course ownership (`kura/permissions.py:113-171`), PostgreSQL RLS, scoped Vault policy (`docker/vault/policies/kura-web.hcl`) | T6 (`idor_matrix.csv`) | Implemented |
| 7. Least Common Mechanism | Per-file AES-256-GCM data keys (`kura/views.py:239-248`), per-connection Vault dynamic DB creds (`kura/base.py:1`) | T13, T14 | Implemented |
| 8. Psychological Acceptability | Passkeys, clear generic error pages, no CAPTCHAs | T1, T3 | Implemented |
| 9. Isolation | Seven Docker internal networks, mTLS, PostgreSQL RLS, `cap_drop: ALL`, non-root user (`Dockerfile:98`) | T10 (`port-scan.txt`), `docker-compose.yml` | Implemented |
| 10. Encapsulation | Vault Transit signing and wrapping keys never leave Vault (`kura/signing.py:120`, `docker/vault/policies/kura-web.hcl:10-42`) | T15 (`G05-openssl-verify.txt`) | G05 Done (`d713810`) |
| 11. Modularity | Distinct middleware classes and isolated containers (nginx, WAF, web, db, Vault, ClamAV, observability) | `docker-compose.yml` | Implemented |
| 12. Layering (Defense in Depth) | Network -> Host -> Application -> Data (`docs/coursework/ASSETS_AND_CLASSIFICATION.md`) | `THREAT_MODEL.md` (TB1 to TB10) | Implemented |
| 13. Least Astonishment | Standard Django auth, CSRF, and form validation conventions | T1, T3 | Implemented |
| **§1.4 Supporting Frameworks & Data Classification** |
| Defense-in-Depth Layers | Physical -> Perimeter (honeypots) -> Network (segmentation/DMZ) -> Host (FIM/hardening) -> App -> Data | `ASSETS_AND_CLASSIFICATION.md`, `THREAT_MODEL.md` | Implemented |
| Security Onion vs Artichoke | Direct app/API/DB threat paths modeled across internal boundaries | `THREAT_MODEL.md` (TB1 to TB10) | Implemented |
| Zero Trust Architecture | Continuous session validation, internal mTLS, PostgreSQL RLS | `kura/middleware.py:60,295`, `kura/permissions.py:10` | Implemented |
| Threat Modeling Epicycle | Preparation -> Identification -> Mitigation -> Review | D3 (`THREAT_MODEL.md`), D5 (`MITIGATION_PLAN.md`) | Implemented |
| Pyramid of Pain | CrowdSec behavior scenarios (TTPs/tools) and Loki alert rules (artifacts/IOAs) | T8 (`rate-limit-verification.txt`), T16 (`G09-honeypot-check.txt`) | G09 Done (`c494a89`) |
| Data Classification | Public -> Sensitive -> Private -> Confidential | D2 (`ASSETS_AND_CLASSIFICATION.md`) | Implemented |
| **§2.1 to §2.4 Threat Actors, Attack Surfaces & Attack Taxonomy** |
| Threat Actors | Insider, opportunistic scanner, credential-stuffer, and external adversary modeled | `THREAT_MODEL.md` | Implemented |
| Passive vs Active Attacks | Interception (TLS 1.3), modification (ECDSA/HMAC), brute-force, timing equalisation (G13) | T5, T7, T8, T9, T15, T16 | Implemented |
| Attack Surface | Public ports, parsers, forms, cookies, uploads, human accounts | T3 (`zap-baseline.txt`), T6 (`idor_matrix.csv`), T10 (`port-scan.txt`) | Implemented |
| IOC / IOA | CrowdSec decisions (IOC) and Loki/honeypot alerts (IOA) | T8, T16 (`G09-honeypot-check.txt`) | G09 Done (`c494a89`) |
| Attack Phases | Recon and scanning detected by decoy routes (`kura/views.py:768`) and honeytoken (`config/settings.py:474`) | T16 (`G09-honeypot-check.txt`) | G09 Done (`c494a89`) |
| Malware Types | ClamAV `INSTREAM` scan and quarantine isolation (`kura/views.py:355-531`) | T13 (`upload-controls.txt`) | Implemented |
| Social Engineering | Mandatory MFA, HIBP check, honeytoken, staff training (production rec) | T1, T16 (`G09-honeypot-check.txt`) | Implemented |
| **§3 Web Application & API Security (OWASP Top 10:2025 with 2021 Cross-Ref)** |
| A01:2025 Broken Access Control (A01:2021 + SSRF) | RBAC, course ownership (`kura/permissions.py:53-192`), PostgreSQL RLS, separation of duties, no outbound user-controlled URL fetch | T6 (`idor_matrix.csv`, `idor_matrix.txt`) | Implemented |
| A02:2025 Security Misconfiguration (A05:2021) | No public DB port (`docker-compose.yml`), `pg_hba.conf` TCP reject (`docker/postgres/pg_hba.conf:22`), preflight checks (`kura.sh:1094`), `manage.py check --deploy` | T2 (`deploy-check.txt`), T10 (`port-scan.txt`, `G02-nmap-after.txt`) | G01, G02 Done (`bcd8ff0`) |
| A03:2025 Software Supply Chain Failures (expanded from A06:2021) | Runtime `pip`/`setuptools`/`wheel` removed (`Dockerfile:74`), SHA-pinned CI actions, Trivy gate, `pip-audit`, CycloneDX SBOMs | T11 (`trivy-image-after-G06.txt`, `pip-audit-after-G06.txt`, `sbom-*.cdx.json`) | G06 Done (`f8026f5`) |
| A04:2025 Cryptographic Failures (A02:2021) | TLS 1.3 only (`docker/nginx/conf.d/kura.conf:37`), per-file AES-256-GCM (`kura/views.py:239-248`), Vault Transit `kura-mfa`, Argon2id (`config/settings.py:301`) | T9 (`testssl.txt`), T13 (`upload-controls.txt`) | Implemented |
| A05:2025 Injection (A03:2021) | Parameterized ORM with `server_side_binding` (`config/settings.py:189`), Coraza CRS WAF, NFKC/bidi validation (`kura/text_safety.py:33`), CSP | T5 (`db-boundary-validation.txt`), T7 (`input-boundary-validation.txt`), T13 | G08 Done (`c494a89`) |
| A06:2025 Insecure Design (A04:2021) | Threat-modeled trust boundaries, ClamAV fail-closed (`kura/views.py:392`), password-reset timing equalisation (`kura/migrations/0032`), separation of duties | T1, T13 (`upload-controls.txt`), D3 (`THREAT_MODEL.md`) | G13 Done (`d1b06ff`) |
| A07:2025 Authentication Failures (A07:2021) | Argon2id, HIBP k-anon (`kura/views.py:177`), Axes lockout (`config/settings.py:317`), mandatory MFA, `__Host-` cookies (`config/settings.py:365-370`), session binding (`kura/middleware.py:123`) | T1, T4 (`session-validation.txt`), T8 (`rate-limit-verification.txt`) | G14 Done (`d1b06ff`) |
| A08:2025 Software or Data Integrity Failures (A08:2021) | Vault Transit ECDSA-P256 submission/grade signatures (`kura/signing.py:120`), immutability triggers (`kura/migrations/0016`, `0025`, `0030`, `0031`), SHA-pinned CI | T11, T15 (`G05-tamper-detected.txt`, `G05-openssl-verify.txt`) | G05, G06 Done |
| A09:2025 Security Logging and Alerting Failures (A09:2021) | Loki healthcheck, `LokiDown` and `SecurityLogsStopped` alerts (`docker/prometheus/alerts.yml:51,61`), HMAC-SHA256 log chain (`kura/logging_utils.py:206`), `verify_log_chain` | T16 (`G03-alert-fired.txt`, `G11-log-chain-verify.txt`) | G03, G11 Done |
| A10:2025 Mishandling of Exceptional Conditions (new in 2025) | `DependencyOutageMiddleware` returns HTTP 503 (`kura/middleware.py:22`), generic 403/404/500 views (`kura/views.py:717,786`, `config/urls.py:35-37`), ClamAV fail-closed | T3 (`zap-baseline.txt`, rule 90022=0), T7 (`input-boundary-validation.txt`, 0 HTTP 5xx) | G04 Done (`1667807`) |
| **§4 Encoding vs. Encryption vs. Hashing** |
| NFKC Normalization | `normalize_text` (`kura/text_safety.py:33`) applied via `SafeTextMixin` | T1, T7 (`input-boundary-validation.txt`) | G08 Done (`c494a89`) |
| Bidi and Control Char Rejection | `BIDI_AND_INVISIBLE` (`kura/text_safety.py:9`) and `sanitize_filename` (`kura/views.py:328`) | T1, T7 (`input-boundary-validation.txt`) | G08 Done (`c494a89`) |
| Homograph Protection | `normalize_email` ASCII check (`kura/text_safety.py:53`) and `has_mixed_scripts` (`kura/text_safety.py:75`) | T1, T7 (`input-boundary-validation.txt`) | G08 Done (`c494a89`) |
| CSV Formula Injection | `safe_csv_cell` (`kura/views.py:6383`) | T1 (`django-tests-2026-12.txt`) | Implemented |
| UTF-8 Consistency | `charset utf-8` (`docker/nginx/conf.d/kura.conf:31`) and UTF-8 DB init | T7 (`input-boundary-validation.txt`) | G08 Done (`c494a89`) |
| **§5 Cryptography, Integrity, PKI & Data Protection** |
| Symmetric Encryption | Per-file AES-256-GCM (`kura/views.py:239-248`) with Vault-wrapped data key; pgBackRest AES-256-CBC (`docker/postgres/pgbackrest.conf:10`) | T13, T14 | Implemented |
| Asymmetric Signatures | Vault Transit ECDSA-P256 (`kura/signing.py:120,154,217`) | T15 (`G05-openssl-verify.txt`, `G05-tamper-detected.txt`) | G05 Done (`d713810`) |
| Key Management | Vault Transit `auto_rotate_period=720h` (`kura.sh:495-501`), Docker secrets (`docker-compose.yml:995-1015`) | T11, T15 | G01, G02 Done (`bcd8ff0`) |
| TLS | TLS 1.3 only at nginx (`docker/nginx/conf.d/kura.conf:37`) | T9 (`testssl.txt`, `testssl-openssl.txt`) | Implemented |
| mTLS | Vault PKI certificates mounted across internal services (`docker-compose.yml`) | T10, `docker-compose.yml` | Implemented |
| Certificate Revocation (CRL) | Chain and expiry validated; internal CRL checking deferred | Optional gap G16 (P3) | Deferred (P3) |
| Password Hashing | Argon2id (`config/settings.py:301`), 12-character minimum (`config/settings.py:217`) | T1, T2 (`deploy-check.txt`) | Implemented |
| **§5.7 Common Crypto Mistakes (8)** |
| 1. Rolling own crypto | Uses Vault Transit, Python `cryptography` AESGCM, and Django Argon2id | `kura/signing.py:120`, `kura/views.py:246` | Implemented |
| 2. Hardcoding keys | Moved to Docker secrets and Vault; checked by secret grep | `G01-inspect-after.txt`, `G01-preflight.txt` | G01, G02 Done (`bcd8ff0`) |
| 3. Plaintext keys in env/code | Verified by `check_no_inline_secrets` (`kura.sh:1094`) | `G01-preflight.txt`, `G02-preflight.txt` | G01 Done (`bcd8ff0`) |
| 4. Weak algorithms | AES-256-GCM, ECDSA-P256, Argon2id, SHA-256 (SHA-1 limited to HIBP protocol with `usedforsecurity=False`) | T9, T12 (`SEMGREP_TRIAGE.md`), T15 | Implemented |
| 5. No key rotation | Vault Transit `auto_rotate_period=720h` (`kura.sh:495-501`) and AppRole rotation (`kura.sh:719`) | `kura.sh:495-501`, `kura.sh:719` | Implemented |
| 6. Insecure random | `secrets` module and `os.urandom` for keys, nonces, tokens | T12 (`bandit.txt`, `semgrep-after.txt`) | Implemented |
| 7. Side-channel timing leaks | Constant-time comparisons (`kura/middleware.py:123`), dummy hash (`kura/backends.py:28`), reset queue (`kura/migrations/0032`) | T1 (`django-tests-2026-12.txt`) | G13 Done (`d1b06ff`) |
| 8. Key reuse | Per-file AES-256-GCM keys (`kura/views.py:246`), separate `log_hmac_key` (`config/settings.py:68`), 15-min DB creds (`kura/base.py:1`) | T11, T13, T16 | G11 Done (`d1b06ff`) |
| **§6 Network Security Architecture, Defenses & Protocol Vulnerabilities** |
| DMZ and Segmentation | Docker internal networks (`app`, `backend`, `clamav`, `egress`, `frontend`, `observability`, `docker_api`) | `docker-compose.yml`, T10 (`port-scan.txt`) | Implemented |
| Default Deny | nftables default-drop policy (`docker/nftables/kura.nft`) | `G02-preflight.txt` | G02 Done (`bcd8ff0`) |
| Stateful vs Proxy Firewall | nftables (stateful host firewall) + Coraza CRS (HTTP proxy WAF) | `docker/nftables/kura.nft`, `docker-compose.yml` | D5 (`MITIGATION_PLAN.md`) |
| NIDS / HIPS Placement | CrowdSec log-based IPS + Loki alerting + host FIM (`kura.sh:1645`) | T8 (`rate-limit-verification.txt`), T16 (`G09-honeypot-check.txt`, `G17-fim-check.txt`) | G17 Done (`d1b06ff`) |
| L2/L3/L4 Protocol Attacks | Not applicable inside single-VM virtual Docker bridge; covered in DC mitigation plan | D5 (`MITIGATION_PLAN.md`) | Covered in D5 |
| DNS Security | Pinned resolver `1.1.1.1` (`docker-compose.yml`), no user-controlled DNS lookups | `docker-compose.yml` | Implemented |
| Wireless (WPA3) | Not applicable to wired server prototype; covered in DC mitigation plan | D5 (`MITIGATION_PLAN.md`) | Covered in D5 |
| **§7 Security Governance, Policies, Testing & Human Factors** |
| Policy Validation | Report-to-code reconciliation (`docs/coursework/IMPLEMENTATION_STATUS.md`) | D1 to D6 review | G15 Done |
| SANS Top 25 / Common Mistakes | Secret isolation (G01/G02), patching/SBOM (G06), input validation (G08), access control (T6), logging/alerts (G03/G11), encryption | T1 to T16 | Implemented |
| Testing Types | White-box SAST (Semgrep/Bandit, T12), passive DAST (ZAP, T3), defensive QA boundary/IDOR/rate-limit checks (T4 to T8), TLS/port/container/restore/signature/alert checks (T9 to T16) | `docs/coursework/TEST_RESULTS_SUMMARY.md` | T4 active ZAP manual |
| Human Factors | Mandatory MFA, HIBP breach check, honeytoken, awareness training (production rec) | T1, T16 (`G09-honeypot-check.txt`) | Implemented |

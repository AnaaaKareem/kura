# Lecture Traceability Matrix

Based on `security_concepts_reference.md` (lecture/lab notes sections §1–§7) and `docs/Kura_Security_Gap_Plan.md` references.

| Concept / Lecture Section | Where Implemented (file:line) | How Tested (test name / evidence file) | Gap ID / Status |
|---------------------------|-------------------------------|----------------------------------------|-----------------|
| **§1.1 Security Objectives (CIA → CIAAA + Non-Repudiation)** |
| Confidentiality | TLS 1.3 (nginx), mTLS (internal), AES-256-GCM (kura/views.py:567), Vault Transit (kura/signing.py:1) | T9 (testssl.txt), T13, T14 | Implemented |
| Integrity | HMAC-SHA256 log chain (kura/logging_utils.py:45), ECDSA signatures (kura/signing.py:1), RLS triggers (kura/migrations/0030) | T15 (G05-tamper-detected.txt), T16 (G11-log-chain-verify.txt) | Implemented |
| Availability | Rate limiting (nginx, axes), HA (pgBackRest), Loki healthcheck, CrowdSec | T8 (bruteforce-check.txt), T14 (restore-drill), T16 (G03-alert-fired.txt) | Implemented |
| Authentication | Argon2id, HIBP k-anon (kura/views.py:162), Axes lockout, Mandatory MFA (TOTP/WebAuthn), Passkeys | T1, T3, T8 | Implemented |
| Authorization | RBAC + RLS (kura/permissions.py:154, migrations/0026), Separation of duties (Admin/Registrar blocked) | T6 (idor_matrix.csv) | Implemented |
| Accountability | Structured logfmt + HMAC chain (kura/logging_utils.py:45), Loki 180d, pgAudit | T16 (G11-log-chain-verify.txt), T14 | Implemented |
| Non-Repudiation | Vault Transit ECDSA-P256 signatures (kura/signing.py:1, kura/views.py:258), Public key at /.well-known/kura-receipts.pem | T15 (G05-tamper-detected.txt, G05-openssl-verify.txt) | G05 ✓ |
| **§1.2 Risk & Core Terminology** |
| Risk formula / Asset / Vulnerability / Exploit | Risk register (D1: risk_register.csv) with before/after scores | D1, D3 (THREAT_MODEL.md) | Implemented |
| Triage | Semgrep/Bandit triage (SEMGREP_TRIAGE.md) | T12 (semgrep-after.txt, bandit.txt) | G07 ✓ |
| **§1.3 Fundamental Security Design Principles (13)** |
| 1. Economy of Mechanism | Simple middleware stack, no unnecessary services | T1 (388 tests pass) | Implemented |
| 2. Fail-Safe Defaults | 503 on dep outage (kura/middleware.py:22), ClamAV fail-closed (kura/views.py:392) | T3, T7, T13 | Implemented |
| 3. Complete Mediation | LoginRequiredMiddleware (kura/middleware.py:60), Passkey Origin check (kura/views.py:1277) | T6, T12 | G12 ✓ |
| 4. Open Design | All code in repo, no security by obscurity | T12 (Semgrep/Bandit) | Implemented |
| 5. Separation of Privilege | MFA, separation of duties (kura/permissions.py:200) | T6, T8 | Implemented |
| 6. Least Privilege | RBAC + per-course ownership, RLS policies | T6 (idor_matrix.csv) | Implemented |
| 7. Least Common Mechanism | Per-file AES keys, per-request Vault dynamic creds | T13, T14 | Implemented |
| 8. Psychological Acceptability | Passkeys, generic errors, no CAPTCHAs | T1, T3 | Implemented |
| 9. Isolation | Docker networks, mTLS, RLS, capability drop | docker-compose.yml, cap_drop | Implemented |
| 10. Encapsulation | Vault Transit keys never leave Vault | kura/signing.py:1 | Implemented |
| 11. Modularity | Middleware chain, separate services (WAF, ClamAV, Vault) | docker-compose.yml | Implemented |
| 12. Layering (Defense in Depth) | Network → Host → App → Data (ASSETS_AND_CLASSIFICATION.md) | THREAT_MODEL.md TB1-TB10 | Implemented |
| 13. Least Astonishment | Standard Django patterns, familiar auth flows | T1, T3 | Implemented |
| **§1.4 Supporting Frameworks & Data Classification** |
| Defense-in-Depth Layers | Physical → Perimeter (honeypots) → Network (VLANs/DMZ) → Server (OS hardening) → App (secure code) → Data (encryption) | ASSETS_AND_CLASSIFICATION.md, THREAT_MODEL.md | Implemented |
| Security Onion vs Artichoke | Borderless app model: direct app/API/DB targeting | THREAT_MODEL.md (TB1-TB10) | Implemented |
| Zero Trust Architecture | Continuous authN/authZ, mTLS everywhere, RLS | kura/middleware.py, kura/permissions.py | Implemented |
| Threat Modeling Epicycle | Preparation → Identification → Mitigation → Review | D3 (THREAT_MODEL.md), D5 (MITIGATION_PLAN.md) | Implemented |
| Pyramid of Pain | Hash → IP → Domain → Artifacts → Tools → TTPs | CrowdSec (tools/TTPs), Loki alerts (artifacts) | Implemented |
| Data Classification | Public → Sensitive → Private → Confidential | D2 (ASSETS_AND_CLASSIFICATION.md) | Implemented |
| **§2.1–2.4 Threat Landscape, Attack Surfaces & Attack Taxonomy** |
| Threat Actors | Internal, Script Kiddies, Hacktivists, Brokers, Criminals, APT | THREAT_MODEL.md | Implemented |
| Passive vs Active Attacks | Interception, Traffic Analysis, DoS, Modification, Fabrication, Replay, Timing | T5 (SQLi), T7 (Fuzzing), T8 (Brute force), T16 (Log chain) | Implemented |
| Attack Surface | Open ports, parsers, APIs, cookies, filesystems, humans | T3 (ZAP), T10 (nmap), T6 (IDOR) | Implemented |
| IOC/IOA | CrowdSec decisions (IOC), Loki alerts (IOA) | T8, T16 | Implemented |
| Attack Phases | Recon → Scanning → Weaponization → Exploitation → Persistence → Covering Tracks | CrowdSec scenarios, honeypots, alerts | G09 ✓ |
| Malware Types | Virus, Worm, Trojan, Spyware, Ransomware | ClamAV (T13), upload controls | Implemented |
| Social Engineering | Phishing, SMiShing, Vishing, Pretexting, Elicitation | MFA, HIBP, honeytoken, awareness (prod rec) | Implemented |
| **§3 Web Application & API Security (OWASP Top 10 & App Attacks)** |
| A01:2025 Broken Access Control | IDOR tests, RLS, RBAC, separation of duties | T6 (idor_matrix.csv) | Implemented |
| A02:2025 Cryptographic Failures | TLS 1.3 only, AES-256-GCM, Vault Transit, Argon2id | T9 (testssl.txt), T13, T15 | Implemented |
| A03:2025 Injection | Parameterized ORM, ClamAV, libmagic, NFKC, CSP | T5 (sqli-probing.txt), T7, T13 | Implemented |
| A04:2025 Insecure Design | Fail-closed, deny-by-default, threat modeled | kura/middleware.py:22, THREAT_MODEL.md | Implemented |
| A05:2025 Security Misconfiguration | Preflight checks, SHA-pinned CI, .trivyignore | T2 (deploy-check.txt), T11, T12 | Implemented |
| A06:2025 Vulnerable Components | Trivy, pip-audit, SHA pinning, SBOM | T11 (trivy-*, sbom-*), T12 | G06 ✓ |
| A07:2025 Auth Failures | Argon2id, HIBP, Axes, MFA, session validation | T1, T3, T8 | Implemented |
| A08:2025 Software Integrity | SBOM, SHA-pinned actions, Trivy gate, signed receipts | T11, T12, T15 | G06 ✓ |
| A09:2025 Logging Failures | HMAC chain, Loki 180d, LokiDown/SecurityLogsStopped alerts | T14, T16 (G03-alert-fired.txt, G11-log-chain-verify.txt) | G03, G11 ✓ |
| A10:2025 SSRF | No outbound user-controlled requests | grep -r "requests.get\|urllib" kura/ | Implemented |
| **§4 Encoding vs. Encryption vs. Hashing** |
| NFKC Normalization | kura/text_safety.py:1 | T7, T13 | G08 ✓ |
| Bidi/Control Char Rejection | kura/text_safety.py:40 (BIDI_AND_INVISIBLE) | T7, T13 | G08 ✓ |
| Homograph Protection | Email ASCII-only after NFKC (kura/text_safety.py:42) | T7, T13 | G08 ✓ |
| CSV Formula Injection | safe_csv_cell (kura/views.py:150) | T1 | Implemented |
| Encoding Attacks | Payload obfuscation via encodings | kura/text_safety.py, G08 | G08 ✓ |
| **§5 Cryptography, Integrity, PKI & Data Protection** |
| Symmetric Encryption | AES-256-GCM per-file (kura/views.py:567) | T13, T14 | Implemented |
| Asymmetric Encryption | Vault Transit ECDSA-P256 (kura/signing.py:1) | T15 (G05) | G05 ✓ |
| Key Management | Vault Transit auto-rotate 720h, Docker secrets | docker/vault/policies/kura-web.hcl:5 | G01, G02 ✓ |
| TLS | TLS 1.3 only at nginx (docker/nginx/conf.d/kura.conf:15) | T9 (testssl.txt) | Implemented |
| mTLS | Internal services (Vault PKI, certs/internal/) | docker-compose.yml certs mounts | Implemented |
| Certificate Verification | Chain + expiry (no CRL in prototype) | G16 (optional) | G16 (P3) |
| Password Hashing | Argon2id (Django default), 12-char min | config/settings.py:337 | Implemented |
| **§5.7 Common Crypto Mistakes (8)** |
| 1. Rolling own crypto | Avoided (Vault Transit, Django auth) | kura/signing.py uses Vault | Implemented |
| 2. Hardcoding keys | Docker secrets, Vault (G01, G02 fixed) | bcd8ff0 | G01, G02 ✓ |
| 3. Plaintext keys | Never in env, never in code | kura.sh preflight check_no_inline_secrets | Implemented |
| 4. Weak algorithms | AES-256-GCM, ECDSA-P256, Argon2id | kura/views.py:567, kura/signing.py:1 | Implemented |
| 5. No key rotation | Auto-rotate 720h (Vault Transit) | docker/vault/policies/kura-web.hcl:5 | Implemented |
| 6. Insecure random | secrets.token_urlsafe, os.urandom | kura/management/commands/seed_demo_data.py | Implemented |
| 7. Side channels | Constant-time compare (hmac.compare_digest) | kura/middleware.py:125, kura/backends.py:58 | Implemented |
| 8. Key reuse | Per-file keys, per-request DB creds | kura/views.py:567, kura/base.py:1 | Implemented |
| **§6 Network Security Architecture, Defenses & Protocol Vulnerabilities** |
| DMZ / Segmentation | Docker networks (app, backend, clamav, egress, frontend, observability) | docker-compose.yml networks | Implemented |
| Default Deny | nftables default-drop (docker/nftables/kura.nft) | G02 ✓ | G02 ✓ |
| Stateful vs Proxy Firewall | nftables (stateful), Coraza (proxy/WAF) | docker/nftables/kura.nft, docker-compose.yml waf: | D5 (MITIGATION_PLAN.md) |
| NIDS/HIPS Placement | CrowdSec (NIDS-like), Loki alerts (HIPS-like) | docker/crowdsec/, docker/prometheus/alerts.yml | D5 |
| L2/L3/L4 Protocol Attacks | ARP spoofing, VLAN hopping, IP spoofing, SYN flood | Not in prototype scope (virtual net) | D5 |
| DNS Security | 1.1.1.1 only, no user-controlled DNS | docker-compose.yml dns: 1.1.1.1 | Implemented |
| Wireless (WPA3) | Not in prototype scope | D5 (MITIGATION_PLAN.md) | D5 |
| **§7 Security Governance, Policies, Testing & Human Factors** |
| Policy Validation | Report vs code alignment (IMPLEMENTATION_STATUS.md) | G15 ✓ | G15 ✓ |
| SANS Top 25 / Common Mistakes | Hardcoded creds (G01,G02), missing patches (G06), weak auth, insecure defaults, exposed DB, supply chain, insufficient logging, no encryption | All gaps addressed | Implemented |
| Testing Types | White-box (SAST: Semgrep/Bandit), Black-box (DAST: ZAP/sqlmap/fuzzing), Fuzzing (T7), Pen test (T5,T6,T8), Code review (T12), Incident response (Alertmanager) | T1-T16 | T4 partial |
| Human Factors | Phishing, awareness, Shadow IT | MFA, HIBP, honeytoken, training (prod rec) | Implemented |

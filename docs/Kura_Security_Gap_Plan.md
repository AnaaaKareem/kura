# Kura: Security Gap Plan for Coding Agents

**Audience:** coding agents (opencode + Nemotron, Antigravity) working on the Kura repository inside WSL.
**Author of the audit:** Claude, 25 Nov 2026.
**Coursework:** KH6000CMD Security Report, "Security Evaluation Report of an IT system". **Due 13 Dec 2026 on Moodle.**
**Inputs read:** `KH6000CMD_CW.docx` (brief + rubric), `security_concepts_reference.md` (lecture/lab notes, sections numbered §1 to §7 below), the whole Kura tree, `docs/coursework/pdf/Kura Secure Learning Management System.pdf` (the design report), and everything in `docs/evidence/`.

All paths in this plan are relative to the Kura repository root (the folder that holds `manage.py`, `docker-compose.yml` and `kura.sh`).

---

## 0. Rules for agents (read before touching anything)

1. **Kura is already heavily hardened.** Most of the brief is already met. This plan lists only the gaps. Do not rewrite or "simplify" existing security code. If a step seems to need deleting an existing control, stop and ask the human.
2. **One work package = one branch = one commit (or a small series).** Branch name: `gap/<ID>-<short-name>`, e.g. `gap/G01-vault-secret-in-compose`. Commit message starts with the gap ID.
3. **Never commit secrets.** Nothing under `secrets/`, `certs/`, `.env`, and no literal tokens, passwords, role IDs or secret IDs in any file. If you find one, that is a P0 finding (see G01).
4. **Never weaken a test to make it pass.** Do not delete, skip or `@unittest.skip` an existing test. Do not lower a threshold. If an existing test fails after your change, your change is wrong or the test needs a justified update that you describe in the commit message.
5. **Never run** `docker compose down -v`, `docker volume rm`, `DROP DATABASE`, or anything that deletes the `postgres_data`, `postgres_backups` or Vault volumes. `kura.sh` already refuses this; keep it that way.
6. **Keep the comment style.** Existing code explains every security decision in a plain-English comment above it, and docstrings have "Who can use it" and "Security" lines. New code must do the same, because the coursework report quotes these comments as evidence.
7. **Every gap closes with evidence.** Each work package lists files to save under `docs/evidence/` (create `docs/evidence/2026-12/` for new runs). The report needs before/after proof, not just code.
8. **Update the traceability files** (`docs/coursework/LECTURE_TRACEABILITY.md` and `docs/coursework/risk_register.csv`, created in D1/D4) whenever you close a gap.
9. If a step is ambiguous, prefer the reading that keeps the system *more* restrictive (fail-closed, deny-by-default, notes §1.3 principle 2).

### 0.1 How to run things in WSL

There is no documented test command in the repo copy that was audited. **First task for any agent (before G01):**

1. Look in `.github/workflows/security.yml` (Semgrep scanned it, so it exists in your checkout) and any `Makefile`, `README*`, `AGENTS.md`, `CLAUDE.md` for the exact test command CI uses.
2. If none exists, use this harness (tests need PostgreSQL because of Row-Level Security migrations):
   ```bash
   # disposable Postgres for tests only (never the compose db)
   docker run -d --name kura-test-db -e POSTGRES_PASSWORD=testpass -e POSTGRES_USER=kura-admin \
     -e POSTGRES_DB=kura -p 127.0.0.1:55432:5432 postgres:17
   python -m venv .venv && . .venv/bin/activate
   pip install --require-hashes -r requirements.lock.txt
   export DEBUG=True VAULT_ENABLED=False CLAMAV_REQUIRED=False DATABASE_HOST=127.0.0.1 \
          DATABASE_PORT=55432 DATABASE_USER=kura-admin DATABASE_PASSWORD=testpass DB_SSL_MODE=
   python manage.py check
   python manage.py test kura -v 2
   ```
3. Write the command that works into `AGENTS.md` at the repo root (create it) under "How to test", so every later agent uses the same one.
4. Re-run only failing tests while fixing (`python manage.py test kura.tests.ClassName.test_name`). Run the full suite once at the end of each work package.

Also run before every commit:
```bash
ruff check .            # must not add new findings vs docs/evidence/ruff.txt
python manage.py check --deploy   # with DEBUG=False and a 50+ char SECRET_KEY exported
```

---

## 1. What the coursework asks for (summary of the brief)

Scenario: Simpsons University migrating to an electronic LMS, expanding the on-prem data centre and moving non-critical workloads to the cloud. Must respect GDPR, FERPA and local privacy law. You are the CISO.

| Rubric item | Weight | What must exist at submission |
|---|---|---|
| Risk Assessment | 25% | Threats, vulnerabilities, impacts identified and scored. **Risk Register + Treatment Plan** is a named deliverable. |
| Mitigation plan & recommendations | 20% | Data-centre weaknesses, strategies for critical issues, securing the expanded data centre and cloud integration. |
| Build Web Application | 20% | Own web app with at least authentication, data storage, user management, login page, home page, "implementing all possible security features" (input validation, output encoding, authN, authZ, session management, encryption / data protection). |
| Security Testing | 20% | Vulnerability scanning **and** code review, plus other tests. |
| Presentation & Reporting | 15% | Analyse test results, residual risks, recommendations, PowerPoint. |

Deliverables: full report with step-by-step documentation, risk register & treatment plan, all code, PowerPoint. Rubric rewards "specific and convincing justification" and evidence, so every control needs a file reference and a test or scan that proves it.

## 2. What Kura already has (do not redo)

Verified in code:

- **AuthN:** Argon2id hashing, 12-char minimum, Django validators, HIBP k-anonymity breach check (`kura/views.py:162`), password history (5), django-axes lockout driven by a live `SecurityPolicy` row, constant-time dummy hash for unknown users (`kura/backends.py`), generic login errors, mandatory MFA (TOTP with Vault-encrypted seeds, HMAC-hashed recovery codes, FIDO2 passkeys), step-up re-auth within 5 min for sensitive actions (`kura/permissions.py:has_fresh_second_factor`).
- **Sessions:** HttpOnly/Secure/SameSite cookies, 30-min idle + 12-h absolute expiry, server-side `UserSession` records bound by HMAC to the session key, revocation, deactivation/lock kicks users out (`kura/middleware.py`).
- **AuthZ:** global `LoginRequiredMiddleware` (deny by default), RBAC + per-course ownership checks, separation of duties (Admin/Registrar blocked from grades), PostgreSQL Row-Level Security via `RowLevelSecurityMiddleware`, DB-level triggers (attempt-file lock, submission-hash immutability, grade-history insert-only).
- **Input/output:** Django forms with `max_length`, parameterised ORM only (no raw SQL with user input found), no `|safe`/`mark_safe` in templates, strict CSP without inline scripts, CSV formula-injection guard (`safe_csv_cell`).
- **Uploads:** 25 MiB cap, ClamAV INSTREAM fail-closed, quarantine table, libmagic MIME + extension match, SHA-256, per-file AES-256-GCM with Vault-wrapped RSA-4096 data keys bound to file ID (AAD), integrity re-check on download, forced `attachment` disposition.
- **Crypto & secrets:** Vault Transit, Vault dynamic DB users (15 min), Vault PKI internal mTLS between every hop, Docker secrets, key auto-rotation (720 h), TLS 1.3 only at nginx.
- **Infra:** Nginx → Coraza WAF (OWASP CRS, PL1 blocking / PL2 detection) → Gunicorn over mTLS; internal Docker networks; read-only containers, `cap_drop`, `no-new-privileges`, resource limits; nftables default-drop host firewall with egress allowlist; CrowdSec with custom scenarios (login/MFA brute force, reset abuse, IDOR probing, WAF repeat offender) and nftables bouncer.
- **Monitoring:** structured logfmt security events with secret redaction, Alloy → Loki (180 days) with LogQL alerts, Prometheus + Alertmanager → Telegram, pgAudit.
- **Resilience/compliance:** pgBackRest encrypted WAL + off-site repo, restore drill command, GDPR privacy dashboard (export, restriction, erasure), retention purge, IP anonymisation, inactive-account disablement.
- **Testing evidence:** Semgrep, Trivy (fs + image), pip-audit, ZAP baseline, ruff, ~85 test classes.

## 3. Gap summary

Priority: **P0** = real vulnerability or regression, fix first. **P1** = lecture technique or rubric item not yet demonstrated. **P2** = hardening that strengthens the report. **P3** = optional if time allows.

| ID | P | Gap (one line) | Brief / rubric | Lecture notes | Effort |
|---|---|---|---|---|---|
| G01 | P0 | Vault AppRole `VAULT_ROLE_ID` and `VAULT_SECRET_ID` hard-coded in `docker-compose.yml:200-201` | Build (encryption/data protection), Risk | §5.7 #2, #3, #7; OWASP 2025 A02/A04 | S |
| G02 | P0 | PostgreSQL published on `0.0.0.0:5432` (`docker-compose.yml:22-23`) and `kura-admin` superuser accepts password-only logins from any host (`pg_hba.conf`) | Mitigation (data centre), Build | §6.1 DMZ/segmentation, §6.2 default deny, §7.2 #1, #5, #6 | S |
| G03 | P0 | Loki was crash-looping (`docs/evidence/ports.txt`: `Restarting (1)`) and has no healthcheck or "logs stopped" alert | Testing, Mitigation | §6.3 SIEM, §1.1 accountability; OWASP A09 | S-M |
| G04 | P0 | ZAP saw HTTP 500 on `POST /login/` and `POST /password/reset/`; root cause was assumed, never proven | Testing, Build | §3.2 generic errors, §3.4 error leakage; OWASP 2025 A10 | M |
| G05 | P1 | No **digital signatures / non-repudiation** anywhere: submission receipts and grade finalisation use plain SHA-256 in the same DB | Build (data protection), Report depth | §1.1 non-repudiation, §5.3, §5.4 digital signatures, §5.5 | M-L |
| G06 | P1 | Supply chain: runtime image still ships vulnerable `setuptools 70.3.0`, `urllib3 2.7.0`, `msgpack` (post-rebuild Trivy); no SBOM; GitHub Actions pinned by mutable tag | Testing (vuln scanning) | §7.2 #2, §5.7 #6; OWASP 2025 A03 | S-M |
| G07 | P1 | 28 Semgrep findings left un-triaged (fixed vs false positive not recorded) | Testing (code review) | §7.3 false positives / "false utopia" | S |
| G08 | P1 | Unicode / encoding attacks not handled: no NFKC normalisation of emails/names, bidi override (U+202E) and control chars allowed in names, titles and file names | Build (input validation) | §4.2 Mojibake, payload obfuscation, UTF-8 | S-M |
| G09 | P1 | No deception layer (honeypot routes / honeytoken account) to catch reconnaissance | Mitigation, Testing | §1.4 defence-in-depth (honeypots), §2.3 IOA/IOC, §6.3 | S |
| G10 | P1 | Security testing evidence incomplete: ZAP baseline only (unauthenticated), no authenticated active scan, no SQLi/fuzz evidence, no TLS scan, no nmap from outside, restore drill ran on an **empty** DB (0 rows) | Testing (20%), Reporting | §7.3 white/black box, fuzzing vs brute force; §7.2 #4 test backups | M |
| G11 | P2 | Security log lines are not tamper-evident (no HMAC / sequence numbers); deletion or edit on the host would go unnoticed | Build, Risk | §1.1 accountability, §5.4 HMAC, §6.3 HIDS log tampering | M |
| G12 | P2 | `passkey_auth_complete_view` is `@csrf_exempt` with no compensating Origin check | Build (session mgmt) | §3.4 CSRF, §1.3 complete mediation | S |
| G13 | P2 | Password-reset request does more work for known emails than unknown ones (timing-based account enumeration) | Build (authN) | §3.3, §2.2 timing attacks | S |
| G14 | P2 | Session / CSRF cookies lack the `__Host-` prefix | Build (session mgmt) | §3.3 session tokens | S |
| G15 | P2 | Report vs code drift: report describes Cloudflare Tunnel, NetBird WireGuard, modules / exam answer keys, CI blocking deploys; code uses SSH tunnel, modules were removed by migration `0029_strip_to_security_core`, `VAULT_DATABASE_CREDENTIALS` was turned off in one ZAP run | Reporting, Justification | §7.1 policy validation | S |
| G16 | P3 | Internal PKI has no revocation (CRL) checking on mTLS hops | Build | §5.5 certificate verification step 3 (CRL/OCSP) | M |
| G17 | P3 | No file-integrity monitoring of host config (compose, nginx, nftables, sshd) | Mitigation | §2.4 FIM, §6.3 HIDS (Tripwire) | S-M |
| D1-D6 | P1 | Coursework documents: risk register rows, STRIDE threat model, data classification, test-results summary, traceability matrix, slide outline | Risk 25%, Mitigation 20%, Reporting 15% | §1.2, §1.4, §7.1, §7.3 | M |

Recommended order: G01 → G02 → G04 → G03 → G06 → G07 → G05 → G08 → G09 → G12 → G13 → G14 → G11 → G10 (re-run all scans last, after code changes) → D1-D6 → G15 → G16/G17 if time.

---

## 4. Work packages

### G01 (P0): Remove hard-coded Vault AppRole credentials from compose

**Why.** `docker-compose.yml` lines ~199-201 set `VAULT_ROLE_ID` and `VAULT_SECRET_ID` as literal environment values for the `web` service. The secret ID is a live credential: with it and network reach to Vault, anyone can log in as `kura-web` and decrypt every TOTP seed and every file key. It also ends up in `docker inspect`, `/proc/<pid>/environ` and Git history. This is notes §5.7 mistake #3 ("hardcoding keys or secrets") and #2 ("reading keys as plaintext instead of a vault"), the exact pattern the lecture warns about. The fix is already half-built: `config/settings.py` reads `/run/secrets/vault_role_id` first via `read_secret()`, the top-level `secrets:` block already defines `vault_role_id` and `vault_secret_id`, and `kura.sh vault-init` already writes those files.

**Files.** `docker-compose.yml`, `kura.sh`, `kura/tests_security_leads_part2.py` (or a new `kura/tests_security_gaps.py`), `docs/SECURITY_TRIVY_FINDINGS.md`.

**Steps.**
1. In `docker-compose.yml`, `web` service:
   - Delete the two lines `VAULT_ROLE_ID: "..."` and `VAULT_SECRET_ID: "..."` and the comment above them that says "no Docker secret files needed".
   - Under `web.secrets:` add `- vault_role_id` and `- vault_secret_id` next to `- django_secret_key`. Add a comment: "AppRole bootstrap credentials come from Docker secrets (mode 600, owner 10001), never from environment variables, so they do not appear in docker inspect or process listings."
   - Check `kura-migrate` and any other service for the same literals; apply the same change if found.
2. Grep the whole repo (including `docs/`, `kura.sh`, `docs/postman/`) for the two UUID values and for `VAULT_SECRET_ID:`. Remove any literal occurrence.
3. **Rotate the leaked secret ID** (it is in Git history, so treat it as compromised). Add a `kura.sh` subcommand `vault-rotate-approle` that:
   - runs `vault write -f auth/approle/role/kura-web/secret-id` to mint a new one into `secrets/vault_secret_id.txt` (reuse `fix_secret_file`),
   - destroys the old accessor (`vault list auth/approle/role/kura-web/secret-id` then `vault write auth/approle/role/kura-web/secret-id-accessor/destroy secret_id_accessor=<old>`),
   - restarts `web`.
   Follow the existing `kura.sh` style: `say`/`skip`/`die`, `--dry-run` support, `confirm` before destroying. Document it in `cmd_help`.
4. Add a preflight check `check_no_inline_secrets` in `kura.sh` (call it from `cmd_preflight`): parse `docker compose config --format json`, FAIL if any service `environment` key matches `(?i)(secret|password|token|_key)$` with a non-empty literal value, except an allowlist of non-secret names (`VAULT_TRANSIT_KEY`, `VAULT_FILES_KEY`, `DB_SSL_KEY` which is a path, `POSTGRES_PASSWORD_FILE`, `GF_SECURITY_ADMIN_PASSWORD__FILE`, `VAULT_SECRET_ID` must NOT be in the allowlist).
5. Add a unit test (pattern: the existing tests that read `docker-compose.yml` in `tests_security_leads_part2.py`) that loads the compose YAML and asserts no service environment contains `VAULT_SECRET_ID` or `VAULT_ROLE_ID`, and that `web.secrets` includes both names.

**Acceptance.**
- `grep -rn "VAULT_SECRET_ID:" docker-compose.yml` returns nothing.
- `sudo ./kura.sh preflight` shows `[PASS]` for the new check.
- `docker compose up -d web` then `docker compose exec web python -c "from django.conf import settings; print(bool(settings.VAULT_SECRET_ID))"` prints `True`, and `docker inspect kura-web | grep -i secret_id` prints nothing.
- MFA login and a file download still work (Vault reachable).
- New test passes; full suite passes.

**Evidence.** `docs/evidence/2026-12/G01-inspect-before.txt` (redact the value to the first 4 chars), `G01-inspect-after.txt`, `G01-preflight.txt`.

**Report mapping.** Risk register row "Secret exposure through configuration", Testing section "code review found hard-coded credential", lecture §5.7.

---

### G02 (P0): Close the published PostgreSQL port and tighten superuser access

**Why.** `docker-compose.yml:22-23` publishes `5432:5432` on all interfaces. Docker DNATs published ports through the FORWARD hook, and `docker/nftables/kura.nft`'s `forward` chain accepts everything except CrowdSec bans, so the host firewall does **not** protect it. `docker/postgres/pg_hba.conf` lets the `kura-admin` superuser log in from `all` with only `scram-sha-256` (no client certificate). Result: the database superuser can be brute-forced from the internet. The evidence file `docs/evidence/ports.txt` shows `kura-db ... 5432/tcp` (not published), so this is a regression added later, probably while debugging. The comment above the service even says "on an internal network". Notes §6.1 (DMZ isolates DB from internet), §6.2 (default deny), §7.2 mistakes #5 and #6.

**Files.** `docker-compose.yml`, `docker/postgres/pg_hba.conf`, `kura.sh` (preflight already has `check_published_ports`), tests.

**Steps.**
1. Remove the `ports:` block from the `db` service entirely. If a developer needs host access, add a commented-out alternative bound to loopback only: `# - "127.0.0.1:5432:5432"  # local debugging only, never commit uncommented`.
2. In `pg_hba.conf`, change the `kura-admin` line from `hostssl all kura-admin all scram-sha-256` to require a client certificate as well: `hostssl all kura-admin all scram-sha-256 clientcert=verify-full`. If `kura-admin` has no client cert in `certs/internal/`, instead restrict it to the Unix socket only (delete the `hostssl` line; the `local all all scram-sha-256` line already covers `docker compose exec db psql`). Check every `kura.sh` call that uses `kura-admin` (`vault-init`, `restore-drill`, backup scripts) still works: they use `docker compose exec -T db ... psql -U kura-admin` over the local socket. **Vault's database secrets engine connects as `vault_admin`, not `kura-admin`**, so it is unaffected; confirm in `docker/postgres/vault-roles.sql`.
3. Add a comment block above the `kura-admin` rule explaining why (superuser never reachable over TCP without a certificate).
4. Add a test that loads `docker-compose.yml` and asserts `db` has no `ports`, and a test that parses `pg_hba.conf` and asserts no `hostssl` line for `kura-admin` ends with bare `scram-sha-256`.

**Acceptance.**
- `sudo ./kura.sh preflight` → `[PASS] published ports: only nginx 80 and 443 ...`.
- From another machine on the LAN (or from WSL to the VM IP): `nmap -Pn -p 5432 <vm-ip>` shows `filtered` or `closed`.
- `docker compose exec db sh -c 'psql -h db -U kura-admin -d kura -c "select 1"'` without a client cert is rejected; the socket form still works.
- `./kura.sh restore-drill` still passes.

**Evidence.** `G02-nmap-before.txt`, `G02-nmap-after.txt`, `G02-preflight.txt`, `G02-ss-tlnp.txt` (`ss -tlnp` on the host).

---

### G03 (P0): Make the log pipeline reliable and alert when it stops

**Why.** Logging is how Kura satisfies accountability (§1.1) and SIEM (§6.3). In `docs/evidence/ports.txt` Loki is `Restarting (1)`. If Loki is down, every LogQL alert in `docker/loki/rules/fake/kura-alerts.yml` is silent and nobody is told (OWASP 2025 A09 "Logging & Alerting Failures"). Loki has no `healthcheck` in compose.

**Files.** `docker-compose.yml` (loki service, ~line 534), `docker/loki/loki.yml`, `docker/prometheus/alerts.yml`, `docker/prometheus/prometheus.yml`, `docker/alloy/config.alloy`.

**Steps.**
1. Reproduce: `docker compose up -d loki && docker compose logs --tail=200 loki`. Record the crash reason in `docs/evidence/2026-12/G03-loki-crash.txt`. Typical causes with this config: compactor `delete_request_store` missing when `retention_enabled: true` (Loki 3.x requires `compactor.delete_request_store: filesystem`), a read-only root without a writable `/var/loki` volume, or a permissions mismatch on the volume. Fix the real cause; do not disable retention (the 180-day retention is a legal requirement stated in the file).
2. Add a healthcheck to the loki service, e.g. `test: ["CMD", "wget", "-qO-", "http://127.0.0.1:3100/ready"]` (check the image has `wget`; otherwise use `/usr/bin/loki -version` plus the `/ready` endpoint through Alloy), `interval: 30s`, `retries: 5`, `start_period: 60s`.
3. Make Prometheus scrape Loki's `/metrics` (job `loki`) and Alloy's metrics if not already.
4. Add Prometheus alerts in `docker/prometheus/alerts.yml`:
   - `LokiDown`: `up{job="loki"} == 0 for 2m`, severity critical.
   - `SecurityLogsStopped`: no `web` log lines ingested for 10 minutes, e.g. `sum(rate(loki_distributor_lines_received_total[10m])) == 0` or, on the Alloy side, `rate(loki_write_sent_entries_total[10m]) == 0`.
   Use the same label and annotation style as the existing rules.
5. Add a Loki rule `absent_over_time({service="web"}[15m])` as a second, independent signal.

**Acceptance.** `docker compose ps loki` shows `healthy` for 30 minutes. `docker compose stop loki` → Alertmanager receives `LokiDown` within 3 minutes (screenshot or `amtool alert query` output). Start Loki again, alert resolves.

**Evidence.** `G03-loki-crash.txt`, `G03-ps-healthy.txt`, `G03-alert-fired.png` or `.txt`.

---

### G04 (P0): Find and fix the real cause of the 500s on POST /login/ and /password/reset/

**Why.** ZAP recorded HTTP 500 on both POSTs and the write-up in `docs/SECURITY_TRIVY_FINDINGS.md` says the cause is "ZAP not keeping CSRF cookies". That explanation does not hold: a CSRF failure goes to `kura.views.csrf_failure_view`, which returns **403**, never 500. A 500 means an unhandled exception, which is OWASP 2025 **A10 "Mishandling of Exceptional Conditions"** and notes §3.2 / §3.4 (error handling). A marker reading the report will spot this.

**Files.** `kura/views.py` (`login_view` ~line 935, `password_reset_request_view` ~line 1960), `kura/middleware.py`, `kura/forms.py`, `config/settings.py`, tests.

**Steps.**
1. Reproduce against the running stack with the payload shapes ZAP sends. Try each, note status code and the matching `event="server.error"` line in `docker compose logs web` (enable a temporary `DEBUG_PROPAGATE_EXCEPTIONS` only in a local run, never in compose):
   ```bash
   # 1. no CSRF cookie at all
   curl -sk -o /dev/null -w "%{http_code}\n" -X POST https://localhost/login/ -d "email=a@b.c&password=x"
   # 2. valid cookie+token, ZAP-style junk values
   #    (fetch the token first with a cookie jar, then POST)
   #    email=ZAP, email="<script>", password left empty, very long email (5000 chars),
   #    non-UTF-8 bytes (--data-binary $'email=\xff\xfe'), duplicated fields, JSON body with
   #    Content-Type: application/json, multipart body, header X-Real-IP: garbage
   ```
   Also try with `Host:` set to an unknown host (Django raises `DisallowedHost` → should be 400) and with nginx's `limit_req` exceeded.
2. Prime suspects to check in code:
   - `AxesProxyHandler.is_locked(request, {"username": email})` in `login_view` raising on unexpected input.
   - django-axes `AXES_LOCKOUT_CALLABLE` / `get_axes_failure_limit` reading `get_security_policy()` when the DB cache table is missing.
   - `RateLimitMiddleware` or `RowLevelSecurityMiddleware` DB errors.
   - Vault dynamic DB credentials expiring mid-request (`kura/base.py` raises `OperationalError`). The ZAP summary notes `VAULT_DATABASE_CREDENTIALS` was switched off because of a username-template mismatch. If the 500s stop when Vault creds are off, the template mismatch is the bug: align the Vault role's `username_template` (`kura.sh vault-init`, step 5) with the `/^kura_dyn_/` rule in `pg_hba.conf`.
   - `UnicodeDecodeError` on a body that isn't UTF-8.
3. Fix the root cause. For anything that is *bad client input*, the response must be 400 with the generic form error, never 500. For a genuine dependency outage (DB, Vault), return 503 with the generic page and log `server.dependency_unavailable`.
4. Add regression tests for every payload in step 1 asserting `status_code in (400, 403, 429)` and that the body does not contain `Traceback`, `File "/`, or any setting name.
5. Re-run ZAP baseline (G10) and update `docs/SECURITY_TRIVY_FINDINGS.md`: replace the "ZAP-specific" justification with the proven root cause and the fix.

**Acceptance.** All step-1 payloads return 4xx. ZAP alert 90022 "Application Error Disclosure" count is 0. New tests pass.

**Evidence.** `G04-repro-before.txt` (curl outputs + log lines), `G04-repro-after.txt`, new ZAP report.

---

### G05 (P1): Digital signatures for submission receipts and grade decisions (non-repudiation)

**Why.** The lecture notes treat **non-repudiation** as a security goal of its own (§1.1) and say only public-key digital signatures provide it (§5.4: "authentic, unforgeable, non-reusable, non-repudiable"). Kura today stores a plain SHA-256 `submission_hash` in the same database as the data (`compute_submission_hash`, `kura/views.py:4761`). §5.4 says a plain hash "does not defend against MitM: an attacker can modify both the message and its hash". A DBA or an attacker with DB write access can change a submission and recompute the hash, and a student cannot prove the receipt email is genuine. Signing with a Vault Transit asymmetric key (private key never leaves Vault) fixes both and shows hybrid PKI use in the report. This is the single most visible lecture technique still missing.

**Design.**
- New Vault Transit key `kura-receipts`, `type=ecdsa-p256` (ECC, §5.3: same security as RSA with smaller keys), `exportable=false`, auto-rotate 720h like the others. Vault keeps old versions so old signatures still verify.
- Sign: `transit/sign/kura-receipts` with `hash_algorithm=sha2-256`, `signature_algorithm` default, input = base64 of a canonical JSON document.
- Verify: `transit/verify/kura-receipts`, and also publish the public key so anyone can verify offline (`transit/keys/kura-receipts` returns public keys; expose at `/.well-known/kura-receipts.pem`, public, no login, so a student or external examiner can verify without trusting Kura's UI).

**Files.** `kura.sh` (`cmd_vault_init` step 4), `docker/vault/policies/kura-web.hcl`, `kura/models.py`, new migration `kura/migrations/0031_receipt_signatures.py`, `kura/views.py`, new `kura/signing.py`, `kura/urls.py`, `kura/templates/kura/assessments/attempt_detail.html`, `kura/templates/kura/grades/*` (finalise/release), new management command `kura/management/commands/verify_signatures.py`, `kura/management/commands/finalize_attempts.py`, tests.

**Steps.**
1. **Vault.** In `cmd_vault_init` after the `kura-files` key: `vault_root write -f transit/keys/kura-receipts type=ecdsa-p256` and `vault_root write transit/keys/kura-receipts/config auto_rotate_period=720h`. Make it idempotent (skip if `vault_root read transit/keys/kura-receipts` succeeds) so it can be run on the existing Vault; add a `kura.sh vault-add-receipts-key` subcommand for already-initialised installs.
2. **Policy.** In `kura-web.hcl` add, with the same comment style:
   ```hcl
   # Sign submission receipts and grade decisions (non-repudiation). Django never sees the private key.
   path "transit/sign/kura-receipts"   { capabilities = ["update"] }
   path "transit/verify/kura-receipts" { capabilities = ["update"] }
   # Read the public half so it can be published for offline verification.
   path "transit/keys/kura-receipts"   { capabilities = ["read"] }
   ```
   Then `vault policy write kura-web docker/vault/policies/kura-web.hcl` (add to vault-init and to the new subcommand).
3. **`kura/signing.py`** (new). Functions, each with a docstring and "Security:" line:
   - `canonical_payload(kind, fields: dict) -> bytes`: `json.dumps({"v": 1, "kind": kind, **fields}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Canonical form matters: the same data must always produce the same bytes.
   - `sign_payload(payload: bytes) -> str`: Vault `client.secrets.transit.sign_data(name=settings.VAULT_RECEIPTS_KEY, hash_input=b64(payload), hash_algorithm="sha2-256", mount_point=...)` → returns `vault:vN:...`. Use `kura.base.get_vault_client`. On failure: log `vault.error {"operation":"sign_payload"}` and raise `ValidationError` (fail closed: do not seal a submission without a signature when Vault is enabled).
   - `verify_payload(payload, signature) -> bool` via `transit/verify`.
   - `public_key_pem() -> str` (cached for 1 hour).
   - When `VAULT_ENABLED=False` (dev/tests): sign with an in-process Ed25519 key generated once per process from `cryptography`, prefix signature `dev:` so it can never be confused with a production signature, and have `verify_payload` reject `dev:` signatures when `VAULT_ENABLED=True`.
   - Add `VAULT_RECEIPTS_KEY = os.environ.get("VAULT_RECEIPTS_KEY", "kura-receipts")` to `config/settings.py` next to `VAULT_FILES_KEY`.
4. **Models + migration.** Add to `AssessmentAttempt`: `submission_signature = models.TextField(blank=True, default="")`. Add to `Grade`: `finalization_signature` and `release_signature` (TextField, blank). Migration `0031`:
   - adds the columns;
   - **updates the existing immutability trigger from `0025_submission_hash_immutability_trigger.py`** so `submission_signature` is also frozen once set (read 0025 and 0030 first; write the new trigger with `CREATE OR REPLACE FUNCTION`, keep the old behaviour intact);
   - keeps RLS policies from `0026` working (no new table, so only check the column grants: if `0026_rls_and_readonly_revokes.py` grants column-level privileges, grant the new columns the same way).
5. **Sign on submit.** In `assessment_submit_view` (inside the existing `transaction.atomic()` after `attempt.submission_hash = ...`):
   ```python
   payload = canonical_payload("submission", {
       "attempt_id": str(attempt.id), "student_id": str(attempt.student_id),
       "assessment_id": str(attempt.assessment_id),
       "submitted_at": attempt.submitted_at.isoformat(),
       "submission_hash": attempt.submission_hash,
   })
   attempt.submission_signature = sign_payload(payload)
   ```
   Do the same in `finalize_attempts.py`. Put the signature and the verification URL in the receipt email lines.
6. **Sign grade decisions.** In `grade_finalize_view` and `grade_release_view` (and `course_result_release_view` if it changes grade state) sign `{"grade_id","attempt_id","score","status","actor_id","at"}` and store in the matching field. This binds the instructor's identity to the decision (instructor cannot later deny finalising a grade; notes §1.1 "Non-repudiation: preventing an actor from denying they originated an action").
7. **Verification surfaces.**
   - Public route `/.well-known/kura-receipts.pem` (`@login_not_required`, GET only, `Content-Type: application/x-pem-file`, `Cache-Control: public, max-age=3600`). Add to `kura/urls.py`; note that `LoginRequiredMiddleware` needs the decorator.
   - On `attempt_detail.html` show "Signature: valid (key version N)" or "INVALID" by calling `verify_payload` (student owner, course staff only; reuse the view's existing permission checks).
   - Management command `verify_signatures [--since DATE]`: walks attempts and grades inside `service_rls_context()`, recomputes `compute_submission_hash`, verifies signatures, prints a table, exits non-zero if any fail, logs `integrity.signature_failed` at ERROR for each failure. Add it to `docker/cron/kura.crontab` nightly, and add a Loki alert on `event="integrity.signature_failed"`.
8. **Tests** (new file `kura/tests_signatures.py`, `VAULT_ENABLED=False` so the dev Ed25519 path runs; mock Vault for the Vault path the same way existing Vault tests use `MagicMock`):
   - submit → signature present and verifies;
   - change `submission_hash` or `submitted_at` in the DB (bypass the trigger with a superuser connection in `TransactionTestCase`, or call `verify_payload` on a modified payload) → verification fails;
   - `dev:` signature rejected when `VAULT_ENABLED=True`;
   - `/.well-known/kura-receipts.pem` reachable anonymously, returns PEM;
   - `verify_signatures` exits 1 when a record is tampered;
   - trigger refuses to change `submission_signature` after it is set.
9. **Docs.** Add a short `docs/coursework/NON_REPUDIATION.md`: threat (DBA or attacker edits a submission or a grade), why hash alone fails (§5.4), how ECDSA via Vault fixes it, how a student verifies with `openssl dgst -sha256 -verify kura-receipts.pem -signature sig.der payload.json` (Vault signatures are `vault:vN:<base64 DER>`; document stripping the prefix and base64-decoding).

**Acceptance.** All new tests pass. A real submission in the running stack shows "Signature: valid". Manually editing the row via `psql` as `kura-admin` makes `python manage.py verify_signatures` print FAIL and exit 1, and a Loki alert fires.

**Evidence.** `G05-verify-ok.txt`, `G05-tamper-detected.txt`, `G05-openssl-verify.txt`, screenshot of attempt page.

---

### G06 (P1): Supply-chain hardening (OWASP 2025 A03)

**Why.** `docs/evidence/trivy-image-post-rebuild.txt` (Python section) still reports `setuptools 70.3.0` (HIGH, CVE-2025-47273), `urllib3 2.7.0` (HIGH ×2) and `msgpack 1.1.2` (HIGH) in the runtime image, even though `requirements.lock.txt` pins `urllib3==2.8.0`. These come from the base image's bundled `pip`/`setuptools` or a stale layer. No SBOM is produced, and Semgrep flagged mutable GitHub Action tags. Notes §7.2 mistake #2 (failing to patch), §5.7 #6, OWASP 2025 A03 "Software Supply Chain Failures".

**Files.** `Dockerfile`, `.github/workflows/security.yml`, `.dockerignore`, `docs/SECURITY_TRIVY_FINDINGS.md`.

**Steps.**
1. In the `runtime` stage of `Dockerfile`, after `COPY --from=builder /install /usr/local`, remove packaging tools the app never needs at run time:
   `RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true; rm -rf /usr/local/lib/python3.14/site-packages/pip* /usr/local/lib/python3.14/site-packages/setuptools* /usr/local/lib/python3.14/ensurepip`
   Comment why (smaller attack surface, removes CVE-2025-47273; the app container is read-only and never installs packages).
2. Find where `urllib3 2.7.0` and `msgpack` come from: `docker run --rm --entrypoint sh kura-web:latest -c "pip show urllib3 msgpack 2>/dev/null; find / -name 'urllib3-*.dist-info' -o -name 'msgpack-*.dist-info' 2>/dev/null"` (do it before step 1 removes pip, or use `python -c "import urllib3; print(urllib3.__version__, urllib3.__file__)"`). If it's a vendored copy inside pip, step 1 removes it. If it is a real top-level install, the image is stale: rebuild with `docker compose build --no-cache --pull web`.
3. **`.dockerignore`**: the `static` stage does `COPY . /app`. Verify `.dockerignore` exists and excludes at least `.git`, `.env`, `secrets/`, `certs/`, `.venv`, `docs/evidence/`, `*.key`, `*.pem`, `staticfiles/`. Create or extend it. Add a test that reads `.dockerignore` and asserts those entries.
4. **SBOM.** Generate CycloneDX SBOMs and keep them as evidence:
   `trivy image --format cyclonedx -o docs/evidence/2026-12/sbom-kura-web.cdx.json kura-web:latest` and the same for `kura-nginx`. Add a CI step that produces the SBOM as a build artifact.
5. **CI pinning.** In `.github/workflows/security.yml` replace every `uses: owner/action@vX` with the full commit SHA plus a comment `# vX.Y.Z` (Semgrep rule `github-actions-mutable-action-tag`). Add `pip-audit -r requirements.lock.txt --strict` (allowing only the two documented python-jose/ecdsa IDs via `--ignore-vuln` with a comment pointing to the risk acceptance) and make Trivy fail on HIGH/CRITICAL with `--ignore-unfixed` plus a `.trivyignore` listing only the accepted IDs with justification and an expiry date comment.
6. Re-scan: `trivy image kura-web:latest > docs/evidence/2026-12/trivy-image-after-G06.txt`; Python section must show only the two accepted IDs. Update the tables in `docs/SECURITY_TRIVY_FINDINGS.md`.

**Acceptance.** Python-pkg section of the new Trivy report: 0 HIGH/CRITICAL except the accepted python-jose/ecdsa. `docker run --rm --entrypoint python kura-web:latest -m pip --version` fails (pip gone). App still starts, tests still pass.

---

### G07 (P1): Triage all Semgrep findings (code review evidence)

**Why.** The brief's Security Testing item names **code review** explicitly. `docs/evidence/semgrep.txt` has 28 blocking findings with no recorded triage. Notes §7.3: automated scanners give high false positives and a "false utopia"; the marker wants to see you separate true from false positives.

**Steps.**
1. Re-run: `semgrep --config auto --json -o docs/evidence/2026-12/semgrep-before.json .` and the text form.
2. Create `docs/coursework/SEMGREP_TRIAGE.md` with one row per finding: rule ID, file:line, verdict (True positive / False positive / Accepted risk), reason, action. Known items from the existing run:
   - `github-actions-mutable-action-tag` → TP, fixed in G06.
   - `nginx missing-internal` in `docker/nginx/conf.d/kura.conf` → read the flagged `location`; if it serves files only nginx should reach, add `internal;`, else FP with reason.
   - `unvalidated-password` in `kura/backends.py`, `kura/models.py`, `kura/views.py:1864`, `:2101`, `seed_demo_data.py`, `tests.py` → FP: `PasswordChangeForm.clean` and `PasswordResetConfirmForm.clean` call `validate_password_policy` → `validate_password` (`kura/forms.py:41-43, 263, 352`) before the view calls `set_password`; the backend call is the constant-time dummy hash. Annotate each line with `# nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password -- validated in <Form>.clean()`.
   - `django-no-csrf-token` in 5 templates (`security_policy.html`, `assessment_create.html`, `checkin.html`, `admin_course_form.html`, `staff_assign.html`) → open each: if a `<form method="post">` lacks `{% csrf_token %}`, that is a TP, add it (Django would reject the post anyway, so it is a functional bug too). If they are GET forms, FP.
   - `no-csrf-exempt` (`passkey_auth_complete_view`) → accepted with compensating control from G12.
   - `direct-use-of-httpresponse` → FP if content is static text; confirm.
   - `python-logger-credential-disclosure` in `kura/vault_secrets.py` → FP: only `type(error).__name__` is logged; annotate.
   - `insecure-hash-algorithm-sha1` → FP: HIBP k-anonymity protocol requires SHA-1 and `usedforsecurity=False` is set.
   - `hardcoded-password-default-argument`, `non-literal-import` in tests → FP (test code).
3. Also run **Bandit** as a second SAST tool (cross-checking is a lecture point): `bandit -r kura config -x kura/tests*.py -f txt -o docs/evidence/2026-12/bandit.txt`, triage HIGH/MEDIUM the same way.
4. Re-run Semgrep: target 0 un-annotated findings. Save `semgrep-after.txt`.

---

### G08 (P1): Unicode and encoding hardening

**Why.** Notes §4.2: Mojibake attacks when UTF-8 isn't enforced consistently, and payload obfuscation via encodings. Kura's DB is UTF-8 (`POSTGRES_INITDB_ARGS`) and Django forms strip NUL, but:
- emails are only `.strip().lower()`: `ＡＤＭＩＮ@kura.edu` (full-width) or a Cyrillic `а` can create a look-alike account (homograph / account confusion);
- names, course titles, file names accept bidi controls like U+202E (RIGHT-TO-LEFT OVERRIDE), so `report‮fdp.exe` displays as `reportexe.pdf` (classic file-name spoofing for phishing inside the LMS);
- `sanitize_filename` (`kura/views.py:318`) only strips path separators.

**Files.** new `kura/text_safety.py`, `kura/forms.py`, `kura/views.py` (`sanitize_filename`), `kura/models.py` (`UserManager.normalize_email` if present), tests.

**Steps.**
1. `kura/text_safety.py`:
   - `BIDI_AND_INVISIBLE = {U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, U+FEFF, U+00AD}` plus all `unicodedata.category(ch) in ("Cc","Cf")` except `\t` and `\n` for multi-line fields.
   - `normalize_text(value, multiline=False)`: `unicodedata.normalize("NFKC", value)`, then reject (raise `ValidationError("This field contains characters that are not allowed.")`) if any char is in the forbidden set. Rejecting is better than silently stripping (§3.2 "reject unexpected formats").
   - `normalize_email(value)`: NFKC, lower-case, then require the result to be ASCII (`value.isascii()`). Kura's domain is institutional (`kura.edu`), so non-ASCII local parts aren't needed; reject with a clear message.
   - `has_mixed_scripts(value)`: optional check that a single name token doesn't mix Latin with Cyrillic/Greek (use `unicodedata.name(ch).split()[0]`); log `input.mixed_script` at INFO rather than reject (names can legitimately mix scripts).
2. Apply in forms: a mixin `SafeTextMixin` whose `clean()` runs `normalize_text` on every `CharField` value (multiline for `Textarea` widgets) and `normalize_email` on every `EmailField`. Add it to `LoginForm`, `PasswordResetRequestForm`, `StaffCreateForm`, `StudentCreateForm`, `CourseCreateForm`, `AdminCourseForm`, `AssessmentCreateForm`, `CourseFileForm`, `GradeEntryForm`, `GradeChangeRequestForm`, `GradeChangeRequestReviewForm`, `ManualAttendanceForm`, `ScheduleForm`, filter forms (`q` fields). Do **not** apply to password fields (passwords may contain any Unicode; Django handles them).
3. `sanitize_filename`: after the existing path stripping, apply NFKC, drop forbidden chars, collapse whitespace, cap at 200 chars keeping the extension. If anything was removed, log `file.name_sanitized`. The upload pipeline then checks the extension against libmagic as today.
4. Ensure the user model saves emails through `normalize_email` (check `UserManager` in `kura/models.py:249`).
5. Add `<meta charset="utf-8">` check: confirm `kura/templates/kura/base.html` and `templates/base.html` declare it; nginx `charset utf-8;` in `docker/nginx/conf.d/kura.conf` server block.
6. Tests: full-width email normalises to ASCII and logs in; Cyrillic-homoglyph email rejected at staff/student creation; `"x‮fdp.exe"` file name rejected or sanitised; course title with U+200B rejected; multi-line feedback with `\n` accepted; password containing emoji still works.

**Acceptance.** Tests pass. ZAP/curl with `email=%EF%BC%A1dmin%40kura.edu` behaves the same as `admin@kura.edu`.

---

### G09 (P1): Deception layer: honeypot routes and a honeytoken account

**Why.** Notes §1.4 lists honeypots in the perimeter layer of defence-in-depth, and §2.3 distinguishes IOAs (attack in progress). Kura has no route that no legitimate user ever hits; such a route gives zero-false-positive detection of scanners (Pyramid of Pain: moves detection from IPs toward tools/TTPs).

**Files.** `kura/urls.py`, `kura/views.py`, `docker/crowdsec/scenarios/honeypot-hit.yaml` (new), `docker/crowdsec/parsers/kura-django-logfmt.yaml`, `docker/loki/rules/fake/kura-alerts.yml`, `docker/coraza/rules.d/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` (only if Coraza blocks the decoys first), `kura/management/commands/seed_demo_data.py`, `kura/views.py` login path.

**Steps.**
1. Decoy routes (all `@login_not_required`, any method): `/wp-login.php`, `/wp-admin/`, `/.env`, `/.git/config`, `/phpmyadmin/`, `/admin/login/` (Django admin is installed but not routed, so this is a natural lure), `/backup.sql`, `/api/v1/users`. View `honeypot_view`: log `security.honeypot.hit` at WARNING with path and method (no body), then return the normal `404.html` with status 404 so the attacker learns nothing. Keep the list in one constant `HONEYPOT_PATHS` with a comment. Make sure `RateLimitMiddleware`/`SecurityEnforcementMiddleware` don't interfere.
2. Honeytoken account: in `seed_demo_data` (and documented for production) create a user `it-support@kura.edu` with an unguessable random password that is never given to anyone, `is_active=True`, no roles. In `login_view`, if the submitted identifier hash equals this account's, log `security.honeytoken.used` at ERROR (still return the normal generic failure). Store the honeytoken email in settings via env var `KURA_HONEYTOKEN_EMAIL` so it isn't in code.
3. CrowdSec scenario `honeypot-hit.yaml`: `type: trigger`, filter on `evt.Meta.event == 'security.honeypot.hit'` or `security.honeytoken.used`, `blackhole: 1m`, labels `remediation: true`, ban 4h via `profiles.yaml`. Extend the logfmt parser if it doesn't already expose `event` as `evt.Meta.event`. Keep the admin allowlist in `kura-whitelist.yaml` effective.
4. Loki alert `HoneypotHit` (severity warning) and `HoneytokenLogin` (severity critical).
5. Tests: each decoy path returns 404 and emits the log event; honeytoken login returns the same message/status as a bad password and emits the ERROR event; normal 404s do **not** emit the honeypot event.

**Acceptance.** `curl -sk https://localhost/.env` → 404; within 1 min `cscli decisions list` shows the source IP banned (test from a non-allowlisted IP or temporarily remove your IP from the whitelist, then restore it).

---

### G10 (P1): Complete the security-testing evidence (run last, after code changes)

**Why.** Security Testing is 20% and the Reporting item asks to "analyse test results, identify residual risks". Current evidence is an unauthenticated ZAP baseline, Semgrep, Trivy, pip-audit and a restore drill on an empty database. Notes §7.3: combine white-box (SAST, code review) with black-box (DAST, external pentest), and fuzzing.

Save everything under `docs/evidence/2026-12/`. For each tool record: command, tool version, date, target, raw output, and a 3-line summary.

| # | Test | Command (WSL, against the running stack) | Pass criterion |
|---|---|---|---|
| T1 | Unit + security test suite with coverage | `coverage run manage.py test kura && coverage report -m > coverage.txt` | all pass; record % for `views.py`, `middleware.py`, `permissions.py` |
| T2 | Django deploy check | `DEBUG=False SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(64))') python manage.py check --deploy` | 0 warnings, or each justified |
| T3 | ZAP baseline (passive) | `docker run --rm --network host -v $PWD/docs/evidence/2026-12:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://localhost -r zap-baseline.html -I` | 0 High/Medium; 90022 gone after G04 |
| T4 | **ZAP authenticated full/active scan** | `zap-full-scan.py` with a context file: login URL `/login/`, a test **student** user with MFA disabled only on a throwaway seeded DB, logged-in indicator `Sign out`, exclude `/logout/`. Repeat as **instructor**. | 0 High; list Mediums with verdict |
| T5 | SQL injection probing | `sqlmap -u "https://localhost/registrar/students/?q=test" --cookie="sessionid=...;csrftoken=..." --batch --level 3 --risk 2 --random-agent` (repeat for `admin/users/?q=`, `attendance/history/?q=`) | "not injectable"; show that Coraza also blocked many payloads (WAF log lines) |
| T6 | IDOR / access-control matrix | script `docs/evidence/2026-12/idor_matrix.py` (requests + two student sessions + one TA): student A requests student B's `attempts/<id>/`, `attempts/<id>/files/<id>/download/`, `grades/<id>/change-request/`; TA requests `grades/<id>/finalize/`; Registrar requests `courses/<id>/grades/` | every forbidden cell is 403/404; table saved as CSV |
| T7 | Fuzzing the forms | `ffuf` or ZAP fuzzer with SecLists `Fuzzing/` payloads on login, reset, course create, search `q` | no 500s; WAF blocks logged |
| T8 | Brute-force control check | `hydra` or a 30-request Python loop against `/login/` | axes 429 after policy limit, nginx `limit_req` 503/429, CrowdSec ban; capture all three log lines |
| T9 | TLS configuration | `docker run --rm --network host drwetter/testssl.sh https://localhost` | TLS 1.3 only, no weak ciphers, HSTS present |
| T10 | External port scan | from another host: `nmap -Pn -sV -p- <vm-ip>` and `nmap --script vulners -sV -p 80,443 <vm-ip>` | only 80, 443 (and 22 from allowlisted IP) |
| T11 | Container/dependency scans | Trivy fs + image (all custom images), pip-audit, SBOM (G06) | only accepted IDs |
| T12 | SAST | Semgrep + Bandit (G07) | 0 un-triaged |
| T13 | Upload controls | EICAR test file (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`), PDF renamed `.html`, 26 MiB file, zip bomb (42.zip) | quarantined / rejected; quarantine row visible to Admin |
| T14 | Backup & restore drill **with data** | `python manage.py seed_demo_data` (or the docker equivalent), then `sudo ./kura.sh restore-drill` | non-zero row counts match (current evidence shows 0 → 0, which proves nothing) |
| T15 | Signature tamper test | from G05 | tamper detected |
| T16 | Log pipeline | from G03 | LokiDown alert fires |
| T17 | Service vulnerability script scan (`nmap vulners`) | `nmap -sV --script vulners <host> -oN docs/evidence/security-tests/<TS>_nmap-vulners.txt` | Only ports 80 and 443 open; server version banners hidden (`server_tokens off`); 0 Critical/High CVEs matched |
| T18 | Web server and WAF baseline scan (`Nikto`) | `nikto -h https://localhost -ssl -output docs/evidence/security-tests/<TS>_nikto.txt` | TLS 1.3 enforced, security headers present, probe payloads blocked with 403/404/429 by Coraza CRS, Nginx rate limits, or CrowdSec |

Then write `docs/coursework/TEST_RESULTS_SUMMARY.md`: one table, per test: objective, tool, white/black box, result, findings (count by severity), fix applied (gap ID / commit), residual risk, link to raw file. Finish with a "Residual risks" section (at least: python-jose/ecdsa transitive CVEs, HIBP check fails open, Debian base-image OS CVEs without fixes, single-VM availability, Gmail SMTP dependency, self-signed public cert in the prototype, human factors/phishing).

---

### G11 (P2): Tamper-evident security log (HMAC + sequence numbers)

**Why.** Notes §1.1 (accountability: immutable logging), §5.4 (HMAC gives integrity + authentication), §6.3 ("logs can be tampered with if not shipped off-host"). Today a host root user could edit Docker's JSON log files before Alloy ships them, or delete lines in Loki's filesystem store, without detection.

**Files.** `kura/logging_utils.py`, `config/settings.py`, `docker-compose.yml` (new Docker secret `log_hmac_key`), `kura.sh` (`GENERATED_SECRETS`), new command `kura/management/commands/verify_log_chain.py`, tests.

**Steps.**
1. New generated secret `log_hmac_key` (add to `GENERATED_SECRETS` in `kura.sh`, owner 10001, top-level `secrets:` and `web.secrets`). Separate from `SECRET_KEY` so rotating one doesn't affect the other (§5.5 key separation).
2. In `log_security_event`, after building `parts`: add `worker=<pid>` and `seq=<per-process counter>` (use `itertools.count()` guarded by a `threading.Lock`), then `mac=` first 32 hex chars of `HMAC-SHA256(log_hmac_key, prev_mac || line_without_mac)` where `prev_mac` is the previous MAC from the same worker (start value = HMAC of `"start:" + pid + boot_time`). Emit a `log.chain.start` event on worker boot.
3. `verify_log_chain --from <Loki export file or stdin>`: groups lines by `worker`, recomputes the chain, reports first broken `seq` (edit) and gaps in `seq` (deletion). Document how to export from Loki with `logcli query '{service="web"}' --since=24h --output=raw`.
4. Keep the existing format otherwise; check CrowdSec parser `kura-django-logfmt.yaml` and the Alloy pipeline still parse the line (extra keys are fine in logfmt). Run the existing logging tests.
5. Tests: chain verifies on a generated sequence; editing one line breaks it at that `seq`; removing a line is reported as a gap.

---

### G12 (P2): Compensating control for the CSRF-exempt passkey endpoint

**Why.** `passkey_auth_complete_view` (`kura/views.py:1277`) is `@csrf_exempt` because django-mfa2's JavaScript doesn't send the token. WebAuthn binds the origin into the signed client data, which mitigates most of it, but notes §1.3 "complete mediation" and §3.4 argue for an explicit server-side check.

**Steps.** Before calling `FIDO2.authenticate_complete`:
1. `if request.method != "POST": return HttpResponseNotAllowed(["POST"])`.
2. Require the `Origin` header (or `Referer` if Origin absent) to equal `settings.SITE_URL`'s scheme+host (also accept `https://localhost` only when `DEBUG`). Else log `access.csrf_failed {"reason":"passkey_origin"}` and return 403.
3. Require `has_valid_pre_mfa_window(request)` (the password step happened in the last 5 minutes) **if** Kura's passkey flow is always step 2; read `mfa_login_callback` first to confirm. If passkeys can be a first factor, skip this sub-step and say so in a comment.
4. Tests: wrong Origin → 403; missing Origin and Referer → 403; correct Origin proceeds to the library (mock it).
5. Update the Semgrep triage row (G07) to "accepted with compensating control".

---

### G13 (P2): Equalise password-reset request timing

**Why.** In `password_reset_request_view` a known email triggers a count query, a token insert, an email insert and a log; an unknown email does none. Response-time differences reveal which accounts exist (notes §3.3 enumeration; §2.2 timing). The message is already generic; the timing isn't.

**Steps.** Move the per-account work out of the request: always enqueue a lightweight job row (e.g. `OutgoingEmail` with `event_key="password-reset-request:<random>"`, `status=pending_lookup`, `to_email=<normalised email>`), and let `send_queued_emails` resolve the account, apply the 2-per-5-min rule, create the token and send. Alternatively (simpler) pad: measure the known-path time and `time.sleep` the unknown path to a fixed floor (e.g. 250 ms ± small jitter) for both branches. Prefer the queue approach; document the choice. Test: mock `time.perf_counter` or assert both branches perform the same number of DB writes (`assertNumQueries`).

---

### G14 (P2): `__Host-` cookie prefixes

**Why.** Notes §3.3: session tokens are short-lived passwords. `__Host-` forces `Secure`, `Path=/` and no `Domain`, blocking cookie injection from sibling subdomains.

**Steps.** In `config/settings.py`, inside the `if not DEBUG:` block: `SESSION_COOKIE_NAME = "__Host-kura_session"`, `CSRF_COOKIE_NAME = "__Host-kura_csrftoken"`. Check every place that hard-codes `sessionid` or `csrftoken`: `kura/logging_utils.py` `REDACTED_LOG_KEYS` (add the new names), `docs/postman/kura.postman_collection.json`, CrowdSec/Coraza exclusions in `docker/coraza/rules.d/`, `static/js/*` (django-mfa2 JS reads the CSRF cookie by name: check `static/mfa/` and set `CSRF_COOKIE_NAME` usage accordingly, otherwise passkeys break). Tests: with `DEBUG=False` override, login response sets `__Host-kura_session` with `Secure; Path=/` and no `Domain`.

---

### G15 (P2): Align the report with the code (justification and evidence)

**Why.** The rubric rewards "specific and convincing justification". Several claims in `docs/coursework/pdf/Kura Secure Learning Management System.pdf` don't match the code: Cloudflare Tunnel/cloudflared and NetBird WireGuard (code: public nginx on 80/443 and an SSH tunnel for Grafana, `kura/views.py` dashboard card); modules, sections, exam answer keys, module target levels (removed in `kura/migrations/0029_strip_to_security_core.py`); "Trivy automatically blocking deployments" (only true after G06's CI step); dynamic DB credentials (switched off in one ZAP run, see G04). The risk register section defines columns but has **no rows**.

**Steps.** Create `docs/coursework/IMPLEMENTATION_STATUS.md`: a table of every control the report claims, with status `Implemented (file:line)`, `Implemented differently (explain)`, `Production recommendation only (out of prototype scope)`, `Removed`. Agents must not edit the PDF; the human updates the report from this table.

---

### G16 (P3): Revocation checking for internal mTLS certificates

Notes §5.5 lists three certificate checks: chain, validity dates, **revocation**. Kura checks the first two. Steps: enable the CRL endpoint on Vault's PKI mount (`vault write pki_int/config/urls crl_distribution_points=https://vault:8200/v1/pki_int/crl`), add `kura.sh renew-crl` (daily cron) that fetches `pki_int/crl/pem` into `certs/internal/crl.pem`, configure `proxy_ssl_crl` in nginx and the WAF, `ssl_crl_file` in `postgresql.conf`, and Gunicorn's `ca_certs` + a CRL-aware SSL context in `gunicorn.conf.py` (Python `ssl.VERIFY_CRL_CHECK_LEAF`). Test: revoke the `web` cert in Vault, refresh CRL, confirm WAF → web connections fail; re-issue and recover. Only do this if everything above is done.

### G17 (P3): Host file-integrity monitoring

Notes §2.4 and §6.3 (Tripwire / FIM). Add `kura.sh fim-baseline` (SHA-256 of `docker-compose.yml`, `docker/**`, `/etc/nftables.d/kura.nft`, `/etc/ssh/sshd_config.d/kura-sshd.conf`, `Dockerfile`, `gunicorn.conf.py`, `config/settings.py`) written to `/var/lib/kura/fim-baseline.json` (root, 600) and `kura.sh fim-check` (hourly cron) that logs `fim.changed path=... ` to the host journal / a file Alloy collects, plus a Loki alert. Alternative: install AIDE on the VM and document it. Either is fine; document the choice.

---

## 5. Coursework document track (agents draft, the student finalises)

These are Markdown/CSV drafts the student pastes into the report. Agents must base every statement on a file in the repo and cite it as `path:line`.

### D1. Risk register + treatment plan (`docs/coursework/risk_register.csv` and `.md`)
Columns exactly as the report defines them, plus treatment fields: `ID, Asset, Threat (STRIDE), Vulnerability, OWASP 2025 ref, Lecture §, Initial L, Initial I, Initial S, Initial level, Applied controls (file refs), Residual L, Residual I, Residual S, Residual level, Treatment (Mitigate/Transfer/Avoid/Accept), Owner, Further action, Review date`. Use the report's 5×5 matrix and level bands. Minimum 25 rows covering: web app (credential stuffing, session hijack, IDOR, XSS, SQLi, CSRF, malicious upload, grade tampering, submission repudiation (G05), error leakage (G04), secret exposure (G01)), data layer (DB exposure (G02), backup loss/ransomware, key compromise), infrastructure (DDoS, host compromise, container escape, supply chain (G06), log pipeline failure (G03)), people/process (phishing of staff, insider admin abuse, lost laptop), data centre (power loss, physical intrusion, capacity exhaustion as in the scenario), cloud (misconfigured storage bucket, IAM over-privilege, provider outage, data residency vs GDPR/FERPA). Gaps G01-G04 should appear with their *before* and *after* scores so the report shows the treatment working.

### D2. Asset inventory & data classification (`docs/coursework/ASSETS_AND_CLASSIFICATION.md`)
Notes §1.4 organisational model (Public → Sensitive → Private → Confidential). List every model in `kura/models.py`, every secret, every volume, every log stream; assign class, owner, retention (`purge_retention.py`, Loki 180 days), protection at rest (app-level AES-GCM / Vault Transit / pgBackRest cipher / none) and in transit (TLS 1.3 / mTLS). Highlight the §5.6 four layers and which one each asset uses.

### D3. STRIDE threat model (`docs/coursework/THREAT_MODEL.md`)
Use `architecture.py` / `docs/coursework/pdf/kuras_secure_architecture_v2.png` as the data-flow diagram. For each element (browser, nginx, WAF, web, db, vault, clamav, observability, admin SSH) and each trust boundary, list S/T/R/I/D/E threats and the mitigating control (file ref) or the gap ID. Notes §1.4 "Threat Modeling Epicycle: Preparation → Identification → Mitigation → Review".

### D4. Lecture traceability matrix (`docs/coursework/LECTURE_TRACEABILITY.md`)
One row per item in `security_concepts_reference.md` that applies to a web system (design principles §1.3 all 13, OWASP Top 10 2021 and 2025, §3.2 injection defences, §3.3 BAC list, §3.4 other attacks, §4 encoding, §5.2-5.7 crypto incl. the 8 common mistakes, §6.2 firewall types, §6.3 IDS/IPS/SIEM, §7.2 SANS mistakes, §7.3 testing types and incident response). Columns: concept, where implemented (file:line), how it's tested (test name or evidence file), gap ID if not yet done, or "not applicable to this system" with a one-line reason (e.g. Layer-2 ARP spoofing is a data-centre network control, cover it in the mitigation plan, not in the app).

### D5. Data-centre and cloud mitigation table (`docs/coursework/MITIGATION_PLAN.md`)
For the brief's infrastructure (multiple servers, 1 TB storage, routers/switches/firewalls, backup systems) and the cloud migration of non-critical workloads: weakness → strategy → control → lecture § → cost tier (low/medium/high, the brief asks for cost optimisation). Include VLAN vs physical segmentation trade-off (§6.1), stateful vs proxy firewalls (§6.2), NIDS/HIPS placement (§6.3), L2/L3/L4 protocol attacks (§6.4), DNS defences, wireless (WPA3, APs outside the core), backups 3-2-1 + immutable, shared-responsibility model, which LMS workloads are "non-critical" and may move to cloud (e.g. static course materials, observability) vs must stay on-prem (grades, identities). Map each to the prototype's equivalent where one exists (e.g. Docker internal networks ≈ VLANs; nftables ≈ host firewall; Coraza ≈ proxy/WAF; CrowdSec ≈ IPS).

### D6. Presentation outline (`docs/coursework/PRESENTATION_OUTLINE.md`)
12-15 slides: problem & scenario; architecture; risk assessment method and top-10 risks heat map; key controls by layer (defence in depth); three "deep dive" demos (MFA + session revocation, signed submission receipt + tamper detection, honeypot → CrowdSec ban); testing approach (white/black box); results before/after; residual risks; data-centre & cloud recommendations; conclusion. For each slide: title, 3 bullets, the screenshot/evidence file to use, and a likely examiner question with a short answer.

---

## 6. Verification runbook (run at the very end)

1. `git status` clean except intended files. `git log --oneline` shows one commit series per gap ID.
2. `docker compose build --no-cache --pull` then `docker compose up -d`; `./kura.sh health` all green; `sudo ./kura.sh preflight` ends with PASS.
3. Full test suite passes (command from `AGENTS.md`); coverage report saved.
4. Manual smoke as each role (Admin, Registrar, Department head, Instructor, TA, Student): log in with MFA, open the home page, do one allowed action and one forbidden action (expect 403/404).
5. All T1-T16 evidence files exist in `docs/evidence/2026-12/` and `TEST_RESULTS_SUMMARY.md` links each one.
6. `docs/coursework/` contains: `risk_register.csv/.md`, `ASSETS_AND_CLASSIFICATION.md`, `THREAT_MODEL.md`, `LECTURE_TRACEABILITY.md`, `MITIGATION_PLAN.md`, `SEMGREP_TRIAGE.md`, `NON_REPUDIATION.md`, `IMPLEMENTATION_STATUS.md`, `TEST_RESULTS_SUMMARY.md`, `PRESENTATION_OUTLINE.md`.
7. `grep -rniE "(secret_id|password|token)\s*[:=]\s*['\"][A-Za-z0-9-]{12,}" --include=*.yml --include=*.py --include=*.sh .` returns nothing outside tests.

## 7. Definition of done per gap

A gap is done only when: code change merged on its branch; at least one new automated test proves it; evidence saved; the risk register row updated with residual score; the traceability matrix row points to the commit/test; nothing in §0 was violated.

## 8. Things the audit could not see

- Hidden files weren't in the copy that was audited: `.github/`, `.dockerignore`, `.gitignore`, `.env`, `certs/`, `secrets/`. Agents must check them in the WSL checkout (G01 step 2, G06 step 3).
- The live VM state (whether it has a public IP) wasn't checked. G02 is a P0 either way because the compose file is what gets deployed.
- Lecture/lab PDFs under `Lectures_Labs/` were not re-read; the notes file was treated as the authoritative summary of them.

# Handoff: finishing docs/Kura_Security_Gap_Plan.md

Written 2026-11-25 19:16 (local). Branch `security-tests`. Read this whole file first, then `docs/Kura_Security_Gap_Plan.md` (sections 4 G10, 5 D1-D6, 6 verification) and `AGENTS.md`.

## 1. State of the work

### Committed and pushed to origin/security-tests

| Commit | Gaps | What it did |
|---|---|---|
| 1667807 | G03, G04 | DB or Vault outage returns 503 (`DependencyOutageMiddleware` in `kura/middleware.py`, `503.html`), Loki scrape job in `docker/alloy/config.alloy`, alerts `LokiDown`, `SecurityLogsStopped`, `WebLogsAbsent` |
| bcd8ff0 | G01, G02 | Vault AppRole ids moved to Docker secrets, Postgres 5432 no longer published, `kura-admin` TCP login rejected in `pg_hba.conf`, `kura.sh vault-rotate-approle`, `check_no_inline_secrets` |
| f8026f5 | G06, G12 | pip/setuptools/wheel removed from runtime image, GitHub Actions pinned to SHAs, `.trivyignore`, SBOMs, passkey endpoint Origin and pre-MFA checks |
| 18489f4 | G07 | Semgrep and Bandit triage, `docs/coursework/SEMGREP_TRIAGE.md`, Semgrep 0 findings |
| d713810 | G05 | Vault Transit ECDSA receipts (`kura/signing.py`, migration 0031, `/.well-known/kura-receipts.pem`, `verify_signatures`, `docs/coursework/NON_REPUDIATION.md`) |
| c494a89 | G08, G09 | Unicode safety (`kura/text_safety.py`, `SafeTextMixin`), honeypot routes, honeytoken account, CrowdSec and Loki rules |
| d1b06ff | G13, G14, G11, G17 | Password-reset timing equalised (migration 0032), `__Host-` cookies, HMAC-chained security log plus `verify_log_chain`, host FIM (`kura.sh fim-baseline`, `fim-check`) |

Checks run on the tree at d1b06ff: 388 tests OK (skipped=8), `ruff check .` clean, `manage.py check --deploy` 0 issues, Semgrep 0 findings. G13 required one justified test edit: `kura/tests.py` `test_request_always_emails_a_link` now calls `call_command("send_queued_emails")` first, because the lookup moved into the queue worker. Do not undo this.

G16 (mTLS CRL) is optional and untouched. G15 and D1-D6 are not started.

### Uncommitted in the working tree (all under `docs/evidence/2026-12/`)

Generated this session, not yet committed:

| Gap test | File | Result |
|---|---|---|
| T1 | `django-tests-2026-12.txt`, `coverage.txt` | 388 tests OK, skipped=8, total coverage 88% of 10998 statements, `kura/views.py` 72%, `kura/permissions.py` 88%. `kura/middleware.py` percentage is in `coverage.txt`, grep for it |
| T2 | `deploy-check.txt` | 0 issues |
| T3 | `zap-baseline.html`, `zap-baseline.txt`, `zap.yaml` | FAIL 0, WARN 5, PASS 63. 90022 is PASS. See warning 4.2 |
| T9 | `testssl.txt`, `testssl-openssl.txt` | TLS 1.3 only. testssl grade T because of the self-signed cert |
| T10 | `port-scan.txt` | Only 80 and 443 public, 3000 and 8085 loopback, 5432, 8200, 3100, 9090, 8000, 3310 closed |
| T11, T12 | `trivy-fs.txt`, `trivy-fs-all.txt` plus older `trivy-image-after-G06.txt`, `pip-audit-after-G06.txt`, `sbom-*.cdx.json`, `semgrep-after.txt`, `bandit.txt` | requirements.txt 0 vulnerabilities |
| G17 | `G17-fim-check.txt` | `fim.ok checked=57`, then tampered baseline reports `fim.changed path="Dockerfile"` exit 1 |
| T16 (log chain) | `G11-log-chain-verify.txt` | live web logs: PASS 14 lines, tampered copy: `Line 22 worker=8 seq=1: tampered or forged HMAC signature.` exit 1 |

Unfinished or broken:

| Item | State |
|---|---|
| T15 / G03 alert drill | Background task `task-823` was still running when I stopped. It stops the `loki` container, polls Prometheus for `LokiDown`, then starts Loki and polls for recovery. Output goes to `docs/evidence/2026-12/G03-alert-fired.txt`. See 3.1 |
| T13 upload controls | `upload-controls.txt` is bad. The ClamAV half worked (EICAR: `Eicar-Test-Signature FOUND`, clean PDF: `OK`). The Python half crashed on `User.objects.filter(roles__name="Student")`. Redo, see 3.2 |
| T14 restore drill | Not done. See 3.3 |
| T4 to T8 | Not started. See 3.4 |
| TEST_RESULTS_SUMMARY.md, G15, D1-D6 | Not started |

## 2. Environment facts (observed, do not re-discover)

- Branch `security-tests`. Remote `origin` is https://github.com/AnaaaKareem/kura.git. Commit per gap or milestone, message starts with the gap ID, push to `origin/security-tests`.
- Disposable DB container `kura-test-db` (postgres:17-alpine) on `127.0.0.1:55432`, user `kura-admin`, password `testpass`, db `kura`. A throwaway database `kura_dast_temp` already exists on it, migrated to 0032 and seeded with `seed_demo_data`. Drop it when T4 to T8 are done.
- The live Compose stack (13 services) is running. `web`, `nginx`, `crowdsec` were rebuilt from the current tree and are healthy. **Live `kura-vault` is sealed** and its unseal keys are operator-held, so live `web` cannot get database credentials and answers POSTs that touch the DB with 503 (this is the G04 behaviour working). Never run `vault operator init`, never try to guess unseal keys.
- `secrets/log_hmac_key.txt` was created locally (mode 644, owner anaaa). It is gitignored. `kura.sh preflight` flags it as "expected 600 10001"; fixing needs root (`sudo chown 10001 secrets/log_hmac_key.txt && sudo chmod 600 ...`). Ask the user to run that. Preflight also fails 15 other checks only because the user cannot read root-owned secrets and `.env` has `DEBUG=true`. Record preflight honestly as "run as non-root, N fails all permission related", do not hide it.
- Sandbox rules: run sandboxed first. These need `BypassSandbox: true`: `docker`, `manage.py test`, anything connecting to `127.0.0.1:55432`, `semgrep`, `pip-audit`, `trivy`, `git add/commit/push`.
- Tools: `/tmp/kura-sec-tools` is a venv with bandit, coverage, sqlmap, requests. Keep `.venv` untouched. Coverage run pattern: `PYTHONPATH="$(/tmp/kura-sec-tools/bin/python -c 'import site; print(site.getsitepackages()[0])')" .venv/bin/python -m coverage ...`.
- Test env prefix (use for every manage.py call against the throwaway DB):
  ```bash
  DEBUG=True VAULT_ENABLED=False VAULT_DATABASE_CREDENTIALS=False CLAMAV_REQUIRED=False \
  DATABASE_HOST=127.0.0.1 DATABASE_PORT=55432 DATABASE_NAME=kura_dast_temp \
  DATABASE_USER=kura-admin DATABASE_PASSWORD=testpass DB_SSL_MODE= \
  SECRET_KEY=local-test-secret-key-not-for-production-min-50-chars-long
  ```
- Safety rules from AGENTS.md: never `docker compose down -v`, never `docker volume rm` on persistent `kura_*` volumes (`kura_vault_data`, `kura_pgedge_postgres_data`, `kura_postgres_backups*`, `kura_loki_data`, ...), never `DROP DATABASE` on anything but `kura_dast_temp`, never commit `secrets/`, `certs/`, `.env`, tokens. Never weaken or skip tests.
- Writing style (user requirement, humanizer skill at `/home/anaaa/.gemini/config/skills/humanizer/SKILL.md`): in commit messages and all `docs/` prose use zero em dashes, zero en dashes, no spaced double hyphens, no "not X but Y" or "rather than" contrasts, no forced triads, no dramatic one-line closers, none of these words: crucial, pivotal, delve, landscape, underscores, highlighting, ensuring, bolstered, meticulous, showcase, testament, figurative "robust". Check with `grep -rnP "\x{2014}|\x{2013}| -- " docs/coursework/` which must print nothing.
- Code comments: keep plain-English security rationale above security checks, and `Who can use it:` / `Security:` lines in view and helper docstrings.
- Only state facts you saw in a file or tool output. Quote exact counts.

## 3. Remaining work, with how I would do each step

### 3.1 Finish T15 (G03 alert drill)

1. `manage_task` status on `task-823`. If it is still running let it finish (it polls at most 18 times 10 s for firing, then 18 times for recovery).
2. When done run `docker compose ps loki prometheus alertmanager`. If `loki` is not running: `docker compose start loki`. Loki must end healthy; this is a hard requirement because Loki is part of the live stack.
3. Read `docs/evidence/2026-12/G03-alert-fired.txt`. Pass criterion: a `LokiDown` entry in state `firing`, then recovery with the `loki` target `health: up`. The `for:` duration of the rule is in `docker/prometheus/alerts.yml`; if the drill window was too short to reach firing, re-run it once with a longer loop (the script polls Prometheus from inside `kura-web` with `docker exec kura-web python -c 'urllib...'` against `http://prometheus:9090/api/v1/alerts`). If firing never appears, say so in the summary and investigate the rule, do not fake it.
4. The earlier `G03-*` files already exist from the first G03 commit; cross-reference them in the summary.

### 3.2 Redo T13 (upload controls)

The file is flagged binary because ClamAV replies end in NUL. Strip with `tr -d '\000'` when saving. The Python half failed on a wrong guess about the user model. Before rewriting it:

1. `grep -n "def validate_and_save_upload\|def _scan\|def sanitize_filename\|class QuarantinedFile" kura/*.py` and read the function signatures and the exact way it raises (ValidationError or returns a result).
2. `grep -n "class UserRole\|roles" kura/models.py | head` to learn how a Student user is selected. Or reuse the seeded demo student by email (`seed_demo_data.py` has them).
3. Write a small script under `docs/evidence/2026-12/upload_controls.py` (Django setup with the env prefix from section 2) that tests: PDF bytes named `.html` (expect MIME mismatch rejection), a 26 MiB file (expect size rejection, limit is 25 MiB), EICAR (expect a `QuarantinedFile` row; to reach ClamAV from the host either point the scanner at the running container or patch the scan function to return the signature, and say which one you did), and a small zip-bomb style archive (a 42.zip download is not possible offline, so generate a highly compressed zip of zeros and report what the pipeline does; if it is accepted as an unknown type, record that honestly as a finding).
4. Save raw output to `upload-controls.txt` (keep the ClamAV INSTREAM lines from the existing run: EICAR FOUND, clean OK).

### 3.3 T14 (restore drill with data)

Facts: live DB tables `users`, `courses`, `enrollments` have no rows (only roles, permissions, content types). A stopped container `kura-restore-drill` (exited 8 hours before my check, created 2 days earlier) and volume `kura_restore_drill_20261123124201` exist from an older drill, so `./kura.sh restore-drill` refuses to run ("already exists").

Options, in order of safety:
1. Ask the user for approval to (a) rename the old container with `docker rename kura-restore-drill kura-restore-drill-20261123` (reversible, do not delete its volume), (b) seed demo data into the live DB, (c) take a fresh pgBackRest backup, then run the drill. Seeding the live DB needs a Django process that reaches the DB without Vault, for example `docker compose run --rm -e VAULT_DATABASE_CREDENTIALS=False ... web python manage.py seed_demo_data`. Check `docker-compose.yml` for how `kura-migrate` connects and copy that route; do not guess. Then run the backup (look in `docker/postgres/` and `kura.sh` for the backup command; cron entries are in `docker/cron/kura.crontab`) and finally `./kura.sh restore-drill`.
2. If the user does not approve touching live data, document honestly in `restore-drill-with-data.txt` that the live DB holds 0 rows in the compared tables so a 0 to 0 comparison proves nothing, keep the pgBackRest facts you can show (`docker compose exec db pgbackrest info` if available), and list it as a residual risk in the summary.
3. After a successful drill, remove only the drill artefacts the script prints (container `kura-restore-drill`, volume `kura_restore_drill_<time>`). The Nov 23 volume belongs to an earlier run, ask before removing it.

### 3.4 T4 to T8 (authenticated DAST, sqlmap, IDOR, fuzzing, brute force)

Why a local server: live `web` answers 503 for anything needing the DB (Vault sealed). So run a disposable Django server against `kura_dast_temp`.

Start it (background daemon, `IsDaemon: true`):
```bash
<env prefix from section 2> .venv/bin/python manage.py runserver 127.0.0.1:18000 --noreload
```
(`DEBUG=True` means plain HTTP and the non-`__Host-` cookie names `kura_session`? Check `config/settings.py` for the exact cookie names under DEBUG; in DEBUG they are the defaults `sessionid` and `csrftoken`.) Stop the server when done.

Getting logged-in sessions without TOTP: read `kura/tests_security_fixtures.py` (login and MFA helpers) and `kura/middleware.py` (which session keys the MFA gate needs, for example `mfa_verified_at`). Create the session in Python with `django.contrib.sessions.backends.db.SessionStore`, set `_auth_user_id`, `_auth_user_backend`, `_auth_user_hash` (use `user.get_session_auth_hash()`), plus the MFA timestamp keys, `save()`, and use `session_key` as the `sessionid` cookie. Alternative: use `django.test.Client.force_login` then copy the cookie. Demo users: see `kura/management/commands/seed_demo_data.py` for emails and roles (student, TA, instructor, registrar, admin).

| Test | How | Evidence file | Pass |
|---|---|---|---|
| T4 | `docker run --rm --network host -v $PWD/docs/evidence/2026-12:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t http://127.0.0.1:18000 ...` with a Replacer rule or hook script that adds the `Cookie` header, once as student and once as instructor, exclude `/logout/`. If the full scan is too slow use `zap-baseline.py -m 5` plus `zap-api` style spider, and state the limit used. Run as user `-u $(id -u)` so files are writable | `zap-active-student.txt`, `zap-active-instructor.txt` (+ html) | 0 High, each Medium has a verdict |
| T5 | `/tmp/kura-sec-tools/bin/sqlmap -u "http://127.0.0.1:18000/registrar/students/?q=test" --cookie="sessionid=...;csrftoken=..." --batch --level 3 --risk 2 --random-agent --output-dir=/tmp/sqlmap-out`, repeat for `/admin/users/?q=test` and `/attendance/history/?q=test` (use a session with the right role for each). Then send classic payloads (`' OR 1=1--`, `1 UNION SELECT NULL--`) to `https://localhost/login/` with curl and capture WAF lines: `docker compose logs --tail=200 waf` | `sqli-probing.txt` | "not injectable" for all, WAF block lines present |
| T6 | Write `docs/evidence/2026-12/idor_matrix.py` using `requests` (venv `/tmp/kura-sec-tools`) and the sessions above. Cells: student A requests student B's `/attempts/<id>/`, the file download URL, `/grades/<id>/change-request/`; TA requests `/grades/<id>/finalize/`; registrar requests `/courses/<id>/grades/`. Find the exact routes with `grep -n path kura/urls.py` (routes are in `kura/urls.py`, names in `ROUTE_CLASS_MAP` of `kura/tests_security_routes.py`). Write `idor_matrix.csv` and `idor_matrix.txt` | `idor_matrix.py/.csv/.txt` | every forbidden cell is 403 or 404 |
| T7 | Python fuzz loop (ffuf is not installed): payload list of XSS, SQLi, NUL bytes, bidi controls, malformed UTF-8 (send raw bytes), 1 MB strings, against `/login/`, `/password/reset/`, course create, `?q=`. Count status codes. Also run a smaller set through `https://localhost` to capture WAF blocks | `form-fuzzing.txt` | zero HTTP 500 on the local server, WAF block excerpt |
| T8 | 30 rapid bad logins to `http://127.0.0.1:18000/login/` (expect axes 429 after the policy limit, see `AXES_FAILURE_LIMIT` in `config/settings.py`), 60 rapid requests to `https://localhost/login/` (expect nginx `limit_req` 429 or 503, see `docker/nginx/conf.d/kura.conf`), then `docker exec kura-crowdsec cscli decisions list` and `cscli alerts list`. Capture one log line from each layer | `bruteforce-check.txt` | all three layers visible. If CrowdSec does not ban because live web returns 503 and no `auth.login.failed` events reach it, say so and show `cscli metrics` instead |

Cautions for T8 and honeypot checks: your own IP may get banned (nftables bouncer, CrowdSec). The allowlist is `docker/crowdsec/` `kura-whitelist.yaml`. If you get banned, remove the decision with `docker exec kura-crowdsec cscli decisions delete --ip <ip>` and mention it in the evidence. Also run the G09 acceptance once: `curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/.env` expects 404, then `cscli decisions list` and save to `G09-honeypot-ban.txt`. If localhost is allowlisted the ban will not appear, state that.

Cleanup after T4 to T8: stop the runserver task, `docker exec kura-test-db psql -U kura-admin -d kura -c "DROP DATABASE kura_dast_temp;"` (this is the only allowed DROP DATABASE), `rm -rf /tmp/sqlmap-out`.

### 3.5 Write docs/coursework/TEST_RESULTS_SUMMARY.md

One table with a row per T1 to T16: objective, tool and version, white or black box, result, findings by severity, fix applied (gap ID and commit hash from section 1), residual risk, relative link to the raw file in `docs/evidence/2026-12/`. T15 is the signature tamper test (`G05-tamper-detected.txt`), T16 is the log pipeline (`G03-alert-fired.txt`, `G11-log-chain-verify.txt`). Findings to carry in honestly:

- ZAP baseline had 5 warnings: cache-control on `/privacy/`, suspicious comments in `static/js/theme.*.js`, non-storable content, and two informational "Authentication Request / Session Management Response Identified". The login POST showed 503 because live Vault was sealed during the scan. Say so, and say the authenticated scans (T4) ran against the local server.
- testssl grade T is caused by the self-signed certificate. testssl also printed "Forward Secrecy not supported" while listing X25519 ECDH TLS 1.3 suites; treat it as a testssl TLS-1.3-only artefact and say you did not investigate further unless you do.
- Coverage numbers from section 1.
- Residual risks section must include at least: python-jose and ecdsa transitive CVEs (see `docs/SECURITY_TRIVY_FINDINGS.md`), HIBP check fails open, Debian base-image OS CVEs without fixes, single-VM availability, Gmail SMTP dependency, self-signed public certificate, human factors and phishing, and the T14 limitation if the drill ran on an empty DB.

### 3.6 Commit the evidence (milestone)

```bash
git add docs/evidence/2026-12 docs/coursework/TEST_RESULTS_SUMMARY.md docs/HANDOFF_Security_Gap_Plan.md
git commit -m "G10: add security testing evidence T1-T16 and results summary"
git push origin security-tests
```
Check `git status` first: no `secrets/`, `certs/`, `.env`. The evidence directory is mode 777 and some files are world-writable; harmless.

### 3.7 G15: docs/coursework/IMPLEMENTATION_STATUS.md

Table of every control claimed in `docs/coursework/pdf/Kura Secure Learning Management System.pdf` with status `Implemented (file:line)`, `Implemented differently (explain)`, `Production recommendation only`, or `Removed`. Do not edit the PDF. Read the PDF text with `pdftotext -layout "docs/coursework/pdf/Kura Secure Learning Management System.pdf" -` (or Python `pypdf`) and use these known mismatches as the start:

- Cloudflare Tunnel (`cloudflared`) and NetBird WireGuard mesh (PDF pp. 5, 6, 26, 27, 31, 32): code exposes nginx on 80 and 443 directly with an nftables host firewall and the CrowdSec bouncer (`docker-compose.yml`), Grafana only on `127.0.0.1:3000` behind an SSH tunnel (`architecture.py` around lines 176-178). Status: implemented differently or production recommendation.
- Python 3.13 and Django 5.2 LTS (PDF pp. 5, 25): code uses Python 3.14 and Django 6.1.2 (`Dockerfile`, `requirements.lock.txt`).
- Tailwind and HTMX (pp. 5, 26): code uses local Bootstrap 5 static files.
- `django-two-factor-auth` (p. 25): code uses `django-otp`, `qrcode`, `django-mfa2` (`requirements.lock.txt`).
- Coraza CRS WAF container `kura-waf` sits in front of the app in compose (the PDF describes nginx as the layer).
- Modules, module target levels, sections, section items, exam answer keys, JSONB assessments, grade schemes, grade appeals, `LoginAttempt`: removed or replaced in `kura/migrations/0029_strip_to_security_core.py` (appeals became `GradeChangeRequest`, `LoginAttempt` became django-axes, assessments became file-upload `AssessmentAttempt` and `AttemptFile`). Status: Removed.
- "Trivy automatically blocks deployments" (p. 32): true after G06, `.github/workflows/security.yml`.
- "vault_role_id and vault_secret_id never in env, PostgreSQL internal" (p. 31): had regressed, fixed by G01 and G02 (bcd8ff0).
- Risk register (pp. 37-38) defines columns and the 5x5 matrix but has no rows: filled by D1.

Look up every `file:line` with `grep -n` before writing it. Line numbers shift, so cite what you actually grep after the last code edit.

### 3.8 D1 to D6 (all under docs/coursework/)

Spec is `docs/Kura_Security_Gap_Plan.md` section 5. Practical notes:

- **D1 `risk_register.csv` and `risk_register.md`.** At least 28 rows (plan says 25 minimum; G01 to G04 need before and after scores). Columns exactly: `ID, Asset, Threat (STRIDE), Vulnerability, OWASP 2025 ref, Lecture §, Initial L, Initial I, Initial S, Initial level, Applied controls (file refs), Residual L, Residual I, Residual S, Residual level, Treatment (Mitigate/Transfer/Avoid/Accept), Owner, Further action, Review date`. S is the product L times I. Bands: 1-4 Low, 5-9 Medium, 10-16 High, 20-25 Critical. Generate the CSV with a small Python script that computes S and the level from L and I so arithmetic is never wrong, and validate: row count, no empty cells, levels match bands. Required topics: credential stuffing, session hijack, IDOR, XSS, SQLi, CSRF, malicious upload, grade tampering, submission repudiation (G05), error leakage (G04), secret exposure (G01), DB exposure (G02), backup loss or ransomware, key compromise, DDoS, host compromise, container escape, supply chain (G06), log pipeline failure (G03), phishing of staff, insider admin abuse, lost laptop, power loss, physical intrusion, capacity exhaustion, cloud misconfigured bucket, cloud IAM over-privilege, provider outage, data residency versus GDPR, FERPA and Egyptian Law 151/2020 and 175/2018. The scenario is Simpsons University (see the brief in `docs/coursework/KH6000CMD_CW.docx`).
- **D2 `ASSETS_AND_CLASSIFICATION.md`.** Classes Public, Sensitive, Private, Confidential. One row per model in `kura/models.py` (`grep -n "^class .*models.Model" kura/models.py`), every secret in `GENERATED_SECRETS` and `secrets:` of `docker-compose.yml`, every volume, every log stream. Columns: class, owner, retention (`purge_retention.py`, Loki 180 days), at-rest protection (app-level AES-GCM, Vault Transit, pgBackRest cipher, none), in-transit (TLS 1.3, mTLS).
- **D3 `THREAT_MODEL.md`.** STRIDE per element (browser, nginx, WAF, web, db, vault, clamav, observability, admin SSH) and per trust boundary. Use `architecture.py` as the data-flow source. Each threat cites a control `file:line` or a gap ID.
- **D4 `LECTURE_TRACEABILITY.md`.** The plan mentions `security_concepts_reference.md`. A `find` for lecture or concepts files in the repo showed nothing I could use, so run `find / -name "security_concepts_reference.md" -not -path "*/node_modules/*" 2>/dev/null` and `ls Lectures_Labs 2>/dev/null`. If it does not exist, ask the user for it. Do not invent lecture section numbers; if you must proceed, use only the section numbers quoted in `docs/Kura_Security_Gap_Plan.md` and mark the rest "section number to confirm".
- **D5 `MITIGATION_PLAN.md`.** Table: weakness, strategy, control, lecture section, cost tier (low, medium, high). Cover VLAN versus physical segmentation, stateful versus proxy firewalls, NIDS and HIPS placement, L2/L3/L4 attacks, DNS, wireless (WPA3), 3-2-1 plus immutable backups, shared responsibility, which workloads may move to cloud (static course material, observability) versus stay on-prem (grades, identities), and the prototype equivalents (Docker internal networks for VLANs, nftables, Coraza, CrowdSec).
- **D6 `PRESENTATION_OUTLINE.md`.** 12 to 15 slides, each with title, 3 bullets, evidence file to show, and a likely examiner question with a short answer. Include the three demos: MFA and session revocation, signed receipt and tamper detection (`G05-*` files), honeypot to CrowdSec ban.

Every statement must be traceable to a file. Run the humanizer dash check on each file as you finish it.

### 3.9 Final verification (plan section 6)

1. Full tests (AGENTS.md command, 6 modules). Expect 388 tests, skipped=8, unless you add tests.
2. `.venv/bin/ruff check .`
3. `check --deploy` with `DEBUG=False` (command in AGENTS.md).
4. `.venv/bin/semgrep --config auto .` expects 0 findings (needs BypassSandbox).
5. Secret grep from plan section 6 item 7; it must return nothing outside tests.
6. `ls docs/coursework/` shows all of: `risk_register.csv`, `risk_register.md`, `ASSETS_AND_CLASSIFICATION.md`, `THREAT_MODEL.md`, `LECTURE_TRACEABILITY.md`, `MITIGATION_PLAN.md`, `SEMGREP_TRIAGE.md`, `NON_REPUDIATION.md`, `IMPLEMENTATION_STATUS.md`, `TEST_RESULTS_SUMMARY.md`, `PRESENTATION_OUTLINE.md`. Every T1 to T16 evidence file exists and is linked.
7. `git log --oneline` shows a commit series per gap ID, `git status` clean, `git push origin security-tests`.
8. Cleanup: `docker rm -f kura-test-db` (disposable, its volume is anonymous), `rm -rf /tmp/sqlmap-out /tmp/kura-sec-tools`, confirm `docker compose ps` shows all 13 services up and `loki` healthy. The skipped plan items to mention to the user in the final message: `sudo ./kura.sh preflight` (needs root, user must run it), the manual six-role smoke test (plan 6.4, partly covered by `idor_matrix`), screenshots (G05, plan evidence list), the external `nmap` from another host (T10 was run from the same machine), G16.

## 4. Things I would flag to the user in the final report

1. Vault is sealed on the live stack, so live DB-backed behaviour could only be shown by the 503 path (G04) and by a throwaway local server.
2. T14 may stay empty without approval to seed live data.
3. `secrets/log_hmac_key.txt` ownership fix needs root.
4. Preflight cannot pass fully as a non-root user.
5. All evidence for T10 comes from the host itself, not a second machine.

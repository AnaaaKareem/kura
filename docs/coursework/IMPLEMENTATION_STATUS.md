# Implementation Status: PDF Report vs Code

This table maps security controls claimed in `docs/coursework/pdf/Kura Secure Learning Management System.pdf` to their verified status in the repository.

| PDF Section / Claim | PDF Page(s) | Status | File:Line / Explanation |
|---------------------|-------------|--------|-------------------------|
| **Architecture & Infrastructure** |
| Cloudflare Tunnel (`cloudflared`) for public ingress | 5, 6, 26, 27, 31, 32 | Implemented differently | Public nginx on ports 80 and 443 with nftables host firewall and CrowdSec bouncer (`docker-compose.yml`, `docker/nftables/kura.nft`). SSH tunnel documented for Grafana (`architecture.py:176-178`). |
| NetBird WireGuard mesh for service-to-service | 5, 6, 26, 27, 31, 32 | Implemented differently | Docker internal networks (`docker-compose.yml` networks: `app`, `backend`, `clamav`, `egress`, `frontend`, `observability`, `docker_api`) with mTLS between hops. |
| PostgreSQL on internal network only | 31 | Implemented | `docker-compose.yml` `db` service has no `ports:` block; `docker/postgres/pg_hba.conf:25-36` requires client certs for `kura_app` and rejects `kura-admin` over TCP (`pg_hba.conf:22`). |
| Vault AppRole credentials in Docker secrets | 31 | Implemented | `docker-compose.yml:1012-1015` mounts `vault_role_id` and `vault_secret_id` as Docker secrets; `kura.sh:719` (`cmd_vault_rotate_approle`) rotates them. |
| **Application Stack** |
| Python 3.13 | 5, 25 | Implemented differently | Python 3.14 (`Dockerfile`, `requirements.lock.txt`). |
| Django 5.2 LTS | 5, 25 | Implemented differently | Django 6.1.2 (`requirements.lock.txt`). |
| Tailwind CSS + HTMX | 5, 26 | Implemented differently | Bootstrap 5 static assets (`Dockerfile` nginx stage copies `static/`). |
| `django-two-factor-auth` | 25 | Implemented differently | `django-otp`, `qrcode`, and `django-mfa2` (`requirements.lock.txt`). |
| Coraza CRS WAF container `kura-waf` in front of app | 26, 31 | Implemented | `docker-compose.yml` `waf` service (Coraza CRS) sits between nginx and Gunicorn over mTLS. |
| **Data Model** |
| Modules, module target levels | 5, 26 | Removed | Stripped by `kura/migrations/0029_strip_to_security_core.py`. |
| Sections, section items | 5, 26 | Removed | Stripped by `kura/migrations/0029_strip_to_security_core.py`. |
| Exam answer keys | 5, 26 | Removed | Stripped by `kura/migrations/0029_strip_to_security_core.py`. |
| JSONB assessments | 26 | Removed | Replaced by file-upload `AssessmentAttempt` (`kura/models.py:1034`) and `AttemptFile` (`kura/models.py:1067`). |
| Grade schemes | 26 | Removed | Replaced by `GradeComponentType` (`kura/models.py:139`) and `CourseResult` (`kura/models.py:1228`). |
| Grade appeals | 26 | Implemented differently | Replaced by `GradeChangeRequest` (`kura/models.py:1177`). |
| `LoginAttempt` model | 26 | Removed | Replaced by `django-axes` (`axes_accessattempt` table; `config/settings.py:317-323`). |
| **Security Controls** |
| Trivy automatically blocks deployments | 32 | Implemented | `.github/workflows/security.yml` runs Trivy with `--exit-code 1` on HIGH and CRITICAL findings; `.trivyignore` records accepted transitive CVEs with review dates. |
| Vault dynamic DB credentials (15 min TTL) | 31 | Implemented | Custom PostgreSQL engine in `kura/base.py` enabled by `VAULT_DATABASE_CREDENTIALS=True` (`config/settings.py:196`). During the passive ZAP baseline run, `VAULT_DATABASE_CREDENTIALS` stayed `True` while live `kura-vault` was sealed, so DB-backed POST paths returned HTTP 503 via `DependencyOutageMiddleware`. |
| Vault AppRole credentials never in environment variables | 31 | Implemented | Fixed by G01 (`bcd8ff0`): `vault_role_id` and `vault_secret_id` moved out of container `environment:` into Docker secrets (`docker-compose.yml:1012-1015`) and checked by `check_no_inline_secrets` (`kura.sh:1094`). |
| **Risk Register** |
| Risk register with 5x5 matrix | 37-38 | Implemented | `docs/coursework/risk_register.csv` and `docs/coursework/risk_register.md` (D1) contain 28 rows with before and after scores for G01 to G04. |
| **Testing Evidence** |
| Semgrep, Trivy, pip-audit, ZAP baseline | 32 | Implemented | Run and saved under `docs/evidence/2026-12/`; summarized in `docs/coursework/TEST_RESULTS_SUMMARY.md`. |
| Restore drill with data | 32 | Implemented | `./kura.sh restore-drill` (`kura.sh:1516`) compares row counts; T14 passed with 8 users, 1 course, 2 enrollments, 1 assessment, 0 grades, and 0 outgoing emails matching in 21 seconds. |
| **Compliance** |
| GDPR privacy dashboard (export, restriction, erasure) | 33-34 | Implemented | `kura/views.py:2520-2699` privacy views and `kura/management/commands/purge_retention.py`. |
| Retention purge (180 days Loki, configurable DB) | 34 | Implemented | `docker/loki/loki.yml` sets 180-day retention; `purge_retention.py` enforces DB retention windows. |
| IP anonymisation | 34 | Implemented | `kura/logging_utils.py:82` (`get_client_ip`) and retention/privacy controls. |
| Inactive account disablement | 34 | Implemented | `SecurityPolicy` (`kura/models.py:1278`) and scheduled management commands. |

## Legend

- **Implemented**: Control exists in code as described, with verified `file:line` reference.
- **Implemented differently**: Control achieves the same security objective using a different technology or design; actual implementation is cited.
- **Production recommendation only**: Control is planned for production deployment outside prototype scope.
- **Removed**: Feature existed in an earlier design and was removed by `kura/migrations/0029_strip_to_security_core.py`.

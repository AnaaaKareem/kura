# Implementation Status: PDF Report vs Code

This table maps every security control claimed in `docs/coursework/pdf/Kura Secure Learning Management System.pdf` to its implementation status in the codebase.

| PDF Section / Claim | PDF Page(s) | Status | File:Line / Explanation |
|---------------------|-------------|--------|-------------------------|
| **Architecture & Infrastructure** |
| Cloudflare Tunnel (cloudflared) for public ingress | 5, 6, 26, 27, 31, 32 | Implemented differently | Public nginx on 80/443 with nftables host firewall + CrowdSec bouncer (`docker-compose.yml`, `docker/nftables/kura.nft`). SSH tunnel for Grafana (`kura/views.py:176-178`). |
| NetBird WireGuard mesh for service-to-service | 5, 6, 26, 27, 31, 32 | Implemented differently | Docker internal networks (`docker-compose.yml` networks: app, backend, clamav, egress, frontend, observability, docker_api) with mTLS between all hops. |
| PostgreSQL on internal network only | 31 | Implemented | `docker-compose.yml` db service has no `ports:` block; `pg_hba.conf` requires client cert for `kura-admin` TCP. |
| Vault AppRole credentials in Docker secrets | 31 | Implemented | `docker-compose.yml` web.secrets includes `vault_role_id`, `vault_secret_id`; `kura.sh vault-rotate-approle` rotates. |
| **Application Stack** |
| Python 3.13 | 5, 25 | Implemented differently | Python 3.14 (`Dockerfile`, `requirements.lock.txt`). |
| Django 5.2 LTS | 5, 25 | Implemented differently | Django 6.1.2 (`requirements.lock.txt`). |
| Tailwind CSS + HTMX | 5, 26 | Implemented differently | Bootstrap 5 static files (`Dockerfile` nginx stage copies `static/`). |
| `django-two-factor-auth` | 25 | Implemented differently | `django-otp`, `qrcode`, `django-mfa2` (`requirements.lock.txt`). |
| Coraza CRS WAF container `kura-waf` in front of app | 26, 31 | Implemented | `docker-compose.yml` waf service (Coraza CRS) between nginx and gunicorn over mTLS. |
| **Data Model** |
| Modules, module target levels | 5, 26 | Removed | Stripped by migration `kura/migrations/0029_strip_to_security_core.py`. |
| Sections, section items | 5, 26 | Removed | Same migration `0029`. |
| Exam answer keys | 5, 26 | Removed | Same migration `0029`. |
| JSONB assessments | 26 | Removed | Replaced by file-upload `AssessmentAttempt` + `AttemptFile`. |
| Grade schemes | 26 | Removed | Replaced by `GradeComponentType` + `CourseResult`. |
| Grade appeals | 26 | Implemented differently | Replaced by `GradeChangeRequest` (`kura/models.py:763`). |
| `LoginAttempt` model | 26 | Removed | Replaced by django-axes (`axes_accessattempt` table). |
| **Security Controls** |
| Trivy automatically blocks deployments | 32 | Implemented | `.github/workflows/security.yml` runs Trivy with `--exit-code 1` on HIGH/CRITICAL; `.trivyignore` documents accepted CVEs. |
| Vault dynamic DB credentials (15 min TTL) | 31 | Implemented | `kura/base.py` custom backend; `VAULT_DATABASE_CREDENTIALS=True` in compose; temporarily disabled for ZAP baseline. |
| `VAULT_DATABASE_CREDENTIALS` never in env | 31 | Implemented | Fixed by G01/G02 (bcd8ff0); now in Docker secrets. |
| **Risk Register** |
| Risk register with 5×5 matrix | 37-38 | Implemented | `docs/coursework/risk_register.csv` (D1) with before/after scores for G01-G04. |
| **Testing Evidence** |
| Semgrep, Trivy, pip-audit, ZAP baseline | 32 | Implemented | All run in CI; evidence in `docs/evidence/2026-12/`. |
| Restore drill with data | 32 | Implemented | `./kura.sh restore-drill` compares row counts; T14 passed with 8 users, 1 course, 2 enrollments. |
| **Compliance** |
| GDPR privacy dashboard (export, restriction, erasure) | 33-34 | Implemented | `kura/views.py` privacy endpoints; `kura/management/commands/purge_retention.py`. |
| Retention purge (180 days Loki, configurable DB) | 34 | Implemented | `docker/loki/loki.yml` retention 180d; `purge_retention.py` for DB. |
| IP anonymisation | 34 | Implemented | `kura/middleware.py` `get_client_ip` with anonymisation option. |
| Inactive account disablement | 34 | Implemented | `SecurityPolicy` model + management command. |

## Legend

- **Implemented**: Control exists in code as described, with file:line reference.
- **Implemented differently**: Control achieves same goal via different technology/approach; documented with actual implementation reference.
- **Production recommendation only**: Control is a production recommendation not implemented in prototype scope.
- **Removed**: Control was in earlier design but removed by migration `0029_strip_to_security_core.py`.

# Asset Inventory & Data Classification

**Classification Scheme (per Lecture §1.4):**
- **Public**: Information intended for public consumption
- **Sensitive**: Internal operational information requiring baseline access control
- **Private**: Personal data (GDPR Art. 4) requiring strong access control and auditing
- **Confidential**: High-sensitivity assets (keys, secrets, grades, encrypted submissions) requiring strict isolation and cryptographic protection

## Database Models (all 33 models in `kura/models.py`)

| Model (`kura/models.py`) | Classification | Owner | Retention | At-Rest Protection | In-Transit Protection |
|--------------------------|---------------|-------|-----------|-------------------|----------------------|
| `User` (`kura/models.py:290`) | Private | Registrar | 7 years post-graduation | Argon2id password hash (`config/settings.py:301`), Vault Transit `kura-mfa` AES-256-GCM96 on `mfa_secret` (`kura/views.py:200-237`), PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`) | TLS 1.3 (nginx) + mTLS (internal) |
| `Department` (`kura/models.py:362`) | Sensitive | Admin | Permanent | Host LUKS + pgBackRest AES-256-CBC backups | TLS 1.3 + mTLS |
| `Building` (`kura/models.py:389`) | Public | Admin | Permanent | Host LUKS + pgBackRest backups (reference campus data) | TLS 1.3 + mTLS |
| `Room` (`kura/models.py:398`) | Public | Admin | Permanent | Host LUKS + pgBackRest backups (reference room data) | TLS 1.3 + mTLS |
| `Role` (`kura/models.py:411`) | Sensitive | Admin | Permanent | Host LUKS + pgBackRest backups (reference RBAC catalog) | TLS 1.3 + mTLS |
| `UserRole` (`kura/models.py:429`) | Private | Registrar | 7 years | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `SystemPermission` (`kura/models.py:451`) | Sensitive | Admin | Permanent | Host LUKS + pgBackRest backups (reference permission catalog) | TLS 1.3 + mTLS |
| `RolePermission` (`kura/models.py:472`) | Sensitive | Admin | Permanent | Host LUKS + pgBackRest backups (role-to-permission mapping) | TLS 1.3 + mTLS |
| `StudentProfile` (`kura/models.py:493`) | Private | Registrar | 7 years post-graduation | PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`), host LUKS + pgBackRest | TLS 1.3 + mTLS |
| `StaffProfile` (`kura/models.py:519`) | Private | Admin | 7 years post-employment | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `PasswordResetToken` (`kura/models.py:549`) | Confidential | User | 1 hour (purged by `purge_retention.py`) | SHA-256 hashed token only (plaintext never stored) | TLS 1.3 + mTLS |
| `UserSession` (`kura/models.py:570`) | Private | User | 30 min idle / 12 hours absolute | HMAC-SHA256 session-to-user binding (`kura/middleware.py:123`) | TLS 1.3 + mTLS |
| `Course` (`kura/models.py:596`) | Sensitive | Dept Head | Permanent | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `CourseStaff` (`kura/models.py:635`) | Private | Dept Head | 7 years | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `Enrollment` (`kura/models.py:662`) | Private | Registrar | 7 years | PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`), host LUKS + pgBackRest | TLS 1.3 + mTLS |
| `CourseFile` (`kura/models.py:701`) | Sensitive | Instructor | 7 years | Link table referencing `StoredFile` and encrypted `FileContent` | TLS 1.3 + mTLS |
| `StoredFile` (`kura/models.py:727`) | Private | Uploader | 7 years | Sanitized filename, detected MIME, SHA-256 hash; raw bytes stored encrypted in `FileContent` | TLS 1.3 + mTLS |
| `FileContent` (`kura/models.py:760`) | Confidential | System | 7 years | Per-file AES-256-GCM encryption (`kura/views.py:239-248`) with data key wrapped by Vault Transit `kura-files` (`docker/vault/policies/kura-web.hcl:20`) | mTLS (app to DB and Vault) |
| `OutgoingEmail` (`kura/models.py:793`) | Private | System | 30 days (`purge_retention.py`) | Metadata and `pending_lookup` hash (`kura/migrations/0032_outgoing_email_pending_lookup.py`), host LUKS + pgBackRest | TLS 1.3 (SMTP) + mTLS |
| `QuarantinedFile` (`kura/models.py:823`) | Confidential | Admin | 7 days (`purge_retention.py`) | Isolated on separate `quarantine` DB alias (`kura/views.py:510`, `config/settings.py:203`); unencrypted raw sample retained for malware triage only | mTLS (app to DB) |
| `Schedule` (`kura/models.py:862`) | Sensitive | Dept Head | 7 years | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `ModuleAttendanceSession` (`kura/models.py:898`) | Sensitive | Instructor | 3 years | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `AttendanceRecord` (`kura/models.py:928`) | Private | Instructor | 3 years | PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`), host LUKS + pgBackRest | TLS 1.3 + mTLS |
| `Assessment` (`kura/models.py:975`) | Sensitive | Instructor | 7 years | Host LUKS + pgBackRest backups | TLS 1.3 + mTLS |
| `AssessmentFile` (`kura/models.py:1013`) | Confidential | Instructor | 7 years | Link table referencing `StoredFile` and AES-256-GCM encrypted `FileContent` | TLS 1.3 + mTLS |
| `AssessmentAttempt` (`kura/models.py:1034`) | Private | Instructor | 7 years | Immutable SHA-256 `submission_hash` trigger (`kura/migrations/0025_submission_hash_immutability_trigger.py`) + Vault Transit ECDSA-P256 `submission_signature` (`kura/signing.py:80`, `kura/migrations/0031_receipt_signatures.py`) | TLS 1.3 + mTLS |
| `AttemptFile` (`kura/models.py:1067`) | Confidential | Instructor | 7 years | Link table to encrypted `FileContent`, locked post-submission by `check_attempt_files_lock()` trigger (`kura/migrations/0030_fix_attempt_files_lock_trigger.py`) | TLS 1.3 + mTLS |
| `Grade` (`kura/models.py:1091`) | Confidential | Instructor | 7 years | PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`) + Vault Transit ECDSA-P256 `finalization_signature` and `release_signature` (`kura/signing.py:99`, `kura/migrations/0031_receipt_signatures.py`) | TLS 1.3 + mTLS |
| `GradeHistory` (`kura/models.py:1135`) | Confidential | Instructor | 7 years | Append-only audit table enforced by insert-only trigger (`kura/migrations/0016_grade_history_insert_only.py`) | TLS 1.3 + mTLS |
| `GradeChangeRequest` (`kura/models.py:1177`) | Confidential | Instructor | 7 years | PostgreSQL RLS + audit logging of request and review decisions | TLS 1.3 + mTLS |
| `CourseResult` (`kura/models.py:1228`) | Confidential | Instructor | 7 years | PostgreSQL RLS (`kura/migrations/0026_rls_and_readonly_revokes.py`), host LUKS + pgBackRest | TLS 1.3 + mTLS |
| `PasswordHistory` (`kura/models.py:1265`) | Confidential | User | Last 5 passwords | Argon2id password hashes (`config/settings.py:301`) | TLS 1.3 + mTLS |
| `SecurityPolicy` (`kura/models.py:1278`) | Sensitive | Admin | Permanent | Singleton runtime security policy table, host LUKS + pgBackRest | TLS 1.3 + mTLS |

## Secrets (from `docker-compose.yml:995-1015`, `kura.sh:21-26`, and Vault)

| Secret | Source | Classification | Owner | Rotation | At-Rest | In-Transit |
|--------|--------|---------------|-------|----------|---------|------------|
| `db_password` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:996` | Confidential | DBA | Manual | Docker secret file (mode 600, mounted at `/run/secrets/`) | mTLS (PostgreSQL) |
| `backup_encryption_key` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:998` | Confidential | DBA | Manual | Docker secret file (mode 600) | mTLS (pgBackRest) |
| `django_secret_key` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:1000` | Confidential | System | Manual | Docker secret file (mode 600, uid 10001) | Local memory only |
| `log_hmac_key` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:1002` | Confidential | System | Manual | Docker secret file (mode 600, uid 10001) | Local memory only |
| `crowdsec_bouncer_key` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:1004` | Confidential | SOC | Manual | Docker secret file (mode 600) | Localhost API (127.0.0.1:8085) |
| `grafana_admin_password` | `kura.sh:21` (`GENERATED_SECRETS`), `docker-compose.yml:1006` | Confidential | Admin | Manual | Docker secret file (mode 600) | Localhost SSH tunnel (127.0.0.1:3000) |
| `grafana_viewer_password` | `kura.sh:21` (`GENERATED_SECRETS`) | Confidential | Admin | Manual | Host secret file (mode 600, provisioned via `kura.sh`) | Localhost SSH tunnel (127.0.0.1:3000) |
| `telegram_bot_token` | `kura.sh:24` (`EXTERNAL_SECRETS`), `docker-compose.yml:1008` | Confidential | Admin | Manual | Docker secret file (mode 600) | TLS 1.3 (Telegram API) |
| `telegram_chat_id` | `kura.sh:24` (`EXTERNAL_SECRETS`), `docker-compose.yml:1010` | Sensitive | Admin | Manual | Docker secret file (mode 600) | TLS 1.3 (Telegram API) |
| `vault_role_id` | `kura.sh:24` (`EXTERNAL_SECRETS`), `docker-compose.yml:1012` | Confidential | System | `kura.sh vault-rotate-approle` (`kura.sh:719`) | Docker secret file (mode 600, uid 10001) | mTLS to Vault |
| `vault_secret_id` | `kura.sh:24` (`EXTERNAL_SECRETS`), `docker-compose.yml:1014` | Confidential | System | `kura.sh vault-rotate-approle` (`kura.sh:719`) | Docker secret file (mode 600, uid 10001) | mTLS to Vault |
| `vault_issuer_role_id` | `kura.sh:26` (`HOST_ONLY_SECRETS`) | Confidential | System | Manual / AppRole rotation | Host-only secret file (mode 600, never mounted in containers) | mTLS to Vault (host cert renewal) |
| `vault_issuer_secret_id` | `kura.sh:26` (`HOST_ONLY_SECRETS`) | Confidential | System | Manual / AppRole rotation | Host-only secret file (mode 600, never mounted in containers) | mTLS to Vault (host cert renewal) |
| `gmail-app-password` | Vault KV v2 (`docker/vault/policies/kura-web.hcl:50`) | Confidential | Admin | Manual in Vault KV v2 | Encrypted inside Vault storage (no disk secret file) | mTLS (app to Vault) + TLS 1.3 (SMTP) |
| Internal CA & service certificates | Vault PKI (`certs/internal/`) | Confidential | System | Renewed via host issuer script | Mode 600 private keys in `certs/internal/` | mTLS across all internal hops |

## Volumes (all 11 unique volumes in `docker-compose.yml:970-992`)

| Volume | Classification | Owner | Retention | At-Rest | In-Transit |
|--------|---------------|-------|-----------|---------|------------|
| `kura_pgedge_postgres_data` | Confidential | DBA | Per model retention policy | Host LUKS + pgBackRest cipher | mTLS (app and backup) |
| `kura_postgres_backups` | Confidential | DBA | 7 full + 14 diff (`docker/postgres/pgbackrest.conf:13-14`) | AES-256-CBC (`pgbackrest.conf:10`) | mTLS |
| `kura_postgres_backups_offsite` | Confidential | DBA | 7 full + 14 diff (`docker/postgres/pgbackrest.conf:21-22`) | AES-256-CBC (`pgbackrest.conf:20`) | mTLS (offsite sync) |
| `kura_vault_data` | Confidential | Vault Admin | Permanent | Vault seal encryption + host LUKS | mTLS |
| `kura_loki_data` | Private | SOC | 180 days (`docker/loki/loki.yml`) | Host LUKS | TLS 1.3 (Alloy to Loki) |
| `kura_alloy_data` | Sensitive | System | Rolling positions | Host LUKS | N/A (local state) |
| `kura_grafana_data` | Sensitive | Admin | Permanent | Host LUKS | Localhost SSH tunnel |
| `kura_prometheus_data` | Sensitive | SOC | Rolling TSDB | Host LUKS | Internal observability network |
| `kura_crowdsec_data` | Sensitive | SOC | Operational decisions | Host LUKS | Localhost LAPI |
| `kura_crowdsec_config` | Sensitive | SOC | Permanent | Host LUKS | N/A |
| `kura_clamav_db` | Sensitive | System | Refreshed daily by freshclam | Host LUKS | HTTPS (signature updates) |

## Log Streams

| Log Stream | Classification | Owner | Retention | At-Rest | In-Transit |
|------------|---------------|-------|-----------|---------|------------|
| nginx access and error logs | Sensitive | SOC | 180 days (Loki) | Loki TSDB (host LUKS) | TLS 1.3 (Alloy to Loki) |
| Gunicorn and Django app logs | Private | SOC | 180 days | Loki TSDB | TLS 1.3 |
| Security events (HMAC-chained) | Confidential | SOC | 180 days | Loki TSDB + HMAC-SHA256 chain (`kura/logging_utils.py:206`) | TLS 1.3 |
| pgAudit logs | Confidential | DBA | 180 days | Loki TSDB (`log_parameter = off` with `server_side_binding`) | TLS 1.3 |
| CrowdSec decisions | Sensitive | SOC | 180 days | Loki TSDB | TLS 1.3 |
| Vault audit log | Confidential | Vault Admin | 180 days | Loki TSDB | TLS 1.3 |
| pgBackRest logs | Sensitive | DBA | Retained with backup volume | Host LUKS | Local container storage |

## Protection Layer Mapping (per Lecture §5.6)

| Asset Category | Layer 1: Network | Layer 2: Host | Layer 3: Application | Layer 4: Data |
|----------------|------------------|---------------|----------------------|---------------|
| User PII | nftables default-drop, CrowdSec | Read-only containers, non-root (`Dockerfile:98`) | Argon2id, mandatory MFA, PostgreSQL RLS | Vault Transit `kura-mfa` on `mfa_secret`, host LUKS |
| Grades and Submissions | Internal Docker networks only | `cap_drop: ALL`, `no-new-privileges` | RBAC, separation of duties, insert-only triggers | Vault Transit ECDSA-P256 signatures, per-file AES-256-GCM on `FileContent` |
| Encryption Keys | Vault on internal `backend` network with mTLS | Vault sealed at rest; HSM recommended for production | Scoped Vault policy (`docker/vault/policies/kura-web.hcl`) | Auto-rotation `720h` (`kura.sh:495-501`), keys never exported |
| Backups | Isolated `egress` / offsite mount | Separate `kura_postgres_backups_offsite` volume | Encrypted WAL + automated `kura.sh restore-drill` | pgBackRest AES-256-CBC encryption |
| Logs | Internal `observability` network | Alloy TLS shipping, host FIM (`kura.sh:1645`) | Structured logfmt redaction (`kura/logging_utils.py:45`) | HMAC-SHA256 sequence chain + `verify_log_chain`, 180-day retention |

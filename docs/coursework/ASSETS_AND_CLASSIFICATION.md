# Asset Inventory & Data Classification

**Classification Scheme (per Lecture §1.4):**
- **Public**: Information intended for public consumption
- **Sensitive**: Internal information requiring basic protection
- **Private**: Personal data (GDPR Art. 4) requiring strong protection
- **Confidential**: Highest sensitivity (keys, secrets, grades) requiring maximum protection

## Database Models (from `kura/models.py`)

| Model | Classification | Owner | Retention | At-Rest Protection | In-Transit Protection |
|-------|---------------|-------|-----------|-------------------|----------------------|
| User | Private | Registrar | 7 years post-graduation | App-level: AES-GCM via Vault Transit (kura/views.py:567) | TLS 1.3 (nginx) + mTLS (internal) |
| UserRole | Private | Registrar | 7 years | Same as User | Same |
| Role | Sensitive | Admin | Permanent | None (reference data) | TLS 1.3 |
| Department | Sensitive | Admin | Permanent | None | TLS 1.3 |
| Course | Sensitive | Dept Head | Permanent | None | TLS 1.3 |
| CourseStaff | Private | Dept Head | 7 years | Same | Same |
| Enrollment | Private | Registrar | 7 years | Same | Same |
| Assessment | Sensitive | Instructor | 7 years | None | TLS 1.3 |
| AssessmentAttempt | Private | Instructor | 7 years | AES-GCM (kura/views.py:567) | TLS 1.3 + mTLS |
| AttemptFile | Confidential | Instructor | 7 years | AES-256-GCM per-file + Vault-wrapped RSA-4096 (kura/views.py:567) | TLS 1.3 + mTLS |
| Grade | Confidential | Instructor | 7 years | Vault Transit ECDSA signature (kura/signing.py:1) | TLS 1.3 + mTLS |
| GradeChangeRequest | Confidential | Instructor | 7 years | Same | Same |
| GradeHistory | Confidential | Instructor | 7 years | Insert-only trigger (kura/migrations/0030) | Same |
| AttendanceRecord | Private | Instructor | 3 years | None | TLS 1.3 |
| StoredFile | Confidential | Uploader | 7 years | AES-256-GCM + Vault-wrapped key (kura/views.py:567) | TLS 1.3 + mTLS |
| FileContent | Confidential | System | 7 years | Encrypted blob (kura/views.py:567) | N/A (DB internal) |
| QuarantinedFile | Confidential | Admin | 7 days | Plaintext (for analysis) + separate DB connection | TLS 1.3 |
| UserSession | Private | User | 12 hours absolute | HMAC-SHA256 binding (kura/middleware.py:125) | TLS 1.3 |
| SecurityPolicy | Sensitive | Admin | Permanent | None | TLS 1.3 |
| OutgoingEmail | Private | System | 30 days | None (metadata only) | TLS 1.3 (SMTP) |
| PasswordResetToken | Confidential | User | 24 hours | Hashed in DB | TLS 1.3 |
| PasswordHistory | Confidential | User | 5 generations | Hashed (Argon2id) | TLS 1.3 |

## Secrets (from `docker-compose.yml` `secrets:` and `kura.sh GENERATED_SECRETS`)

| Secret | Classification | Owner | Rotation | At-Rest | In-Transit |
|--------|---------------|-------|----------|---------|------------|
| django_secret_key | Confidential | System | Manual | Docker secret (mode 600, uid 10001) | mTLS to Vault |
| vault_role_id | Confidential | System | 720h via kura.sh vault-rotate-approle | Docker secret | mTLS to Vault |
| vault_secret_id | Confidential | System | 720h via rotation | Docker secret | mTLS to Vault |
| db_password | Confidential | DBA | Manual | Docker secret | mTLS (PostgreSQL) |
| backup_encryption_key | Confidential | DBA | Manual | Docker secret | mTLS (pgBackRest) |
| log_hmac_key | Confidential | System | Manual | Docker secret | N/A (host) |
| telegram_bot_token | Confidential | Admin | Manual | Docker secret | TLS 1.3 (Telegram API) |
| telegram_chat_id | Sensitive | Admin | Manual | Docker secret | TLS 1.3 |
| CA certificates | Confidential | System | 825 days | certs/internal/ (mode 600) | mTLS |
| Service certificates | Confidential | System | 825 days | certs/internal/ (mode 600) | mTLS |

## Volumes (from `docker-compose.yml` `volumes:`)

| Volume | Classification | Owner | Retention | At-Rest | In-Transit |
|--------|---------------|-------|-----------|---------|------------|
| kura_pgedge_postgres_data | Confidential | DBA | Per retention policy | LUKS (host) + pgBackRest cipher | mTLS (backup) |
| kura_postgres_backups | Confidential | DBA | 7 full + 14 diff | AES-256-CBC (pgBackRest) | mTLS |
| kura_postgres_backups_offsite | Confidential | DBA | 7 full + 14 diff | AES-256-CBC | mTLS (offsite sync) |
| kura_vault_data | Confidential | Vault Admin | Permanent | LUKS (host) | mTLS |
| kura_loki_data | Private | SOC | 180 days | LUKS (host) | TLS 1.3 (Alloy→Loki) |
| kura_clamav_db | Sensitive | System | N/A | LUKS (host) | N/A |
| kura_alloy_data | Sensitive | System | N/A | LUKS (host) | N/A |
| kura_grafana_data | Sensitive | Admin | N/A | LUKS (host) | N/A |
| kura_prometheus_data | Sensitive | SOC | N/A | LUKS (host) | N/A |
| kura_crowdsec_data | Sensitive | SOC | N/A | LUKS (host) | N/A |
| kura_crowdsec_config | Sensitive | SOC | N/A | LUKS (host) | N/A |
| kura_clamav_db | Sensitive | System | N/A | LUKS (host) | N/A |

## Log Streams

| Log Stream | Classification | Owner | Retention | At-Rest | In-Transit |
|------------|---------------|-------|-----------|---------|------------|
| nginx access/error | Sensitive | SOC | 180 days (Loki) | Loki TSDB (LUKS) | TLS 1.3 (Alloy→Loki) |
| gunicorn/app logs | Private | SOC | 180 days | Loki TSDB | TLS 1.3 |
| security events (HMAC-chained) | Confidential | SOC | 180 days | Loki TSDB | TLS 1.3 |
| pgAudit | Confidential | DBA | 180 days | Loki TSDB | TLS 1.3 |
| CrowdSec decisions | Sensitive | SOC | 180 days | Loki TSDB | TLS 1.3 |
| Vault audit | Confidential | Vault Admin | 180 days | Loki TSDB | TLS 1.3 |
| pgBackRest logs | Sensitive | DBA | 7 years | Backup volume (AES-256) | mTLS |

## Protection Layer Mapping (per Lecture §5.6)

| Asset Category | Layer 1: Network | Layer 2: Host | Layer 3: Application | Layer 4: Data |
|----------------|------------------|---------------|----------------------|---------------|
| User PII | nftables default-drop, CrowdSec | Read-only containers, non-root | Argon2id, MFA, RLS | App-level AES-GCM, Vault Transit |
| Grades/Submissions | Internal networks only | Capability drop, no-new-privs | RBAC, Separation of duties | Vault Transit ECDSA, AES-256-GCM |
| Encryption Keys | Vault internal mTLS | Vault sealed, HSM (prod) | Vault Transit API | Auto-rotation 720h, never exported |
| Backups | Offsite repo isolated | pgBackRest cipher | Encrypted WAL | AES-256-CBC, separate volume |
| Logs | Loki internal network | Alloy TLS, FIM host | HMAC-SHA256 chain | 180-day retention, verify_log_chain |

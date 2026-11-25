# Cryptographic Non-Repudiation for Submissions and Grades (G05)

## Problem Statement

Before G05, submitted attempts in Kura recorded only a SHA-256 integrity hash (`AssessmentAttempt.submission_hash`) stored inside PostgreSQL alongside the submission timestamp and file metadata (`kura/views.py:4855`). A hash verifies accidental corruption, yet it shares a trust boundary with the database itself. A malicious database administrator or an attacker who gains PostgreSQL write privileges and temporarily disables the immutability trigger can alter a student submission row or grade score, recompute the matching SHA-256 digest, and erase evidence of tampering. Likewise, an external examiner or student cannot verify an emailed receipt without trusting Kura's database state.

## Architecture and Design

Kura adds asymmetric digital signatures managed by HashiCorp Vault's Transit secrets engine (`kura/signing.py`):

1. **Isolated ECDSA Signing Key (`kura-receipts`):** `kura.sh` (`cmd_vault_init` and `cmd_vault_add_receipts_key`) creates a non-exportable `ecdsa-p256` Transit key (`auto_rotate_period=720h`). The private key never leaves Vault memory.
2. **Least-Privilege Vault Policy (`docker/vault/policies/kura-web.hcl`):** The `kura-web` role is restricted to `transit/sign/kura-receipts` (`update`), `transit/verify/kura-receipts` (`update`), and `transit/keys/kura-receipts` (`read` for the public verification key).
3. **Canonical Deterministic Payloads (`kura/signing.py`):** Submissions and grade transitions serialize into sorted compact JSON (`{"v":1,"kind":...}`) with timestamps normalized to UTC ISO-8601 and decimal scores formatted to two decimal places before signing with SHA-256 (`hash_algorithm="sha2-256"`).
4. **Fail-Closed Sealing (`kura/views.py`, `kura/management/commands/finalize_attempts.py`):**
   - `assessment_submit_view` and `finalize_attempts` compute `submission_signature` inside the same database transaction that sets `submission_hash`.
   - `grade_finalize_view`, `grade_release_view`, and `grade_change_request_review_view` record `finalization_signature` and `release_signature` binding the score, status, and authorizing instructor or department head UUID.
   - Database migration `0031_receipt_signatures.py` updates the `protect_submission_hash()` PostgreSQL trigger so `submission_signature` becomes immutable once recorded.
5. **Development Domain Separation:** When `VAULT_ENABLED=False` (automated test suites), `kura/signing.py` signs with an ephemeral per-process Ed25519 key and prefixes signatures with `dev:v1:`. Whenever `VAULT_ENABLED=True`, `verify_payload()` rejects `dev:` signatures unconditionally.
6. **Public Verification and Automated Auditing:**
   - `GET /.well-known/kura-receipts.pem` (`kura/urls.py`) serves the public verification key anonymously with `Cache-Control: public, max-age=3600` (`kura/middleware.py`).
   - `attempt_detail_view` and `attempt_detail.html` display `Signature: valid (key version N)` or `Signature: INVALID`.
   - `python manage.py verify_signatures` runs nightly via `docker/cron/kura.crontab`, logs `integrity.signature_failed` at `ERROR` on any discrepancy (triggering the `SignatureVerificationFailed` Loki alert in `docker/loki/rules/fake/kura-alerts.yml`), and exits non-zero.

## Offline Verification Procedure with OpenSSL

Vault Transit returns signatures formatted as `vault:v<N>:<base64-asn1-der>`. A student or external examiner can verify a receipt payload without querying Kura's database:

1. Download the public verification key:
   ```bash
   curl -fsS https://your-kura-host/.well-known/kura-receipts.pem -o kura-receipts.pem
   ```
2. Strip the `vault:v<N>:` prefix from the signature shown on the receipt or attempt detail page and base64-decode the ASN.1 DER signature bytes:
   ```bash
   printf '%s' '<base64_after_colon>' | base64 -d > sig.der
   ```
3. Verify the exact canonical JSON byte string (`payload.json`, no trailing newline) with OpenSSL:
   ```bash
   openssl dgst -sha256 -verify kura-receipts.pem -signature sig.der payload.json
   ```
   A valid receipt prints `Verified OK`. Raw command output for a sample verification is archived in `docs/evidence/2026-12/G05-openssl-verify.txt`.

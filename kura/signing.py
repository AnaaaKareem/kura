"""Cryptographic signing and verification for submission receipts and grade decisions.

Provides non-repudiation (G05) using Vault Transit ECDSA P-256 keys in production so the
private signing key never leaves Vault, and an in-process Ed25519 key for local testing when
VAULT_ENABLED is False. Development signatures carry a ``dev:`` prefix that production
verification rejects unconditionally.
"""

import base64
import datetime
import json
import logging
import re
import threading
import time
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from django.core.exceptions import ValidationError

from kura.base import get_vault_client
from kura.logging_utils import log_security_event

_DEV_KEY_LOCK = threading.Lock()
_DEV_PRIVATE_KEY = None

_PUBLIC_KEY_CACHE_LOCK = threading.Lock()
_PUBLIC_KEY_CACHE = {"key": None, "pem": "", "expires_at": 0.0}
_PUBLIC_KEY_TTL_SECONDS = 3600

_VERSION_RE = re.compile(r"^(?:vault|dev):v(\d+):")


def _get_dev_private_key():
    """Return the process-wide Ed25519 development keypair used when Vault is disabled.

    Who can use it: Internal helpers in kura.signing during local dev/test runs.
    Security: Never invoked when VAULT_ENABLED is True; dev signatures carry a 'dev:'
    prefix that verify_payload rejects whenever Vault is enabled.
    """
    global _DEV_PRIVATE_KEY
    with _DEV_KEY_LOCK:
        if _DEV_PRIVATE_KEY is None:
            _DEV_PRIVATE_KEY = Ed25519PrivateKey.generate()
        return _DEV_PRIVATE_KEY


def _normalize_timestamp(value):
    """Format a datetime consistently in UTC ISO-8601 form for deterministic signing."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc)
    return value.isoformat()


def _normalize_score(value):
    """Format a score decimal to two decimal places for deterministic signing."""
    if value is None:
        return ""
    return f"{Decimal(str(value)):.2f}"


def canonical_payload(kind, fields):
    """Serialize a signed record payload into deterministic canonical UTF-8 JSON bytes.

    Who can use it: Submission and grading workflows and verification commands.
    Security: Uses sorted keys and minimal JSON separators so identical field values
    always hash and verify identically across database reloads and offline OpenSSL checks.
    """
    document = {"v": 1, "kind": kind, **fields}
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_submission_payload(attempt):
    """Build the canonical payload signed when sealing an assessment attempt.

    Who can use it: assessment_submit_view, finalize_attempts, attempt_detail_view, verify_signatures.
    Security: Binds the attempt UUID, student UUID, assessment UUID, UTC submission timestamp,
    and SHA-256 submission hash together so altering any field breaks verification.
    """
    return canonical_payload(
        "submission",
        {
            "attempt_id": str(attempt.id),
            "student_id": str(attempt.student_id),
            "assessment_id": str(attempt.assessment_id),
            "submitted_at": _normalize_timestamp(attempt.submitted_at),
            "submission_hash": attempt.submission_hash or "",
        },
    )


def build_grade_payload(grade, *, status, actor_id, at, score=None):
    """Build the canonical payload signed for grade finalization or release decisions.

    Who can use it: grade_finalize_view, grade_release_view, grade_change_request_review_view, verify_signatures.
    Security: Binds grade identity, attempt identity, score, lifecycle status, authorizing actor,
    and UTC timestamp so instructors cannot repudiate grade decisions and DB edits fail verification.
    """
    effective_score = grade.score if score is None else score
    return canonical_payload(
        "grade",
        {
            "grade_id": str(grade.id),
            "attempt_id": str(grade.attempt_id),
            "score": _normalize_score(effective_score),
            "status": str(status),
            "actor_id": str(actor_id) if actor_id else "",
            "at": _normalize_timestamp(at),
        },
    )


def sign_payload(payload):
    """Sign canonical payload bytes using Vault Transit ECDSA or dev Ed25519 fallback.

    Who can use it: Submission and grade transition workflows inside transaction.atomic().
    Security: Fails closed when VAULT_ENABLED is True by logging vault.error and raising
    ValidationError so no un-signed receipt or grade approval can be sealed during an outage.
    """
    payload_bytes = bytes(payload)
    # Without Vault (local dev and tests) sign with the throwaway Ed25519 key.
    if not getattr(settings, "VAULT_ENABLED", False):
        sig_bytes = _get_dev_private_key().sign(payload_bytes)
        return "dev:v1:" + base64.b64encode(sig_bytes).decode("ascii")

    # Vault signs the SHA-256 digest of the payload, so the private key never reaches Django.
    try:
        client = get_vault_client()
        response = client.secrets.transit.sign_data(
            name=settings.VAULT_RECEIPTS_KEY,
            hash_input=base64.b64encode(payload_bytes).decode("ascii"),
            hash_algorithm="sha2-256",
            mount_point=settings.VAULT_TRANSIT_MOUNT,
        )
        signature = response["data"]["signature"]
        # Refuse anything that is not a Vault Transit signature before it is stored.
        if not isinstance(signature, str) or not signature.startswith("vault:v"):
            raise ValueError("Unexpected signature format returned by Vault Transit.")
        return signature
    except Exception as error:
        log_security_event(
            None,
            "vault.error",
            {"operation": "sign_payload", "error_type": type(error).__name__},
            level=logging.ERROR,
        )
        raise ValidationError("Digital receipt signing failed because Vault is unavailable.") from error


def verify_payload(payload, signature):
    """Verify a receipt or grade signature against canonical payload bytes.

    Who can use it: attempt_detail_view, verify_signatures management command, test suite.
    Security: Unconditionally rejects 'dev:' signatures when VAULT_ENABLED is True, and
    returns False on malformed signatures or Vault verification failures (fail closed).
    """
    if not signature or not isinstance(signature, str):
        return False

    payload_bytes = bytes(payload)
    vault_enabled = bool(getattr(settings, "VAULT_ENABLED", False))

    # A dev signature proves nothing in production, so it is rejected there.
    if signature.startswith("dev:"):
        if vault_enabled:
            return False
        match = re.match(r"^dev:v\d+:(.+)$", signature)
        if not match:
            return False
        try:
            sig_bytes = base64.b64decode(match.group(1).encode("ascii"), validate=True)
            _get_dev_private_key().public_key().verify(sig_bytes, payload_bytes)
            return True
        except (ValueError, InvalidSignature):
            return False

    # Any other format, or a Vault signature with Vault off, cannot be checked: treat as invalid.
    if not signature.startswith("vault:v") or not vault_enabled:
        return False

    try:
        client = get_vault_client()
        response = client.secrets.transit.verify_signed_data(
            name=settings.VAULT_RECEIPTS_KEY,
            hash_input=base64.b64encode(payload_bytes).decode("ascii"),
            signature=signature,
            hash_algorithm="sha2-256",
            mount_point=settings.VAULT_TRANSIT_MOUNT,
        )
        return bool(response.get("data", {}).get("valid"))
    except Exception as error:
        log_security_event(
            None,
            "vault.error",
            {"operation": "verify_payload", "error_type": type(error).__name__},
            level=logging.ERROR,
        )
        return False


def parse_signature_version(signature):
    """Extract the integer key version N from a 'vault:vN:...' or 'dev:vN:...' signature.

    Who can use it: attempt_detail_view and verify_signatures reporting helpers.
    Security: Parses only a bounded digit prefix via regex without decoding untrusted payloads.
    """
    if not signature or not isinstance(signature, str):
        return None
    match = _VERSION_RE.match(signature)
    if not match:
        return None
    return int(match.group(1))


def public_key_pem():
    """Return the current receipt verification public key in PEM format, cached for 1 hour.

    Who can use it: Public /.well-known/kura-receipts.pem endpoint for offline verification.
    Security: Exposes only the public verification key from Vault Transit (never private
    material); falls back to the in-process dev public key only when VAULT_ENABLED is False.
    """
    vault_enabled = bool(getattr(settings, "VAULT_ENABLED", False))
    cache_key = (vault_enabled, getattr(settings, "VAULT_RECEIPTS_KEY", "kura-receipts"))
    now = time.monotonic()

    # Serve the cached PEM while it is fresh so the public endpoint does not call Vault on every hit.
    with _PUBLIC_KEY_CACHE_LOCK:
        if _PUBLIC_KEY_CACHE["key"] == cache_key and _PUBLIC_KEY_CACHE["expires_at"] > now and _PUBLIC_KEY_CACHE["pem"]:
            return _PUBLIC_KEY_CACHE["pem"]

    if not vault_enabled:
        pem = (
            _get_dev_private_key()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
    else:
        try:
            client = get_vault_client()
            response = client.secrets.transit.read_key(
                name=settings.VAULT_RECEIPTS_KEY,
                mount_point=settings.VAULT_TRANSIT_MOUNT,
            )
            data = response.get("data", {})
            # Verification keys rotate, so publish the newest version's public key.
            latest_version = str(data.get("latest_version", "1"))
            keys = data.get("keys", {})
            key_info = keys.get(latest_version) or {}
            pem = key_info.get("public_key", "")
            if not pem:
                raise ValueError("Public key material missing from Vault Transit response.")
        except Exception as error:
            log_security_event(
                None,
                "vault.error",
                {"operation": "public_key_pem", "error_type": type(error).__name__},
                level=logging.ERROR,
            )
            raise ValidationError("Receipt verification public key is unavailable.") from error

    with _PUBLIC_KEY_CACHE_LOCK:
        _PUBLIC_KEY_CACHE["key"] = cache_key
        _PUBLIC_KEY_CACHE["pem"] = pem
        _PUBLIC_KEY_CACHE["expires_at"] = now + _PUBLIC_KEY_TTL_SECONDS
    return pem

"""
HashiCorp Vault helper functions for Kura LMS:
1. Transit engine: encrypts and decrypts MFA TOTP secret seeds (AES-256-GCM).
   A second Transit key encrypts exam answer keys the same way.
2. Database engine: temporary PostgreSQL users (15 minutes) for Django's connections.
(Internal TLS certificates are issued by certs/renew-certs-from-vault.sh, not by Django.)
"""

import base64
import json
import logging
import os
import time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ValidationError
import hvac

from .logging_utils import log_security_event


def get_vault_client():
    """
    Logs in to Vault with Kura's AppRole and returns a ready-to-use client.
    The role ID and secret ID come from Docker secrets (settings.py). Vault
    answers with a 15-minute token whose policy (docker/vault/policies/kura-web.hcl)
    only allows encrypting and decrypting with the kura-mfa and kura-answer-keys keys.
    verify=VAULT_CA_CERT makes the connection fail unless Vault's certificate was
    signed by our internal CA, so nothing else can pretend to be Vault.
    """
    client = hvac.Client(url=settings.VAULT_URL, verify=settings.VAULT_CA_CERT)

    # AppRole login. hvac stores the returned token in the client for us.
    client.auth.approle.login(
        role_id=settings.VAULT_ROLE_ID,
        secret_id=settings.VAULT_SECRET_ID,
    )
    return client


def encrypt_mfa_secret(secret_plaintext):
    """
    Encrypts an MFA TOTP seed using Vault Transit (AES-256-GCM).
    Returns ciphertext formatted like 'vault:v1:...', or plaintext when Vault is disabled.
    """
    if not secret_plaintext:
        return None

    # In local development when Vault is disabled, keep the value as-is.
    if not getattr(settings, "VAULT_ENABLED", False):
        return secret_plaintext

    try:
        client = get_vault_client()

        # Vault Transit requires plaintext data to be base64-encoded.
        encoded_plaintext = base64.b64encode(secret_plaintext.encode("utf-8")).decode("utf-8")

        # Request encryption from Vault's Transit engine.
        response = client.secrets.transit.encrypt_data(
            name=settings.VAULT_TRANSIT_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            plaintext=encoded_plaintext,
        )

        return response["data"]["ciphertext"]

    except Exception as exc:
        log_security_event(None, "vault.error", {"operation": "encrypt_mfa_secret"}, level=logging.ERROR)
        raise ValidationError("MFA secret encryption failed. The security vault is unreachable.") from exc


def decrypt_mfa_secret(ciphertext):
    """
    Decrypts an MFA TOTP ciphertext retrieved from the database back into plaintext.
    """
    if not ciphertext:
        return None

    # In local development (Vault disabled) the seed is stored as-is.
    if not getattr(settings, "VAULT_ENABLED", False):
        return ciphertext

    # With Vault on, only accept real Vault ciphertext. A plain-text seed here
    # means it was never encrypted (or someone wrote it in directly), so refuse it.
    if not ciphertext.startswith("vault:"):
        log_security_event(None, "vault.error", {"operation": "decrypt_mfa_secret_invalid_ciphertext"}, level=logging.ERROR)
        raise ValidationError("MFA secret is not encrypted.")

    try:
        client = get_vault_client()

        # Request decryption from Vault's Transit engine.
        response = client.secrets.transit.decrypt_data(
            name=settings.VAULT_TRANSIT_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            ciphertext=ciphertext,
        )

        # Decode the base64 plaintext returned by Vault.
        encoded_plaintext = response["data"]["plaintext"]
        return base64.b64decode(encoded_plaintext.encode("utf-8")).decode("utf-8")

    except Exception as exc:
        log_security_event(None, "vault.error", {"operation": "decrypt_mfa_secret"}, level=logging.ERROR)
        raise ValidationError("MFA secret decryption failed. The security vault is unreachable.") from exc


def encrypt_answer_key(answer_key_dict):
    """
    Encrypts an exam answer key with Vault Transit (key "kura-answer-keys",
    AES-256-GCM) before it is saved in ExamAnswerKey.answer_key_json.
    Returns {"ciphertext": "vault:v1:..."}, which still fits the JSON field,
    so the model does not change. Anyone reading the table directly (a database
    dump, a backup, the read-only role or an SQL injection) sees only ciphertext.
    With Vault disabled (local development and tests) the dictionary is kept as-is.
    Raises ValidationError if Vault cannot be reached.
    """
    # In local development when Vault is disabled, keep the value as-is.
    if not getattr(settings, "VAULT_ENABLED", False):
        return answer_key_dict

    try:
        client = get_vault_client()

        # Turn the dictionary into JSON text, then base64 (Vault Transit needs base64).
        answer_key_text = json.dumps(answer_key_dict, sort_keys=True)
        encoded_plaintext = base64.b64encode(answer_key_text.encode("utf-8")).decode("utf-8")

        # Ask Vault to encrypt it. Vault never gives the key itself to Django.
        response = client.secrets.transit.encrypt_data(
            name=settings.VAULT_ANSWER_KEYS_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            plaintext=encoded_plaintext,
        )
        return {"ciphertext": response["data"]["ciphertext"]}

    except Exception as exc:
        # Only the operation is logged, never the answer key.
        log_security_event(None, "vault.error", {"operation": "encrypt_answer_key"}, level=logging.ERROR)
        raise ValidationError("Answer key encryption failed. The security vault is unreachable.") from exc


def decrypt_answer_key(stored_json):
    """
    Turns the value saved in ExamAnswerKey.answer_key_json back into the answer
    key dictionary, in memory only (it is never saved decrypted).
    With Vault disabled (local development and tests) the value is returned as-is.
    With Vault on, only real Vault ciphertext is accepted: a plain answer key
    means it was never encrypted, so it is refused (run encrypt_answer_keys).
    Raises ValidationError if the value is not encrypted or Vault cannot be reached.
    """
    # In local development (Vault disabled) the answer key is stored as-is.
    if not getattr(settings, "VAULT_ENABLED", False):
        return stored_json

    # With Vault on, refuse anything that is not Vault ciphertext.
    ciphertext = stored_json.get("ciphertext", "")
    if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
        log_security_event(None, "vault.error", {"operation": "decrypt_answer_key_not_encrypted"}, level=logging.ERROR)
        raise ValidationError("Answer key is not encrypted.")

    try:
        client = get_vault_client()

        # Ask Vault to decrypt it, then turn the base64 JSON text back into a dictionary.
        response = client.secrets.transit.decrypt_data(
            name=settings.VAULT_ANSWER_KEYS_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            ciphertext=ciphertext,
        )
        answer_key_text = base64.b64decode(response["data"]["plaintext"].encode("utf-8")).decode("utf-8")
        return json.loads(answer_key_text)

    except Exception as exc:
        log_security_event(None, "vault.error", {"operation": "decrypt_answer_key"}, level=logging.ERROR)
        raise ValidationError("Answer key decryption failed. The security vault is unreachable.") from exc


def encrypt_file_content(content_bytes, stored_file_id):
    """
    Encrypts uploaded file bytes using hybrid encryption:
    - Generates a fresh 256-bit AES-GCM data key and 96-bit nonce per file.
    - Encrypts content_bytes with StoredFile.id as associated data so ciphertexts cannot be swapped.
    - Wraps the data key through Vault Transit (RSA-4096 / RSA-OAEP, key 'kura-files').
    When VAULT_ENABLED is False, falls back to unencrypted storage (encryption_version=0).
    """
    raw_bytes = bytes(content_bytes)
    if not getattr(settings, "VAULT_ENABLED", False):
        return {
            "content": raw_bytes,
            "wrapped_key": "",
            "nonce": b"",
            "encryption_version": 0,
        }

    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = str(stored_file_id).encode("utf-8")
    ciphertext = AESGCM(data_key).encrypt(nonce, raw_bytes, aad)

    try:
        client = get_vault_client()
        encoded_data_key = base64.b64encode(data_key).decode("utf-8")
        response = client.secrets.transit.encrypt_data(
            name=settings.VAULT_FILES_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            plaintext=encoded_data_key,
        )
        wrapped_key = response["data"]["ciphertext"]
    except Exception as exc:
        log_security_event(None, "vault.error", {"operation": "encrypt_file_content"}, level=logging.ERROR)
        raise ValidationError("File encryption failed. The security vault is unreachable.") from exc

    return {
        "content": ciphertext,
        "wrapped_key": wrapped_key,
        "nonce": nonce,
        "encryption_version": 1,
    }


def decrypt_file_content(file_content):
    """
    Decrypts a FileContent row in memory after unwrapping its AES-256-GCM data key via Vault.
    Logs file.decrypt_failed (never keys, nonces, or plaintext) and raises ValidationError on failure.
    """
    version = file_content.encryption_version
    vault_enabled = getattr(settings, "VAULT_ENABLED", False)

    if not vault_enabled:
        if version == 0:
            return bytes(file_content.content)
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "vault_disabled"},
            level=logging.ERROR,
        )
        raise ValidationError("Encrypted files cannot be read while Vault is disabled.")

    if version == 0:
        if getattr(settings, "ALLOW_LEGACY_UNENCRYPTED_FILE_READS", False):
            return bytes(file_content.content)
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "unencrypted_legacy_file"},
            level=logging.ERROR,
        )
        raise ValidationError("File decryption failed.")

    if version != 1:
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "unsupported_version"},
            level=logging.ERROR,
        )
        raise ValidationError("File decryption failed.")

    wrapped_key = file_content.wrapped_key or ""
    nonce = bytes(file_content.nonce)
    if not wrapped_key.startswith("vault:") or len(nonce) != 12:
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "invalid_envelope"},
            level=logging.ERROR,
        )
        raise ValidationError("File decryption failed.")

    try:
        client = get_vault_client()
        response = client.secrets.transit.decrypt_data(
            name=settings.VAULT_FILES_KEY,
            mount_point=settings.VAULT_TRANSIT_MOUNT,
            ciphertext=wrapped_key,
        )
        data_key = base64.b64decode(response["data"]["plaintext"].encode("utf-8"))
    except Exception as exc:
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "vault_unwrap_failed"},
            level=logging.ERROR,
        )
        raise ValidationError("File decryption failed.") from exc

    try:
        aad = str(file_content.file_id).encode("utf-8")
        return AESGCM(data_key).decrypt(nonce, bytes(file_content.content), aad)
    except (InvalidTag, ValueError, TypeError) as exc:
        log_security_event(
            None,
            "file.decrypt_failed",
            {"file_id": file_content.file_id, "reason": "gcm_auth_failed"},
            level=logging.ERROR,
        )
        raise ValidationError("File decryption failed.") from exc


# The current temporary database login for this worker process. Every new
# database connection made by this process reuses it until it is nearly expired.
# (Gunicorn runs each worker as a separate process with one thread, so each
# worker has its own copy and nothing else changes it at the same time.)
database_login_cache = {"username": "", "password": "", "refresh_after": 0}


def get_dynamic_database_credentials():
    """
    Returns a temporary PostgreSQL username and password from Vault.
    Vault creates a new database user (role "kura-app") that is a member of
    kura_app and is dropped after 15 minutes. We keep it in database_login_cache
    and only ask Vault for a new one when less than 5 minutes are left, so not
    every web request creates a new database user.
    Raises ValidationError if Vault cannot be reached or is sealed.
    """
    # Reuse the cached login while it still has more than 5 minutes left.
    if time.time() < database_login_cache["refresh_after"]:
        return database_login_cache

    # Ask Vault for a new temporary user. Only the error is logged, never the password.
    try:
        client = get_vault_client()
        response = client.secrets.database.generate_credentials(
            name=settings.VAULT_DB_ROLE,
            mount_point=settings.VAULT_DB_MOUNT,
        )
    except Exception as exc:
        log_security_event(None, "vault.error", {"operation": "get_dynamic_database_credentials"}, level=logging.ERROR)
        raise ValidationError("Could not get a database login from Vault.") from exc

    # Remember the new login, and plan to replace it 5 minutes (300 seconds)
    # before Vault drops the user, so no connection starts with an expired login.
    database_login_cache["username"] = response["data"]["username"]
    database_login_cache["password"] = response["data"]["password"]
    database_login_cache["refresh_after"] = time.time() + response["lease_duration"] - 300
    return database_login_cache

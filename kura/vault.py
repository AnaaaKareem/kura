"""
HashiCorp Vault helper functions for Kura LMS:
1. Transit engine: encrypts and decrypts MFA TOTP secret seeds (AES-256-GCM).
2. Database engine: temporary PostgreSQL users (15 minutes) for Django's connections.
(Internal TLS certificates are issued by certs/renew-certs-from-vault.sh, not by Django.)
"""

import base64
import logging
import time
from django.conf import settings
from django.core.exceptions import ValidationError
import hvac

logger = logging.getLogger(__name__)


def get_vault_client():
    """
    Logs in to Vault with Kura's AppRole and returns a ready-to-use client.
    The role ID and secret ID come from Docker secrets (settings.py). Vault
    answers with a 15-minute token whose policy (docker/vault/policies/kura-web.hcl)
    only allows encrypting and decrypting with the kura-mfa key.
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
        logger.error('event=vault.error operation="encrypt_mfa_secret"')
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
        logger.error('event=vault.error operation="decrypt_mfa_secret_invalid_ciphertext"')
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
        logger.error('event=vault.error operation="decrypt_mfa_secret"')
        raise ValidationError("MFA secret decryption failed. The security vault is unreachable.") from exc


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
        logger.error('event=vault.error operation="get_dynamic_database_credentials"')
        raise ValidationError("Could not get a database login from Vault.") from exc

    # Remember the new login, and plan to replace it 5 minutes (300 seconds)
    # before Vault drops the user, so no connection starts with an expired login.
    database_login_cache["username"] = response["data"]["username"]
    database_login_cache["password"] = response["data"]["password"]
    database_login_cache["refresh_after"] = time.time() + response["lease_duration"] - 300
    return database_login_cache

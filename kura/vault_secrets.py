"""
Vault-backed secret retrieval for Kura.

Reads sensitive values (Gmail app password) from HashiCorp Vault KV v2
instead of Docker secret files, so no secret file needs to exist on disk.
Secrets live in memory only.

Authenticates with the kura-web AppRole (role_id / secret_id still read
from Docker secret files -- those bootstrap credentials cannot themselves
live in Vault without a chicken-and-egg problem).
"""

import logging

import hvac
from django.conf import settings

logger = logging.getLogger("kura.security")

# KV v2 paths for secrets that used to live in Docker secret files.
GMAIL_APP_PASSWORD_PATH = "gmail-app-password"
MIGRATOR_KEY_PATH = "migrator-key"

_client_cache = {"client": None}


def _vault_client():
    """Authenticate to Vault with the kura-web AppRole and return a client."""
    if _client_cache["client"] is not None:
        return _client_cache["client"]
    client = hvac.Client(
        url=settings.VAULT_URL,
        verify=settings.VAULT_CA_CERT,
    )
    client.auth.approle.login(
        role_id=settings.VAULT_ROLE_ID,
        secret_id=settings.VAULT_SECRET_ID,
    )
    _client_cache["client"] = client
    return client


def get_secret(path):
    """
    Read a secret string from Vault KV v2 at ``secret/data/<path>``.

    Returns the value of the ``value`` key in the secret data, or None if
    the path does not exist. Raises on Vault communication errors so
    callers can fail closed.
    """
    client = _vault_client()
    response = client.secrets.kv.v2.read_secret_version(path=path)
    data = response.get("data", {}).get("data", {})
    return data.get("value")


def get_gmail_app_password():
    """
    Return the Gmail app password from Vault, or empty string if unavailable.

    Empty string means Django settings still load (important for collectstatic
    builds where Vault may not be running); SMTP authentication will fail at
    send time and mail stays queued, which is acceptable.
    """
    try:
        value = get_secret(GMAIL_APP_PASSWORD_PATH)
        if value:
            return value
    except Exception as error:  # Vault unreachable, auth failure, missing path
        # Log only the exception class name, never the path payload or credential value.
        logger.warning("Vault unavailable for gmail app password: %s", type(error).__name__)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
    return ""


def get_migrator_key():
    """
    Return the migration private key from Vault, or empty string if unavailable.

    Does not gate on VAULT_ENABLED: the entrypoint calls this with
    VAULT_ENABLED=False (migrations don't use Vault database credentials)
    but still needs the migrator key from Vault KV.
    """
    try:
        value = get_secret(MIGRATOR_KEY_PATH)
        if value:
            return value
    except Exception as error:
        logger.warning("Vault unavailable for migrator key: %s", type(error).__name__)
    return ""

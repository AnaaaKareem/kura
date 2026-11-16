"""
Kura's PostgreSQL database backend.

Django opens connections with a temporary login from Vault, cached per worker.
Vault drops each temporary user after 15 minutes, limiting how long a stolen
password works. The kura_app role cannot log in directly.

Turned on in config/settings.py when VAULT_DATABASE_CREDENTIALS=True (Docker only).
"""

import logging
import time

import hvac
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.backends.postgresql import base
from django.db.utils import OperationalError

from kura.logging_utils import log_security_event


def get_vault_client():
    """Authenticate to Vault using the application's AppRole and internal CA."""
    client = hvac.Client(url=settings.VAULT_URL, verify=settings.VAULT_CA_CERT)
    client.auth.approle.login(role_id=settings.VAULT_ROLE_ID, secret_id=settings.VAULT_SECRET_ID)
    return client


# Reuse the temporary login until five minutes before it expires.
database_login_cache = {"username": "", "password": "", "refresh_after": 0}


def get_dynamic_database_credentials():
    """Get and cache Vault's short-lived PostgreSQL login for this worker."""
    if time.time() < database_login_cache["refresh_after"]:
        return database_login_cache

    # Do not log the credentials when Vault cannot issue a login.
    try:
        client = get_vault_client()
        response = client.secrets.database.generate_credentials(
            name=settings.VAULT_DB_ROLE,
            mount_point=settings.VAULT_DB_MOUNT,
        )
    except Exception as error:
        log_security_event(None, "vault.error", {"operation": "get_dynamic_database_credentials"}, level=logging.ERROR)
        raise ValidationError("Could not get a database login from Vault.") from error

    database_login_cache["username"] = response["data"]["username"]
    database_login_cache["password"] = response["data"]["password"]
    database_login_cache["refresh_after"] = time.time() + response["lease_duration"] - 300
    return database_login_cache


class DatabaseWrapper(base.DatabaseWrapper):
    """
    Django's PostgreSQL backend with a Vault-issued login.

    Django requires the name DatabaseWrapper in base.py; only connection
    parameters are overridden.
    """

    def get_connection_params(self):
        """Keep Django's database and TLS settings, but use a temporary Vault login."""
        connection_params = super().get_connection_params()

        # Get the temporary login from Vault (reused until it is nearly expired).
        # Report Vault failures as database connection errors so Django shows its generic error page.
        try:
            database_login = get_dynamic_database_credentials()
        except ValidationError as error:
            raise OperationalError("Could not get a database login from Vault.") from error

        # Log in with the temporary username and password.
        connection_params["user"] = database_login["username"]
        connection_params["password"] = database_login["password"]
        return connection_params

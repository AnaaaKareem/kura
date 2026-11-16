"""
Kura's PostgreSQL database backend.

It is Django's normal PostgreSQL backend with ONE change: before each new
database connection, it asks Vault for a temporary username and
password, instead of using a fixed account from settings. Vault drops each
temporary user after 15 minutes, so a stolen database password stops working
quickly, and nobody can log in as kura_app directly.

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
    Django's PostgreSQL DatabaseWrapper, with the login taken from Vault.
    Django requires a database backend to be a class named DatabaseWrapper in a
    file named base.py, which is why this is a class (it only changes one method).
    """

    def get_connection_params(self):
        # Start from Django's normal connection settings: host, port, database
        # name and the TLS options (CA certificate, Django's client certificate).
        connection_params = super().get_connection_params()

        # Get the temporary login from Vault (reused until it is nearly expired).
        # If Vault is down or sealed, report it as a database connection error,
        # so Django shows its normal generic error page and never the details.
        try:
            database_login = get_dynamic_database_credentials()
        except ValidationError as error:
            raise OperationalError("Could not get a database login from Vault.") from error

        # Log in with the temporary username and password.
        connection_params["user"] = database_login["username"]
        connection_params["password"] = database_login["password"]
        return connection_params

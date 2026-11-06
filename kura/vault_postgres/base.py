"""
Kura's PostgreSQL database backend.

It is Django's normal PostgreSQL backend with ONE change: before each new
database connection, it asks Vault (kura/vault.py) for a temporary username and
password, instead of using a fixed account from settings. Vault drops each
temporary user after 15 minutes, so a stolen database password stops working
quickly, and nobody can log in as kura_app directly.

Turned on in config/settings.py when VAULT_DATABASE_CREDENTIALS=True (Docker only).
"""

from django.core.exceptions import ValidationError
from django.db.backends.postgresql import base
from django.db.utils import OperationalError

from kura.vault import get_dynamic_database_credentials


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

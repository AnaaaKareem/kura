"""Django app configuration for Kura."""
from django.apps import AppConfig


class KuraConfig(AppConfig):
    name = "kura"

    def ready(self):
        """Initialize the per-worker HMAC-SHA256 log chain when Django boots."""
        from .logging_utils import ensure_log_chain_started

        ensure_log_chain_started()

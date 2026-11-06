import hashlib
import logging
import urllib.error
import urllib.request
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class BreachedPasswordValidator:
    """
    Validates passwords against HaveIBeenPwned using k-anonymity.
    Only the first five characters of the SHA-1 hash leave the server,
    which keeps the original password completely private.
    """

    # Public k-anonymity API endpoint for breached password hashes
    API_URL = "https://api.pwnedpasswords.com/range/"
    # Request timeout in seconds
    TIMEOUT = 2.5

    def validate(self, password, user=None):
        """
        Checks whether a password appears in the public HaveIBeenPwned database.
        Raises ValidationError if the password is found in a breach.
        """
        # Send only a short hash prefix so the plaintext password stays on this server.
        # SHA-1 is required here because HaveIBeenPwned's range API is indexed by
        # SHA-1. It is only a lookup key (never used to store or sign anything),
        # so usedforsecurity=False says exactly that.
        sha1_hash = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        request_url = f"{self.API_URL}{prefix}"
        req = urllib.request.Request(request_url, headers={"User-Agent": "Kura-LMS-BreachedPasswordValidator"})

        try:
            # The breach service returns matching suffixes for this prefix.
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as response:
                content = response.read().decode("utf-8")
                for line in content.splitlines():
                    entry_hash = line.split(":", 1)[0].strip()
                    if entry_hash == suffix:
                        raise ValidationError(
                            "This password has appeared in a known data breach. Choose a different, unique password.",
                            code="password_breached",
                        )
        except urllib.error.URLError as error:
            # Network failures log a warning rather than blocking valid password updates
            # Only the network error is logged, never the password or its hash.
            logger.warning("Breached password lookup timed out or failed: %s", error)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure

    def get_help_text(self):
        """
        Returns the password rule message shown in forms and help text.
        """
        return "Your password must not appear in any known public data breaches."

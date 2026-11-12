import hashlib
import logging
import ssl
import urllib.request
from django.conf import settings
from django.core.exceptions import ValidationError

from .logging_utils import log_security_event


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
            # Check HaveIBeenPwned's certificate against the public certificate
            # authorities (in Docker, the default store is Kura's internal CA only).
            if settings.BREACH_CHECK_CA_FILE:
                tls_context = ssl.create_default_context(cafile=settings.BREACH_CHECK_CA_FILE)
            else:
                tls_context = ssl.create_default_context()

            # In Docker, go through the breach-proxy container (the only way out);
            # otherwise connect directly. TLS still runs end to end, so the proxy
            # cannot see the hash prefix or the answer.
            handlers = [urllib.request.HTTPSHandler(context=tls_context)]
            if settings.BREACH_CHECK_PROXY_URL:
                handlers.append(urllib.request.ProxyHandler({"https": settings.BREACH_CHECK_PROXY_URL}))
            else:
                handlers.append(urllib.request.ProxyHandler({}))
            opener = urllib.request.build_opener(*handlers)

            # The breach service returns matching suffixes for this prefix.
            with opener.open(req, timeout=self.TIMEOUT) as response:
                content = response.read().decode("utf-8")
                for line in content.splitlines():
                    entry_hash = line.split(":", 1)[0].strip()
                    if entry_hash == suffix:
                        raise ValidationError(
                            "This password has appeared in a known data breach. Choose a different, unique password.",
                            code="password_breached",
                        )
        except OSError as error:
            # Network failures (no route, proxy down, timeout, certificate
            # problem) log a warning rather than blocking valid password
            # updates. The Loki alert BreachCheckUnavailable fires on this
            # event, so a check that keeps failing is noticed.
            # Only the kind of error is logged, never the password or its hash.
            log_security_event(None, "auth.breach_check.unavailable", {"error_type": type(error).__name__}, level=logging.WARNING)  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure

    def get_help_text(self):
        """
        Returns the password rule message shown in forms and help text.
        """
        return "Your password must not appear in any known public data breaches."

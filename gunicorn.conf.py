"""
Gunicorn configuration for Kura LMS.

Supports Mutual TLS (mTLS) for Hop 1: Nginx -> Django.
When MTLS_ENABLED=True:
- Listens on port 8443 with TLS 1.3 / 1.2.
- Enforces mutual client certificate verification (ssl.CERT_REQUIRED).
- Only clients presenting certificates signed by ca.crt (such as Nginx) are accepted.
When MTLS_ENABLED=False (default in development and testing):
- Listens on port 8000 with standard HTTP.
"""

import os
import ssl

mtls_enabled = os.environ.get("MTLS_ENABLED", "False").lower() in ("true", "1")

# Network socket binding: 8443 for HTTPS/mTLS, 8000 for plaintext HTTP
if mtls_enabled:
    bind = "0.0.0.0:8443"
else:
    bind = "0.0.0.0:8000"
workers = int(os.environ.get("GUNICORN_WORKERS", "3"))
# Nginx and the WAF log requests after redacting password-reset tokens. Gunicorn
# cannot safely redact paths, so only its errors are sent to the container log.
accesslog = None
errorlog = "-"
timeout = 60

# Mutual TLS (mTLS) settings
if mtls_enabled:
    certfile = os.environ.get("GUNICORN_CERTFILE", "/certs/internal/web.crt")
    keyfile = os.environ.get("GUNICORN_KEYFILE", "/certs/internal/web.key")
    ca_certs = os.environ.get("GUNICORN_CA_CERTS", "/certs/internal/ca.crt")
    # Require client certificate verification (ssl.CERT_REQUIRED)
    cert_reqs = ssl.CERT_REQUIRED
    ssl_version = ssl.PROTOCOL_TLS_SERVER

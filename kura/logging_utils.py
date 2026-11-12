"""Shared security logging helpers.

Every security event in Kura is written to the "kura.security" logger so the
lines have the same fields and escaping. These helpers live outside views.py
because kura.views imports kura.files and kura.vault, so those modules cannot
import the helpers from views without a circular import (LOG-04).
"""

import ipaddress
import json
import logging
import re

from django.conf import settings

security_logger = logging.getLogger("kura.security")


def get_client_ip(request):
    """
    Returns the IP address of the real visitor.
    Used by: session records, rate limits, attendance, assessment lab checks,
    the rate-limit middleware, and django-axes (AXES_CLIENT_IP_CALLABLE).
    Security: the X-Real-IP header is only trusted when TRUST_PROXY_IP_HEADER is
    on (only the WAF can reach Gunicorn then). The value must be a valid IP
    address, otherwise we fall back to REMOTE_ADDR, so a forged or garbage
    header can never be stored or used.
    """
    # The address of whatever connected to Django (the WAF in production).
    remote_addr = request.META.get("REMOTE_ADDR") or "127.0.0.1"

    # Without a trusted proxy in front, the header could be faked: ignore it.
    if not settings.TRUST_PROXY_IP_HEADER:
        return remote_addr

    # Use the visitor's address sent by the WAF, if it is a real IP address.
    header_value = request.META.get("HTTP_X_REAL_IP", "").strip()
    try:
        return str(ipaddress.ip_address(header_value))
    except ValueError:
        return remote_addr


def log_security_event(request, event, details, level=logging.INFO):
    """Write one escaped, searchable security event without logging secrets.

    The actor is named actor_user_id so event details can separately identify
    the affected user without creating duplicate logfmt keys. Pass request=None
    from code that has no request, such as management commands.
    """
    # The proxy creates lowercase hexadecimal IDs; reject anything else before logging it.
    request_id = "-"
    if request is not None:
        received_request_id = request.META.get("HTTP_X_REQUEST_ID", "")
        if re.fullmatch(r"[0-9a-f]{32}", received_request_id):
            request_id = received_request_id

    # Password-reset URLs contain bearer tokens, so replace the token before writing the path.
    path = "-"
    if request is not None:
        path = re.sub(r"^/password/reset/[^/]+/", "/password/reset/<redacted>/", request.path)

    # Record the request context while distinguishing the actor from event subjects.
    parts = ["event=" + json.dumps(str(event))]
    if request is not None:
        actor_user_id = "anonymous"
        if hasattr(request, "user") and request.user.is_authenticated:
            actor_user_id = str(request.user.id)
        parts.extend(
            [
                "ip=" + json.dumps(get_client_ip(request)),
                "actor_user_id=" + json.dumps(actor_user_id),
                "request_id=" + json.dumps(request_id),
                "path=" + json.dumps(path),
                "method=" + json.dumps(request.method),
            ]
        )

    # Sort fields and encode after limiting their size, keeping every value valid JSON.
    for key in sorted(details):
        value = json.dumps(str(details[key])[:500])
        parts.append(str(key) + "=" + value)

    # Join first so untrusted values are never used as a logging format string.
    line = " ".join(parts)
    security_logger.log(level, line)


def log_invalid_form(request, form):
    """Record a rejected form without writing any submitted value.

    Who calls it: views that validate a security-relevant admin or auth form.
    Security: logs only the form class name and the names of the invalid fields,
    so a typed password, email or free-text value never reaches the log (LOG-03).
    """
    log_security_event(
        request,
        "input.invalid",
        {"form": form.__class__.__name__, "fields": sorted(form.errors.keys())},
        logging.WARNING,
    )

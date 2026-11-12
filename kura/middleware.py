import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.crypto import constant_time_compare
from django.utils import timezone
from .models import UserSession
from .views import get_client_ip, log_security_event

User = get_user_model()


class SessionValidationMiddleware:
    """
    Checks active sessions on each request. Ends the session if the account
    has been locked, deactivated, or revoked by an administrator.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Look up the account even if Django already treated a deactivated user as anonymous.
        account_user = None
        if request.user.is_authenticated:
            account_user = request.user
        else:
            session_user_id = request.session.get("_auth_user_id")
            session_auth_hash = request.session.get("_auth_user_hash")
            if session_user_id and session_auth_hash:
                possible_user = User.objects.filter(pk=session_user_id).first()
                if possible_user and constant_time_compare(
                    possible_user.get_session_auth_hash(),
                    session_auth_hash,
                ):
                    account_user = possible_user

        # Log out deactivated accounts immediately.
        if account_user and not account_user.is_active:
            if not request.user.is_authenticated:
                request.user = account_user
            log_security_event(request, "session.invalid", {"reason": "deactivated"}, level=logging.WARNING)
            logout(request)
            messages.error(request, "This account has been deactivated. Contact the administrator.")
            return redirect("kura:login")

        # Log out locked accounts and display the unlock timestamp.
        if account_user and account_user.locked_until and account_user.locked_until > timezone.now():
            lock_time = timezone.localtime(account_user.locked_until).strftime("%d %b, %H:%M")
            if not request.user.is_authenticated:
                request.user = account_user
            log_security_event(request, "session.invalid", {"reason": "locked"}, level=logging.WARNING)
            logout(request)
            messages.error(request, f"This account is currently locked until {lock_time}.")
            return redirect("kura:login")

        # Check whether the tracked session record has been revoked or expired.
        if request.user.is_authenticated:
            session_id = request.session.get("user_session_id")
            if session_id:
                try:
                    user_session = UserSession.objects.filter(
                        id=session_id,
                        user=request.user,
                    ).first()

                    if not user_session or user_session.revoked_at is not None:
                        reason = "revoked"
                    elif user_session.expires_at <= timezone.now():
                        reason = "expired"
                    else:
                        reason = None

                    # End revoked or expired sessions and ask the user to log in again.
                    if reason:
                        log_security_event(request, "session.invalid", {"reason": reason}, level=logging.WARNING)
                        logout(request)
                        messages.error(request, "Your session was ended. Please sign in again.")
                        return redirect("kura:login")
                except (ValueError, TypeError):
                    log_security_event(request, "session.invalid", {"reason": "revoked"}, level=logging.WARNING)
                    logout(request)
                    messages.error(request, "Your session was ended. Please sign in again.")
                    return redirect("kura:login")

        return self.get_response(request)


def add_no_store_headers(response):
    """
    Marks an authenticated response as sensitive so browsers and proxies do not cache it.
    Used for every response path in SecurityEnforcementMiddleware, including redirects.
    """
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response["Pragma"] = "no-cache"
    return response


class SecurityEnforcementMiddleware:
    """
    Enforces mandatory security onboarding for logged-in users:
    forces password rotation on first login, and requires MFA setup
    before granting access to any platform features.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Anonymous users do not need onboarding redirects.
        if not request.user.is_authenticated:
            return self.get_response(request)

        path = request.path_info

        # Allow static files, media uploads, and logout without redirection.
        if settings.STATIC_URL and path.startswith(settings.STATIC_URL):
            return add_no_store_headers(self.get_response(request))
        if settings.MEDIA_URL and settings.MEDIA_URL != "/" and path.startswith(settings.MEDIA_URL):
            return add_no_store_headers(self.get_response(request))
        if path == reverse("kura:logout"):
            return add_no_store_headers(self.get_response(request))

        # Force password change on first login. The redirect and the allowed page
        # both carry no-store, so a sensitive onboarding page is never cached.
        password_change_url = reverse("kura:password_change")
        if request.user.must_change_password:
            if path != password_change_url:
                return add_no_store_headers(redirect("kura:password_change"))
            return add_no_store_headers(self.get_response(request))

        # Force mandatory MFA enrollment before accessing other pages.
        mfa_setup_url = reverse("kura:mfa_setup")
        mfa_complete_url = reverse("kura:mfa_setup_complete")
        if not request.user.mfa_enabled:
            if path not in (mfa_setup_url, mfa_complete_url, password_change_url):
                return add_no_store_headers(redirect("kura:mfa_setup"))

        response = self.get_response(request)

        # Prevent browser caching of sensitive authenticated content.
        return add_no_store_headers(response)


class RateLimitMiddleware:
    """
    Applies sliding-window rate limits on file uploads (20/min) and autosave calls (120/min)
    to protect server capacity against bursts.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        # The real visitor's IP, not the WAF's (see get_client_ip in views.py).
        client_ip = get_client_ip(request)
        user_key = client_ip
        if request.user.is_authenticated:
            user_key = f"{request.user.id}"

        limit = None
        window = 60

        if "upload" in path:
            limit = 20
            cache_key = f"rate_limit_upload_{user_key}"
        elif "autosave" in path:
            limit = 120
            cache_key = f"rate_limit_autosave_{user_key}"

        if limit:
            from django.core.cache import caches
            from django.http import HttpResponse

            # Use the shared DatabaseCache so all Gunicorn workers enforce one counter (AUTH-08).
            ratelimit_cache = caches["ratelimit"]
            count = ratelimit_cache.get(cache_key, 0)
            if count >= limit:
                # Record only the rate-limit bucket, never a submitted filename or file data.
                bucket = "upload" if "upload" in path else "autosave"
                log_security_event(request, "ratelimit.hit", {"bucket": bucket}, logging.WARNING)
                return HttpResponse("Rate limit exceeded. Please wait before retrying.", status=429)
            ratelimit_cache.set(cache_key, count + 1, timeout=window)

        return self.get_response(request)


class RowLevelSecurityMiddleware:
    """
    Sets the active user ID in the PostgreSQL connection session for Row-Level Security.
    Ensures database-level isolation so SQL queries only return records the user may view.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Pass the current user ID to PostgreSQL for session-level RLS policies.
        if request.user.is_authenticated:
            from django.db import connection

            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET kura.current_user_id = %s;", [str(request.user.id)])
            except Exception as error:
                # Fail closed: database policies treat a missing user id as unrestricted.
                log_security_event(
                    request,
                    "rls.context_failed",
                    {"error_type": error.__class__.__name__},
                    level=logging.ERROR,
                )
                return HttpResponse("Service unavailable.", status=503)

        response = self.get_response(request)

        # Reset session context after response to prevent connection pool leakage.
        if request.user.is_authenticated:
            from django.db import connection

            try:
                with connection.cursor() as cursor:
                    cursor.execute("RESET kura.current_user_id;")
            except Exception as error:
                # Log reset failure and close connection so stale context cannot leak.
                log_security_event(
                    request,
                    "rls.reset_failed",
                    {"error_type": error.__class__.__name__},
                    level=logging.WARNING,
                )
                connection.close()

        return response

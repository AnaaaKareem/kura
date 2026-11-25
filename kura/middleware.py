import hmac
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.db import DatabaseError, InterfaceError, OperationalError
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template import loader
from django.urls import Resolver404, resolve, reverse
from django.utils.crypto import constant_time_compare
from django.utils import timezone
from .models import UserSession, get_security_policy
from .views import get_client_ip, hash_session_token, log_security_event

User = get_user_model()


class DependencyOutageMiddleware:
    """Return HTTP 503 when PostgreSQL or Vault cannot serve a request.

    Who can use it: Middleware stack for all incoming HTTP requests.
    Security: Prevents database or Vault connection outages from surfacing as
    unhandled 500 errors and emits server.dependency_unavailable without leaking details.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _unavailable_response(self, request, error):
        log_security_event(
            request,
            "server.dependency_unavailable",
            {"error_type": type(error).__name__},
            level=logging.ERROR,
            include_actor=False,
        )
        html_body = loader.get_template("503.html").render({})
        response = HttpResponse(html_body, status=503)
        response["Retry-After"] = "30"
        return response

    def __call__(self, request):
        try:
            return self.get_response(request)
        except (OperationalError, InterfaceError) as error:
            return self._unavailable_response(request, error)

    def process_exception(self, request, exception):
        # Catch dependency errors raised inside views before Django renders handler500.
        if isinstance(exception, (OperationalError, InterfaceError)):
            return self._unavailable_response(request, exception)
        return None


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

        # Check whether the tracked session record exists, is active, and is unexpired.
        if request.user.is_authenticated:
            session_id = request.session.get("user_session_id")
            if not session_id:
                log_security_event(request, "session.invalid", {"reason": "untracked"}, level=logging.WARNING)
                logout(request)
                messages.error(request, "Your session was ended. Please sign in again.")
                return redirect("kura:login")
            try:
                user_session = UserSession.objects.filter(
                    id=session_id,
                    user=request.user,
                ).first()

                session_key = request.session.session_key
                if not user_session or user_session.revoked_at is not None:
                    reason = "revoked"
                elif user_session.expires_at <= timezone.now():
                    reason = "expired"
                elif not session_key or not hmac.compare_digest(
                    user_session.session_token_hash,
                    hash_session_token(session_key),
                ):
                    reason = "token_mismatch"
                else:
                    reason = None

                # End revoked or expired sessions and ask the user to log in again.
                if reason:
                    log_security_event(request, "session.invalid", {"reason": reason}, level=logging.WARNING)
                    logout(request)
                    messages.error(request, "Your session was ended. Please sign in again.")
                    return redirect("kura:login")

                # Refresh sliding idle timeout from the active SecurityPolicy row (O6).
                idle_seconds = get_security_policy()["session_idle_minutes"] * 60
                request.session.set_expiry(idle_seconds)
            except (ValueError, TypeError):
                log_security_event(request, "session.invalid", {"reason": "revoked"}, level=logging.WARNING)
                logout(request)
                messages.error(request, "Your session was ended. Please sign in again.")
                return redirect("kura:login")

        response = self.get_response(request)
        response.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        return response


def add_no_store_headers(response):
    """Mark an authenticated response as sensitive so browsers and proxies do not cache it.
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

        # Force password change on first login.
        # The redirect and the allowed page both carry no-store, so a sensitive onboarding page is never cached.
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
    Applies sliding-window rate limits on file uploads (20/min)
    and text searches (60/min) to protect server capacity against bursts.
    """

    UPLOAD_URL_NAMES = {
        "assessment_attempt_file_upload",
        "assessment_file_upload",
        # Course material files.
        "course_file_upload",
    }
    # List pages with a free-text "q" filter.
    # Enrollment search has its own limit in views.py.
    SEARCH_URL_NAMES = {
        "admin_sessions",
        "admin_users",
        "staff_list",
        "student_list",
        "attendance_history",
        "course_grades",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Match resolved URL names so substring URLs are not miscounted (P7).
        limit = None
        bucket = None
        window = 60
        # Uploads are POST.
        # Searches are GET and only count when a search term is sent, so plain page loads and pagination stay free.
        # Counting only touches the rate-limit cache.
        has_search_term = request.method == "GET" and request.GET.get("q", "").strip() != ""
        if request.method == "POST" or has_search_term:
            try:
                match = resolve(request.path_info)
            except Resolver404:
                match = None
            if match is not None and request.method == "POST":
                if match.url_name in self.UPLOAD_URL_NAMES:
                    limit = 20
                    bucket = "upload"
            elif match is not None and match.url_name in self.SEARCH_URL_NAMES:
                limit = 60
                bucket = "search"

        if limit and bucket:
            from django.core.cache import caches
            from django.http import HttpResponse

            client_ip = get_client_ip(request)
            cache_keys = [f"rate_limit_{bucket}_ip_{client_ip}"]
            if request.user.is_authenticated:
                cache_keys.insert(0, f"rate_limit_{bucket}_{request.user.id}")

            # Use the shared DatabaseCache so all Gunicorn workers enforce both per-user and per-IP counters (AUTH-08, P7).
            ratelimit_cache = caches["ratelimit"]
            try:
                if any(ratelimit_cache.get(key, 0) >= limit for key in cache_keys):
                    log_security_event(request, "ratelimit.hit", {"bucket": bucket}, logging.WARNING)
                    response = HttpResponse("Rate limit exceeded. Please wait before retrying.", status=429)
                    response["Retry-After"] = str(window)
                    return response
                for key in cache_keys:
                    ratelimit_cache.set(key, ratelimit_cache.get(key, 0) + 1, timeout=window)
            except DatabaseError as error:
                # Fail closed with 503 if the rate-limit backing store is unreachable.
                log_security_event(
                    request,
                    "server.dependency_unavailable",
                    {"error_type": type(error).__name__},
                    level=logging.ERROR,
                    include_actor=False,
                )
                return HttpResponse("Service unavailable.", status=503)

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
                    # Use set_config(..., false) for session-wide SET with psycopg 3 bound parameters.
                    cursor.execute("SELECT set_config('kura.current_user_id', %s, false);", [str(request.user.id)])
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

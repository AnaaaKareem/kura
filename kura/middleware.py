from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.crypto import constant_time_compare
from django.utils import timezone
from .models import UserSession

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
            logout(request)
            messages.error(request, "This account has been deactivated. Contact the administrator.")
            return redirect("kura:login")

        # Log out locked accounts and display the unlock timestamp.
        if account_user and account_user.locked_until and account_user.locked_until > timezone.now():
            lock_time = timezone.localtime(account_user.locked_until).strftime("%d %b, %H:%M")
            logout(request)
            messages.error(request, f"This account is currently locked until {lock_time}.")
            return redirect("kura:login")

        # Check whether the tracked session record has been revoked or expired.
        if request.user.is_authenticated:
            session_id = request.session.get("user_session_id")
            if session_id:
                try:
                    active_session = UserSession.objects.filter(
                        id=session_id,
                        user=request.user,
                        revoked_at__isnull=True,
                        expires_at__gt=timezone.now(),
                    ).first()

                    # End revoked or expired sessions and ask the user to log in again.
                    if not active_session:
                        logout(request)
                        messages.error(request, "Your session was ended. Please sign in again.")
                        return redirect("kura:login")
                except (ValueError, TypeError):
                    logout(request)
                    messages.error(request, "Your session was ended. Please sign in again.")
                    return redirect("kura:login")

        return self.get_response(request)


from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.urls import reverse


class SecurityEnforcementMiddleware:
    """
    Forces users to change their password on their first login.
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
            return self.get_response(request)
        if settings.MEDIA_URL and settings.MEDIA_URL != "/" and path.startswith(settings.MEDIA_URL):
            return self.get_response(request)
        if path == reverse("kura:logout"):
            return self.get_response(request)

        # Force password change on first login.
        password_change_url = reverse("kura:password_change")
        if request.user.must_change_password:
            if path != password_change_url:
                return redirect("kura:password_change")
            return self.get_response(request)

        mfa_setup_url = reverse("kura:mfa_setup")
        mfa_complete_url = reverse("kura:mfa_setup_complete")
        if not request.user.mfa_enabled:
            if path not in (mfa_setup_url, mfa_complete_url, password_change_url):
                return redirect("kura:mfa_setup")

        response = self.get_response(request)

        # Prevent browser caching of sensitive authenticated content.
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"
        return response

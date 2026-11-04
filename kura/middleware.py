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

        response = self.get_response(request)

        # Prevent browser caching of sensitive authenticated content.
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"
        return response

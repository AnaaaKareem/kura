from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils import timezone

User = get_user_model()


class KuraAuthBackend(ModelBackend):
    """
    Authenticates users against institutional email and password credentials.
    Enforces administrative account locks (locked_until) and active status checks,
    returning identical failure responses to prevent credential and timing enumeration.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Checks a submitted email and password against an active, unlocked account.
        Returns the user if credentials match, or None if authentication fails.
        """
        # The username parameter receives the submitted email address
        email = username or kwargs.get("email")
        if not email or not password:
            return None

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Constant-time dummy hash computation to prevent timing attacks
            User().set_password(password)
            return None

        # Verify password hash
        if not user.check_password(password):
            return None

        # Deny deactivated accounts
        if not user.is_active:
            return None

        # Enforce administrative account locks
        if user.locked_until and user.locked_until > timezone.now():
            return None

        return user

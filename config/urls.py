from django.contrib.auth.decorators import login_required
from django.urls import include, path
from mfa import FIDO2
from mfa import views as mfa_views

from kura import views as kura_views

# Only the passkey (FIDO2) pages of django-mfa2 are published. The library also
# ships TOTP, email codes, recovery codes, U2F and "trusted device" pages, but
# Kura has its own TOTP and recovery code views, and the others are not used.
# Leaving them out means they cannot be reached at all (smaller attack surface).
# The addresses and names below are the library's own, so its passkey
# templates and JavaScript keep working unchanged.
passkey_urlpatterns = [
    # Start page for adding a passkey (linked from Kura's Passkeys page).
    # django-mfa2 does not require a login on its registration pages, so
    # login_required is added here: only a fully signed-in user (password AND
    # second factor) may add a passkey to their own account.
    path("fido2/", login_required(FIDO2.start), name="start_fido2"),
    # Registering a new passkey: the browser asks for a challenge, then sends
    # the signed answer. Kura's own wrapper handles the second step (below);
    # it already has @login_required.
    path("fido2/begin_reg", login_required(FIDO2.begin_registeration), name="fido2_begin_reg"),
    path("fido2/complete_reg", kura_views.passkey_register_complete_view, name="fido2_complete_reg"),
    # Signing in with a passkey after the password step.
    path("fido2/auth", FIDO2.auth, name="fido2_auth"),
    path("fido2/begin_auth", FIDO2.authenticate_begin, name="fido2_begin_auth"),
    path("fido2/complete_auth", kura_views.passkey_auth_complete_view, name="fido2_complete_auth"),
    # The "Not me" link on the passkey sign-in page: forgets the remembered
    # user name and goes back to the login page.
    path("reset", mfa_views.reset_cookie, name="mfa_reset_cookie"),
]

urlpatterns = [
    # Kura's wrapper for "fido2/complete_reg" calls the library's own view,
    # then logs auth.passkey.added.
    path("mfa/", include(passkey_urlpatterns)),
    path("", include("kura.urls")),
]

# Route permission, not-found, and server-error responses through security logging and generic pages.
handler403 = "kura.views.permission_denied_view"
handler404 = "kura.views.not_found_view"
handler500 = "kura.views.server_error_view"

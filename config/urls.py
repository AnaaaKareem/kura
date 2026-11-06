from django.urls import include, path

from kura import views as kura_views

urlpatterns = [
    # Kura's wrapper must come BEFORE the django-mfa2 URLs so it handles this
    # path: it calls the library's own view, then logs auth.passkey.added.
    path("mfa/fido2/complete_reg", kura_views.passkey_register_complete_view, name="fido2_complete_reg"),
    path("mfa/", include("mfa.urls")),
    path("", include("kura.urls")),
]

# Route permission exceptions through the security logger and a generic page.
handler403 = "kura.views.permission_denied_view"

from django.urls import include, path

from kura import views as kura_views

urlpatterns = [
    path("", include("kura.urls")),
]

# Route permission exceptions through the security logger and a generic page.
handler403 = "kura.views.permission_denied_view"

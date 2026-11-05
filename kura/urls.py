from django.urls import path
from . import views

app_name = "kura"
urlpatterns = [
    path("", views.home_view, name="home"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("password/change/", views.password_change_view, name="password_change"),
    path("password/reset/", views.password_reset_request_view, name="password_reset_request"),
    path("password/reset/<str:token>/", views.password_reset_confirm_view, name="password_reset_confirm"),
]

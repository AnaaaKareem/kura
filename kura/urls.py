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
    path("login/mfa/", views.mfa_verify_view, name="mfa_verify"),
    path("mfa/setup/", views.mfa_setup_view, name="mfa_setup"),
    path("mfa/complete/", views.mfa_setup_complete_view, name="mfa_setup_complete"),
    path("account/sessions/", views.user_sessions_view, name="user_sessions"),
    path("admin/sessions/", views.admin_sessions_view, name="admin_sessions"),
    path("admin/sessions/revoke/", views.admin_sessions_revoke_view, name="admin_sessions_revoke"),
    path("admin/staff/", views.staff_list_view, name="staff_list"),
    path("admin/staff/new/", views.staff_create_view, name="staff_create"),
    path("admin/users/<uuid:user_id>/deactivate/", views.user_deactivate_view, name="user_deactivate"),
    path("admin/users/<uuid:user_id>/lock/", views.user_lock_toggle_view, name="user_lock_toggle"),
    path("admin/users/<uuid:user_id>/roles/", views.user_roles_view, name="user_roles"),
    path("admin/courses/new/", views.admin_course_create_view, name="admin_course_create"),
    path("admin/courses/<uuid:course_id>/edit/", views.admin_course_edit_view, name="admin_course_edit"),
]

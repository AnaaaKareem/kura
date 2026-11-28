"""URL routes for the Kura app, grouped by feature area.

Views are private by default because of the global login gate. The few public
views carry @login_not_required in views.py. The last routes are honeypots with no names.
"""
from django.urls import path
from . import views

app_name = "kura"

urlpatterns = [
    path("admin/staff/settings/", views.staff_settings_view, name="staff_settings"),
    # Dashboard home page
    path("", views.home_view, name="home"),
    # Authentication routes
    path("login/", views.login_view, name="login"),
    path("login/mfa/", views.mfa_verify_view, name="mfa_verify"),
    path("logout/", views.logout_view, name="logout"),
    # Password management routes
    path("password/change/", views.password_change_view, name="password_change"),
    path("password/reset/", views.password_reset_request_view, name="password_reset_request"),
    path("password/reset/<str:token>/", views.password_reset_confirm_view, name="password_reset_confirm"),
    # Multi-factor authentication routes
    path("mfa/setup/", views.mfa_setup_view, name="mfa_setup"),
    path("mfa/confirm/", views.mfa_reauth_view, name="mfa_reauth"),
    path("mfa/complete/", views.mfa_setup_complete_view, name="mfa_setup_complete"),
    path("mfa/reset/", views.mfa_reset_view, name="mfa_reset"),
    # Passkey (WebAuthn / FIDO2) management routes
    path("passkeys/", views.passkey_manage_view, name="passkey_manage"),
    path("passkeys/<int:key_id>/delete/", views.passkey_delete_view, name="passkey_delete"),
    # User sessions & privacy management
    path("privacy/", views.privacy_notice_view, name="privacy_notice"),
    path(".well-known/kura-receipts.pem", views.receipts_public_key_view, name="receipts_public_key"),
    path("account/privacy/", views.privacy_dashboard_view, name="privacy_dashboard"),
    path("account/privacy/export/", views.privacy_export_view, name="privacy_export"),
    path("account/privacy/restrict/", views.privacy_restrict_view, name="privacy_restrict"),
    path("account/privacy/erasure/", views.privacy_erasure_view, name="privacy_erasure"),
    path("account/sessions/", views.user_sessions_view, name="user_sessions"),
    path("account/sessions/<uuid:session_id>/revoke/", views.user_session_revoke_view, name="user_session_revoke"),
    path("admin/sessions/", views.admin_sessions_view, name="admin_sessions"),
    path("admin/users/<uuid:user_id>/mfa-reset/", views.admin_user_mfa_reset_view, name="admin_user_mfa_reset"),
    path("admin/security-policy/", views.security_policy_view, name="security_policy"),
    path("admin/quarantine/", views.quarantine_list_view, name="quarantine_list"),
    path(
        "admin/quarantine/<uuid:quarantined_file_id>/delete/",
        views.quarantine_delete_view,
        name="quarantine_delete",
    ),
    path("admin/sessions/revoke/", views.admin_sessions_revoke_view, name="admin_sessions_revoke"),
    # Admin management routes
    path("admin/staff/", views.staff_list_view, name="staff_list"),
    path("admin/staff/new/", views.staff_create_view, name="staff_create"),
    path("admin/users/", views.admin_users_view, name="admin_users"),
    path("admin/users/<uuid:user_id>/deactivate/", views.user_deactivate_view, name="user_deactivate"),
    path("admin/users/<uuid:user_id>/lock/", views.user_lock_toggle_view, name="user_lock_toggle"),
    path("admin/users/<uuid:user_id>/roles/", views.user_roles_view, name="user_roles"),
    # Registrar enrollment routes
    path("registrar/students/new/", views.student_create_view, name="student_create"),
    path("registrar/students/", views.student_list_view, name="student_list"),
    path("registrar/students/<uuid:student_id>/", views.student_profile_view, name="student_profile"),
    path("registrar/enrollments/", views.enrollment_list_view, name="enrollment_list"),
    path("registrar/enrollments/new/", views.enrollment_create_view, name="enrollment_create"),
    path("registrar/enrollments/<uuid:enrollment_id>/drop/", views.enrollment_drop_view, name="enrollment_drop"),
    # Courses and content routes
    path("courses/", views.course_list_view, name="course_list"),
    path("admin/courses/new/", views.admin_course_create_view, name="admin_course_create"),
    path("admin/courses/<uuid:course_id>/edit/", views.admin_course_edit_view, name="admin_course_edit"),
    path("courses/new/", views.course_create_view, name="course_create"),
    path("courses/<uuid:course_id>/", views.course_detail_view, name="course_detail"),
    path("courses/<uuid:course_id>/publish/", views.course_publish_toggle_view, name="course_publish_toggle"),
    path("courses/<uuid:course_id>/staff/assign/", views.course_staff_assign_view, name="course_staff_assign"),
    path("courses/<uuid:course_id>/ta/assign/", views.course_ta_assign_view, name="course_ta_assign"),
    path("courses/<uuid:course_id>/files/upload/", views.course_file_upload_view, name="course_file_upload"),
    path(
        "course-files/<uuid:course_file_id>/visibility/",
        views.course_file_visibility_toggle_view,
        name="course_file_visibility_toggle",
    ),
    path("course-files/<uuid:course_file_id>/delete/", views.course_file_delete_view, name="course_file_delete"),
    path("courses/<uuid:course_id>/files/<uuid:file_id>/download/", views.file_download_view, name="file_download"),
    # Schedules and attendance routes
    path("schedules/", views.schedule_list_view, name="schedule_list"),
    path("courses/<uuid:course_id>/schedules/new/", views.schedule_create_view, name="schedule_create"),
    path("schedules/<uuid:schedule_id>/edit/", views.schedule_edit_view, name="schedule_edit"),
    path("schedules/<uuid:schedule_id>/delete/", views.schedule_delete_view, name="schedule_delete"),
    path(
        "courses/<uuid:course_id>/attendance/start/",
        views.attendance_session_start_view,
        name="attendance_session_start",
    ),
    path("attendance/<uuid:session_id>/", views.attendance_session_detail_view, name="attendance_session_detail"),
    path("attendance/<uuid:session_id>/close/", views.attendance_session_close_view, name="attendance_session_close"),
    path("attendance/<uuid:session_id>/checkin/", views.student_checkin_view, name="student_checkin"),
    path("attendance/<uuid:session_id>/manual/", views.attendance_manual_record_view, name="attendance_manual_record"),
    path("attendance/history/", views.attendance_history_view, name="attendance_history"),
    # Assessments, attempts and submissions routes
    path("courses/<uuid:course_id>/assessments/new/", views.assessment_create_view, name="assessment_create"),
    path("assessments/<uuid:assessment_id>/", views.assessment_detail_view, name="assessment_detail"),
    path("assessments/<uuid:assessment_id>/edit/", views.assessment_create_view, name="assessment_edit"),
    path("assessments/<uuid:assessment_id>/delete/", views.assessment_delete_view, name="assessment_delete"),
    path(
        "assessments/<uuid:assessment_id>/files/upload/",
        views.assessment_file_upload_view,
        name="assessment_file_upload",
    ),
    path(
        "assessments/<uuid:assessment_id>/files/<uuid:file_id>/download/",
        views.assessment_file_download_view,
        name="assessment_file_download",
    ),
    path(
        "assessments/<uuid:assessment_id>/start/", views.assessment_attempt_start_view, name="assessment_attempt_start"
    ),
    path("attempts/<uuid:attempt_id>/", views.attempt_detail_view, name="attempt_detail"),
    path(
        "attempts/<uuid:attempt_id>/files/<uuid:file_id>/download/",
        views.attempt_file_download_view,
        name="attempt_file_download",
    ),
    path("attempts/<uuid:attempt_id>/take/", views.assessment_take_view, name="assessment_take"),
    path(
        "attempts/<uuid:attempt_id>/files/upload/",
        views.assessment_attempt_file_upload_view,
        name="assessment_attempt_file_upload",
    ),
    path(
        "attempts/<uuid:attempt_id>/files/<uuid:file_id>/delete/",
        views.assessment_attempt_file_delete_view,
        name="assessment_attempt_file_delete",
    ),
    path("attempts/<uuid:attempt_id>/submit/", views.assessment_submit_view, name="assessment_submit"),
    # Grades, results and transcripts routes
    path("courses/<uuid:course_id>/grades/", views.course_grades_view, name="course_grades"),
    path("attempts/<uuid:attempt_id>/grade/", views.grade_entry_view, name="grade_entry"),
    path("grades/<uuid:grade_id>/finalize/", views.grade_finalize_view, name="grade_finalize"),
    path("grades/<uuid:grade_id>/release/", views.grade_release_view, name="grade_release"),
    path("grades/my/", views.student_grades_view, name="student_grades"),
    path(
        "grades/<uuid:grade_id>/change-request/",
        views.grade_change_request_create_view,
        name="grade_change_request_create",
    ),
    path(
        "change-requests/<uuid:request_id>/review/",
        views.grade_change_request_review_view,
        name="grade_change_request_review",
    ),
    path(
        "courses/<uuid:course_id>/results/calculate/",
        views.course_result_calculate_view,
        name="course_result_calculate",
    ),
    path("courses/<uuid:course_id>/results/release/", views.course_result_release_view, name="course_result_release"),
    path("transcript/", views.student_transcript_view, name="student_transcript"),
    path("departments/<int:department_id>/reports/", views.department_reports_view, name="department_reports"),
]

# Deception lure routes are registered without `name=` so automated route-contract enumeration keeps its named-route boundary.
urlpatterns += [path(honeypot_path, views.honeypot_view) for honeypot_path in views.HONEYPOT_PATHS]

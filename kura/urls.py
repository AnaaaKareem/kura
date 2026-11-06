from django.urls import path
from . import views

app_name = "kura"

urlpatterns = [
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
    path("mfa/complete/", views.mfa_setup_complete_view, name="mfa_setup_complete"),
    # User sessions management
    path("account/sessions/", views.user_sessions_view, name="user_sessions"),
    path("admin/sessions/", views.admin_sessions_view, name="admin_sessions"),
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
    path("admin/users/<uuid:user_id>/deactivate/", views.user_deactivate_view, name="user_deactivate"),
    path("admin/users/<uuid:user_id>/lock/", views.user_lock_toggle_view, name="user_lock_toggle"),
    path("admin/users/<uuid:user_id>/roles/", views.user_roles_view, name="user_roles"),
    # Registrar enrollment routes
    path("registrar/students/new/", views.student_create_view, name="student_create"),
    path("registrar/students/", views.student_list_view, name="student_list"),
    path("registrar/students/<uuid:student_id>/", views.student_profile_view, name="student_profile"),
    path("registrar/enrollments/", views.enrollment_list_view, name="enrollment_list"),
    path("registrar/enrollments/new/", views.enrollment_create_view, name="enrollment_create"),
    path("registrar/enrollments/search/", views.enrollment_search_view, name="enrollment_search"),
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
    path("courses/<uuid:course_id>/modules/new/", views.module_create_view, name="module_create"),
    path("modules/<uuid:module_id>/edit/", views.module_edit_view, name="module_edit"),
    path("modules/<uuid:module_id>/delete/", views.module_delete_view, name="module_delete"),
    path("modules/<uuid:module_id>/sections/new/", views.section_create_view, name="section_create"),
    path("sections/<uuid:section_id>/edit/", views.section_edit_view, name="section_edit"),
    path("sections/<uuid:section_id>/items/new/", views.item_create_view, name="item_create"),
    path(
        "sections/<uuid:section_id>/visibility/", views.section_visibility_toggle_view, name="section_visibility_toggle"
    ),
    path("sections/<uuid:section_id>/delete/", views.section_delete_view, name="section_delete"),
    path("sections/<uuid:section_id>/items/preview/", views.item_preview_view, name="item_preview"),
    path("items/<uuid:item_id>/visibility/", views.item_visibility_toggle_view, name="item_visibility_toggle"),
    path("items/<uuid:item_id>/edit/", views.item_edit_view, name="item_edit"),
    path("items/<uuid:item_id>/delete/", views.item_delete_view, name="item_delete"),
    path("courses/<uuid:course_id>/files/<uuid:file_id>/download/", views.file_download_view, name="file_download"),
    # Schedules and attendance routes
    path("schedules/", views.schedule_list_view, name="schedule_list"),
    path("courses/<uuid:course_id>/schedules/new/", views.schedule_create_view, name="schedule_create"),
    path("schedules/<uuid:schedule_id>/edit/", views.schedule_edit_view, name="schedule_edit"),
    path("schedules/<uuid:schedule_id>/delete/", views.schedule_delete_view, name="schedule_delete"),
    path(
        "modules/<uuid:module_id>/attendance/start/",
        views.attendance_session_start_view,
        name="attendance_session_start",
    ),
    path("attendance/<uuid:session_id>/", views.attendance_session_detail_view, name="attendance_session_detail"),
    path("attendance/<uuid:session_id>/close/", views.attendance_session_close_view, name="attendance_session_close"),
    path("attendance/<uuid:session_id>/checkin/", views.student_checkin_view, name="student_checkin"),
    path("attendance/<uuid:session_id>/manual/", views.attendance_manual_record_view, name="attendance_manual_record"),
    path("attendance/history/", views.attendance_history_view, name="attendance_history"),
    # Assessments, attempts and submissions routes
    path("sections/<uuid:section_id>/assessments/new/", views.assessment_create_view, name="assessment_create"),
    path(
        "sections/<uuid:section_id>/assessments/question-form/",
        views.assessment_question_form_view,
        name="assessment_question_form",
    ),
    path("assessments/<uuid:assessment_id>/", views.assessment_detail_view, name="assessment_detail"),
    path("assessments/<uuid:assessment_id>/edit/", views.assessment_create_view, name="assessment_edit"),
    path("assessments/<uuid:assessment_id>/delete/", views.assessment_delete_view, name="assessment_delete"),
    path(
        "assessments/<uuid:assessment_id>/files/upload/",
        views.assessment_file_upload_view,
        name="assessment_file_upload",
    ),
    path(
        "assessments/<uuid:assessment_id>/scanned-upload/",
        views.scanned_paper_staff_upload_view,
        name="scanned_paper_staff_upload",
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
    path("attempts/<uuid:attempt_id>/autosave/", views.assessment_autosave_view, name="assessment_autosave"),
    path(
        "attempts/<uuid:attempt_id>/files/upload/",
        views.assessment_attempt_file_upload_view,
        name="assessment_attempt_file_upload",
    ),
    path("attempts/<uuid:attempt_id>/submit/", views.assessment_submit_view, name="assessment_submit"),
    # Grades, appeals, results and transcripts routes
    path("courses/<uuid:course_id>/grades/", views.course_grades_view, name="course_grades"),
    path("attempts/<uuid:attempt_id>/grade/", views.grade_entry_view, name="grade_entry"),
    path("grades/<uuid:grade_id>/finalize/", views.grade_finalize_view, name="grade_finalize"),
    path("grades/<uuid:grade_id>/release/", views.grade_release_view, name="grade_release"),
    path("grades/my/", views.student_grades_view, name="student_grades"),
    path("grades/<uuid:grade_id>/appeal/", views.grade_appeal_create_view, name="grade_appeal_create"),
    path("appeals/<uuid:appeal_id>/review/", views.grade_appeal_review_view, name="grade_appeal_review"),
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
]

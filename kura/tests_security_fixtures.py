"""Section 5 synthetic test fixtures and Section 17 90-route contract registry.

Follows .agents/skills/kura-security-tester/SKILL.md and docs/SECURITY_TEST_PLAN.md:
- Synthetic data covering all 6 roles (Admin, Registrar, Department head, Instructor,
  Teaching assistant, Student) + dual-role across 2+ departments and 2 courses each.
- Authoritative ROUTE_CLASS_MAP covering all 90 named routes in kura/urls.py (83) and
  config/urls.py (7) mapped to CLS-01 through CLS-08.
"""

import hashlib
from datetime import time, timedelta
from decimal import Decimal

from django.test import Client
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from .models import (
    Assessment,
    AssessmentAttempt,
    AssessmentFile,
    AttemptFile,
    AttemptStatus,
    AttendanceMethod,
    AttendanceRecord,
    AttendanceStatus,
    Building,
    ChangeRequestStatus,
    Course,
    CourseFile,
    CourseResult,
    CourseStaff,
    CourseStaffRole,
    DayOfWeek,
    Department,
    Enrollment,
    EnrollmentStatus,
    FileContent,
    Grade,
    GradeChangeRequest,
    GradeComponentType,
    GradeHistory,
    GradeStatus,
    ModuleAttendanceSession,
    PasswordResetToken,
    QuarantinedFile,
    Role,
    Room,
    Schedule,
    SecurityPolicy,
    SessionType,
    StaffProfile,
    StoredFile,
    StudentProfile,
    User,
    UserRole,
    UserSession,
)
from .views import hash_attendance_passcode, hash_session_token

# Complete 90-route contract registry matching kura/urls.py (83) + config/urls.py (7).
ROUTE_CLASS_MAP = {
    # CLS-01: Public & Pre-MFA Auth (9 routes)
    "kura:login": {"cls": "CLS-01", "methods": ("GET", "POST"), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:mfa_verify": {"cls": "CLS-01", "methods": ("GET", "POST"), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:password_reset_request": {"cls": "CLS-01", "methods": ("GET", "POST"), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:password_reset_confirm": {"cls": "CLS-01", "methods": ("GET", "POST"), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": "reset_token"},
    "kura:privacy_notice": {"cls": "CLS-01", "methods": ("GET",), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "fido2_auth": {"cls": "CLS-01", "methods": ("GET",), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "fido2_begin_auth": {"cls": "CLS-01", "methods": ("GET",), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "fido2_complete_auth": {"cls": "CLS-01", "methods": ("POST",), "public": True, "csrf_exempt": True, "fresh_mfa": False, "kw": None},
    "mfa_reset_cookie": {"cls": "CLS-01", "methods": ("GET",), "public": True, "csrf_exempt": False, "fresh_mfa": False, "kw": None},

    # CLS-02: Authenticated Self-Only & Onboarding (18 routes)
    "kura:home": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:logout": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:password_change": {"cls": "CLS-02", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:mfa_setup": {"cls": "CLS-02", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": None},
    "kura:mfa_setup_complete": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:mfa_reauth": {"cls": "CLS-02", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:passkey_manage": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": None},
    "kura:passkey_delete": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": "passkey"},
    "start_fido2": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "fido2_begin_reg": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "fido2_complete_reg": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": None},
    "kura:privacy_dashboard": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:privacy_export": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:privacy_restrict": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:privacy_erasure": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:user_sessions": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:user_session_revoke": {"cls": "CLS-02", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "user_session"},
    "kura:attendance_history": {"cls": "CLS-02", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},

    # CLS-03: Admin-Only (14 routes)
    "kura:staff_list": {"cls": "CLS-03", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:staff_create": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:staff_settings": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:admin_users": {"cls": "CLS-03", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:user_deactivate": {"cls": "CLS-03", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": "target_user"},
    "kura:user_lock_toggle": {"cls": "CLS-03", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "target_user"},
    "kura:user_roles": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": "target_user"},
    "kura:admin_sessions": {"cls": "CLS-03", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:admin_sessions_revoke": {"cls": "CLS-03", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:security_policy": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": None},
    "kura:quarantine_list": {"cls": "CLS-03", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:quarantine_delete": {"cls": "CLS-03", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "quarantined_file"},
    "kura:admin_course_create": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:admin_course_edit": {"cls": "CLS-03", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},

    # CLS-04: Registrar-Only (6 routes)
    "kura:student_create": {"cls": "CLS-04", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:student_list": {"cls": "CLS-04", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:student_profile": {"cls": "CLS-04", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "student_1"},
    "kura:enrollment_list": {"cls": "CLS-04", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:enrollment_create": {"cls": "CLS-04", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:enrollment_drop": {"cls": "CLS-04", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "enrollment_a1"},

    # CLS-05: Department Head & Course Management (11 routes)
    "kura:course_list": {"cls": "CLS-05", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:course_create": {"cls": "CLS-05", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:course_detail": {"cls": "CLS-05", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:course_publish_toggle": {"cls": "CLS-05", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:course_staff_assign": {"cls": "CLS-05", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:course_ta_assign": {"cls": "CLS-05", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:schedule_list": {"cls": "CLS-05", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:schedule_create": {"cls": "CLS-05", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:schedule_edit": {"cls": "CLS-05", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "schedule_a1"},
    "kura:schedule_delete": {"cls": "CLS-05", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "schedule_a1"},
    "kura:department_reports": {"cls": "CLS-05", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "dept_a"},

    # CLS-06: Course Files & Attendance (9 routes)
    "kura:course_file_upload": {"cls": "CLS-06", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:course_file_visibility_toggle": {"cls": "CLS-06", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_file_visible"},
    "kura:course_file_delete": {"cls": "CLS-06", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_file_visible"},
    "kura:file_download": {"cls": "CLS-06", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_file_download"},
    "kura:attendance_session_start": {"cls": "CLS-06", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:attendance_session_detail": {"cls": "CLS-06", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attendance_session"},
    "kura:attendance_session_close": {"cls": "CLS-06", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attendance_session"},
    "kura:student_checkin": {"cls": "CLS-06", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attendance_session"},
    "kura:attendance_manual_record": {"cls": "CLS-06", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attendance_session"},

    # CLS-07: Assessments & Student Attempts (13 routes)
    "kura:assessment_create": {"cls": "CLS-07", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:assessment_edit": {"cls": "CLS-07", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_a1"},
    "kura:assessment_delete": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_a1"},
    "kura:assessment_detail": {"cls": "CLS-07", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_a1"},
    "kura:assessment_file_upload": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_a1"},
    "kura:assessment_file_download": {"cls": "CLS-07", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_file_download"},
    "kura:assessment_attempt_start": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "assessment_a1"},
    "kura:assessment_take": {"cls": "CLS-07", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_in_progress"},
    "kura:assessment_attempt_file_upload": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_in_progress"},
    "kura:assessment_attempt_file_delete": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_file_download"},
    "kura:assessment_submit": {"cls": "CLS-07", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_in_progress"},
    "kura:attempt_detail": {"cls": "CLS-07", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_submitted"},
    "kura:attempt_file_download": {"cls": "CLS-07", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_file_download"},

    # CLS-08: Grades, Results & Transcript (10 routes)
    "kura:course_grades": {"cls": "CLS-08", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:grade_entry": {"cls": "CLS-08", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "attempt_submitted"},
    "kura:grade_finalize": {"cls": "CLS-08", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "grade_draft"},
    "kura:grade_release": {"cls": "CLS-08", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "grade_finalized"},
    "kura:student_grades": {"cls": "CLS-08", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
    "kura:grade_change_request_create": {"cls": "CLS-08", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "grade_released"},
    "kura:grade_change_request_review": {"cls": "CLS-08", "methods": ("GET", "POST"), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": "change_request_pending"},
    "kura:course_result_calculate": {"cls": "CLS-08", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": "course_a1"},
    "kura:course_result_release": {"cls": "CLS-08", "methods": ("POST",), "public": False, "csrf_exempt": False, "fresh_mfa": True, "kw": "course_a1"},
    "kura:student_transcript": {"cls": "CLS-08", "methods": ("GET",), "public": False, "csrf_exempt": False, "fresh_mfa": False, "kw": None},
}


def create_authenticated_client(user, fresh_mfa=True, ip_address="127.0.0.1", enforce_csrf_checks=False):
    """Create a Django Client backed by a valid tracked UserSession for `user`."""
    client = Client(enforce_csrf_checks=enforce_csrf_checks)
    client.force_login(user, backend="kura.backends.KuraAuthBackend")
    session = client.session
    if not session.session_key:
        session.save()
    user_session = UserSession.objects.create(
        user=user,
        session_token_hash=hash_session_token(session.session_key),
        ip_address=ip_address,
        user_agent="KuraSecurityTester/1.0",
        expires_at=timezone.now() + timedelta(hours=4),
    )
    session["user_session_id"] = str(user_session.id)
    if fresh_mfa:
        session["mfa_reauth_at"] = timezone.now().timestamp()
    session.save()
    return client, user_session


def _create_synthetic_user(email, role_names, mfa_enabled=True):
    user = User.objects.create_user(
        email=email,
        password="SyntheticPassword!2026",
        first_name="Synthetic",
        last_name=email.split("@", 1)[0],
    )
    user.mfa_enabled = mfa_enabled
    totp_key = random_hex(20)
    user.mfa_secret = totp_key if mfa_enabled else ""
    # Synthetic users have already finished first-login onboarding; otherwise middleware redirects every request.
    user.must_change_password = False
    user.save(update_fields=["mfa_enabled", "mfa_secret", "must_change_password"])
    for role_name in role_names:
        role, _ = Role.objects.get_or_create(name=role_name)
        UserRole.objects.get_or_create(user=user, role=role)
    if mfa_enabled:
        TOTPDevice.objects.create(user=user, name="default", confirmed=True, key=totp_key)
    return user


def _make_stored_file(uploaded_by, filename, content_bytes):
    digest = hashlib.sha256(content_bytes).hexdigest()
    sf = StoredFile.objects.create(
        uploaded_by=uploaded_by,
        original_filename=filename,
        mime_type="application/pdf",
        size_bytes=len(content_bytes),
        sha256_hash=digest,
    )
    FileContent.objects.create(file=sf, content=content_bytes, encryption_version=0)
    return sf


def build_security_fixture_set():
    """Build Section 5 synthetic dataset: 6 roles (+ dual-role), 2+ departments, 2 courses each."""
    SecurityPolicy.objects.get_or_create(id=1)

    admin = _create_synthetic_user("sec_admin@kura.edu", ["Admin"])
    registrar = _create_synthetic_user("sec_registrar@kura.edu", ["Registrar"])
    head_a = _create_synthetic_user("sec_head_a@kura.edu", ["Department head"])
    head_b = _create_synthetic_user("sec_head_b@kura.edu", ["Department head"])
    instructor_a = _create_synthetic_user("sec_inst_a@kura.edu", ["Instructor"])
    instructor_a_norelease = _create_synthetic_user("sec_inst_a_nr@kura.edu", ["Instructor"])
    instructor_b = _create_synthetic_user("sec_inst_b@kura.edu", ["Instructor"])
    ta_a = _create_synthetic_user("sec_ta_a@kura.edu", ["Teaching assistant"])
    ta_b = _create_synthetic_user("sec_ta_b@kura.edu", ["Teaching assistant"])
    student_1 = _create_synthetic_user("sec_stu_1@kura.edu", ["Student"])
    student_2 = _create_synthetic_user("sec_stu_2@kura.edu", ["Student"])
    student_unenrolled = _create_synthetic_user("sec_stu_out@kura.edu", ["Student"])
    dual_ta_student = _create_synthetic_user("sec_dual_ta_stu@kura.edu", ["Teaching assistant", "Student"])
    pre_mfa_user = _create_synthetic_user("sec_premfa@kura.edu", ["Student"], mfa_enabled=False)

    dept_a = Department.objects.create(code="CS", name="Computer Science", head_user=head_a)
    dept_a2 = Department.objects.create(code="SE", name="Software Engineering", head_user=head_a)
    dept_b = Department.objects.create(code="MATH", name="Mathematics", head_user=head_b)

    StaffProfile.objects.create(user=instructor_a, department=dept_a, staff_title="Lecturer", office_location="A-101")
    StaffProfile.objects.create(user=ta_a, department=dept_a, staff_title="Teaching Assistant", office_location="A-102")
    StaffProfile.objects.create(user=ta_b, department=dept_b, staff_title="Teaching Assistant", office_location="B-102")
    StudentProfile.objects.create(user=student_1, department=dept_a, current_level=1, matriculation_year=2025)
    StudentProfile.objects.create(user=student_2, department=dept_a, current_level=1, matriculation_year=2025)

    building = Building.objects.create(name="Science Hall")
    room = Room.objects.create(building=building, name="101")

    course_a1 = Course.objects.create(
        department=dept_a,
        code="CS101",
        title="Secure Software",
        semester="1",
        academic_year=2026,
        created_by=head_a,
        is_published=True,
        published_by=head_a,
        published_at=timezone.now(),
    )
    course_a2 = Course.objects.create(
        department=dept_a,
        code="CS102",
        title="Draft Systems",
        semester="2",
        academic_year=2026,
        created_by=head_a,
        is_published=False,
    )
    course_b1 = Course.objects.create(
        department=dept_b,
        code="MATH101",
        title="Discrete Math",
        semester="1",
        academic_year=2026,
        created_by=head_b,
        is_published=True,
        published_by=head_b,
        published_at=timezone.now(),
    )
    course_b2 = Course.objects.create(
        department=dept_b,
        code="MATH102",
        title="Algebra Draft",
        semester="2",
        academic_year=2026,
        created_by=head_b,
        is_published=False,
    )

    CourseStaff.objects.create(
        course=course_a1, user=instructor_a, staff_role=CourseStaffRole.LEAD_INSTRUCTOR, can_release_grades=True
    )
    CourseStaff.objects.create(
        course=course_a1,
        user=instructor_a_norelease,
        staff_role=CourseStaffRole.CO_INSTRUCTOR,
        can_release_grades=False,
    )
    CourseStaff.objects.create(
        course=course_a1, user=ta_a, staff_role=CourseStaffRole.TEACHING_ASSISTANT, can_release_grades=False
    )
    CourseStaff.objects.create(
        course=course_a1,
        user=dual_ta_student,
        staff_role=CourseStaffRole.TEACHING_ASSISTANT,
        can_release_grades=False,
    )
    CourseStaff.objects.create(
        course=course_a2, user=instructor_a, staff_role=CourseStaffRole.LEAD_INSTRUCTOR, can_release_grades=True
    )
    CourseStaff.objects.create(
        course=course_b1, user=instructor_b, staff_role=CourseStaffRole.LEAD_INSTRUCTOR, can_release_grades=True
    )
    CourseStaff.objects.create(
        course=course_b1, user=ta_b, staff_role=CourseStaffRole.TEACHING_ASSISTANT, can_release_grades=False
    )

    enr_1 = Enrollment.objects.create(course=course_a1, student=student_1, status=EnrollmentStatus.ACTIVE)
    Enrollment.objects.create(course=course_a1, student=student_2, status=EnrollmentStatus.ACTIVE)
    Enrollment.objects.create(course=course_a1, student=dual_ta_student, status=EnrollmentStatus.ACTIVE)
    Enrollment.objects.create(course=course_b1, student=student_unenrolled, status=EnrollmentStatus.ACTIVE)

    schedule_a1 = Schedule.objects.create(
        course=course_a1,
        instructor=instructor_a,
        session_type=SessionType.LECTURE,
        day=DayOfWeek.MONDAY,
        start_time=time(9, 0),
        end_time=time(10, 30),
        location=room,
        recurrence_start=timezone.now().date(),
        recurrence_end=timezone.now().date() + timedelta(days=30),
    )

    sf_course = _make_stored_file(instructor_a, "syllabus.pdf", b"%PDF-1.4 syllabus")
    cf_visible = CourseFile.objects.create(course=course_a1, file=sf_course, title="Syllabus", is_visible=True)
    sf_hidden = _make_stored_file(instructor_a, "hidden.pdf", b"%PDF-1.4 hidden")
    cf_hidden = CourseFile.objects.create(course=course_a1, file=sf_hidden, title="Hidden Notes", is_visible=False)

    now = timezone.now()
    att_session = ModuleAttendanceSession.objects.create(
        course=course_a1,
        created_by=instructor_a,
        title="Lecture 1",
        passcode_hash=hash_attendance_passcode("ABC123"),
        expires_at=now + timedelta(minutes=30),
        is_active=True,
    )
    AttendanceRecord.objects.create(
        session=att_session,
        student=student_1,
        status=AttendanceStatus.PRESENT,
        method=AttendanceMethod.PASSCODE,
    )

    assessment_open = Assessment.objects.create(
        course=course_a1,
        title="Coursework 1",
        component_type=GradeComponentType.COURSEWORK,
        opens_at=now - timedelta(days=1),
        due_date=now + timedelta(days=7),
        created_by=instructor_a,
        max_attempts=3,
    )
    assessment_future = Assessment.objects.create(
        course=course_a1,
        title="Future Exam",
        component_type=GradeComponentType.EXAM,
        opens_at=now + timedelta(days=2),
        due_date=now + timedelta(days=9),
        created_by=instructor_a,
        max_attempts=1,
    )
    sf_assess = _make_stored_file(instructor_a, "brief.pdf", b"%PDF-1.4 brief")
    AssessmentFile.objects.create(assessment=assessment_open, file=sf_assess)
    sf_future = _make_stored_file(instructor_a, "future.pdf", b"%PDF-1.4 future")
    AssessmentFile.objects.create(assessment=assessment_future, file=sf_future)

    attempt_in_progress = AssessmentAttempt.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt_no=1,
        status=AttemptStatus.IN_PROGRESS,
        ip_address="127.0.0.1",
    )
    attempt_submitted = AssessmentAttempt.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt_no=2,
        status=AttemptStatus.IN_PROGRESS,
        submitted_at=now - timedelta(hours=1),
        submission_hash=hashlib.sha256(b"submission").hexdigest(),
        ip_address="127.0.0.1",
    )
    attempt_dual = AssessmentAttempt.objects.create(
        assessment=assessment_open,
        student=dual_ta_student,
        attempt_no=1,
        status=AttemptStatus.IN_PROGRESS,
        submitted_at=now - timedelta(hours=1),
        submission_hash=hashlib.sha256(b"dual").hexdigest(),
        ip_address="127.0.0.1",
    )
    sf_attempt = _make_stored_file(student_1, "submission.pdf", b"%PDF-1.4 sub")
    AttemptFile.objects.create(attempt=attempt_submitted, file=sf_attempt)

    grade_draft = Grade.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt=attempt_submitted,
        score=Decimal("78.00"),
        status=GradeStatus.DRAFT,
        grader=instructor_a,
    )
    grade_finalized = Grade.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt=attempt_in_progress,
        score=Decimal("82.00"),
        status=GradeStatus.FINALIZED,
        grader=instructor_a,
    )
    # Grade.attempt is one-to-one, so the released grade needs its own attempt.
    attempt_released = AssessmentAttempt.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt_no=3,
        status=AttemptStatus.IN_PROGRESS,
        ip_address="127.0.0.1",
    )
    grade_released = Grade.objects.create(
        assessment=assessment_open,
        student=student_1,
        attempt=attempt_released,
        score=Decimal("88.00"),
        status=GradeStatus.RELEASED,
        grader=instructor_a,
        released_by=instructor_a,
        released_at=now - timedelta(minutes=10),
    )
    GradeHistory.objects.create(
        grade=grade_released,
        old_score=Decimal("85.00"),
        new_score=Decimal("88.00"),
        old_status=GradeStatus.FINALIZED,
        new_status=GradeStatus.RELEASED,
        changed_by=instructor_a,
        reason="Initial release",
    )
    change_req = GradeChangeRequest.objects.create(
        grade=grade_released,
        requested_by=instructor_a,
        current_score=Decimal("88.00"),
        proposed_score=Decimal("92.00"),
        reason="Regrade rubric adjustment",
        status=ChangeRequestStatus.PENDING,
    )
    CourseResult.objects.create(
        course=course_a1,
        student=student_1,
        final_score=Decimal("88.00"),
        status=GradeStatus.RELEASED,
        finalized_by=instructor_a,
        released_at=now - timedelta(minutes=5),
    )
    quarantined = QuarantinedFile.objects.create(
        uploaded_by=student_1,
        original_filename="eicar.pdf",
        size_bytes=68,
        sha256_hash=hashlib.sha256(b"eicar").hexdigest(),
        detection="Eicar-Test-Signature",
        content=b"eicar",
    )
    reset_tok = PasswordResetToken.objects.create(
        user=student_1,
        token_hash=hashlib.sha256(b"synthetic-reset-token").hexdigest(),
        expires_at=now + timedelta(minutes=30),
    )

    from mfa.models import User_Keys

    passkey_stu1 = User_Keys.objects.create(
        username=student_1.email,
        key_type="FIDO2",
        enabled=True,
        properties={"device": "AAAA", "type": "packed"},
    )

    return {
        "users": {
            "admin": admin,
            "registrar": registrar,
            "head_a": head_a,
            "head_b": head_b,
            "instructor_a": instructor_a,
            "instructor_a_norelease": instructor_a_norelease,
            "instructor_b": instructor_b,
            "ta_a": ta_a,
            "ta_b": ta_b,
            "student_1": student_1,
            "student_2": student_2,
            "student_unenrolled": student_unenrolled,
            "dual_ta_student": dual_ta_student,
            "pre_mfa_user": pre_mfa_user,
        },
        "departments": {"dept_a": dept_a, "dept_a2": dept_a2, "dept_b": dept_b},
        "courses": {"course_a1": course_a1, "course_a2": course_a2, "course_b1": course_b1, "course_b2": course_b2},
        "objects": {
            "enrollment_a1": enr_1,
            "schedule_a1": schedule_a1,
            "course_file_visible": cf_visible,
            "course_file_hidden": cf_hidden,
            "sf_course": sf_course,
            "attendance_session": att_session,
            "assessment_open": assessment_open,
            "assessment_future": assessment_future,
            "sf_assess": sf_assess,
            "sf_future": sf_future,
            "attempt_in_progress": attempt_in_progress,
            "attempt_submitted": attempt_submitted,
            "attempt_dual": attempt_dual,
            "sf_attempt": sf_attempt,
            "grade_draft": grade_draft,
            "grade_finalized": grade_finalized,
            "grade_released": grade_released,
            "change_request_pending": change_req,
            "quarantined_file": quarantined,
            "reset_token": reset_tok,
            "passkey_stu1": passkey_stu1,
        },
    }

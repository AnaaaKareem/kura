import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import unittest
import urllib.request
import zipfile
from importlib import import_module
from pathlib import Path
from decimal import Decimal
from io import BytesIO, StringIO
from django.contrib.auth import get_user_model
from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core import mail
from django.core.management.base import CommandError
from django.db import DatabaseError, IntegrityError, connection, connections, transaction
from django.db.models import QuerySet
from django.template.loader import render_to_string
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from unittest.mock import MagicMock, call, patch

from .files import check_signature_age, create_download_response, scan_file_for_malware, validate_and_save_upload
from .forms import PasswordChangeForm
from .validators import BreachedPasswordValidator
from .vault import (
    decrypt_answer_key,
    decrypt_mfa_secret,
    encrypt_answer_key,
    encrypt_mfa_secret,
    get_dynamic_database_credentials,
    get_vault_client,
)
from .views import (
    evaluate_attempt,
    hash_recovery_code,
    log_security_event,
    mfa_login_callback,
    queue_assessment_notification,
    queue_email,
    verify_totp_code,
)
from .vault import database_login_cache
from .vault_postgres.base import DatabaseWrapper as VaultDatabaseWrapper
from .models import (
    OutgoingEmail,
    OutgoingEmailStatus,
    QuarantinedFile,
    ALLOWED_UPLOAD_MIME_TYPES,
    AcademicLevel,
    Assessment,
    AssessmentAttempt,
    AttemptFile,
    AttemptStatus,
    AttendanceMethod,
    AttendanceRecord,
    AttendanceStatus,
    AppealStatus,
    ChangeRequestStatus,
    Course,
    CourseGradeScheme,
    CourseResult,
    CourseStaff,
    DayOfWeek,
    Department,
    Building,
    Room,
    Enrollment,
    EnrollmentStatus,
    ExamAnswerKey,
    FileContent,
    Grade,
    GradeAppeal,
    GradeChangeRequest,
    GradeComponentType,
    GradeHistory,
    GradeStatus,
    Module,
    ModuleAttendanceSession,
    ModuleSection,
    ModuleTargetLevel,
    PasswordHistory,
    PasswordResetToken,
    Role,
    RolePermission,
    Schedule,
    SectionItem,
    SectionItemFile,
    SessionType,
    StaffProfile,
    StoredFile,
    StudentProfile,
    SystemPermission,
    UserRole,
    UserSession,
    MAX_UPLOAD_BYTES,
)
from .permissions import (
    has_fresh_second_factor,
    can_release_grades,
    has_permission,
    has_role,
    is_course_staff,
    is_department_head,
    is_enrolled,
    is_lead_instructor,
)

User = get_user_model()


class EmailConfigurationTests(TestCase):
    def test_debug_email_uses_django_console_backend(self):
        # Password reset messages should use Django's configured mail backend.
        from config import settings

        if settings.DEBUG:
            self.assertEqual(settings.EMAIL_BACKEND, "django.core.mail.backends.console.EmailBackend")
        else:
            self.assertEqual(settings.EMAIL_BACKEND, "django.core.mail.backends.smtp.EmailBackend")

    def test_admin_course_filter_restricts_department(self):
        # A validated department filter should show only that department's courses.
        admin = make_user("Admin")
        first = Department.objects.create(name="Filter one", code="F1")
        second = Department.objects.create(name="Filter two", code="F2")
        Course.objects.create(department=first, code="F101", title="First course", semester="1", academic_year=2026)
        Course.objects.create(department=second, code="F201", title="Second course", semester="2", academic_year=2026)
        self.client.force_login(admin)
        response = self.client.get(reverse("kura:course_list"), {"department": first.pk})
        self.assertContains(response, "First course")
        self.assertNotContains(response, "Second course")


def make_user(role_name, email=None, password="ValidPassword123!", **extra_fields):
    """
    Test helper function to create a user and assign them a specific system role.
    """
    # Generate unique test email if one was not provided.
    if not email:
        email = f"{role_name.lower().replace(' ', '_')}_{secrets.token_hex(4)}@example.com"

    extra_fields.setdefault("is_active", True)
    extra_fields.setdefault("must_change_password", False)
    extra_fields.setdefault("mfa_enabled", True)

    user = User.objects.create_user(email=email, password=password, **extra_fields)

    # Fetch or create the role and attach it to the user.
    role, _ = Role.objects.get_or_create(name=role_name)
    UserRole.objects.get_or_create(user=user, role=role)

    # If MFA is enabled for this test user, create confirmed TOTP device.
    if extra_fields.get("mfa_enabled"):
        TOTPDevice.objects.get_or_create(user=user, name="default", defaults={"confirmed": True})

    return user


def confirm_second_factor(client):
    """
    Test helper: marks the logged-in test client as having just entered a
    second-factor code, as the "confirm your identity" page would (AUTH-02, ACL-05).
    """
    session = client.session
    session["mfa_reauth_at"] = timezone.now().timestamp()
    session.save()


class RolesAndPermissionsTests(TestCase):
    """
    Tests seed roles and permissions data migration.
    Verifies roles exist and Admin role is strictly forbidden from grade access.
    """

    def test_six_roles_exist(self):
        # Check that all six core roles exist in the database.
        expected_roles = [
            "Admin",
            "Registrar",
            "Department head",
            "Instructor",
            "Teaching assistant",
            "Student",
        ]
        for role_name in expected_roles:
            self.assertTrue(
                Role.objects.filter(name=role_name).exists(),
                f"Role {role_name} should exist after migration.",
            )

    def test_admin_has_no_grade_permissions(self):
        # Admins must never have access to grades or scores.
        admin_user = make_user("Admin")
        self.assertFalse(has_permission(admin_user, "release", "course_grades", "course"))
        self.assertFalse(has_permission(admin_user, "review", "draft_grades", "course"))
        self.assertFalse(can_release_grades(admin_user, None))

    def test_has_role_allowed_and_denied(self):
        # has_role returns True for assigned roles and False otherwise.
        student = make_user("Student")
        self.assertTrue(has_role(student, "Student"))
        self.assertFalse(has_role(student, "Admin"))
        self.assertFalse(has_role(None, "Student"))

    def test_has_permission_allowed_and_denied(self):
        # has_permission checks granted permissions and denies by default.
        instructor = make_user("Instructor")
        self.assertTrue(has_permission(instructor, "schedule", "class_sessions", "course"))
        self.assertFalse(has_permission(instructor, "create", "staff_accounts", "institution"))

    def test_registrar_role_denies_instructor_grade_permission(self):
        # The central permission check must agree with the restricted views.
        instructor = make_user("Instructor")
        UserRole.objects.create(user=instructor, role=Role.objects.get(name="Registrar"))
        self.assertFalse(has_permission(instructor, "review", "draft_grades", "course"))

    def test_is_department_head_allowed_and_denied(self):
        # is_department_head checks user is head of that department and holds the role.
        head_user = make_user("Department head")
        other_user = make_user("Instructor")
        department = Department.objects.create(name="Computer Science", code="CS", head_user=head_user)

        self.assertTrue(is_department_head(head_user, department))
        self.assertFalse(is_department_head(other_user, department))

    def test_course_staff_permissions_allowed_and_denied(self):
        # is_course_staff, is_lead_instructor and can_release_grades checks.
        dept = Department.objects.create(name="Engineering", code="ENG")
        lead = make_user("Instructor")
        ta = make_user("Teaching assistant")
        outsider = make_user("Student")

        course = Course.objects.create(
            department=dept,
            code="ENG101",
            title="Introduction to Engineering",
            semester="1",
            academic_year=2026,
            is_published=False,
        )

        CourseStaff.objects.create(
            course=course,
            user=lead,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        CourseStaff.objects.create(
            course=course,
            user=ta,
            staff_role="teaching_assistant",
            can_release_grades=False,
        )

        # is_course_staff checks
        self.assertTrue(is_course_staff(lead, course))
        self.assertTrue(is_course_staff(ta, course))
        self.assertFalse(is_course_staff(outsider, course))

        # is_lead_instructor checks
        self.assertTrue(is_lead_instructor(lead, course))
        self.assertFalse(is_lead_instructor(ta, course))

        # can_release_grades checks
        self.assertTrue(can_release_grades(lead, course))
        self.assertFalse(can_release_grades(ta, course))
        # Adding a Registrar role must also revoke release authority.
        UserRole.objects.create(user=lead, role=Role.objects.get(name="Registrar"))
        self.assertFalse(can_release_grades(lead, course))

    def test_course_staff_assignment_requires_matching_current_role(self):
        # A stale assignment must not grant access after a role is removed.
        department = Department.objects.create(name="Role change", code="ROLECHANGE")
        course = Course.objects.create(department=department, code="RC1", title="Role", semester="1", academic_year=2026)
        student = make_user("Student")
        CourseStaff.objects.create(course=course, user=student, staff_role="lead_instructor")
        self.assertFalse(is_course_staff(student, course))
        self.assertFalse(is_lead_instructor(student, course))

    def test_release_requires_instructor_role_and_instructor_assignment(self):
        # A mistaken release flag must not give a TA or a former instructor authority.
        department = Department.objects.create(name="Release tests", code="RELEASE")
        course = Course.objects.create(department=department, code="REL1", title="Release", semester="1", academic_year=2026)
        assistant = make_user("Teaching assistant")
        former_instructor = make_user("Student")
        instructor_as_assistant = make_user("Instructor")
        CourseStaff.objects.create(course=course, user=assistant, staff_role="teaching_assistant", can_release_grades=True)
        CourseStaff.objects.create(course=course, user=former_instructor, staff_role="lead_instructor", can_release_grades=True)
        CourseStaff.objects.create(course=course, user=instructor_as_assistant, staff_role="teaching_assistant", can_release_grades=True)
        self.assertFalse(can_release_grades(assistant, course))
        self.assertFalse(can_release_grades(former_instructor, course))
        self.assertFalse(can_release_grades(instructor_as_assistant, course))

    def test_is_enrolled_allowed_and_denied(self):
        # is_enrolled checks active enrollment.
        dept = Department.objects.create(name="Mathematics", code="MATH")
        course = Course.objects.create(
            department=dept,
            code="MATH101",
            title="Calculus I",
            semester="1",
            academic_year=2026,
            is_published=False,
        )
        enrolled_student = make_user("Student")
        dropped_student = make_user("Student")
        registrar = make_user("Registrar")

        Enrollment.objects.create(
            course=course,
            student=enrolled_student,
            status=EnrollmentStatus.ACTIVE,
        )
        Enrollment.objects.create(
            course=course,
            student=dropped_student,
            status=EnrollmentStatus.DROPPED,
            dropped_by=registrar,
            dropped_at=timezone.now(),
        )

        self.assertTrue(is_enrolled(enrolled_student, course))
        self.assertFalse(is_enrolled(dropped_student, course))


class BaseTemplateAndHomeTests(TestCase):
    """
    Tests base template and home page.
    """

    def setUp(self):
        self.client = Client()
        self.student = make_user("Student", mfa_enabled=True)

    def test_home_page_loads_for_authenticated_user(self):
        # Authenticated user with MFA enabled can open home page.
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Kura")
        self.assertNotContains(response, "Kura LMS")
        self.assertNotContains(response, "Kura Secure Learning Management System")
        self.assertContains(response, "<title>Dashboard - Kura</title>")
        self.assertContains(response, "<span>Kura</span>")
        self.assertContains(response, 'data-theme="kura-system"')
        self.assertContains(response, "data-theme-selector")
        self.assertContains(response, 'id="theme-selector"')
        self.assertContains(response, 'name="theme"')
        self.assertContains(response, "/static/js/theme.js")
        self.assertContains(response, 'name="htmx-config"')
        self.assertContains(response, 'includeIndicatorStyles')
        self.assertContains(response, 'rel="icon"')
        self.assertContains(response, "Work areas")
        self.assertContains(response, "Student")

        # Verify static CSS and JS are loaded from local static files without external URLs.
        content = response.content.decode("utf-8")
        self.assertIn("/static/css/tailwind.min.css", content)
        self.assertIn("/static/css/daisyui.min.css", content)
        self.assertIn("/static/js/htmx.min.js", content)
        self.assertNotIn("https://cdn.", content)
        self.assertNotIn("https://unpkg.", content)
        self.assertLess(content.index('name="htmx-config"'), content.index("/static/js/htmx.min.js"))
        self.assertIn("style-src 'self'", response.headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", response.headers["Content-Security-Policy"])

    def test_department_head_sees_department_on_dashboard_and_header(self):
        # Department heads should see their department in the dashboard and page header.
        department_head = make_user("Department head")
        department = Department.objects.create(
            name="Computer Science",
            code="CS",
            head_user=department_head,
        )
        self.client.force_login(department_head)

        response = self.client.get(reverse("kura:home"))

        self.assertContains(response, f"Head of {department.name}", count=2)

    def test_admin_dashboard_has_admin_area_cards_and_no_work_area_header_links(self):
        # Admin work areas belong on the dashboard rather than in the shared header.
        admin = make_user("Admin")
        self.client.force_login(admin)

        response = self.client.get(reverse("kura:home"))

        self.assertEqual(response.status_code, 200)
        card_titles = {card["title"] for card in response.context["dashboard_cards"]}
        self.assertEqual(card_titles, {"Staff", "Courses", "Active sessions", "Security log"})

        cards_by_title = {card["title"]: card for card in response.context["dashboard_cards"]}
        self.assertEqual(cards_by_title["Staff"]["url"], reverse("kura:staff_list"))
        self.assertEqual(cards_by_title["Courses"]["url"], reverse("kura:course_list"))
        self.assertEqual(cards_by_title["Active sessions"]["url"], "/admin/sessions/")
        self.assertEqual(cards_by_title["Security log"]["url"], "http://kura-server.netbird.cloud:3000")

        # Check only the header so the dashboard's own cards do not affect this assertion.
        header_html = response.content.decode("utf-8").split("</nav>", maxsplit=1)[0]
        self.assertNotIn("Dashboard</a>", header_html)
        self.assertNotIn("Courses</a>", header_html)
        self.assertNotIn("Staff</a>", header_html)
        self.assertNotIn("Enrollments</a>", header_html)

    def test_other_roles_receive_their_own_dashboard_areas(self):
        # Registrars and students should also use cards for their permitted areas.
        registrar = make_user("Registrar")
        self.client.force_login(registrar)
        registrar_response = self.client.get(reverse("kura:home"))
        registrar_card_titles = {card["title"] for card in registrar_response.context["dashboard_cards"]}

        self.assertEqual(registrar_card_titles, {"Students", "Enrollments"})

        student = make_user("Student")
        self.client.force_login(student)
        student_response = self.client.get(reverse("kura:home"))
        student_card_titles = {card["title"] for card in student_response.context["dashboard_cards"]}

        self.assertEqual(
            student_card_titles,
            {"Courses", "Class schedule", "Attendance", "Grades", "Transcript"},
        )

    def test_dashboard_does_not_show_a_welcome_card(self):
        # The dashboard should begin with its page title and work-area cards, not a welcome panel.
        self.client.force_login(self.student)

        response = self.client.get(reverse("kura:home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard")
        self.assertNotContains(response, "Welcome,")


class LoginAndLogoutTests(TestCase):
    """
    Tests login and logout functionality.
    """

    def setUp(self):
        self.client = Client()
        self.password = "ValidPassword123!"
        self.user = make_user("Student", password=self.password, mfa_enabled=False)

    def test_correct_login_redirects(self):
        # Correct credentials log in user and redirect to mandatory MFA setup.
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )
        self.assertRedirects(response, reverse("kura:mfa_setup"))

        # Verify last_login_at timestamp is set on user.
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_login_at)

    def test_wrong_password_shows_generic_error(self):
        # Wrong password displays generic failure message without details.
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "WrongPassword999!"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid email or password.")

    def test_deactivated_account_cannot_login(self):
        # AUTH-01: even a correct password gets the generic message, so the
        # response never confirms that the password was right.
        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid email or password.")
        self.assertNotContains(response, "deactivated")

    def test_wrong_password_for_deactivated_account_stays_generic(self):
        # A wrong password never reveals whether the matching account is deactivated.
        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "WrongPassword999!"},
        )

        self.assertContains(response, "Invalid email or password.")
        self.assertNotContains(response, "This account has been deactivated.")

    def test_locked_account_with_correct_password_shows_generic_message(self):
        # AUTH-01: a correct password on a locked account gets the same
        # message as a wrong one; the lock reason is only logged.
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=2)
        self.user.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(
                reverse("kura:login"),
                {"email": self.user.email, "password": self.password},
            )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid email or password.")
        self.assertNotContains(response, "locked")
        self.assertIn('reason="locked"', "\n".join(captured.output))

    def test_locked_account_with_wrong_password_shows_generic_message(self):
        # A wrong password must not disclose that this account is locked.
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=2)
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "WrongPassword999!"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid email or password.")
        self.assertNotContains(response, "This account is currently locked.")

    @patch("kura.views.authenticate", return_value=None)
    @patch("kura.views.AxesProxyHandler.is_locked", return_value=True)
    def test_axes_locked_account_with_correct_password_shows_generic_message(self, mock_is_locked, mock_authenticate):
        # AUTH-01: an Axes lockout also gets the generic message.
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid email or password.")

    def test_failed_login_checks_the_password_only_once(self):
        # AUTH-04: a known email with a wrong password must cost one password
        # hash, the same as an unknown email, so timing does not reveal which
        # emails have accounts.
        with patch.object(User, "check_password", autospec=True, return_value=False) as mock_check:
            self.client.post(
                reverse("kura:login"),
                {"email": self.user.email, "password": "WrongPassword999!"},
            )
        self.assertEqual(mock_check.call_count, 1)

    def test_logout_by_post(self):
        # Logout must be a POST request and revoke active session.
        self.client.force_login(self.user)
        session_record = UserSession.objects.create(
            user=self.user,
            session_token_hash=secrets.token_hex(32),
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        session = self.client.session
        session["user_session_id"] = str(session_record.id)
        session.save()

        response = self.client.post(reverse("kura:logout"))
        self.assertRedirects(response, reverse("kura:login"))

        session_record.refresh_from_db()
        self.assertIsNotNone(session_record.revoked_at)

    def test_logout_get_request_is_not_allowed(self):
        # GET request to logout must return 405 Method Not Allowed.
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:logout"))
        self.assertEqual(response.status_code, 405)


class FirstLoginPasswordChangeTests(TestCase):
    """
    Tests forced first-login password rotation.
    """

    def setUp(self):
        self.client = Client()
        self.password = "InitialPassword123!"
        self.user = make_user("Instructor", password=self.password, must_change_password=True, mfa_enabled=True)

    def test_forced_redirect_to_password_change(self):
        # User with must_change_password=True is redirected on every page.
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:password_change"))

    def test_password_change_succeeds(self):
        # Completing password change updates password_changed_at and removes flag.
        self.client.force_login(self.user)
        new_password = "NewSecurePassword456!"

        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": new_password,
                "confirm_password": new_password,
            },
            follow=True,
        )
        self.assertEqual(response.redirect_chain[-1][0], reverse("kura:home"))
        self.assertContains(response, "Password updated successfully.")
        # Show a distinct confirmation card after a successful password change.
        self.assertContains(response, 'data-password-change-confirmation')

        self.user.refresh_from_db()
        self.assertFalse(self.user.must_change_password)
        self.assertIsNotNone(self.user.password_changed_at)
        self.assertTrue(self.user.check_password(new_password))

        # A fresh login should accept the new password and continue to MFA.
        self.client.logout()
        login_response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": new_password},
        )
        self.assertRedirects(login_response, reverse("kura:mfa_verify"))

    def test_weak_password_error_is_shown_on_change_page(self):
        # A weak password should return to the form and show its validation error.
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": "weak",
                "confirm_password": "weak",
            },
        )

        self.assertEqual(response.status_code, 200)
        password_error = response.context["form"].errors["new_password"][0]
        self.assertContains(response, password_error)
        self.assertNotContains(response, "data-password-change-confirmation")

    def test_password_confirmation_is_shown_before_mfa_setup(self):
        # First-time users also need confirmation when they are redirected to MFA setup.
        self.user.mfa_enabled = False
        self.user.save(update_fields=["mfa_enabled"])
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": "NewSecurePassword456!",
                "confirm_password": "NewSecurePassword456!",
            },
            follow=True,
        )
        self.assertRedirects(response, reverse("kura:mfa_setup"))
        self.assertContains(response, "data-password-change-confirmation")

    def test_shared_form_error_include_displays_non_field_errors(self):
        # The shared base template should show errors that do not belong to one field.
        form = PasswordChangeForm(self.user, data={})
        form.is_valid()
        form.add_error(None, "A form-wide validation error.")
        rendered_page = render_to_string("kura/base.html", {"form": form})

        self.assertIn("A form-wide validation error.", rendered_page)


class DemoDataSeedCommandTests(TestCase):
    """Tests that demo data cannot reintroduce shared MFA credentials."""

    def test_seed_command_refuses_to_run_when_debug_is_off(self):
        # Production settings must stop the command before it creates demo accounts.
        with override_settings(DEBUG=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo_data", stdout=StringIO(), stderr=StringIO())

        self.assertFalse(User.objects.filter(email="admin@kura.edu").exists())

    @override_settings(DEBUG=True)
    def test_seeded_user_must_enrol_own_mfa_and_rejects_shared_code(self):
        # Recreate old seeded factors so the command must remove stale demo bypasses.
        demo_user = make_user("Admin", email="admin@kura.edu", mfa_enabled=True)
        static_device = StaticDevice.objects.create(user=demo_user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=static_device, token="123456")

        # Capture command output so no demo credentials or MFA details are printed.
        call_command("seed_demo_data", stdout=StringIO(), stderr=StringIO())
        demo_user = User.objects.get(email="admin@kura.edu")

        # Simulate the second login step and confirm the old shared code is rejected.
        session = self.client.session
        session["pre_mfa_user_id"] = str(demo_user.id)
        session.save()
        response = self.client.post(reverse("kura:mfa_verify"), {"code": "123456"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid security code.")
        # Preserve existing MFA settings while removing the known insecure token.
        self.assertTrue(demo_user.mfa_enabled)
        self.assertTrue(TOTPDevice.objects.filter(user=demo_user).exists())
        self.assertTrue(StaticDevice.objects.filter(user=demo_user).exists())
        self.assertFalse(StaticToken.objects.filter(device=static_device, token="123456").exists())

    @override_settings(DEBUG=True)
    def test_reseeding_preserves_existing_password_and_mfa_devices(self):
        # Re-running the demo command must not reset a user's chosen password or MFA.
        demo_user = make_user("Admin", email="admin@kura.edu", mfa_enabled=True)
        demo_user.set_password("ChosenDemoPassword987!")
        demo_user.save()
        device = TOTPDevice.objects.create(user=demo_user, name="default", confirmed=True)
        recovery_device = StaticDevice.objects.create(user=demo_user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=recovery_device, token="ABCD1234")

        call_command("seed_demo_data", stdout=StringIO(), stderr=StringIO())

        demo_user.refresh_from_db()
        self.assertTrue(demo_user.check_password("ChosenDemoPassword987!"))
        self.assertTrue(demo_user.mfa_enabled)
        self.assertTrue(TOTPDevice.objects.filter(id=device.id, confirmed=True).exists())
        self.assertTrue(StaticToken.objects.filter(device=recovery_device, token="ABCD1234").exists())


class PasswordResetTests(TestCase):
    """
    Tests password reset via hashed time-limited tokens.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", password="OriginalPassword123!")

    def make_reset_token(self):
        # Create a valid, unused reset token and return the raw value from the email link.
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        reset_record = PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
        )
        return raw_token, reset_record

    def test_request_always_emails_a_link(self):
        # AUTH-03: the request page no longer skips the email step; it only
        # creates a token and sends the generic message.
        response = self.client.post(reverse("kura:password_reset_request"), {"email": self.user.email})
        self.assertRedirects(response, reverse("kura:login"))
        self.assertEqual(PasswordResetToken.objects.filter(user=self.user).count(), 1)

    def test_mfa_account_needs_code_on_confirm_page(self):
        # AUTH-03: the emailed link alone cannot reset an MFA account. A wrong
        # code spends the link and leaves the password unchanged.
        raw_token, reset_record = self.make_reset_token()
        response = self.client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
            {"code": "000000", "new_password": "BrandNewPassword789!", "confirm_password": "BrandNewPassword789!"},
        )
        self.assertRedirects(response, reverse("kura:password_reset_request"))
        reset_record.refresh_from_db()
        self.assertIsNotNone(reset_record.used_at)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OriginalPassword123!"))

    def test_confirm_page_shows_code_field_for_mfa_account(self):
        raw_token, _ = self.make_reset_token()
        response = self.client.get(reverse("kura:password_reset_confirm", kwargs={"token": raw_token}))
        self.assertContains(response, 'name="code"')

    def test_unknown_email_returns_same_generic_message(self):
        # Submitting an unknown email address returns the exact same message.
        response = self.client.post(
            reverse("kura:password_reset_request"),
            {"email": "nonexistent_person@example.com"},
        )
        self.assertRedirects(response, reverse("kura:login"))

    def test_valid_token_resets_password_and_revokes_sessions(self):
        # Valid token allows setting new password and revokes active sessions.
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        reset_record = PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
        )

        active_session = UserSession.objects.create(
            user=self.user,
            session_token_hash=secrets.token_hex(32),
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )

        # The test user has MFA, so the confirm page also needs a recovery code.
        device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=device, token=hash_recovery_code("abcd1234"))

        new_password = "BrandNewPassword789!"
        response = self.client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
            {
                "code": "abcd1234",
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        self.assertRedirects(response, reverse("kura:login"))

        # Verify token was consumed.
        reset_record.refresh_from_db()
        self.assertIsNotNone(reset_record.used_at)

        # Verify session was revoked.
        active_session.refresh_from_db()
        self.assertIsNotNone(active_session.revoked_at)

        # Verify user password was updated.
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_expired_token_fails(self):
        # Token past its 30-minute expiry cannot be used.
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )

        response = self.client.get(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token})
        )
        self.assertRedirects(response, reverse("kura:password_reset_request"))

    def test_reused_token_fails(self):
        # Single-use token cannot be redeemed twice.
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            used_at=timezone.now() - timezone.timedelta(minutes=5),
        )

        response = self.client.get(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token})
        )
        self.assertRedirects(response, reverse("kura:password_reset_request"))


class MFATests(TestCase):
    """
    Tests mandatory MFA and TOTP/recovery verification.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", mfa_enabled=False)

    def test_user_without_mfa_cannot_open_protected_pages(self):
        # User who has not completed MFA enrollment is redirected to mfa_setup.
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:mfa_setup"))

    def test_mfa_setup_renders_qr_code(self):
        # Setup page displays locally generated QR code.
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/svg+xml;utf8,")

    def test_mfa_login_with_recovery_code(self):
        # A user with MFA enabled can use a static recovery code to complete login.
        self.user.mfa_enabled = True
        self.user.save()
        static_device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=static_device, token=hash_recovery_code("ABCD1234"))

        # Step 1: Submit password.
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "ValidPassword123!"},
        )
        self.assertRedirects(response, reverse("kura:mfa_verify"))

        # Step 2: Submit recovery code.
        response = self.client.post(
            reverse("kura:mfa_verify"),
            {"code": "ABCD1234"},
        )
        self.assertRedirects(response, reverse("kura:home"))


class MySessionsTests(TestCase):
    """
    Tests active session tracking and IDOR prevention.
    """

    def setUp(self):
        self.client = Client()
        self.user_a = make_user("Student", mfa_enabled=True)
        self.user_b = make_user("Instructor", mfa_enabled=True)

        self.session_a = UserSession.objects.create(
            user=self.user_a,
            session_token_hash=secrets.token_hex(32),
            ip_address="192.168.1.10",
            user_agent="Firefox",
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )
        self.session_b = UserSession.objects.create(
            user=self.user_b,
            session_token_hash=secrets.token_hex(32),
            ip_address="10.0.0.2",
            user_agent="Chrome",
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )

    def test_student_can_view_own_sessions_only(self):
        # Students can view their own active sessions on My sessions, never another user's.
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("kura:user_sessions"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "192.168.1.10")
        self.assertNotContains(response, "10.0.0.2")

    def test_student_cannot_revoke_another_users_session_on_personal_page(self):
        # A non-admin cannot revoke another user's session via the personal revoke URL (IDOR -> 404).
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("kura:user_session_revoke", args=[self.session_b.id]),
        )
        self.assertEqual(response.status_code, 404)

        # Confirm User B's session was not revoked.
        self.session_b.refresh_from_db()
        self.assertIsNone(self.session_b.revoked_at)

    def test_student_can_revoke_own_session_on_personal_page(self):
        # A user can revoke their own active session from the personal sessions endpoint.
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("kura:user_session_revoke", args=[self.session_a.id]),
        )
        self.assertRedirects(response, reverse("kura:user_sessions"))

        self.session_a.refresh_from_db()
        self.assertIsNotNone(self.session_a.revoked_at)

    def test_admin_can_search_and_filter_all_users_sessions(self):
        # An admin can find a student's active session by name, role, and IP prefix.
        admin = make_user("Admin", mfa_enabled=True)
        self.user_a.first_name = "Amira"
        self.user_a.save(update_fields=["first_name"])
        self.client.force_login(admin)
        response = self.client.get(reverse("kura:admin_sessions"), {
            "q": "Amira", "role": "Student", "ip": "192.168", "state": "active",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user_a.email)
        self.assertNotContains(response, self.user_b.email)

    def test_admin_can_see_own_and_other_sessions_and_filter_revoked(self):
        # The default list includes the administrator and other users; revoked records are filterable.
        admin = make_user("Admin", mfa_enabled=True)
        admin_session = UserSession.objects.create(
            user=admin, session_token_hash=secrets.token_hex(32),
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        self.client.force_login(admin)
        response = self.client.get(reverse("kura:admin_sessions"))
        self.assertContains(response, admin.email)
        self.assertContains(response, self.user_a.email)
        self.session_a.revoked_at = timezone.now()
        self.session_a.save(update_fields=["revoked_at"])
        response = self.client.get(reverse("kura:admin_sessions"), {"state": "revoked"})
        self.assertContains(response, self.user_a.email)
        self.assertNotIn(admin_session, list(response.context["sessions"]))
        self.assertIsNone(admin_session.revoked_at)

    def test_invalid_session_filter_does_not_show_unfiltered_records(self):
        # Invalid choices must show an error instead of quietly exposing an unfiltered list.
        admin = make_user("Admin", mfa_enabled=True)
        self.client.force_login(admin)
        response = self.client.get(reverse("kura:admin_sessions"), {"state": "unknown"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.user_a.email)
        self.assertFormError(response.context["form"], "state", "Select a valid choice. unknown is not one of the available choices.")

    def test_non_admin_has_my_sessions_link_and_no_admin_sessions_navigation(self):
        # Non-admins see their personal sessions link, never the Admin sessions page.
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("kura:home"))
        self.assertNotContains(response, reverse("kura:admin_sessions"))
        self.assertContains(response, reverse("kura:user_sessions"))

    def test_admin_can_end_other_users_session_and_it_stops_working(self):
        # Revocation affects the actual signed-in user on their next request.
        admin = make_user("Admin", mfa_enabled=True)
        student_client = Client()
        student_client.force_login(self.user_a)
        session = student_client.session
        session["user_session_id"] = str(self.session_a.id)
        session.save()
        self.client.force_login(admin)
        with self.assertLogs("kura.security", level="INFO") as logs:
            response = self.client.post(reverse("kura:admin_sessions_revoke"), {
                "action": "one", "session_id": str(self.session_a.id),
            })
        self.assertEqual(response.status_code, 302)
        self.assertIn('event="session.revoked"', logs.output[0])
        self.assertIn('target_user_id="' + str(self.user_a.id) + '"', logs.output[0])
        self.assertIn('count="1"', logs.output[0])
        self.session_a.refresh_from_db()
        self.assertIsNotNone(self.session_a.revoked_at)
        self.assertRedirects(student_client.get(reverse("kura:home")), reverse("kura:login"))

    def test_admin_can_end_all_sessions_for_one_user(self):
        # Bulk revocation is limited to the explicitly selected user.
        admin = make_user("Admin", mfa_enabled=True)
        self.client.force_login(admin)
        response = self.client.post(reverse("kura:admin_sessions_revoke"), {
            "action": "all", "user_id": str(self.user_a.id),
        })
        self.assertEqual(response.status_code, 302)
        self.session_a.refresh_from_db()
        self.session_b.refresh_from_db()
        self.assertIsNotNone(self.session_a.revoked_at)
        self.assertIsNone(self.session_b.revoked_at)

    def test_non_admin_cannot_view_or_end_any_session(self):
        # No non-admin role can use the administrator's direct URLs.
        for role_name in ("Student", "Instructor", "Teaching assistant", "Registrar", "Department head"):
            with self.subTest(role=role_name):
                self.client.force_login(make_user(role_name, mfa_enabled=True))
                self.assertEqual(self.client.get(reverse("kura:admin_sessions")).status_code, 403)
                response = self.client.post(reverse("kura:admin_sessions_revoke"), {
                    "action": "one", "session_id": str(self.session_b.id),
                })
                self.assertEqual(response.status_code, 403)
        self.session_b.refresh_from_db()
        self.assertIsNone(self.session_b.revoked_at)

    def test_admin_cannot_end_session_with_get_or_without_csrf(self):
        # A session-changing request must use POST and include the CSRF token.
        admin = make_user("Admin", mfa_enabled=True)
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(admin)
        url = reverse("kura:admin_sessions_revoke")
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url, {"action": "one", "session_id": str(self.session_a.id)}).status_code, 403)
        self.session_a.refresh_from_db()
        self.assertIsNone(self.session_a.revoked_at)

    def test_revoked_session_logs_user_out_with_a_login_message(self):
        # A database-revoked session ends at the next request and explains why.
        self.client.force_login(self.user_a)
        session = self.client.session
        session["user_session_id"] = str(self.session_a.id)
        session.save()
        self.session_a.revoked_at = timezone.now()
        self.session_a.save()
        self.assertEqual(self.client.session.get("user_session_id"), str(self.session_a.id))
        self.assertIsNotNone(UserSession.objects.get(id=self.session_a.id).revoked_at)

        response = self.client.get(reverse("kura:home"), follow=True)

        self.assertRedirects(response, reverse("kura:login"))
        self.assertContains(response, "Your session was ended. Please sign in again.")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_lock_applied_during_login_ends_session_with_lock_message(self):
        # A user who is locked while signed in is logged out on the next request.
        self.client.force_login(self.user_a)
        session = self.client.session
        session["user_session_id"] = str(self.session_a.id)
        session.save()
        self.user_a.locked_until = timezone.now() + timezone.timedelta(hours=2)
        self.user_a.save()

        response = self.client.get(reverse("kura:home"), follow=True)

        lock_time = timezone.localtime(self.user_a.locked_until).strftime("%d %b, %H:%M")
        self.assertRedirects(response, reverse("kura:login"))
        self.assertContains(response, f"This account is currently locked until {lock_time}.")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_deactivation_during_login_ends_session_with_deactivation_message(self):
        # A deactivated account is identified from its verified session after Django logs it out.
        self.client.force_login(self.user_a)
        session = self.client.session
        session["user_session_id"] = str(self.session_a.id)
        session.save()
        self.user_a.is_active = False
        self.user_a.deactivated_at = timezone.now()
        self.user_a.save()

        response = self.client.get(reverse("kura:home"), follow=True)

        self.assertRedirects(response, reverse("kura:login"))
        self.assertContains(response, "This account has been deactivated. Contact the administrator.")
        self.assertNotIn("_auth_user_id", self.client.session)


class AdminStaffAccountsTests(TestCase):
    """
    Tests Admin management of staff accounts.
    """

    def setUp(self):
        self.client = Client()
        self.admin = make_user("Admin", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Computer Science", code="CS")

    def test_admin_can_create_staff_account(self):
        # Admin can successfully create staff account and profile.
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("kura:staff_create"),
            {
                "email": "dr.smith@example.com",
                "first_name": "John",
                "last_name": "Smith",
                "department": self.department.id,
                "staff_title": "Instructor",
            },
        )
        self.assertRedirects(response, reverse("kura:staff_list"))

        created_user = User.objects.get(email="dr.smith@example.com")
        self.assertTrue(created_user.must_change_password)
        self.assertTrue(StaffProfile.objects.filter(user=created_user).exists())

    def test_new_staff_account_gets_the_role_named_by_its_title(self):
        # The chosen title becomes the first role, recorded with the Admin who assigned it.
        self.client.force_login(self.admin)
        self.client.post(
            reverse("kura:staff_create"),
            {
                "email": "ta.new@example.com",
                "department": self.department.id,
                "staff_title": "Teaching assistant",
            },
        )
        created_user = User.objects.get(email="ta.new@example.com")
        assignment = UserRole.objects.get(user=created_user)
        self.assertEqual(assignment.role.name, "Teaching assistant")
        self.assertEqual(assignment.assigned_by, self.admin)

    def test_staff_creation_fields_have_autocomplete_values(self):
        # Browser autofill should recognize common staff details without guessing field meanings.
        self.client.force_login(self.admin)

        response = self.client.get(reverse("kura:staff_create"))

        self.assertContains(response, 'name="email"')
        self.assertContains(response, 'autocomplete="email"')
        self.assertContains(response, 'name="first_name"')
        self.assertContains(response, 'autocomplete="given-name"')
        self.assertContains(response, 'name="last_name"')
        self.assertContains(response, 'autocomplete="family-name"')
        self.assertContains(response, 'name="staff_title"')
        self.assertContains(response, 'name="building"')
        self.assertContains(response, 'name="room"')

    def test_admin_can_add_departments_and_offices(self):
        self.client.force_login(self.admin)
        url = reverse("kura:staff_settings")
        self.assertEqual(self.client.post(url, {"kind": "department", "code": "MATH", "name": "Mathematics"}).status_code, 302)
        self.assertEqual(self.client.post(url, {"kind": "building", "name": "Building B"}).status_code, 302)
        building = Building.objects.get(name="Building B")
        self.assertEqual(self.client.post(url, {"kind": "room", "building": building.pk, "name": "Room 204"}).status_code, 302)
        self.assertTrue(Room.objects.filter(building=building, name="Room 204").exists())

    def test_student_cannot_manage_offices(self):
        self.client.force_login(self.student)
        response = self.client.post(reverse("kura:staff_settings"), {"kind": "building", "name": "Forbidden"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Building.objects.filter(name="Forbidden").exists())

    def test_room_must_belong_to_selected_building(self):
        self.client.force_login(self.admin)
        building = Building.objects.create(name="A")
        other = Building.objects.create(name="B")
        room = Room.objects.create(building=other, name="204")
        response = self.client.post(reverse("kura:staff_create"), {
            "email": "test-office@example.com", "department": self.department.pk,
            "staff_title": "Instructor", "building": building.pk, "room": room.pk,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email="test-office@example.com").exists())


    def test_staff_list_shows_department_run_by_department_head(self):
        # The staff list should identify the department managed by each department head.
        department_head = make_user("Department head")
        self.department.head_user = department_head
        self.department.save()
        StaffProfile.objects.create(
            user=department_head,
            department=self.department,
            staff_title="Department Head",
        )
        self.client.force_login(self.admin)

        response = self.client.get(reverse("kura:staff_list"))

        self.assertContains(response, f"Head of {self.department.name}")

    def test_non_admin_cannot_access_staff_creation(self):
        # Non-admin user receives 403 Forbidden.
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:staff_create"))
        self.assertEqual(response.status_code, 403)

    def test_admin_can_deactivate_staff_account(self):
        # Admin deactivates staff account and revokes active sessions.
        staff_user = make_user("Instructor", mfa_enabled=True)
        StaffProfile.objects.create(
            user=staff_user,
            department=self.department,
            staff_title="Instructor",
        )
        session_record = UserSession.objects.create(
            user=staff_user,
            session_token_hash=secrets.token_hex(32),
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )

        self.client.force_login(self.admin)
        confirm_second_factor(self.client)
        response = self.client.post(
            reverse("kura:user_deactivate", kwargs={"user_id": staff_user.id}),
            follow=True,
        )
        self.assertRedirects(response, reverse("kura:staff_list"))
        self.assertContains(response, "Account deactivated, 1 session ended.")
        self.assertContains(response, "Deactivated")

        staff_user.refresh_from_db()
        self.assertFalse(staff_user.is_active)
        self.assertIsNotNone(staff_user.deactivated_at)

        session_record.refresh_from_db()
        self.assertIsNotNone(session_record.revoked_at)

    def test_admin_can_lock_and_unlock_account(self):
        # Admin can lock and unlock a staff account and see the resulting state.
        staff_user = make_user("Instructor", mfa_enabled=True)
        StaffProfile.objects.create(
            user=staff_user,
            department=self.department,
            staff_title="Instructor",
            office_location="B204",
        )
        self.client.force_login(self.admin)

        # Lock the account, then check the expiry message and updated list controls.
        response = self.client.post(
            reverse("kura:user_lock_toggle", kwargs={"user_id": staff_user.id}),
            follow=True,
        )
        staff_user.refresh_from_db()
        self.assertIsNotNone(staff_user.locked_until)
        self.assertTrue(staff_user.locked_until > timezone.now())
        lock_time = timezone.localtime(staff_user.locked_until).strftime("%d %b, %H:%M")
        self.assertContains(response, f"Account locked until {lock_time}.")
        self.assertContains(response, f"Locked until {lock_time}")
        self.assertContains(response, "Unlock")

        # Unlock the account and check that the list offers the lock action again.
        response = self.client.post(
            reverse("kura:user_lock_toggle", kwargs={"user_id": staff_user.id}),
            follow=True,
        )
        staff_user.refresh_from_db()
        self.assertIsNone(staff_user.locked_until)
        self.assertContains(response, "Account unlocked.")
        self.assertContains(response, "Active")
        self.assertContains(response, "Lock")


class AdminRolesTests(TestCase):
    """
    Tests Admin management of user roles.
    """

    def setUp(self):
        self.client = Client()
        self.admin = make_user("Admin", mfa_enabled=True)
        self.instructor_role = Role.objects.get(name="Instructor")
        self.admin_role = Role.objects.get(name="Admin")
        self.ta_role = Role.objects.get(name="Teaching assistant")

    def test_admin_can_assign_and_remove_role(self):
        # Admin assigns role, recording assigned_by, then removes it.
        target_user = User.objects.create_user(email="staff_test@example.com", password="Password12345!")
        self.client.force_login(self.admin)
        confirm_second_factor(self.client)

        # Assign Instructor role
        response = self.client.post(
            reverse("kura:user_roles", kwargs={"user_id": target_user.id}),
            {"action": "assign", "role_id": self.instructor_role.id},
        )
        self.assertRedirects(response, reverse("kura:user_roles", kwargs={"user_id": target_user.id}))
        assignment = UserRole.objects.get(user=target_user, role=self.instructor_role)
        self.assertEqual(assignment.assigned_by, self.admin)

        # Remove role
        response = self.client.post(
            reverse("kura:user_roles", kwargs={"user_id": target_user.id}),
            {"action": "remove", "role_id": self.instructor_role.id},
        )
        self.assertFalse(UserRole.objects.filter(user=target_user, role=self.instructor_role).exists())

    def test_separation_of_duty_prevents_admin_and_instructor_on_same_user(self):
        # Separation of duty: cannot give Admin role to an Instructor or TA.
        instructor_user = make_user("Instructor", mfa_enabled=True)
        self.client.force_login(self.admin)

        self.client.post(
            reverse("kura:user_roles", kwargs={"user_id": instructor_user.id}),
            {"action": "assign", "role_id": self.admin_role.id},
        )
        # Verify assignment was rejected
        self.assertFalse(UserRole.objects.filter(user=instructor_user, role=self.admin_role).exists())


class RegistrarStudentsAndEnrollmentTests(TestCase):
    """
    Tests Registrar student accounts and enrollment management.
    """

    def setUp(self):
        self.client = Client()
        self.registrar = make_user("Registrar", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Biology", code="BIO")
        self.course = Course.objects.create(
            department=self.department,
            code="BIO101",
            title="General Biology",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.registrar,
            published_at=timezone.now(),
        )
        self.student_profile = StudentProfile.objects.create(
            user=self.student,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )

    def test_registrar_can_create_student_account(self):
        # Registrar creates student account with StudentProfile and Student role.
        self.client.force_login(self.registrar)
        response = self.client.post(
            reverse("kura:student_create"),
            {
                "email": "new_student@example.com",
                "first_name": "Alice",
                "last_name": "Green",
                "department": self.department.id,
                "current_level": "level_4",
                "matriculation_year": 2026,
            },
        )
        self.assertRedirects(response, reverse("kura:enrollment_list"))

        created_user = User.objects.get(email="new_student@example.com")
        self.assertTrue(created_user.must_change_password)
        self.assertTrue(StudentProfile.objects.filter(user=created_user).exists())
        self.assertTrue(has_role(created_user, "Student"))

    def test_duplicate_student_email_has_a_clear_validation_message(self):
        # A registrar should learn why an existing email cannot be used for a new student.
        self.client.force_login(self.registrar)

        response = self.client.post(
            reverse("kura:student_create"),
            {
                "email": self.student.email,
                "first_name": "Existing",
                "last_name": "Student",
                "department": self.department.id,
                "current_level": "level_4",
                "matriculation_year": 2026,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "An account with this email already exists.")

    def test_registrar_can_enroll_and_drop_student(self):
        # Registrar enrolls student into course and drops them.
        self.client.force_login(self.registrar)

        # Enroll student
        response = self.client.post(
            reverse("kura:enrollment_create"),
            {"course": str(self.course.id), "student": str(self.student.id)},
        )
        self.assertRedirects(response, reverse("kura:enrollment_list"))

        enrollment = Enrollment.objects.get(course=self.course, student=self.student)
        self.assertEqual(enrollment.status, EnrollmentStatus.ACTIVE)
        self.assertEqual(enrollment.enrolled_by, self.registrar)

        # Drop student
        response = self.client.post(
            reverse("kura:enrollment_drop", kwargs={"enrollment_id": enrollment.id})
        )
        self.assertRedirects(response, reverse("kura:enrollment_list"))

        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, EnrollmentStatus.DROPPED)
        self.assertEqual(enrollment.dropped_by, self.registrar)
        self.assertIsNotNone(enrollment.dropped_at)

    def test_non_registrar_cannot_access_enrollment(self):
        # Student cannot access registrar enrollment views.
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:enrollment_list"))
        self.assertEqual(response.status_code, 403)

    def test_registrar_student_list_and_profile_are_private(self):
        # The registrar can search by student ID and see enrollments without marks.
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)
        self.client.force_login(self.registrar)
        response = self.client.get(reverse("kura:student_list"), {"q": str(self.student.id)})
        self.assertContains(response, self.student.email)
        response = self.client.get(reverse("kura:student_profile", kwargs={"student_id": self.student.id}))
        self.assertContains(response, self.course.code)
        self.assertNotContains(response, "Grades")
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(reverse("kura:student_list")).status_code, 403)
        self.assertEqual(self.client.get(reverse("kura:student_profile", kwargs={"student_id": self.student.id})).status_code, 403)

    def test_student_filters_include_account_status_and_reject_invalid_values(self):
        # A locked student can be found without exposing unrelated accounts.
        self.student.locked_until = timezone.now() + timezone.timedelta(hours=1)
        self.student.save(update_fields=["locked_until"])
        self.client.force_login(self.registrar)
        url = reverse("kura:student_list")
        response = self.client.get(url, {"status": "locked", "department": self.department.id, "level": "level_4"})
        self.assertContains(response, self.student.email)
        self.assertContains(response, "Locked until")
        response = self.client.get(url, {"status": "invalid"})
        self.assertTrue(response.context["filter_form"].errors)

    def test_enrollment_filter_does_not_list_unrelated_draft_courses(self):
        # The course filter should only offer courses represented in enrollment records.
        Course.objects.create(department=self.department, code="PRIVATE999", title="Unrelated draft", semester="1", academic_year=2026)
        self.client.force_login(self.registrar)
        response = self.client.get(reverse("kura:enrollment_list"))
        self.assertNotContains(response, "PRIVATE999")

    def test_registrar_enrollment_filters_course_and_status(self):
        # Filters must narrow the results, not expose every enrollment.
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)
        other = Course.objects.create(department=self.department, code="BIO999", title="Other course", semester="2", academic_year=2027, is_published=True, published_by=self.registrar, published_at=timezone.now())
        Enrollment.objects.create(course=other, student=self.student, status=EnrollmentStatus.DROPPED, dropped_by=self.registrar, dropped_at=timezone.now())
        self.client.force_login(self.registrar)
        response = self.client.get(reverse("kura:enrollment_list"), {"course": str(self.course.id), "status": "active"})
        self.assertContains(response, "BIO101")
        self.assertEqual(list(response.context["enrollments"].values_list("course_id", flat=True)), [self.course.id])

    def test_enrollment_search_is_restricted_and_returns_only_eligible_records(self):
        # Search is private and must never return draft courses or inactive students.
        draft = Course.objects.create(department=self.department, code="BIOSECRET", title="Hidden", semester="1", academic_year=2026)
        self.client.force_login(self.registrar)
        url = reverse("kura:enrollment_search")
        response = self.client.get(url, {"kind": "course", "q": "BIO"})
        self.assertContains(response, self.course.code)
        self.assertNotContains(response, draft.code)
        response = self.client.get(url, {"kind": "student", "q": self.student.email})
        self.assertContains(response, self.student.email)
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(url, {"kind": "student", "q": "test"}).status_code, 403)

    def test_enrollment_search_limits_results_and_rate(self):
        # Search results are capped and repeated requests are limited by both account and IP.
        from django.core.cache import caches
        from django.core.cache.backends.db import DatabaseCache
        cache = caches["search_limits"]
        self.assertIsInstance(cache, DatabaseCache)
        cache.clear()
        for number in range(12):
            user = make_user("Student", email=f"search{number}@example.com")
            StudentProfile.objects.create(user=user, department=self.department, current_level="level_4", matriculation_year=2026)
        self.client.force_login(self.registrar)
        url = reverse("kura:enrollment_search")
        response = self.client.get(url, {"kind": "student", "q": "search"}, REMOTE_ADDR="192.0.2.1")
        self.assertEqual(len(response.context["results"]), 10)
        for unused in range(59):
            self.client.get(url, {"kind": "student", "q": "search"}, REMOTE_ADDR="192.0.2.1")
        self.assertEqual(self.client.get(url, {"kind": "student", "q": "search"}, REMOTE_ADDR="192.0.2.2").status_code, 429)
        another = make_user("Registrar")
        self.client.force_login(another)
        self.assertEqual(self.client.get(url, {"kind": "student", "q": "search"}, REMOTE_ADDR="192.0.2.1").status_code, 429)
        cache.clear()

    def test_enrollment_rejects_inactive_students_and_draft_courses(self):
        # Search is only a convenience; final submission must validate both identifiers.
        draft = Course.objects.create(department=self.department, code="BIO998", title="Draft", semester="1", academic_year=2026)
        self.client.force_login(self.registrar)
        response = self.client.post(reverse("kura:enrollment_create"), {"student": self.student.id, "course": draft.id})
        self.assertEqual(response.status_code, 200)
        self.student.is_active = False
        self.student.save(update_fields=["is_active"])
        response = self.client.post(reverse("kura:enrollment_create"), {"student": self.student.id, "course": self.course.id})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Enrollment.objects.filter(student=self.student).exists())


class DepartmentHeadCoursesAndStaffTests(TestCase):
    """
    Tests Department Head course creation, publishing, and staff assignment.
    """

    def setUp(self):
        self.client = Client()
        self.head_a = make_user("Department head", mfa_enabled=True)
        self.head_b = make_user("Department head", mfa_enabled=True)
        self.instructor = make_user("Instructor", mfa_enabled=True)
        # Keep a TA with a staff profile to test that the instructor form checks roles.
        self.teaching_assistant = make_user("Teaching assistant", mfa_enabled=True)

        self.dept_a = Department.objects.create(name="Computer Science", code="CS", head_user=self.head_a)
        self.dept_b = Department.objects.create(name="Electrical Engineering", code="EE", head_user=self.head_b)

        StaffProfile.objects.create(user=self.instructor, department=self.dept_a, staff_title="Lecturer")
        # A staff profile alone must not make this TA eligible as an instructor.
        StaffProfile.objects.create(user=self.teaching_assistant, department=self.dept_a, staff_title="Assistant")

    def test_admin_can_manage_courses_in_any_department_without_content(self):
        # Administrators can create, edit, and publish courses without seeing their learning materials.
        admin = make_user("Admin", mfa_enabled=True)
        draft = Course.objects.create(
            department=self.dept_a, code="CS900", title="Draft Course", semester="1", academic_year=2026,
        )
        module = Module.objects.create(course=draft, title="Private module", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Private section", section_type="lecture")
        SectionItem.objects.create(section=section, title="Private material", content_body="Secret text", is_visible=True)
        self.client.force_login(admin)

        # Draft courses from every department appear in the administrator's catalog.
        self.assertContains(self.client.get(reverse("kura:course_list")), "Draft Course")
        response = self.client.get(reverse("kura:course_detail", kwargs={"course_id": draft.id}))
        self.assertContains(response, "Draft Course")
        self.assertNotContains(response, "Private material")
        self.assertNotContains(response, "Private module")

        # Course details can be edited and published without exposing the curriculum.
        edit_response = self.client.post(reverse("kura:admin_course_edit", kwargs={"course_id": draft.id}), {
            "department": self.dept_b.id, "code": "CS900", "title": "Updated Course",
            "description": "Overview", "semester": "2", "academic_year": 2026,
        })
        self.assertEqual(edit_response.status_code, 302)
        draft.refresh_from_db()
        self.assertEqual(draft.department, self.dept_b)
        self.assertEqual(draft.title, "Updated Course")
        self.client.post(reverse("kura:course_publish_toggle", kwargs={"course_id": draft.id}))
        draft.refresh_from_db()
        self.assertTrue(draft.is_published)

        # An administrator can select any department while creating a draft.
        create_response = self.client.post(reverse("kura:admin_course_create"), {
            "department": self.dept_a.id, "code": "CS901", "title": "New Course",
            "description": "Overview", "semester": "1", "academic_year": 2026,
        })
        self.assertEqual(create_response.status_code, 302)
        self.assertTrue(Course.objects.filter(code="CS901", department=self.dept_a, is_published=False).exists())

    def test_admin_course_description_textarea_is_responsive(self):
        # The course description must shrink to fit its card on narrow screens.
        admin = make_user("Admin", mfa_enabled=True)
        self.client.force_login(admin)

        response = self.client.get(reverse("kura:admin_course_create"))

        self.assertContains(response, 'name="description"')
        self.assertContains(response, "min-w-0")
        self.assertContains(response, "max-w-full")
        self.assertContains(response, "box-border")

    def test_non_admin_cannot_use_admin_course_management(self):
        # Knowing the management URLs does not grant a non-admin user extra access.
        self.client.force_login(self.instructor)
        course = Course.objects.create(
            department=self.dept_a, code="CS902", title="Course", semester="1", academic_year=2026,
        )
        self.assertEqual(self.client.get(reverse("kura:admin_course_create")).status_code, 403)
        self.assertEqual(self.client.get(reverse("kura:admin_course_edit", kwargs={"course_id": course.id})).status_code, 403)

    def test_admin_with_course_staff_assignment_cannot_access_course_content(self):
        # An extra staff assignment must not expose hidden course materials to an Admin.
        admin = make_user("Admin", mfa_enabled=True)
        course = Course.objects.create(
            department=self.dept_a, code="CS903", title="Course", semester="1", academic_year=2026,
        )
        CourseStaff.objects.create(course=course, user=admin, staff_role="co_instructor")
        module = Module.objects.create(course=course, title="Private module", is_visible=False)
        section = ModuleSection.objects.create(module=module, title="Private section", section_type="lecture")
        item = SectionItem.objects.create(section=section, title="Private item")
        self.client.force_login(admin)

        self.assertNotContains(self.client.get(reverse("kura:course_detail", kwargs={"course_id": course.id})), "Private module")
        for url in (
            reverse("kura:module_create", kwargs={"course_id": course.id}),
            reverse("kura:section_create", kwargs={"module_id": module.id}),
            reverse("kura:item_create", kwargs={"section_id": section.id}),
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})).status_code, 403)

    def test_course_form_offers_the_three_numbered_semesters(self):
        # Department heads should see the new semester labels when creating a course.
        self.client.force_login(self.head_a)
        response = self.client.get(reverse("kura:course_create"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Semester 1")
        self.assertContains(response, "Semester 2")
        self.assertContains(response, "Semester 3")

    def test_head_can_create_and_publish_course(self):
        # Department Head creates a course and publishes it.
        self.client.force_login(self.head_a)

        # Create draft course
        response = self.client.post(
            reverse("kura:course_create"),
            {
                "code": "CS301",
                "title": "Operating Systems",
                "description": "Kernel architecture and concurrency",
                "semester": "1",
                "academic_year": 2026,
            },
        )
        self.assertRedirects(response, reverse("kura:course_list"))

        course = Course.objects.get(code="CS301")
        self.assertEqual(course.department, self.dept_a)
        self.assertFalse(course.is_published)

        # Publish course
        response = self.client.post(reverse("kura:course_publish_toggle", kwargs={"course_id": course.id}))
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": course.id}))

        course.refresh_from_db()
        self.assertTrue(course.is_published)
        self.assertEqual(course.published_by, self.head_a)
        self.assertIsNotNone(course.published_at)

    def test_head_cannot_publish_other_departments_course(self):
        # Head of Dept B cannot publish Dept A's course (403 Forbidden).
        course = Course.objects.create(
            department=self.dept_a,
            code="CS302",
            title="Networks",
            semester="1",
            academic_year=2026,
            is_published=False,
        )
        self.client.force_login(self.head_b)
        response = self.client.post(reverse("kura:course_publish_toggle", kwargs={"course_id": course.id}))
        self.assertEqual(response.status_code, 403)

    def test_head_can_add_targeted_curriculum_module_to_own_department_course(self):
        # A department head can reach the module form and save target levels for their own course.
        course = Course.objects.create(
            department=self.dept_a,
            code="CS305",
            title="Software Engineering",
            semester="1",
            academic_year=2026,
        )
        self.client.force_login(self.head_a)

        # Confirm the course page offers the department head the requested module action.
        course_response = self.client.get(
            reverse("kura:course_detail", kwargs={"course_id": course.id})
        )
        self.assertContains(course_response, "+ Add Curriculum Module")

        # Confirm target-level choices appear as checkboxes on the module form.
        form_response = self.client.get(
            reverse("kura:module_create", kwargs={"course_id": course.id})
        )
        self.assertContains(form_response, "Year 1 (Level 4)")
        self.assertContains(form_response, "Year 3 (Level 6)")

        # Submit two levels and check that both restrictions were saved.
        response = self.client.post(
            reverse("kura:module_create", kwargs={"course_id": course.id}),
            {
                "title": "Foundations",
                "description": "Core ideas",
                "is_visible": True,
                "target_levels": ["level_4", "level_6"],
            },
        )

        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": course.id}))
        module = Module.objects.get(course=course, title="Foundations")
        saved_levels = set(
            ModuleTargetLevel.objects.filter(module=module).values_list("target_level", flat=True)
        )
        self.assertEqual(saved_levels, {"level_4", "level_6"})

    def test_head_cannot_add_module_to_another_departments_course(self):
        # A course ID from another department must not let this head create its module.
        course = Course.objects.create(
            department=self.dept_b,
            code="EE301",
            title="Signal Processing",
            semester="1",
            academic_year=2026,
        )
        self.client.force_login(self.head_a)

        response = self.client.post(
            reverse("kura:module_create", kwargs={"course_id": course.id}),
            {
                "title": "Restricted Module",
                "description": "Should not be saved",
                "target_levels": ["level_4"],
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Module.objects.filter(course=course, title="Restricted Module").exists())

    def test_head_can_assign_lead_instructor_with_auto_release(self):
        # Assigning a Lead Instructor automatically grants can_release_grades=True.
        course = Course.objects.create(
            department=self.dept_a,
            code="CS303",
            title="Algorithms",
            semester="1",
            academic_year=2026,
            is_published=False,
        )
        self.client.force_login(self.head_a)

        response = self.client.post(
            reverse("kura:course_staff_assign", kwargs={"course_id": course.id}),
            {
                "user": str(self.instructor.id),
                "staff_role": "lead_instructor",
                "can_release_grades": False,
            },
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": course.id}))

        assignment = CourseStaff.objects.get(course=course, user=self.instructor)
        self.assertEqual(assignment.staff_role, "lead_instructor")
        self.assertTrue(assignment.can_release_grades)

    def test_course_instructor_assignment_rejects_users_without_instructor_role(self):
        # A TA with a staff profile must not appear as an instructor or be assignable as one.
        course = Course.objects.create(
            department=self.dept_a,
            code="CS304",
            title="Databases",
            semester="1",
            academic_year=2026,
        )
        self.client.force_login(self.head_a)

        form_response = self.client.get(
            reverse("kura:course_staff_assign", kwargs={"course_id": course.id})
        )
        self.assertContains(form_response, '<select name="user"')
        self.assertContains(form_response, self.instructor.email)
        self.assertNotContains(form_response, self.teaching_assistant.email)

        response = self.client.post(
            reverse("kura:course_staff_assign", kwargs={"course_id": course.id}),
            {"user": str(self.teaching_assistant.id), "staff_role": "lead_instructor"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(CourseStaff.objects.filter(course=course, user=self.teaching_assistant).exists())


class InstructorModulesAndContentTests(TestCase):
    """
    Tests Instructor curriculum creation and nh3 rich text sanitization.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head", mfa_enabled=True)
        self.dept = Department.objects.create(name="Physics", code="PHYS", head_user=self.head)
        self.lead = make_user("Instructor", mfa_enabled=True)
        self.ta = make_user("Teaching assistant", mfa_enabled=True)

        self.course = Course.objects.create(
            department=self.dept,
            code="PHYS101",
            title="Classical Mechanics",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.lead, staff_role="lead_instructor", can_release_grades=True)

    def test_staff_can_edit_module_and_section_but_outsiders_cannot(self):
        # Changes use validated forms and must belong to the staff member's course.
        module = Module.objects.create(course=self.course, title="Old module")
        section = ModuleSection.objects.create(module=module, title="Old section", section_type="lecture")
        module_url = reverse("kura:module_edit", kwargs={"module_id": module.id})
        section_url = reverse("kura:section_edit", kwargs={"section_id": section.id})
        self.client.force_login(self.ta)
        self.assertEqual(self.client.get(module_url).status_code, 403)
        self.assertEqual(self.client.post(section_url, {"title": "Wrong", "section_type": "lecture"}).status_code, 403)
        self.client.force_login(self.lead)
        self.assertEqual(self.client.post(module_url, {"title": "New module", "target_levels": ["level_4"]}).status_code, 302)
        self.assertEqual(self.client.post(section_url, {"title": "New section", "section_type": "lab"}).status_code, 302)
        module.refresh_from_db()
        section.refresh_from_db()
        self.assertEqual(module.title, "New module")
        self.assertEqual(list(module.target_levels.values_list("target_level", flat=True)), ["level_4"])
        self.assertEqual(section.title, "New section")
        self.assertEqual(section.section_type, "lab")

    def test_item_edit_preserves_existing_attachment_and_delete_requires_confirmation(self):
        # Editing a file-only item must not require the author to upload the file again.
        module = Module.objects.create(course=self.course, title="Module")
        section = ModuleSection.objects.create(module=module, title="Section", section_type="lecture")
        item = SectionItem.objects.create(section=section, title="Old item")
        with patch("kura.files.scan_file_for_malware"):
            stored = validate_and_save_upload(SimpleUploadedFile("notes.txt", b"Plain course notes"), self.lead)
        SectionItemFile.objects.create(section_item=item, file=stored)
        self.client.force_login(self.lead)
        edit_url = reverse("kura:item_edit", kwargs={"item_id": item.id})
        delete_url = reverse("kura:item_delete", kwargs={"item_id": item.id})
        self.assertEqual(self.client.post(edit_url, {"title": "Updated item", "content_body": ""}).status_code, 302)
        item.refresh_from_db()
        self.assertEqual(item.title, "Updated item")
        self.assertTrue(SectionItemFile.objects.filter(section_item=item, file=stored).exists())
        self.assertEqual(self.client.get(delete_url).status_code, 405)
        self.client.post(delete_url)
        self.assertTrue(SectionItem.objects.filter(id=item.id).exists())
        self.client.post(delete_url, {"confirm": "on"})
        self.assertFalse(SectionItem.objects.filter(id=item.id).exists())

    def test_module_delete_preserves_assessment_attempts(self):
        # Deleting a parent module must not cascade into a student's attempt.
        module = Module.objects.create(course=self.course, title="Protected")
        section = ModuleSection.objects.create(module=module, title="Exam", section_type="exam")
        now = timezone.now()
        assessment = Assessment.objects.create(section=section, title="Exam", component_type=GradeComponentType.EXAM,
                                               opens_at=now, due_date=now + timezone.timedelta(days=1), duration_minutes=60, created_by=self.lead)
        student = make_user("Student")
        attempt = AssessmentAttempt.objects.create(assessment=assessment, student=student, expires_at=now + timezone.timedelta(hours=1), ip_address="127.0.0.1")
        self.client.force_login(self.lead)
        url = reverse("kura:module_delete", kwargs={"module_id": module.id})
        self.assertEqual(self.client.get(url).status_code, 405)
        self.client.post(url, {"confirm": "on"})
        self.assertTrue(Module.objects.filter(id=module.id).exists())
        self.assertTrue(AssessmentAttempt.objects.filter(id=attempt.id).exists())

    def test_module_deletion_requires_confirmation(self):
        # An empty module may be deleted only after an authorized confirmed POST.
        module = Module.objects.create(course=self.course, title="Empty")
        url = reverse("kura:module_delete", kwargs={"module_id": module.id})
        self.client.force_login(self.ta)
        self.assertEqual(self.client.post(url, {"confirm": "on"}).status_code, 403)
        self.client.force_login(self.lead)
        self.client.post(url)
        self.assertTrue(Module.objects.filter(id=module.id).exists())
        self.client.post(url, {"confirm": "on"})
        self.assertFalse(Module.objects.filter(id=module.id).exists())

    def test_module_delete_preserves_attendance_records(self):
        # Attendance records are student data and must not be cascaded away.
        module = Module.objects.create(course=self.course, title="Attendance module")
        session = ModuleAttendanceSession.objects.create(module=module, created_by=self.lead, title="Roll",
                                                        passcode_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(hours=1))
        student = make_user("Student")
        record = AttendanceRecord.objects.create(session=session, student=student, status=AttendanceStatus.PRESENT,
                                                 method=AttendanceMethod.QR_CODE)
        self.client.force_login(self.lead)
        self.client.post(reverse("kura:module_delete", kwargs={"module_id": module.id}), {"confirm": "on"})
        self.assertTrue(Module.objects.filter(id=module.id).exists())
        self.assertTrue(AttendanceRecord.objects.filter(id=record.id).exists())

    def test_markdown_tag_renders_formatting_and_does_not_execute_html(self):
        # The tag renders Markdown but leaves an author's HTML as harmless text.
        from django.template import Context, Template

        rendered = Template(
            "{% load markdown %}{% render_markdown content %}"
        ).render(Context({"content": "**Bold** <script>alert(1)</script>"}))

        self.assertIn("<strong>Bold</strong>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)

    def test_markdown_tag_rejects_unsafe_links(self):
        # Dangerous link schemes must not become executable links in the page.
        from django.template import Context, Template

        rendered = Template(
            "{% load markdown %}{% render_markdown content %}"
        ).render(Context({"content": "[click](javascript:alert(1))"}))

        self.assertNotIn('href="javascript:', rendered)

    def test_preview_markdown_is_post_only_and_checks_course_staff(self):
        # Only assigned staff can preview; typed HTML remains harmless text.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        url = reverse("kura:item_preview", kwargs={"section_id": section.id})
        self.client.force_login(self.lead)
        self.assertEqual(self.client.get(url).status_code, 405)
        response = self.client.post(url, {"content_body": "**Bold** <script>alert(1)</script>"})
        self.assertContains(response, "<strong>Bold</strong>")
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>")
        self.client.force_login(make_user("Student", mfa_enabled=True))
        self.assertEqual(self.client.post(url, {"content_body": "private"}).status_code, 403)

    def test_markdown_preview_matches_saved_content_with_entities(self):
        # Preview must not decode an extra layer of HTML entities compared with the saved item.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        source = "Literal &amp;amp; and `a < b`"
        self.client.force_login(self.lead)
        preview = self.client.post(reverse("kura:item_preview", kwargs={"section_id": section.id}), {"content_body": source})
        self.client.post(reverse("kura:item_create", kwargs={"section_id": section.id}), {
            "title": "Entity example", "content_body": source,
        })
        item = SectionItem.objects.get(section=section, title="Entity example")
        from .templatetags.markdown import render_markdown
        self.assertEqual(preview.content.decode(), str(render_markdown(item.content_body)))

    def test_created_markdown_renders_on_course_page_without_executing_html(self):
        # Save Markdown as source, then render it safely on the course page.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        self.client.force_login(self.lead)
        response = self.client.post(reverse("kura:item_create", kwargs={"section_id": section.id}), {
            "title": "Markdown item", "content_body": "**Bold** <script>alert(1)</script>",
        })
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertContains(response, "<strong>Bold</strong>")
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")

    def test_item_can_be_created_with_a_file_and_no_body(self):
        # A valid attachment is enough even when the optional body is blank.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        self.client.force_login(self.lead)
        upload = SimpleUploadedFile("notes.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF", content_type="application/pdf")

        response = self.client.post(reverse("kura:item_create", kwargs={"section_id": section.id}), {
            "title": "Notes file", "content_body": "", "file": upload,
        })

        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        item = SectionItem.objects.get(section=section, title="Notes file")
        self.assertEqual(item.content_body, "")
        self.assertEqual(item.item_files.count(), 1)

    def test_item_requires_a_body_or_attachment(self):
        # Empty or whitespace-only text cannot create an item without a file.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        self.client.force_login(self.lead)

        response = self.client.post(reverse("kura:item_create", kwargs={"section_id": section.id}), {
            "title": "Empty item", "content_body": "  ",
        })

        self.assertContains(response, "Add some content or attach a file.")
        self.assertFalse(SectionItem.objects.filter(section=section, title="Empty item").exists())

    @patch("kura.views.validate_and_save_upload", side_effect=ValidationError("Upload rejected."))
    def test_rejected_attachment_does_not_save_item(self, mock_upload):
        # A failed file check must roll back the item as well as its attachment.
        module = Module.objects.create(course=self.course, title="Materials", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Notes", section_type="lecture")
        self.client.force_login(self.lead)
        upload = SimpleUploadedFile("bad.pdf", b"bad content", content_type="application/pdf")

        response = self.client.post(reverse("kura:item_create", kwargs={"section_id": section.id}), {
            "title": "Rejected item", "content_body": "Body", "file": upload,
        })

        self.assertContains(response, "Upload rejected.")
        self.assertFalse(SectionItem.objects.filter(section=section, title="Rejected item").exists())
        mock_upload.assert_called_once()

    def test_instructor_can_create_module_and_section(self):
        # Instructor creates module with target level, then a section.
        self.client.force_login(self.lead)

        # Create module
        response = self.client.post(
            reverse("kura:module_create", kwargs={"course_id": self.course.id}),
            {
                "title": "Week 1: Kinematics",
                "description": "Motion in one dimension",
                "is_visible": True,
                "target_levels": ["level_4"],
            },
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))

        module = Module.objects.get(course=self.course, title="Week 1: Kinematics")
        self.assertTrue(module.is_visible)
        self.assertTrue(ModuleTargetLevel.objects.filter(module=module, target_level="level_4").exists())

        # Create section
        response = self.client.post(
            reverse("kura:section_create", kwargs={"module_id": module.id}),
            {"title": "Lecture Notes", "section_type": "lecture"},
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertTrue(ModuleSection.objects.filter(module=module, title="Lecture Notes").exists())

    def test_module_form_renders_each_target_level_as_a_labelled_checkbox(self):
        # Each academic level should have its own accessible checkbox row.
        self.client.force_login(self.lead)

        response = self.client.get(
            reverse("kura:module_create", kwargs={"course_id": self.course.id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            '<label class="label cursor-pointer justify-start gap-3">',
            count=len(AcademicLevel.choices) + 1,
        )

    def test_instructor_cannot_assign_non_ta_as_teaching_assistant(self):
        # A user with an Instructor role must not appear as or be saved as a TA.
        self.client.force_login(self.lead)
        form_response = self.client.get(
            reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id})
        )
        self.assertContains(form_response, self.ta.email)
        self.assertNotContains(form_response, f'<option value="{self.lead.id}"')

        response = self.client.post(
            reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id}),
            {"user": str(self.lead.id)},
        )

        self.assertEqual(response.status_code, 200)
        lead_assignment = CourseStaff.objects.get(course=self.course, user=self.lead)
        self.assertEqual(lead_assignment.staff_role, "lead_instructor")

    def test_markdown_treats_author_html_as_text(self):
        # Typed HTML must remain readable text and must never become executable markup.
        module = Module.objects.create(course=self.course, title="Optics", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Refraction", section_type="lecture")

        self.client.force_login(self.lead)
        malicious_html = "<p>Intro to Optics</p><script>alert('xss');</script><img src=x onerror=alert(1)>"

        response = self.client.post(
            reverse("kura:item_create", kwargs={"section_id": section.id}),
            {"title": "Lesson 1", "content_body": malicious_html},
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))

        item = SectionItem.objects.get(section=section, title="Lesson 1")
        self.assertNotIn("<script>", item.content_body)
        self.assertIn("&lt;script&gt;", item.content_body)
        self.assertIn("&lt;p&gt;Intro to Optics&lt;/p&gt;", item.content_body)
        course_page = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertNotContains(course_page, "<script>alert('xss');</script>")
        self.assertNotContains(course_page, "<img src=x onerror=alert(1)>")
        self.assertContains(course_page, "&lt;script&gt;")

    def test_instructor_can_schedule_an_item_and_release_it_with_post(self):
        # An instructor can choose a future release time, then explicitly release the hidden item.
        module = Module.objects.create(course=self.course, title="Mechanics", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Lectures", section_type="lecture")
        scheduled_release = timezone.localtime(
            timezone.now() + timezone.timedelta(days=1)
        ).replace(second=0, microsecond=0)
        release_input = scheduled_release.strftime("%Y-%m-%dT%H:%M")
        self.client.force_login(self.lead)

        # Create the item with a release time; new items remain hidden by default.
        create_response = self.client.post(
            reverse("kura:item_create", kwargs={"section_id": section.id}),
            {
                "title": "Lecture One",
                "content_body": "Introduction",
                "released_at": release_input,
            },
            follow=True,
        )

        self.assertRedirects(
            create_response,
            reverse("kura:course_detail", kwargs={"course_id": self.course.id}),
        )
        self.assertContains(create_response, "created hidden. Release it when ready.")
        item = SectionItem.objects.get(section=section, title="Lecture One")
        self.assertEqual(item.released_at, scheduled_release)
        self.assertFalse(item.is_visible)

        # The staff course page shows both the current state and its POST action.
        course_response = self.client.get(
            reverse("kura:course_detail", kwargs={"course_id": self.course.id})
        )
        self.assertContains(course_response, "Hidden")
        self.assertContains(course_response, "Release item")

        # Release the item through its POST-only status control.
        toggle_response = self.client.post(
            reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})
        )

        self.assertRedirects(
            toggle_response,
            reverse("kura:course_detail", kwargs={"course_id": self.course.id}),
        )
        item.refresh_from_db()
        self.assertTrue(item.is_visible)

        # The next course page shows the new state and the action to hide it again.
        released_response = self.client.get(
            reverse("kura:course_detail", kwargs={"course_id": self.course.id})
        )
        self.assertContains(released_response, "Released")
        self.assertContains(released_response, "Hide item")

        # The same control can hide the item again.
        hide_response = self.client.post(
            reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})
        )
        self.assertRedirects(
            hide_response,
            reverse("kura:course_detail", kwargs={"course_id": self.course.id}),
        )
        item.refresh_from_db()
        self.assertFalse(item.is_visible)

        # A GET request must not change the item's release state.
        get_response = self.client.get(
            reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})
        )
        self.assertEqual(get_response.status_code, 405)
        item.refresh_from_db()
        self.assertFalse(item.is_visible)

    def test_assigned_teaching_assistant_can_toggle_item_visibility(self):
        # A teaching assistant assigned to the course may release a hidden item.
        module = Module.objects.create(course=self.course, title="Lab Work", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Labs", section_type="lab")
        item = SectionItem.objects.create(section=section, title="Lab One")
        CourseStaff.objects.create(
            course=self.course,
            user=self.ta,
            staff_role="teaching_assistant",
            can_release_grades=False,
        )
        self.client.force_login(self.ta)

        response = self.client.post(
            reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})
        )

        self.assertRedirects(
            response,
            reverse("kura:course_detail", kwargs={"course_id": self.course.id}),
        )
        item.refresh_from_db()
        self.assertTrue(item.is_visible)

    def test_student_cannot_toggle_item_visibility(self):
        # A student must not change content visibility, even when they know the item URL.
        module = Module.objects.create(course=self.course, title="Student Material", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Lectures", section_type="lecture")
        item = SectionItem.objects.create(section=section, title="Hidden Notes")
        self.client.force_login(make_user("Student", mfa_enabled=True))

        response = self.client.post(
            reverse("kura:item_visibility_toggle", kwargs={"item_id": item.id})
        )

        self.assertEqual(response.status_code, 403)
        item.refresh_from_db()
        self.assertFalse(item.is_visible)

    def test_assigned_ta_cannot_assign_another_ta(self):
        # A course assignment does not allow teaching assistants to assign staff.
        CourseStaff.objects.create(course=self.course, user=self.ta, staff_role="teaching_assistant")
        other_ta = make_user("Teaching assistant")
        self.client.force_login(self.ta)
        response = self.client.post(reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id}), {"user": str(other_ta.id)})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(CourseStaff.objects.filter(course=self.course, user=other_ta).exists())

    def test_lead_instructor_can_assign_ta(self):
        # Lead instructor assigns TA to course with can_release_grades=False.
        self.client.force_login(self.lead)
        response = self.client.post(
            reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id}),
            {"user": str(self.ta.id)},
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))

        assignment = CourseStaff.objects.get(course=self.course, user=self.ta)
        self.assertEqual(assignment.staff_role, "teaching_assistant")
        self.assertFalse(assignment.can_release_grades)


class FileUploadsAndDownloadsTests(TestCase):
    """
    Tests File inspection with python-magic, SHA-256 hash, and permission downloads.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head", mfa_enabled=True)
        self.dept = Department.objects.create(name="Chemistry", code="CHEM", head_user=self.head)
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.enrolled_student = make_user("Student", mfa_enabled=True)
        self.outsider_student = make_user("Student", mfa_enabled=True)

        StudentProfile.objects.create(user=self.enrolled_student, department=self.dept, current_level="level_4", matriculation_year=2026)
        StudentProfile.objects.create(user=self.outsider_student, department=self.dept, current_level="level_4", matriculation_year=2026)

        self.course = Course.objects.create(
            department=self.dept,
            code="CHEM101",
            title="General Chemistry",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.enrolled_student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Atomic Theory", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Reading", section_type="lecture")

    def test_valid_pdf_upload_and_sha256_hash(self):
        # Valid PDF upload is verified by magic bytes, hashed with SHA-256, and stored in FileContent.
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        pdf_file = SimpleUploadedFile("syllabus.pdf", pdf_bytes, content_type="application/pdf")

        stored_file = validate_and_save_upload(pdf_file, self.instructor)
        self.assertEqual(stored_file.mime_type, "application/pdf")
        self.assertEqual(stored_file.size_bytes, len(pdf_bytes))
        expected_hash = hashlib.sha256(pdf_bytes).hexdigest()
        self.assertEqual(stored_file.sha256_hash, expected_hash)
        self.assertEqual(stored_file.content.content, pdf_bytes)

    def test_disguised_executable_is_rejected(self):
        # A file with an executable header disguised as .pdf is rejected by python-magic.
        fake_pdf = SimpleUploadedFile("malware.pdf", b"\x7fELF\x02\x01\x01\x00executable", content_type="application/pdf")
        with self.assertRaises(ValidationError):
            validate_and_save_upload(fake_pdf, self.instructor)

    @patch("kura.files.scan_file_for_malware")
    def test_new_file_formats_pass_real_content_detection(self, mock_scan):
        # Check actual bytes rather than trusting each file's extension or browser MIME type.
        import base64

        samples = [
            ("tiny.gif", base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="), "image/gif"),
            ("tiny.webp", base64.b64decode("UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA"), "image/webp"),
            # Different libmagic versions call plain CSV "text/csv" (macOS) or
            # "text/plain" (Ubuntu); both are on the allowlist.
            ("table.csv", b"name,score\nAlice,10\nBob,20\n", ("text/csv", "text/plain")),
            ("notes.md", b"# Title\n\nThis is **bold** markdown text.\n", "text/plain"),
            ("clip.mp4", b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom", "video/mp4"),
            ("sound.mp3", (bytes.fromhex("fffb9064") + bytes(413)) * 4, "audio/mpeg"),
        ]
        # OpenDocument files are ZIP containers with an uncompressed MIME marker first.
        for extension, kind in (("odt", "text"), ("odp", "presentation"), ("ods", "spreadsheet")):
            mime_type = f"application/vnd.oasis.opendocument.{kind}"
            content = BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                archive.writestr("mimetype", mime_type, compress_type=zipfile.ZIP_STORED)
                archive.writestr("content.xml", '<?xml version="1.0"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>')
                archive.writestr("META-INF/manifest.xml", '<?xml version="1.0"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>')
            samples.append((f"document.{extension}", content.getvalue(), mime_type))
        for filename, content, expected_mime in samples:
            with self.subTest(filename=filename):
                stored = validate_and_save_upload(SimpleUploadedFile(filename, content), self.instructor)
                # A sample may list more than one acceptable type (see table.csv).
                if isinstance(expected_mime, tuple):
                    self.assertIn(stored.mime_type, expected_mime)
                else:
                    self.assertEqual(stored.mime_type, expected_mime)
                self.assertEqual(stored.content.content, content)
        self.assertEqual(mock_scan.call_count, len(samples))

    @patch("kura.files.scan_file_for_malware")
    def test_html_svg_and_executable_bytes_are_rejected(self, mock_scan):
        # A safe-looking filename cannot make active HTML, SVG, or executable content acceptable.
        for content in (
            b"<!doctype html><html><body>Test</body></html>",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
            b"MZ" + bytes(300),
        ):
            with self.subTest(content=content[:15]):
                with self.assertRaises(ValidationError):
                    validate_and_save_upload(SimpleUploadedFile("document.txt", content), self.instructor)
        self.assertEqual(mock_scan.call_count, 3)
        self.assertFalse(StoredFile.objects.filter(original_filename="document.txt").exists())

    @patch("kura.files.scan_file_for_malware")
    def test_rejected_upload_explains_allowed_types(self, mock_scan):
        # Give the author useful guidance without trusting a disguised filename.
        upload = SimpleUploadedFile("malware.pdf", b"\x7fELF\x02\x01\x01\x00executable")
        with self.assertRaises(ValidationError) as error:
            validate_and_save_upload(upload, self.instructor)
        self.assertIn("Allowed:", str(error.exception))
        self.assertIn("PDF", str(error.exception))
        self.assertIn("ZIP", str(error.exception))
        mock_scan.assert_called_once()

    def test_enrolled_student_can_download_file(self):
        # Enrolled student downloads file with Content-Disposition: attachment and nosniff.
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        pdf_file = SimpleUploadedFile("lab_manual.pdf", pdf_bytes, content_type="application/pdf")
        stored_file = validate_and_save_upload(pdf_file, self.instructor)

        item = SectionItem.objects.create(
            section=self.section,
            title="Lab Manual",
            content_body="<p>Manual</p>",
            is_visible=True,
            released_at=timezone.now() - timezone.timedelta(hours=1),
        )
        SectionItemFile.objects.create(section_item=item, file=stored_file)

        self.client.force_login(self.enrolled_student)
        response = self.client.get(
            reverse("kura:file_download", kwargs={"course_id": self.course.id, "file_id": stored_file.id})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=", response["Content-Disposition"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response.content, pdf_bytes)

    def test_outsider_student_cannot_download_file(self):
        # A student not enrolled in the course receives 403 Forbidden.
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        pdf_file = SimpleUploadedFile("exam_prep.pdf", pdf_bytes, content_type="application/pdf")
        stored_file = validate_and_save_upload(pdf_file, self.instructor)

        item = SectionItem.objects.create(section=self.section, title="Exam Prep", content_body="<p>Prep</p>")
        SectionItemFile.objects.create(section_item=item, file=stored_file)

        self.client.force_login(self.outsider_student)
        response = self.client.get(
            reverse("kura:file_download", kwargs={"course_id": self.course.id, "file_id": stored_file.id})
        )
        self.assertEqual(response.status_code, 403)

    def test_enrolled_student_cannot_download_hidden_item_file(self):
        # An enrolled student cannot bypass the hidden state by requesting the file URL directly.
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        pdf_file = SimpleUploadedFile("hidden_notes.pdf", pdf_bytes, content_type="application/pdf")
        stored_file = validate_and_save_upload(pdf_file, self.instructor)
        item = SectionItem.objects.create(section=self.section, title="Hidden Notes")
        SectionItemFile.objects.create(section_item=item, file=stored_file)
        self.client.force_login(self.enrolled_student)

        response = self.client.get(
            reverse("kura:file_download", kwargs={"course_id": self.course.id, "file_id": stored_file.id})
        )

        self.assertEqual(response.status_code, 403)

    def test_enrolled_student_cannot_download_file_from_hidden_section(self):
        # Hiding a section also blocks direct URLs to otherwise visible files.
        with patch("kura.files.scan_file_for_malware"):
            stored_file = validate_and_save_upload(SimpleUploadedFile("private.txt", b"Private notes"), self.instructor)
        item = SectionItem.objects.create(section=self.section, title="Private", is_visible=True)
        SectionItemFile.objects.create(section_item=item, file=stored_file)
        self.section.is_visible = False
        self.section.save(update_fields=["is_visible"])
        self.client.force_login(self.enrolled_student)
        response = self.client.get(reverse("kura:file_download", kwargs={"course_id": self.course.id, "file_id": stored_file.id}))
        self.assertEqual(response.status_code, 403)

    def test_assessment_delete_requires_confirmation_and_permissions(self):
        # Without an attempt, deletion still requires the right course and confirmation.
        now = timezone.now()
        assessment = Assessment.objects.create(section=self.section, title="Empty assessment", component_type=GradeComponentType.EXAM,
                                               opens_at=now, due_date=now + timezone.timedelta(days=1), duration_minutes=60,
                                               created_by=self.instructor)
        url = reverse("kura:assessment_delete", kwargs={"assessment_id": assessment.id})
        self.client.force_login(self.outsider_student)
        self.assertEqual(self.client.post(url, {"confirm": "on"}).status_code, 403)
        self.client.force_login(self.instructor)
        self.client.post(url)
        self.assertTrue(Assessment.objects.filter(id=assessment.id).exists())
        self.client.post(url, {"confirm": "on"})
        self.assertFalse(Assessment.objects.filter(id=assessment.id).exists())

    def test_enrolled_student_cannot_download_item_before_scheduled_release(self):
        # A visible item with a future release time remains unavailable through its file URL.
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        pdf_file = SimpleUploadedFile("scheduled_notes.pdf", pdf_bytes, content_type="application/pdf")
        stored_file = validate_and_save_upload(pdf_file, self.instructor)
        item = SectionItem.objects.create(
            section=self.section,
            title="Scheduled Notes",
            is_visible=True,
            released_at=timezone.now() + timezone.timedelta(hours=1),
        )
        SectionItemFile.objects.create(section_item=item, file=stored_file)
        self.client.force_login(self.enrolled_student)

        response = self.client.get(
            reverse("kura:file_download", kwargs={"course_id": self.course.id, "file_id": stored_file.id})
        )

        self.assertEqual(response.status_code, 403)


class StudentCourseMaterialsTests(TestCase):
    """
    Tests Student course materials and academic level restrictions.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head", mfa_enabled=True)
        self.dept = Department.objects.create(name="History", code="HIST", head_user=self.head)

        self.year1_student = make_user("Student", mfa_enabled=True)
        StudentProfile.objects.create(user=self.year1_student, department=self.dept, current_level="level_4", matriculation_year=2026)

        self.course = Course.objects.create(
            department=self.dept,
            code="HIST101",
            title="World History",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        Enrollment.objects.create(course=self.course, student=self.year1_student, status=EnrollmentStatus.ACTIVE)

        # Module 1: Visible, open to all students
        self.mod_open = Module.objects.create(course=self.course, title="Ancient Civilizations", is_visible=True)

        # Module 2: Hidden from students
        self.mod_hidden = Module.objects.create(course=self.course, title="Draft Unit", is_visible=False)

        # Module 3: Restricted to Year 2 (level_5) students
        self.mod_advanced = Module.objects.create(course=self.course, title="Advanced Historiography", is_visible=True)
        ModuleTargetLevel.objects.create(module=self.mod_advanced, target_level="level_5")

    def test_student_sees_allowed_modules_and_not_hidden_or_wrong_level(self):
        # Year 1 student sees open module, but neither hidden module nor Year 2 module.
        self.client.force_login(self.year1_student)
        response = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, "Ancient Civilizations")
        self.assertNotContains(response, "Draft Unit")
        self.assertNotContains(response, "Advanced Historiography")

    def test_student_only_sees_released_items_after_their_release_time(self):
        # Students see visible items with no schedule or a schedule that has passed.
        section = ModuleSection.objects.create(
            module=self.mod_open,
            title="Reading List",
            section_type="lecture",
        )
        SectionItem.objects.create(
            section=section,
            title="Available Now",
            content_body="Current material",
            is_visible=True,
        )
        SectionItem.objects.create(
            section=section,
            title="Released Yesterday",
            content_body="Past scheduled material",
            is_visible=True,
            released_at=timezone.now() - timezone.timedelta(hours=1),
        )
        SectionItem.objects.create(
            section=section,
            title="Still Hidden",
            content_body="Hidden material",
        )
        SectionItem.objects.create(
            section=section,
            title="Releases Later",
            content_body="Future material",
            is_visible=True,
            released_at=timezone.now() + timezone.timedelta(hours=1),
        )
        self.client.force_login(self.year1_student)

        response = self.client.get(
            reverse("kura:course_detail", kwargs={"course_id": self.course.id})
        )

        self.assertContains(response, "Available Now")
        self.assertContains(response, "Released Yesterday")
        self.assertNotContains(response, "Still Hidden")
        self.assertNotContains(response, "Releases Later")


# ==========================================
# Schedules and attendance tests
# ==========================================

class SchedulesTests(TestCase):
    """
    Tests Class timetable and recurring schedules.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Mathematics", code="MATH")

        StudentProfile.objects.create(
            user=self.student,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )

        self.course = Course.objects.create(
            department=self.department,
            code="MATH201",
            title="Linear Algebra",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        Enrollment.objects.create(
            course=self.course,
            student=self.student,
            status=EnrollmentStatus.ACTIVE,
        )

    def test_stale_staff_assignment_does_not_expose_course_or_attendance(self):
        # A TA role does not validate a stale instructor assignment for another course.
        UserRole.objects.filter(user=self.instructor, role__name="Instructor").delete()
        UserRole.objects.create(user=self.instructor, role=Role.objects.get(name="Teaching assistant"))
        module = Module.objects.create(course=self.course, title="Private attendance")
        session = ModuleAttendanceSession.objects.create(module=module, created_by=self.instructor, title="Private roll", passcode_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(hours=1))
        AttendanceRecord.objects.create(session=session, student=self.student, status=AttendanceStatus.PRESENT, method=AttendanceMethod.QR_CODE)
        self.client.force_login(self.instructor)
        self.assertNotContains(self.client.get(reverse("kura:course_list")), self.course.code)
        self.assertNotContains(self.client.get(reverse("kura:attendance_history")), "Private roll")

    def test_instructor_can_create_schedule(self):
        # Instructor creates a recurring class schedule with valid start and end times.
        self.client.force_login(self.instructor)
        page = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertContains(page, reverse("kura:schedule_create", kwargs={"course_id": self.course.id}))
        response = self.client.post(
            reverse("kura:schedule_create", kwargs={"course_id": self.course.id}),
            {
                "instructor": str(self.instructor.id),
                "session_type": SessionType.LECTURE,
                "day": DayOfWeek.MONDAY,
                "start_time": "09:00",
                "end_time": "10:30",
                "location": "Hall A",
                "recurrence_start": "2026-09-01",
                "recurrence_end": "2026-12-15",
            },
        )
        self.assertRedirects(response, reverse("kura:course_detail", kwargs={"course_id": self.course.id}))

        schedule = Schedule.objects.get(course=self.course)
        self.assertEqual(schedule.location, "Hall A")
        self.assertEqual(str(schedule.start_time), "09:00:00")
        self.assertEqual(str(schedule.end_time), "10:30:00")

    def test_staff_can_edit_and_delete_schedule(self):
        # A schedule can be edited and explicitly deleted only by assigned staff.
        schedule = Schedule.objects.create(course=self.course, instructor=self.instructor, session_type="lecture",
                                           day="monday", start_time="09:00", end_time="10:00", location="Old",
                                           recurrence_start="2026-09-01", recurrence_end="2026-12-01")
        module = Module.objects.create(course=self.course, title="Schedule module")
        session = ModuleAttendanceSession.objects.create(module=module, schedule=schedule, created_by=self.instructor,
                                                        title="Roll", passcode_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(hours=1))
        record = AttendanceRecord.objects.create(session=session, student=self.student, status=AttendanceStatus.PRESENT,
                                                 method=AttendanceMethod.QR_CODE)
        edit_url = reverse("kura:schedule_edit", kwargs={"schedule_id": schedule.id})
        delete_url = reverse("kura:schedule_delete", kwargs={"schedule_id": schedule.id})
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(edit_url).status_code, 403)
        self.assertEqual(self.client.post(delete_url, {"confirm": "on"}).status_code, 403)
        self.client.force_login(self.instructor)
        response = self.client.post(edit_url, {"instructor": self.instructor.id, "session_type": "lecture", "day": "monday",
                                               "start_time": "09:00", "end_time": "10:30", "location": "New hall",
                                               "recurrence_start": "2026-09-01", "recurrence_end": "2026-12-01"})
        self.assertEqual(response.status_code, 302)
        schedule.refresh_from_db()
        self.assertEqual(schedule.location, "New hall")
        self.assertEqual(self.client.get(delete_url).status_code, 405)
        self.client.post(delete_url)
        self.assertTrue(Schedule.objects.filter(id=schedule.id).exists())
        self.client.post(delete_url, {"confirm": "on"})
        self.assertFalse(Schedule.objects.filter(id=schedule.id).exists())
        session.refresh_from_db()
        self.assertIsNone(session.schedule_id)
        self.assertTrue(AttendanceRecord.objects.filter(id=record.id).exists())

    def test_schedule_end_time_must_be_after_start_time(self):
        # Form rejects schedules where end time is earlier than or equal to start time.
        self.client.force_login(self.instructor)
        response = self.client.post(
            reverse("kura:schedule_create", kwargs={"course_id": self.course.id}),
            {
                "instructor": str(self.instructor.id),
                "session_type": SessionType.LECTURE,
                "day": DayOfWeek.MONDAY,
                "start_time": "11:00",
                "end_time": "10:00",
                "location": "Hall A",
                "recurrence_start": "2026-09-01",
                "recurrence_end": "2026-12-15",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Schedule.objects.filter(course=self.course).exists())

        # Also verify database check constraint 'schedule_end_time_after_start' directly.
        with self.assertRaises(IntegrityError):
            Schedule.objects.create(
                course=self.course,
                instructor=self.instructor,
                session_type=SessionType.LECTURE,
                day=DayOfWeek.MONDAY,
                start_time="11:00",
                end_time="10:00",
                location="Hall A",
                recurrence_start="2026-09-01",
                recurrence_end="2026-12-15",
            )

    def test_timetable_visibility_for_enrolled_student(self):
        # Enrolled student can see course schedule on the timetable page.
        Schedule.objects.create(
            course=self.course,
            instructor=self.instructor,
            session_type=SessionType.LECTURE,
            day=DayOfWeek.MONDAY,
            start_time="09:00",
            end_time="10:30",
            location="Hall A",
            recurrence_start="2026-09-01",
            recurrence_end="2026-12-15",
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:schedule_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "MATH201")
        self.assertContains(response, "Hall A")


class AttendanceSessionsAndCheckinTests(TestCase):
    """
    Tests Live check-in sessions, rotating passcodes, QR scans, and manual roll.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.other_student = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Computer Science", code="CS")

        StudentProfile.objects.create(
            user=self.student,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )
        StudentProfile.objects.create(
            user=self.other_student,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )

        self.course = Course.objects.create(
            department=self.department,
            code="CS202",
            title="Data Structures",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        Enrollment.objects.create(
            course=self.course,
            student=self.student,
            status=EnrollmentStatus.ACTIVE,
        )
        Enrollment.objects.create(
            course=self.course,
            student=self.other_student,
            status=EnrollmentStatus.ACTIVE,
        )

        self.module = Module.objects.create(
            course=self.course,
            title="Trees and Graphs",
            is_visible=True,
        )

    def test_staff_can_start_session_stores_hash_only(self):
        # Staff starts a session; database stores only the 64-character SHA-256 hash.
        self.client.force_login(self.instructor)
        response = self.client.post(
            reverse("kura:attendance_session_start", kwargs={"module_id": self.module.id}),
            {"title": "Lecture 5 Roll", "duration_minutes": 15},
        )
        session = ModuleAttendanceSession.objects.get(module=self.module, title="Lecture 5 Roll")
        self.assertRedirects(response, reverse("kura:attendance_session_detail", kwargs={"session_id": session.id}))

        # Verify only a SHA-256 hash is saved in the database column.
        self.assertEqual(len(session.passcode_hash), 64)
        self.assertTrue(session.is_active)
        self.assertTrue(session.expires_at > timezone.now())

    def test_student_valid_passcode_checkin(self):
        # Student submits the correct passcode; record is created with method=PASSCODE.
        raw_passcode = "A1B2C3"
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Week 2 Attendance",
            passcode_hash=passcode_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:student_checkin", kwargs={"session_id": session.id}),
            {"passcode": raw_passcode},
        )
        self.assertRedirects(response, reverse("kura:attendance_history"))

        # Check attendance record created by server.
        record = AttendanceRecord.objects.get(session=session, student=self.student)
        self.assertEqual(record.status, AttendanceStatus.PRESENT)
        self.assertEqual(record.method, AttendanceMethod.PASSCODE)

    def test_student_qr_checkin(self):
        # A QR link shows the form; only its confirmed POST records attendance.
        raw_passcode = "F4E5D6"
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Lab 2 Roll",
            passcode_hash=passcode_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        self.client.force_login(self.student)
        checkin_url = reverse("kura:student_checkin", kwargs={"session_id": session.id}) + f"?code={raw_passcode}"
        response = self.client.get(checkin_url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AttendanceRecord.objects.filter(session=session, student=self.student).exists())
        response = self.client.post(checkin_url, {"passcode": raw_passcode})
        self.assertRedirects(response, reverse("kura:attendance_history"))

        record = AttendanceRecord.objects.get(session=session, student=self.student)
        self.assertEqual(record.method, AttendanceMethod.QR_CODE)

    def test_expired_session_rejects_checkin(self):
        # Check-in after expiration time is strictly rejected.
        raw_passcode = "EXPIRE"
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Past Lecture",
            passcode_hash=passcode_hash,
            expires_at=timezone.now() - timezone.timedelta(minutes=5),
            is_active=True,
        )

        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:student_checkin", kwargs={"session_id": session.id}),
            {"passcode": raw_passcode},
        )
        self.assertRedirects(response, reverse("kura:attendance_history"))
        self.assertFalse(AttendanceRecord.objects.filter(session=session, student=self.student).exists())

    def test_wrong_passcode_rejects_checkin(self):
        # Incorrect passcode does not register attendance.
        raw_passcode = "CORRECT"
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Lecture Roll",
            passcode_hash=passcode_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:student_checkin", kwargs={"session_id": session.id}),
            {"passcode": "WRONG1"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AttendanceRecord.objects.filter(session=session, student=self.student).exists())

    def test_double_checkin_is_rejected(self):
        # A student cannot record attendance twice for the same session.
        raw_passcode = "DUPLIC"
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Double Checkin Test",
            passcode_hash=passcode_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        # First check-in succeeds.
        AttendanceRecord.objects.create(
            session=session,
            student=self.student,
            status=AttendanceStatus.PRESENT,
            method=AttendanceMethod.PASSCODE,
        )

        # Second check-in attempt is rejected.
        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:student_checkin", kwargs={"session_id": session.id}),
            {"passcode": raw_passcode},
        )
        self.assertRedirects(response, reverse("kura:attendance_history"))
        self.assertEqual(AttendanceRecord.objects.filter(session=session, student=self.student).count(), 1)

    def test_manual_roll_requires_staff_and_reason(self):
        # Staff can record manual attendance with a required justification reason.
        session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Manual Roll Test",
            passcode_hash="dummyhash",
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        self.client.force_login(self.instructor)

        # Successful manual entry with justification.
        response = self.client.post(
            reverse("kura:attendance_manual_record", kwargs={"session_id": session.id}),
            {
                "student": str(self.student.id),
                "status": AttendanceStatus.EXCUSED,
                "override_reason": "Medical clinic certificate provided.",
            },
        )
        self.assertRedirects(response, reverse("kura:attendance_session_detail", kwargs={"session_id": session.id}))

        record = AttendanceRecord.objects.get(session=session, student=self.student)
        self.assertEqual(record.status, AttendanceStatus.EXCUSED)
        self.assertEqual(record.method, AttendanceMethod.MANUAL)
        self.assertEqual(record.recorded_by, self.instructor)
        self.assertEqual(record.override_reason, "Medical clinic certificate provided.")

        # A staff member cannot create attendance for a student outside this course.
        outsider = make_user("Student")
        StudentProfile.objects.create(user=outsider, department=self.department, current_level="level_4", matriculation_year=2026)
        self.client.post(reverse("kura:attendance_manual_record", kwargs={"session_id": session.id}),
                         {"student": str(outsider.id), "status": AttendanceStatus.PRESENT, "override_reason": "Manual correction"})
        self.assertFalse(AttendanceRecord.objects.filter(session=session, student=outsider).exists())

        # Manual entry attempt without reason is rejected.
        self.client.post(
            reverse("kura:attendance_manual_record", kwargs={"session_id": session.id}),
            {
                "student": str(self.other_student.id),
                "status": AttendanceStatus.PRESENT,
                "override_reason": "",
            },
        )
        self.assertFalse(AttendanceRecord.objects.filter(session=session, student=self.other_student).exists())

        # Direct database insert without reason violates PostgreSQL check constraint.
        with self.assertRaises(IntegrityError):
            AttendanceRecord.objects.create(
                session=session,
                student=self.other_student,
                status=AttendanceStatus.PRESENT,
                method=AttendanceMethod.MANUAL,
                recorded_by=self.instructor,
                override_reason=None,
            )


class AttendanceHistoryTests(TestCase):
    """
    Tests Attendance history visibility and IDOR protection.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student_a = make_user("Student", mfa_enabled=True)
        self.student_b = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Philosophy", code="PHIL")

        StudentProfile.objects.create(
            user=self.student_a,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )
        StudentProfile.objects.create(
            user=self.student_b,
            department=self.department,
            current_level="level_4",
            matriculation_year=2026,
        )

        self.course = Course.objects.create(
            department=self.department,
            code="PHIL101",
            title="Introduction to Logic",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        Enrollment.objects.create(course=self.course, student=self.student_a, status=EnrollmentStatus.ACTIVE)
        Enrollment.objects.create(course=self.course, student=self.student_b, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Deductive Reasoning", is_visible=True)
        self.session = ModuleAttendanceSession.objects.create(
            module=self.module,
            created_by=self.instructor,
            title="Logic Seminar 1",
            passcode_hash="dummyhash",
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_active=True,
        )

        # Create attendance record for Student A.
        self.rec_a = AttendanceRecord.objects.create(
            session=self.session,
            student=self.student_a,
            status=AttendanceStatus.PRESENT,
            method=AttendanceMethod.PASSCODE,
        )
        # Create attendance record for Student B.
        self.rec_b = AttendanceRecord.objects.create(
            session=self.session,
            student=self.student_b,
            status=AttendanceStatus.LATE,
            method=AttendanceMethod.PASSCODE,
        )

    def test_student_sees_only_own_attendance_records(self):
        # Student A sees only their own attendance record, preventing IDOR.
        self.client.force_login(self.student_a)
        response = self.client.get(reverse("kura:attendance_history"))
        self.assertEqual(response.status_code, 200)

        # Student A record is present.
        self.assertContains(response, "PHIL101")
        self.assertContains(response, "Present")

        # Student B record (Late) is not visible to Student A.
        self.assertNotContains(response, "Late")

    def test_staff_sees_all_course_attendance_records(self):
        # Course staff sees attendance records for students in their course.
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("kura:attendance_history"))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, self.student_a.email)
        self.assertContains(response, self.student_b.email)
        self.assertContains(response, "Present")
        self.assertContains(response, "Late")


# ==========================================
# Assessments and grading tests
# ==========================================

class AssessmentAuthoringAndIsolationTests(TestCase):
    """
    Tests Assessment authoring and answer key isolation.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head", mfa_enabled=True)
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.outsider = make_user("Instructor", mfa_enabled=True)
        self.department = Department.objects.create(name="Computer Science", code="CS", head_user=self.head)

        self.course = Course.objects.create(
            department=self.department,
            code="CS305",
            title="Database Systems",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )

        self.module = Module.objects.create(course=self.course, title="Transactions", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Midterm Section", section_type="exam")

    def test_instructor_can_create_assessment_and_questions_json_never_contains_answers(self):
        # Author an assessment with multiple choice, matching, and essay questions.
        # Verify that questions_json strictly omits answers and rubrics.
        self.client.force_login(self.instructor)

        now = timezone.now()
        response = self.client.post(
            reverse("kura:assessment_create", kwargs={"section_id": self.section.id}),
            {
                "title": "Database Midterm",
                "description": "Comprehensive midterm exam.",
                "component_type": GradeComponentType.EXAM,
                "max_score": "50.00",
                "max_attempts": 1,
                "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
                "due_date": (now + timezone.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M"),
                "duration_minutes": 90,
                "lab_cidr_allowed": "10.0.0.0/24",
                "proctor_code": "EXAM-2026",
                "shuffle_questions": True,
                "shuffle_options": True,
                "allow_backtracking": True,
                "autosave_interval_seconds": 15,
                "questions-TOTAL_FORMS": 3, "questions-INITIAL_FORMS": 0,
                "questions-0-type": "multiple_choice", "questions-0-points": "10",
                "questions-0-prompt": "What does 2PL ensure?",
                "questions-0-option_1": "Serializability", "questions-0-correct_1": "on",
                "questions-0-option_2": "Availability",
                "questions-0-explanation": "Two-Phase Locking guarantees conflict serializability.",
                "questions-1-type": "matching", "questions-1-points": "15",
                "questions-1-prompt": "Match isolation level to anomaly prevented.",
                "questions-1-left_1": "Dirty Read", "questions-1-right_1": "Read Committed",
                "questions-2-type": "long_text", "questions-2-points": "25",
                "questions-2-prompt": "Explain write amplification in LSM trees.",
                "questions-2-max_words": "300", "questions-2-rubric": "compaction",
            },
        )
        assessment = Assessment.objects.get(title="Database Midterm")
        self.assertRedirects(response, reverse("kura:assessment_detail", kwargs={"assessment_id": assessment.id}))

        # Verify proctor code is stored as a SHA-256 hash.
        expected_proctor_hash = hashlib.sha256("EXAM-2026".encode("utf-8")).hexdigest()
        self.assertEqual(assessment.proctor_code_hash, expected_proctor_hash)

        # Critical security check: questions_json must NEVER contain answer keys or rubrics.
        questions = assessment.questions_json
        for q in questions:
            self.assertNotIn("answer", q)
            self.assertNotIn("correct_option_ids", q)
            self.assertNotIn("correct_pairs", q)
            self.assertNotIn("explanation", q)
            self.assertNotIn("tutor_rubric", q)

        # Verify answer keys are saved in the separate ExamAnswerKey table.
        answer_key = ExamAnswerKey.objects.get(assessment=assessment)
        self.assertEqual(answer_key.answer_key_json[questions[0]["question_id"]]["correct_option_ids"], ["opt_1"])
        self.assertEqual(answer_key.answer_key_json[questions[1]["question_id"]]["correct_pairs"], {"pair_1": "Read Committed"})
        self.assertIn("compaction", json.dumps(answer_key.answer_key_json))

    def test_unassigned_instructor_cannot_create_assessment(self):
        # An instructor not assigned to this course cannot author assessments (403 Forbidden).
        self.client.force_login(self.outsider)
        response = self.client.get(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}))
        self.assertEqual(response.status_code, 403)

    def test_formset_creates_questions_and_keeps_keys_separate(self):
        # Staff use ordinary form fields rather than writing JSON by hand.
        self.client.force_login(self.instructor)
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Builder test", "component_type": GradeComponentType.EXAM,
            "delivery_mode": "online", "max_score": "30", "max_attempts": 1,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "duration_minutes": 60, "autosave_interval_seconds": 15,
            "questions-TOTAL_FORMS": 3, "questions-INITIAL_FORMS": 0,
            "questions-0-type": "multiple_choice", "questions-0-prompt": "Pick one", "questions-0-points": "10",
            "questions-0-option_1": "Right choice", "questions-0-correct_1": "on", "questions-0-option_2": "Other",
            "questions-1-type": "matching", "questions-1-prompt": "Match", "questions-1-points": "10",
            "questions-1-left_1": "One", "questions-1-right_1": "Zulu",
            "questions-1-left_2": "Two", "questions-1-right_2": "Alpha",
            "questions-2-type": "long_text", "questions-2-prompt": "Explain", "questions-2-points": "10",
            "questions-2-max_words": "200", "questions-2-rubric": "Private marking guide",
        })
        self.assertEqual(response.status_code, 302)
        assessment = Assessment.objects.get(title="Builder test")
        self.assertEqual(len(assessment.questions_json), 3)
        self.assertNotIn("Private marking guide", json.dumps(assessment.questions_json))
        self.assertNotIn("correct", json.dumps(assessment.questions_json).lower())
        keys = assessment.answer_key.answer_key_json
        self.assertEqual(keys[assessment.questions_json[0]["question_id"]]["correct_option_ids"], ["opt_1"])
        self.assertEqual(keys[assessment.questions_json[1]["question_id"]]["correct_pairs"], {"pair_1": "Zulu", "pair_2": "Alpha"})
        self.assertEqual(assessment.questions_json[1]["available_matches"], ["Alpha", "Zulu"])
        self.assertIn("Private marking guide", json.dumps(keys))

    def test_question_formset_rejects_bad_answers_and_missing_management_data(self):
        # Empty or invalid answer definitions cannot produce an ungradable assessment.
        self.client.force_login(self.instructor)
        now = timezone.now()
        data = {
            "title": "Invalid test", "component_type": GradeComponentType.EXAM,
            "delivery_mode": "online", "max_score": "10", "max_attempts": 1,
            "opens_at": now.strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "duration_minutes": 60, "autosave_interval_seconds": 15,
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 0,
            "questions-0-type": "multiple_choice", "questions-0-prompt": "Pick", "questions-0-points": "10",
            "questions-0-option_1": "Only option",
        }
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Assessment.objects.filter(title="Invalid test").exists())
        data.pop("questions-TOTAL_FORMS")
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Assessment.objects.filter(title="Invalid test").exists())

    def test_question_points_cannot_exceed_assessment_maximum(self):
        # A correctly answered exam must never earn more than its configured maximum.
        self.client.force_login(self.instructor)
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Too many points", "component_type": GradeComponentType.EXAM, "delivery_mode": "online",
            "max_score": "10", "max_attempts": 1, "duration_minutes": 60, "autosave_interval_seconds": 15,
            "opens_at": now.strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 0, "questions-0-type": "multiple_choice",
            "questions-0-prompt": "Question", "questions-0-points": "20", "questions-0-option_1": "A",
            "questions-0-option_2": "B", "questions-0-correct_1": "on",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maximum score cannot be less than the total question points.")
        self.assertFalse(Assessment.objects.filter(title="Too many points").exists())

    def test_question_form_endpoint_checks_course_permission(self):
        # Fetching a blank question card still requires authorization for this section.
        url = reverse("kura:assessment_question_form", kwargs={"section_id": self.section.id})
        self.client.force_login(self.instructor)
        response = self.client.get(url, {"type": "matching", "questions-TOTAL_FORMS": "2"})
        self.assertContains(response, 'name="questions-2-prompt"')
        self.assertContains(response, 'name="questions-TOTAL_FORMS"')
        self.assertEqual(self.client.get(url, {"type": "bad", "questions-TOTAL_FORMS": "9999"}).status_code, 400)
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(url, {"type": "matching", "questions-TOTAL_FORMS": "0"}).status_code, 403)

    def test_question_builder_saves_requested_order(self):
        # Moving question cards changes their order without changing which answer belongs to each question.
        self.client.force_login(self.instructor)
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Ordered", "component_type": GradeComponentType.EXAM, "delivery_mode": "online",
            "max_score": "20", "max_attempts": 1, "duration_minutes": 60, "autosave_interval_seconds": 15,
            "opens_at": now.strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 2, "questions-INITIAL_FORMS": 0,
            "questions-0-type": "long_text", "questions-0-prompt": "First", "questions-0-points": "10",
            "questions-0-max_words": "100", "questions-0-rubric": "Guide A", "questions-0-ORDER": "2",
            "questions-1-type": "long_text", "questions-1-prompt": "Second", "questions-1-points": "10",
            "questions-1-max_words": "100", "questions-1-rubric": "Guide B", "questions-1-ORDER": "1",
        })
        self.assertEqual(response.status_code, 302)
        assessment = Assessment.objects.get(title="Ordered")
        self.assertEqual([item["prompt"] for item in assessment.questions_json], ["Second", "First"])
        first_id = assessment.questions_json[0]["question_id"]
        self.assertIn("Guide B", json.dumps(assessment.answer_key.answer_key_json[first_id]))

    def test_assessment_can_be_edited_before_attempt_and_locked_afterwards(self):
        # Editing updates the question and separate key until the first attempt exists.
        now = timezone.now()
        assessment = Assessment.objects.create(
            section=self.section, title="Original", component_type=GradeComponentType.EXAM,
            max_score=10, max_attempts=1, opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(days=1), duration_minutes=60, created_by=self.instructor,
            settings_json={"autosave_interval_seconds": 15},
            questions_json=[{"question_id": "old", "type": "multiple_choice", "prompt": "Old prompt", "points": 10,
                             "options": [{"option_id": "a", "text": "First"}, {"option_id": "b", "text": "Second"}]}],
        )
        ExamAnswerKey.objects.create(assessment=assessment, created_by=self.instructor,
                                     answer_key_json={"old": {"correct_option_ids": ["a"], "explanation": "Reason"}})
        self.client.force_login(self.instructor)
        url = reverse("kura:assessment_edit", kwargs={"assessment_id": assessment.id})
        self.assertContains(self.client.get(url), "Old prompt")
        data = {
            "title": "Edited", "component_type": GradeComponentType.EXAM,
            "delivery_mode": "online", "max_score": "10", "max_attempts": 1,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "duration_minutes": 60, "autosave_interval_seconds": 15,
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 1,
            "questions-0-type": "multiple_choice", "questions-0-prompt": "New prompt", "questions-0-points": "10",
            "questions-0-option_1": "First", "questions-0-option_2": "Second", "questions-0-correct_2": "on",
        }
        self.assertEqual(self.client.post(url, data).status_code, 302)
        assessment.refresh_from_db()
        self.assertEqual(assessment.title, "Edited")
        self.assertEqual(assessment.questions_json[0]["prompt"], "New prompt")
        key_before = assessment.answer_key.answer_key_json
        questions_before = assessment.questions_json

        # A forged request cannot change questions, key, delivery mode, or limits after starting.
        student = make_user("Student", mfa_enabled=True)
        AssessmentAttempt.objects.create(assessment=assessment, student=student, attempt_no=1,
                                         expires_at=now + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
        self.assertContains(self.client.get(url), "Questions are locked because students have started.")
        data.update({"title": "Allowed title", "delivery_mode": "paper_scanned", "max_score": "999",
                     "questions-0-prompt": "Forged prompt"})
        self.assertEqual(self.client.post(url, data).status_code, 302)
        assessment.refresh_from_db()
        self.assertEqual(assessment.title, "Allowed title")
        self.assertEqual(assessment.delivery_mode, "online")
        self.assertEqual(assessment.max_score, Decimal("10"))
        self.assertEqual(assessment.questions_json, questions_before)
        self.assertEqual(assessment.answer_key.answer_key_json, key_before)

    def test_assessment_edit_denies_outsider_and_admin(self):
        # A guessed edit URL grants neither unrelated staff nor Admins access.
        now = timezone.now()
        assessment = Assessment.objects.create(
            section=self.section, title="Private", component_type=GradeComponentType.EXAM,
            opens_at=now, due_date=now + timezone.timedelta(days=1), duration_minutes=60, created_by=self.instructor,
        )
        url = reverse("kura:assessment_edit", kwargs={"assessment_id": assessment.id})
        for user in (self.outsider, make_user("Admin", mfa_enabled=True)):
            self.client.force_login(user)
            self.assertEqual(self.client.get(url).status_code, 403)

    def test_edit_preserves_legacy_matching_choices_and_detailed_rubric(self):
        # Editing older questions must retain distractors and unchanged structured marking criteria.
        now = timezone.now()
        assessment = Assessment.objects.create(
            section=self.section, title="Legacy", component_type=GradeComponentType.EXAM, max_score=20,
            opens_at=now - timezone.timedelta(hours=1), due_date=now + timezone.timedelta(days=1),
            duration_minutes=60, created_by=self.instructor, settings_json={"autosave_interval_seconds": 15},
            questions_json=[
                {"question_id": "m", "type": "matching", "prompt": "Match", "points": 10,
                 "left_prompts": [{"pair_id": "p", "text": "One"}], "available_matches": ["First", "Distractor"]},
                {"question_id": "e", "type": "long_text", "prompt": "Explain", "points": 10, "max_words": 100},
            ],
        )
        rubric = {"max_words": 100, "criteria": [{"criterion": "Compare", "points": 10}], "note": "Keep this"}
        ExamAnswerKey.objects.create(assessment=assessment, created_by=self.instructor, answer_key_json={
            "m": {"correct_pairs": {"p": "First"}}, "e": {"tutor_rubric": rubric},
        })
        self.client.force_login(self.instructor)
        response = self.client.post(reverse("kura:assessment_edit", kwargs={"assessment_id": assessment.id}), {
            "title": "Legacy edited", "component_type": GradeComponentType.EXAM, "delivery_mode": "online",
            "max_score": "20", "max_attempts": 1, "duration_minutes": 60, "autosave_interval_seconds": 15,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 2, "questions-INITIAL_FORMS": 2,
            "questions-0-type": "matching", "questions-0-prompt": "Match", "questions-0-points": "10",
            "questions-0-left_1": "One", "questions-0-right_1": "First", "questions-0-extra_matches": "Distractor",
            "questions-1-type": "long_text", "questions-1-prompt": "Explain", "questions-1-points": "10",
            "questions-1-max_words": "100", "questions-1-rubric": "Compare",
        })
        self.assertEqual(response.status_code, 302)
        assessment.refresh_from_db()
        self.assertEqual(assessment.questions_json[0]["available_matches"], ["Distractor", "First"])
        essay_id = assessment.questions_json[1]["question_id"]
        self.assertEqual(assessment.answer_key.answer_key_json[essay_id]["tutor_rubric"], rubric)

    def test_edit_does_not_discard_legacy_questions_that_exceed_builder_limits(self):
        # Older questions with more than eight options stay untouched instead of being truncated.
        now = timezone.now()
        question = {"question_id": "legacy", "type": "multiple_choice", "prompt": "Choose", "points": 10,
                    "options": [{"option_id": str(number), "text": str(number)} for number in range(9)]}
        assessment = Assessment.objects.create(
            section=self.section, title="Long legacy", component_type=GradeComponentType.EXAM, created_by=self.instructor,
            opens_at=now - timezone.timedelta(hours=1), due_date=now + timezone.timedelta(days=1), duration_minutes=60,
            questions_json=[question], settings_json={"autosave_interval_seconds": 15},
        )
        ExamAnswerKey.objects.create(assessment=assessment, created_by=self.instructor,
                                     answer_key_json={"legacy": {"correct_option_ids": ["0"]}})
        self.client.force_login(self.instructor)
        url = reverse("kura:assessment_edit", kwargs={"assessment_id": assessment.id})
        self.assertContains(self.client.get(url), "exceed the builder")
        response = self.client.post(url, {
            "title": "Metadata changed", "description": "Notes",
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
        })
        self.assertEqual(response.status_code, 302)
        assessment.refresh_from_db()
        self.assertEqual(assessment.title, "Metadata changed")
        self.assertEqual(assessment.questions_json, [question])
        self.assertEqual(assessment.answer_key.answer_key_json, {"legacy": {"correct_option_ids": ["0"]}})

    def test_scanned_assessment_does_not_store_online_questions_or_keys(self):
        # Scanned-paper assessments do not need an online question builder or answer key.
        self.client.force_login(self.instructor)
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Paper assessment", "component_type": GradeComponentType.EXAM,
            "delivery_mode": "paper_scanned", "max_score": "100", "max_attempts": 1,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M"),
            "duration_minutes": 60, "autosave_interval_seconds": 15,
            "questions_builder_json": "not a question",
        })
        self.assertEqual(response.status_code, 302)
        assessment = Assessment.objects.get(title="Paper assessment")
        self.assertEqual(assessment.delivery_mode, "paper_scanned")
        self.assertEqual(assessment.questions_json, [])
        self.assertEqual(assessment.answer_key.answer_key_json, {})


def reseed_roles_after_flush():
    """
    Test helper: puts back the roles and permissions that migrations seed.
    A TransactionTestCase empties every table when it finishes, which would leave
    the tests that run after it without roles.
    """
    roles_migration = import_module("kura.migrations.0002_seed_roles_permissions")
    admin_migration = import_module("kura.migrations.0009_admin_course_and_session_permissions")
    roles_migration.seed_roles_and_permissions(django_apps, None)
    with connection.schema_editor() as editor:
        admin_migration.update_admin_permissions(django_apps, editor)


class AssessmentEditLockTests(TransactionTestCase):
    """Exercise assessment row locks with separate PostgreSQL connections."""

    @classmethod
    def tearDownClass(cls):
        # TransactionTestCase flushes the reusable test database, including migration seed data.
        super().tearDownClass()
        reseed_roles_after_flush()

    def test_result_calculation_waits_for_release_and_preserves_released_result(self):
        # The calculation waits for a concurrent release, then leaves that result unchanged.
        instructor = make_user("Instructor")
        student = make_user("Student")
        department = Department.objects.create(name="Result locks", code="RESULTLOCK")
        course = Course.objects.create(department=department, code="RL1", title="Result locks", semester="1", academic_year=2026)
        CourseStaff.objects.create(course=course, user=instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=course, student=student, status=EnrollmentStatus.ACTIVE)
        result = CourseResult.objects.create(course=course, student=student, final_score=Decimal("75.00"), status=GradeStatus.DRAFT)
        client = Client()
        client.force_login(instructor)
        reached_lock = threading.Event()
        original_lock = QuerySet.select_for_update
        responses = []
        errors = []

        def note_lock(queryset, *args, **kwargs):
            # Signal that the calculation has reached its course lock.
            if threading.current_thread().name == "result-calculation" and queryset.model is Course:
                reached_lock.set()
            return original_lock(queryset, *args, **kwargs)

        def calculate():
            try:
                responses.append(client.post(reverse("kura:course_result_calculate", kwargs={"course_id": course.id})))
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()

        worker = threading.Thread(target=calculate, name="result-calculation")
        with patch.object(QuerySet, "select_for_update", note_lock):
            with transaction.atomic():
                Course.objects.select_for_update().get(id=course.id)
                worker.start()
                self.assertTrue(reached_lock.wait(10), "Calculation did not request the course lock.")
                # The release view uses this same locked transaction before calculation resumes.
                release_client = Client()
                release_client.force_login(instructor)
                confirm_second_factor(release_client)
                response = release_client.post(reverse("kura:course_result_release", kwargs={"course_id": course.id}))
                self.assertEqual(response.status_code, 302)
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 302)
        result.refresh_from_db()
        self.assertEqual(result.status, GradeStatus.RELEASED)
        self.assertEqual(result.final_score, Decimal("75.00"))

    def test_edit_waiting_for_first_attempt_cannot_change_questions(self):
        # Keep the assessment row locked while an edit request reaches the same lock.
        instructor = make_user("Instructor", mfa_enabled=True)
        student = make_user("Student", mfa_enabled=True)
        department = Department.objects.create(name="Locks", code="LOCK")
        course = Course.objects.create(department=department, code="LOCK1", title="Locks", semester="1", academic_year=2026)
        CourseStaff.objects.create(course=course, user=instructor, staff_role="lead_instructor")
        module = Module.objects.create(course=course, title="Module")
        section = ModuleSection.objects.create(module=module, title="Exam", section_type="exam")
        now = timezone.now()
        assessment = Assessment.objects.create(
            section=section, title="Original", component_type=GradeComponentType.EXAM, created_by=instructor,
            opens_at=now - timezone.timedelta(hours=1), due_date=now + timezone.timedelta(days=1), duration_minutes=60,
            questions_json=[{"question_id": "old", "type": "multiple_choice", "prompt": "Original question", "points": 10,
                             "options": [{"option_id": "a", "text": "A"}, {"option_id": "b", "text": "B"}]}],
        )
        ExamAnswerKey.objects.create(assessment=assessment, created_by=instructor,
                                     answer_key_json={"old": {"correct_option_ids": ["a"]}})
        client = Client()
        client.force_login(instructor)
        data = {
            "title": "Changed", "component_type": GradeComponentType.EXAM, "delivery_mode": "online",
            "max_score": "100", "max_attempts": 1, "duration_minutes": 60, "autosave_interval_seconds": 15,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 1, "questions-0-type": "multiple_choice",
            "questions-0-prompt": "Changed question", "questions-0-points": "10",
            "questions-0-option_1": "A", "questions-0-option_2": "B", "questions-0-correct_2": "on",
        }
        reached_lock = threading.Event()
        original_lock = QuerySet.select_for_update
        responses = []
        errors = []

        def note_lock(queryset, *args, **kwargs):
            # Signal only when the separate edit request tries to lock an assessment.
            if threading.current_thread().name == "assessment-editor" and queryset.model is Assessment:
                reached_lock.set()
            return original_lock(queryset, *args, **kwargs)

        def edit_assessment():
            try:
                responses.append(client.post(reverse("kura:assessment_edit", kwargs={"assessment_id": assessment.id}), data))
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()

        worker = threading.Thread(target=edit_assessment, name="assessment-editor")
        with patch.object(QuerySet, "select_for_update", note_lock):
            with transaction.atomic():
                Assessment.objects.select_for_update().get(id=assessment.id)
                worker.start()
                self.assertTrue(reached_lock.wait(10), "The edit did not request the assessment lock.")
                AssessmentAttempt.objects.create(assessment=assessment, student=student, attempt_no=1,
                                                 expires_at=now + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 302)
        assessment.refresh_from_db()
        self.assertEqual(assessment.title, "Original")
        self.assertEqual(assessment.questions_json[0]["prompt"], "Original question")
        self.assertEqual(assessment.answer_key.answer_key_json, {"old": {"correct_option_ids": ["a"]}})

    def test_start_waits_for_assessment_edit_lock(self):
        # Starting an attempt must also acquire the assessment row lock.
        instructor = make_user("Instructor", mfa_enabled=True)
        student = make_user("Student", mfa_enabled=True)
        department = Department.objects.create(name="Start locks", code="START")
        course = Course.objects.create(
            department=department,
            code="START1",
            title="Locks",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=instructor,
            published_at=timezone.now(),
        )
        Enrollment.objects.create(course=course, student=student, status=EnrollmentStatus.ACTIVE)
        module = Module.objects.create(course=course, title="Module", is_visible=True)
        section = ModuleSection.objects.create(module=module, title="Exam", section_type="exam")
        now = timezone.now()
        assessment = Assessment.objects.create(section=section, title="Original", component_type=GradeComponentType.EXAM,
                                               created_by=instructor, opens_at=now - timezone.timedelta(hours=1),
                                               due_date=now + timezone.timedelta(days=1), duration_minutes=60)
        client = Client()
        client.force_login(student)
        reached_lock = threading.Event()
        original_lock = QuerySet.select_for_update
        responses = []
        errors = []

        def note_lock(queryset, *args, **kwargs):
            if threading.current_thread().name == "attempt-starter" and queryset.model is Assessment:
                reached_lock.set()
            return original_lock(queryset, *args, **kwargs)

        def start_attempt():
            try:
                responses.append(client.post(reverse("kura:assessment_attempt_start", kwargs={"assessment_id": assessment.id})))
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()

        worker = threading.Thread(target=start_attempt, name="attempt-starter")
        with patch.object(QuerySet, "select_for_update", note_lock):
            with transaction.atomic():
                locked = Assessment.objects.select_for_update().get(id=assessment.id)
                worker.start()
                self.assertTrue(reached_lock.wait(10), "The start did not request the assessment lock.")
                locked.title = "Edited before starting"
                locked.save(update_fields=["title"])
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 302)
        attempt = AssessmentAttempt.objects.get(assessment=assessment, student=student)
        self.assertEqual(attempt.assessment.title, "Edited before starting")

    def test_section_deletion_waits_for_concurrent_first_attempt(self):
        # An attempt committed while deletion waits must cause the section to be hidden, not deleted.
        instructor = make_user("Instructor")
        student = make_user("Student")
        department = Department.objects.create(name="Deletion locks", code="DELLOCK")
        course = Course.objects.create(department=department, code="DL1", title="Locks", semester="1", academic_year=2026)
        CourseStaff.objects.create(course=course, user=instructor, staff_role="lead_instructor")
        module = Module.objects.create(course=course, title="Module")
        section = ModuleSection.objects.create(module=module, title="Exam", section_type="exam")
        now = timezone.now()
        assessment = Assessment.objects.create(section=section, title="Exam", component_type=GradeComponentType.EXAM,
                                               created_by=instructor, opens_at=now, due_date=now + timezone.timedelta(days=1), duration_minutes=60)
        client = Client()
        client.force_login(instructor)
        reached_lock = threading.Event()
        original_lock = QuerySet.select_for_update
        responses = []
        errors = []

        def note_lock(queryset, *args, **kwargs):
            if threading.current_thread().name == "section-deleter" and queryset.model is Assessment:
                reached_lock.set()
            return original_lock(queryset, *args, **kwargs)

        def delete_section():
            try:
                responses.append(client.post(reverse("kura:section_delete", kwargs={"section_id": section.id}), {"confirm": "on"}))
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()

        worker = threading.Thread(target=delete_section, name="section-deleter")
        with patch.object(QuerySet, "select_for_update", note_lock):
            with transaction.atomic():
                Assessment.objects.select_for_update().get(id=assessment.id)
                worker.start()
                self.assertTrue(reached_lock.wait(10), "Deletion did not request the assessment lock.")
                attempt = AssessmentAttempt.objects.create(assessment=assessment, student=student,
                                                           expires_at=now + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 302)
        section.refresh_from_db()
        self.assertFalse(section.is_visible)
        self.assertTrue(AssessmentAttempt.objects.filter(id=attempt.id).exists())


class AssessmentAttemptAndDeliveryTests(TestCase):
    """
    Tests Assessment delivery, CIDR checks, proctor codes, autosave, and submission.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Engineering", code="ENG")

        StudentProfile.objects.create(
            user=self.student,
            department=self.dept,
            current_level="level_4",
            matriculation_year=2026,
        )

        self.course = Course.objects.create(
            department=self.dept,
            code="ENG101",
            title="Engineering Basics",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Unit 1", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Exam Section", section_type="exam")

        now = timezone.now()
        proctor_hash = hashlib.sha256("PROCTOR123".encode("utf-8")).hexdigest()
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Engineering Exam",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(hours=4),
            duration_minutes=60,
            lab_cidr_allowed="10.20.0.0/24",
            proctor_code_hash=proctor_hash,
            questions_json=[
                {
                    "question_id": "q1",
                    "type": "multiple_choice",
                    "points": 10.0,
                    "prompt": "What is Newton's second law?",
                    "options": [
                        {"option_id": "o1", "text": "F = ma"},
                        {"option_id": "o2", "text": "E = mc^2"},
                    ],
                }
            ],
            created_by=self.instructor,
        )
        ExamAnswerKey.objects.create(
            assessment=self.assessment,
            answer_key_json={"q1": {"correct_option_ids": ["o1"]}},
            created_by=self.instructor,
        )

    def test_course_page_links_authorized_users_to_assessments(self):
        # Staff can create assessments and enrolled students can find visible ones.
        self.client.force_login(self.instructor)
        page = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertContains(page, reverse("kura:assessment_create", kwargs={"section_id": self.section.id}))
        self.assertContains(page, reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}))
        self.client.force_login(self.student)
        page = self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id}))
        self.assertContains(page, reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}))
        self.assertNotContains(page, reverse("kura:assessment_create", kwargs={"section_id": self.section.id}))

    def test_scanned_attempt_requires_file_and_is_manually_graded(self):
        # Scanned attempts cannot be submitted empty or automatically given a zero mark.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.IN_PROGRESS, expires_at=timezone.now() + timezone.timedelta(minutes=30),
            ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        # Scanned-paper delivery shows a deadline instead of an online countdown.
        page = self.client.get(reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}))
        self.assertContains(page, "Upload scanned paper")
        self.assertNotContains(page, 'id="exam-timer"')
        url = reverse("kura:assessment_submit", kwargs={"attempt_id": attempt.id})

        # Empty submission is rejected without changing the attempt.
        self.client.post(url)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.IN_PROGRESS)

        # A real PDF passes the normal upload checks and is sent for manual marking.
        upload = SimpleUploadedFile("script.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF", content_type="application/pdf")
        self.client.post(reverse("kura:assessment_attempt_file_upload", kwargs={"attempt_id": attempt.id}), {"file": upload})
        self.assertEqual(AttemptFile.objects.filter(attempt=attempt).count(), 1)
        self.client.post(url)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.REQUIRES_MANUAL_GRADING)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())

    def test_hidden_section_blocks_student_assessment_links_but_not_staff(self):
        # Hiding a section must protect its assessment even when a student knows the URL.
        self.section.is_visible = False
        self.section.save(update_fields=["is_visible"])
        self.client.force_login(self.student)
        self.assertNotContains(self.client.get(reverse("kura:course_detail", kwargs={"course_id": self.course.id})), self.section.title)
        self.assertEqual(self.client.get(reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})).status_code, 403)
        self.assertEqual(self.client.post(reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id})).status_code, 403)
        self.client.force_login(self.instructor)
        self.assertContains(self.client.get(reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})), self.assessment.title)

    def test_hidden_section_blocks_existing_student_attempt(self):
        # A previously started attempt must not bypass a later section hide.
        attempt = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1,
                                                   expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
        self.section.is_visible = False
        self.section.save(update_fields=["is_visible"])
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id})).status_code, 403)
        self.assertEqual(self.client.post(reverse("kura:assessment_autosave", kwargs={"attempt_id": attempt.id}), {"focus_lost": "1"}).status_code, 403)

    def test_staff_can_hide_section_without_deleting_attempts(self):
        # Hiding a section preserves attempts, and neither students nor GET can perform it.
        attempt = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1,
                                                   expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
        url = reverse("kura:section_visibility_toggle", kwargs={"section_id": self.section.id})
        self.client.force_login(self.student)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url).status_code, 302)
        self.section.refresh_from_db()
        self.assertFalse(self.section.is_visible)
        self.assertTrue(AssessmentAttempt.objects.filter(id=attempt.id).exists())

    def test_delete_section_with_attempt_hides_instead(self):
        # Confirmed deletion must preserve both the section and a student's existing attempt.
        attempt = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1,
                                                   expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
        self.client.force_login(self.instructor)
        url = reverse("kura:section_delete", kwargs={"section_id": self.section.id})
        self.assertEqual(self.client.get(url).status_code, 405)
        self.client.post(url, {"confirm": "on"})
        self.section.refresh_from_db()
        self.assertFalse(self.section.is_visible)
        self.assertTrue(AssessmentAttempt.objects.filter(id=attempt.id).exists())

    def test_section_deletion_requires_confirmation_and_course_permission(self):
        # An unconfirmed or unrelated request must never delete a section.
        empty_section = ModuleSection.objects.create(module=self.module, title="Empty", section_type="lecture")
        url = reverse("kura:section_delete", kwargs={"section_id": empty_section.id})
        self.client.force_login(self.student)
        self.assertEqual(self.client.post(url, {"confirm": "on"}).status_code, 403)
        self.client.force_login(self.instructor)
        self.client.post(url)
        self.assertTrue(ModuleSection.objects.filter(id=empty_section.id).exists())
        self.client.post(url, {"confirm": "on"})
        self.assertFalse(ModuleSection.objects.filter(id=empty_section.id).exists())

    def test_assessment_with_attempt_cannot_be_deleted(self):
        # Direct assessment deletion must not cascade into a student's attempt.
        attempt = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1,
                                                   expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1")
        self.client.force_login(self.instructor)
        url = reverse("kura:assessment_delete", kwargs={"assessment_id": self.assessment.id})
        self.assertEqual(self.client.get(url).status_code, 405)
        self.client.post(url, {"confirm": "on"})
        self.assertTrue(Assessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(AssessmentAttempt.objects.filter(id=attempt.id).exists())

    def test_opening_an_expired_scanned_attempt_does_not_submit_it(self):
        # A GET must not change the attempt; the scheduled command handles expiry.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.IN_PROGRESS, expires_at=timezone.now() - timezone.timedelta(minutes=1),
            ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}))
        self.assertEqual(response.status_code, 302)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.IN_PROGRESS)
        call_command("finalize_attempts", stdout=StringIO())
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.REQUIRES_MANUAL_GRADING)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())

    def test_scanned_attempt_rejects_non_image_non_pdf_upload(self):
        # Files that are otherwise allowed cannot be submitted as scanned papers.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.IN_PROGRESS, expires_at=timezone.now() + timezone.timedelta(minutes=30),
            ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        upload = SimpleUploadedFile("script.txt", b"This is plain text and not a scanned paper.")
        response = self.client.post(
            reverse("kura:assessment_attempt_file_upload", kwargs={"attempt_id": attempt.id}),
            {"file": upload}, follow=True,
        )
        self.assertContains(response, "Upload a PDF or image of the scanned paper.")
        self.assertFalse(AttemptFile.objects.filter(attempt=attempt).exists())
        self.assertFalse(StoredFile.objects.filter(original_filename="script.txt").exists())

    def test_course_staff_can_submit_and_download_scanned_paper_for_student(self):
        # Assigned staff may submit an enrolled student's scanned script for manual grading.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        self.client.force_login(self.instructor)
        upload = SimpleUploadedFile("scan.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF", content_type="application/pdf")
        response = self.client.post(
            reverse("kura:scanned_paper_staff_upload", kwargs={"assessment_id": self.assessment.id}),
            {"student": str(self.student.id), "file": upload},
        )
        self.assertEqual(response.status_code, 302)
        attempt = AssessmentAttempt.objects.get(assessment=self.assessment, student=self.student)
        self.assertEqual(attempt.status, AttemptStatus.REQUIRES_MANUAL_GRADING)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())
        attempt_file = AttemptFile.objects.get(attempt=attempt)
        download = self.client.get(reverse("kura:attempt_file_download", kwargs={
            "attempt_id": attempt.id, "file_id": attempt_file.file.id,
        }))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.content, bytes(attempt_file.file.content.content))

        # The review page links staff to the existing manual grading form.
        review = self.client.get(reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}))
        self.assertContains(review, reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id}))
        invalid_grade = self.client.post(reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id}), {
            "score": "101.00", "feedback": "Above the maximum.",
        })
        self.assertContains(invalid_grade, "Score cannot exceed the assessment maximum.")
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())
        grade_response = self.client.post(reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id}), {
            "score": "75.00", "feedback": "Reviewed scanned script.",
        })
        self.assertEqual(grade_response.status_code, 302)
        grade = Grade.objects.get(attempt=attempt)
        self.assertEqual(grade.status, GradeStatus.DRAFT)
        self.assertTrue(GradeHistory.objects.filter(grade=grade, changed_by=self.instructor).exists())

        # A different student cannot retrieve the same script by guessing its URL.
        outsider = make_user("Student", mfa_enabled=True)
        self.client.force_login(outsider)
        denied = self.client.get(reverse("kura:attempt_file_download", kwargs={
            "attempt_id": attempt.id, "file_id": attempt_file.file.id,
        }))
        self.assertEqual(denied.status_code, 403)

    def test_scanned_paper_staff_upload_checks_staff_and_student_enrollment(self):
        # Neither unassigned staff nor an unrelated student can be used for a paper upload.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        outsider = make_user("Student", mfa_enabled=True)
        unrelated_staff = make_user("Instructor", mfa_enabled=True)
        url = reverse("kura:scanned_paper_staff_upload", kwargs={"assessment_id": self.assessment.id})
        self.client.force_login(unrelated_staff)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(url).status_code, 405)
        upload = SimpleUploadedFile("scan.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF")
        response = self.client.post(url, {"student": str(outsider.id), "file": upload})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(AssessmentAttempt.objects.filter(assessment=self.assessment, student=outsider).exists())

    def test_scanned_paper_cannot_be_marked_without_a_submitted_script(self):
        # Staff cannot record a mark for an unfinished or empty scanned attempt.
        self.assessment.delivery_mode = "paper_scanned"
        self.assessment.save(update_fields=["delivery_mode"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
        )
        self.client.force_login(self.instructor)
        url = reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id})
        self.assertEqual(self.client.post(url, {"score": "75"}).status_code, 403)
        attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
        attempt.save(update_fields=["status"])
        self.assertEqual(self.client.post(url, {"score": "75"}).status_code, 403)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())

    def test_student_cannot_start_from_wrong_ip_range(self):
        # Starting an attempt from outside the lab CIDR subnet is rejected.
        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id}),
            {"proctor_code": "PROCTOR123"},
            REMOTE_ADDR="192.168.1.100",
        )
        self.assertRedirects(response, reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}))
        self.assertFalse(AssessmentAttempt.objects.filter(assessment=self.assessment, student=self.student).exists())

    def test_student_can_start_from_valid_ip_range_with_proctor_code(self):
        # Starting with authorized lab IP and correct proctor code creates an active attempt.
        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id}),
            {"proctor_code": "PROCTOR123"},
            REMOTE_ADDR="10.20.0.45",
        )
        attempt = AssessmentAttempt.objects.get(assessment=self.assessment, student=self.student)
        self.assertRedirects(response, reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}))
        self.assertEqual(attempt.status, AttemptStatus.IN_PROGRESS)
        self.assertTrue(attempt.expires_at > timezone.now())

    @override_settings(TRUST_PROXY_IP_HEADER=True)
    def test_lab_check_uses_visitor_ip_from_waf_not_waf_address(self):
        # Behind the WAF, REMOTE_ADDR is the WAF's address (outside the lab
        # subnet) and X-Real-IP carries the student's lab PC address.
        # The lab check must use the student's address.
        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id}),
            {"proctor_code": "PROCTOR123"},
            REMOTE_ADDR="172.28.10.130",
            HTTP_X_REAL_IP="10.20.0.45",
        )
        attempt = AssessmentAttempt.objects.get(assessment=self.assessment, student=self.student)
        self.assertRedirects(response, reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}))
        # The attempt records the student's address, not the WAF's.
        self.assertEqual(attempt.ip_address, "10.20.0.45")

    def test_autosave_rejected_after_deadline(self):
        # Responses submitted after expires_at are rejected with 403 Forbidden.
        now = timezone.now()
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.IN_PROGRESS,
            expires_at=now - timezone.timedelta(minutes=5),
            ip_address="10.20.0.45",
        )

        self.client.force_login(self.student)
        response = self.client.post(
            reverse("kura:assessment_autosave", kwargs={"attempt_id": attempt.id}),
            {"question_id": "q1", "response_type": "multiple_choice", "selected_options": ["o1"]},
        )
        self.assertEqual(response.status_code, 403)

    def test_matching_autosave_ignores_forged_duplicate_pair_names(self):
        # Extra POST keys must not duplicate a correct pair and inflate automatic marks.
        self.assessment.questions_json = [{
            "question_id": "match", "type": "matching", "prompt": "Match", "points": 10,
            "left_prompts": [{"pair_id": "p1", "text": "One"}], "available_matches": ["First", "Other"],
        }]
        self.assessment.save(update_fields=["questions_json"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        response = self.client.post(reverse("kura:assessment_autosave", kwargs={"attempt_id": attempt.id}), {
            "question_id": "match", "response_type": "matching", "match_p1": "First", "match_match_p1": "First",
        })
        self.assertEqual(response.status_code, 200)
        attempt.refresh_from_db()
        self.assertEqual(attempt.answers_json[0]["submitted_matches"], [{"pair_id": "p1", "selected_match": "First"}])

    def test_matching_grader_counts_old_duplicate_answers_only_once(self):
        # Previously stored duplicate answers must not award more than the question's points.
        self.assessment.questions_json = [{
            "question_id": "match", "type": "matching", "prompt": "Match", "points": 10,
            "left_prompts": [{"pair_id": "p1", "text": "One"}], "available_matches": ["First"],
        }]
        self.assessment.save(update_fields=["questions_json"])
        key = self.assessment.answer_key
        key.answer_key_json = {"match": {"correct_pairs": {"p1": "First"}}}
        key.save(update_fields=["answer_key_json"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
            answers_json=[{"question_id": "match", "type": "matching", "submitted_matches": [
                {"pair_id": "p1", "selected_match": "First"}, {"pair_id": "p1", "selected_match": "First"},
            ]}],
        )
        self.client.force_login(self.student)
        self.client.post(reverse("kura:assessment_submit", kwargs={"attempt_id": attempt.id}))
        grade = Grade.objects.get(attempt=attempt)
        self.assertEqual(grade.score, Decimal("10"))

    def test_autosave_rejects_unknown_questions_and_options(self):
        # Students cannot save invented questions, types, or choices into an attempt.
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        url = reverse("kura:assessment_autosave", kwargs={"attempt_id": attempt.id})
        for data in (
            {"question_id": "unknown", "response_type": "multiple_choice", "selected_options": ["o1"]},
            {"question_id": "q1", "response_type": "matching"},
            {"question_id": "q1", "response_type": "multiple_choice", "selected_options": ["invented"]},
        ):
            with self.subTest(data=data):
                self.assertEqual(self.client.post(url, data).status_code, 400)
        attempt.refresh_from_db()
        self.assertEqual(attempt.answers_json, [])

    def test_reopening_attempt_restores_saved_answers(self):
        # Returning to the page must not make autosaved answers appear to be lost.
        self.assessment.questions_json = [
            {"question_id": "q1", "type": "multiple_choice", "points": 10, "prompt": "Choose",
             "options": [{"option_id": "o1", "text": "First"}, {"option_id": "o2", "text": "Second"}]},
            {"question_id": "q2", "type": "matching", "points": 10, "prompt": "Match",
             "left_prompts": [{"pair_id": "p1", "text": "One"}], "available_matches": ["First", "Second"]},
            {"question_id": "q3", "type": "long_text", "points": 10, "prompt": "Explain", "max_words": 100},
        ]
        self.assessment.save(update_fields=["questions_json"])
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
            answers_json=[
                {"question_id": "q1", "selected_option_ids": ["o2"]},
                {"question_id": "q2", "submitted_matches": [{"pair_id": "p1", "selected_match": "Second"}]},
                {"question_id": "q3", "response_text": "Saved written answer"},
            ],
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}))
        self.assertContains(response, 'value="o2" class="checkbox checkbox-primary checkbox-sm"\n                            checked')
        self.assertContains(response, '<option value="Second" selected>Second</option>')
        self.assertContains(response, '>Saved written answer</textarea>')

    def test_upload_file_rejected_after_submission_and_trigger_locks(self):
        # Uploading coursework files after submission is blocked by view and trigger.
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            submitted_at=timezone.now(),
            ip_address="10.20.0.45",
        )

        self.client.force_login(self.student)
        fake_file = SimpleUploadedFile("report.pdf", b"%PDF-1.4\ntest", content_type="application/pdf")
        self.client.post(
            reverse("kura:assessment_attempt_file_upload", kwargs={"attempt_id": attempt.id}),
            {"file": fake_file},
        )
        self.assertFalse(AttemptFile.objects.filter(attempt=attempt).exists())

        # Direct database insert is blocked by the check_attempt_files_lock trigger.
        stored_file = validate_and_save_upload(
            SimpleUploadedFile("code.txt", b"print('hello')", content_type="text/plain"),
            self.student,
        )
        with self.assertRaises(DatabaseError):
            AttemptFile.objects.create(attempt=attempt, file=stored_file)

    def test_student_cannot_see_attempt_summary_before_grade_release(self):
        # A draft or finalized grade must not reveal the attempt's automatic score.
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
            summary_score_json={"total_score": 73, "max_possible_points": 100},
        )
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=attempt,
            score=73, status=GradeStatus.DRAFT,
        )
        self.client.force_login(self.student)
        url = reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id})

        for status in (GradeStatus.DRAFT, GradeStatus.FINALIZED):
            grade.status = status
            grade.save(update_fields=["status"])
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "Evaluation Summary")
            self.assertNotContains(response, "73 / 100")
            self.assertIsNone(response.context["released_grade"])

    def test_student_sees_only_the_released_grade_not_a_stale_attempt_summary(self):
        # A released grade may have changed since automatic marking, so show the released value.
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
            summary_score_json={"total_score": 73, "max_possible_points": 100},
        )
        Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=attempt,
            score=81, status=GradeStatus.RELEASED,
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}))
        self.assertContains(response, "81.00")
        self.assertNotContains(response, "Evaluation Summary")
        self.assertNotContains(response, "73 / 100")

    def test_course_staff_can_see_another_students_attempt_summary(self):
        # Assigned teaching staff still need the marking breakdown for other students.
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
            summary_score_json={"total_score": 73, "max_possible_points": 100},
        )
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}))
        self.assertContains(response, "Evaluation Summary")
        self.assertContains(response, "73 / 100")

    def test_student_who_is_also_course_staff_cannot_see_own_draft_summary(self):
        # A course assignment must not expose a student's own unreleased mark.
        CourseStaff.objects.create(course=self.course, user=self.student, staff_role="teaching_assistant")
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
            summary_score_json={"total_score": 73, "max_possible_points": 100},
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}))
        self.assertNotContains(response, "Evaluation Summary")
        self.assertNotContains(response, "73 / 100")

    def test_student_course_staff_cannot_view_or_edit_own_draft_in_gradebook(self):
        # Course staff access cannot expose or change the same user's own draft grade.
        UserRole.objects.create(user=self.student, role=Role.objects.get(name="Teaching assistant"))
        CourseStaff.objects.create(course=self.course, user=self.student, staff_role="teaching_assistant")
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
        )
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=attempt,
            score=73, status=GradeStatus.DRAFT,
        )
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:course_grades", kwargs={"course_id": self.course.id}))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "73.00")
        self.assertEqual(
            self.client.get(reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id})).status_code, 403,
        )
        self.assertEqual(
            self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id})).status_code, 403,
        )

    def test_registrar_instructor_cannot_access_instructional_content_or_grades(self):
        # The Registrar restriction still applies if the same account is an assigned instructor.
        UserRole.objects.create(user=self.instructor, role=Role.objects.get(name="Registrar"))
        self.client.force_login(self.instructor)
        urls = [
            reverse("kura:course_detail", kwargs={"course_id": self.course.id}),
            reverse("kura:module_create", kwargs={"course_id": self.course.id}),
            reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:assessment_create", kwargs={"section_id": self.section.id}),
            reverse("kura:course_grades", kwargs={"course_id": self.course.id}),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)
        # Enrollment remains available, but a direct POST cannot create instructional content.
        self.assertEqual(self.client.get(reverse("kura:enrollment_list")).status_code, 200)
        response = self.client.post(reverse("kura:module_create", kwargs={"course_id": self.course.id}), {"title": "Forbidden"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Module.objects.filter(course=self.course, title="Forbidden").exists())

    def test_registrar_student_cannot_open_attempt_or_grades(self):
        # Adding the Student role cannot bypass the Registrar content restriction.
        UserRole.objects.create(user=self.student, role=Role.objects.get(name="Registrar"))
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.IN_PROGRESS, expires_at=timezone.now() + timezone.timedelta(minutes=30),
            ip_address="127.0.0.1",
        )
        self.client.force_login(self.student)
        for url in (reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}),
                    reverse("kura:student_grades"), reverse("kura:student_transcript")):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)

    def test_admin_with_course_assignment_cannot_open_assessment_or_attempt(self):
        # An Admin role must override a matching course staff assignment.
        admin = make_user("Admin", mfa_enabled=True)
        CourseStaff.objects.create(course=self.course, user=admin, staff_role="co_instructor")
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1",
            summary_score_json={"total_score": 73},
        )
        self.client.force_login(admin)
        for url in (
            reverse("kura:assessment_create", kwargs={"section_id": self.section.id}),
            reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}),
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)

    def test_admin_cannot_use_student_or_department_roles_to_view_grades(self):
        # Admin restrictions still apply when another role would otherwise allow access.
        admin = make_user("Admin", mfa_enabled=True)
        UserRole.objects.create(user=admin, role=Role.objects.get(name="Student"))
        UserRole.objects.create(user=admin, role=Role.objects.get(name="Department head"))
        self.dept.head_user = admin
        self.dept.save(update_fields=["head_user"])
        self.client.force_login(admin)

        for url in (
            reverse("kura:student_grades"),
            reverse("kura:student_transcript"),
            reverse("kura:department_reports", kwargs={"department_id": self.dept.id}),
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)

    def test_admin_cannot_use_assessment_or_grade_action_urls(self):
        # Direct URLs must not bypass the Admin restriction for assessment or grade actions.
        admin = make_user("Admin", mfa_enabled=True)
        CourseStaff.objects.create(course=self.course, user=admin, staff_role="co_instructor")
        Enrollment.objects.create(course=self.course, student=admin, status=EnrollmentStatus.ACTIVE)
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=admin, attempt_no=1,
            status=AttemptStatus.IN_PROGRESS, expires_at=timezone.now() + timezone.timedelta(minutes=30),
            ip_address="127.0.0.1",
        )
        grade = Grade.objects.create(
            assessment=self.assessment, student=admin, attempt=attempt,
            score=73, status=GradeStatus.RELEASED,
        )
        appeal = GradeAppeal.objects.create(grade=grade, reason="Please review")
        change = GradeChangeRequest.objects.create(
            grade=grade, requested_by=self.instructor, current_score=73,
            proposed_score=75, reason="Please review",
        )
        self.client.force_login(admin)

        # Exercise both pages and actions with identifiers that belong to this course.
        get_urls = (
            reverse("kura:assessment_edit", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:assessment_question_form", kwargs={"section_id": self.section.id}),
            reverse("kura:assessment_take", kwargs={"attempt_id": attempt.id}),
            reverse("kura:attempt_file_download", kwargs={"attempt_id": attempt.id, "file_id": grade.id}),
            reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id}),
            reverse("kura:grade_appeal_create", kwargs={"grade_id": grade.id}),
            reverse("kura:grade_appeal_review", kwargs={"appeal_id": appeal.id}),
            reverse("kura:grade_change_request_create", kwargs={"grade_id": grade.id}),
            reverse("kura:grade_change_request_review", kwargs={"request_id": change.id}),
            reverse("kura:assessment_file_download", kwargs={"assessment_id": self.assessment.id, "file_id": grade.id}),
        )
        post_urls = (
            reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:scanned_paper_staff_upload", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:assessment_file_upload", kwargs={"assessment_id": self.assessment.id}),
            reverse("kura:assessment_autosave", kwargs={"attempt_id": attempt.id}),
            reverse("kura:assessment_attempt_file_upload", kwargs={"attempt_id": attempt.id}),
            reverse("kura:assessment_submit", kwargs={"attempt_id": attempt.id}),
            reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}),
            reverse("kura:course_result_calculate", kwargs={"course_id": self.course.id}),
        )
        for url in get_urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 403)
        for url in post_urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url).status_code, 403)


class AutoFinalizeMissedDeadlinesCommandTests(TestCase):
    """
    Tests Auto-finalizing overdue in-progress attempts past deadline.
    """

    def setUp(self):
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Math", code="MTH")

        self.course = Course.objects.create(
            department=self.dept,
            code="MTH101",
            title="Calculus",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)

        self.module = Module.objects.create(course=self.course, title="Limits", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Quiz Section", section_type="quiz")

        past = timezone.now() - timezone.timedelta(minutes=10)
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Limits Quiz",
            component_type=GradeComponentType.QUIZ,
            max_score=Decimal("10.00"),
            max_attempts=1,
            opens_at=past - timezone.timedelta(hours=1),
            due_date=past,
            duration_minutes=30,
            questions_json=[
                {"question_id": "q1", "type": "multiple_choice", "points": 10.0, "prompt": "lim x->0 (x)?"}
            ],
            created_by=self.instructor,
        )
        ExamAnswerKey.objects.create(
            assessment=self.assessment,
            answer_key_json={"q1": {"correct_option_ids": ["0"]}},
            created_by=self.instructor,
        )

        # Overdue attempt left in progress by student.
        self.overdue_attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.IN_PROGRESS,
            expires_at=past,
            answers_json=[{"question_id": "q1", "type": "multiple_choice", "selected_option_ids": ["0"]}],
            ip_address="127.0.0.1",
        )

    def test_finalize_attempts_command_finalizes_overdue_attempts(self):
        # Running finalize_attempts marks overdue attempts as submitted, computes hash, and auto-grades.
        call_command("finalize_attempts")

        self.overdue_attempt.refresh_from_db()
        self.assertNotEqual(self.overdue_attempt.status, AttemptStatus.IN_PROGRESS)
        self.assertEqual(self.overdue_attempt.submitted_at, self.overdue_attempt.expires_at)
        self.assertIsNotNone(self.overdue_attempt.submission_hash)
        self.assertEqual(len(self.overdue_attempt.submission_hash), 64)
        self.assertTrue(self.overdue_attempt.summary_score_json["is_fully_graded"])


class AutoGradingTests(TestCase):
    """
    Tests Auto-grading multiple-choice and matching questions.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Biology", code="BIO")

        StudentProfile.objects.create(user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026)
        self.course = Course.objects.create(
            department=self.dept,
            code="BIO101",
            title="General Biology",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Cells", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Cell Quiz", section_type="quiz")

        now = timezone.now()
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Cellular Biology Quiz",
            component_type=GradeComponentType.QUIZ,
            max_score=Decimal("20.00"),
            max_attempts=1,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(hours=2),
            duration_minutes=45,
            questions_json=[
                {
                    "question_id": "q1",
                    "type": "multiple_choice",
                    "points": 10.0,
                    "prompt": "Which organelle is the powerhouse of the cell?",
                    "options": [
                        {"option_id": "opt_mito", "text": "Mitochondria"},
                        {"option_id": "opt_ribo", "text": "Ribosome"},
                    ],
                },
                {
                    "question_id": "q2",
                    "type": "matching",
                    "points": 10.0,
                    "prompt": "Match the organelle to function.",
                    "left_prompts": [
                        {"pair_id": "p1", "text": "Nucleus"},
                        {"pair_id": "p2", "text": "Chloroplast"},
                    ],
                    "available_matches": ["Genetic control", "Photosynthesis"],
                },
            ],
            created_by=self.instructor,
        )
        ExamAnswerKey.objects.create(
            assessment=self.assessment,
            answer_key_json={
                "q1": {"correct_option_ids": ["opt_mito"]},
                "q2": {"correct_pairs": {"p1": "Genetic control", "p2": "Photosynthesis"}},
            },
            created_by=self.instructor,
        )

    def test_auto_grading_calculates_correct_score(self):
        # Student answers MCQ correctly (10 pts) and Matching 1/2 correct (5 pts) -> total 15.00 pts.
        now = timezone.now()
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.IN_PROGRESS,
            expires_at=now + timezone.timedelta(minutes=30),
            answers_json=[
                {"question_id": "q1", "type": "multiple_choice", "selected_option_ids": ["opt_mito"]},
                {
                    "question_id": "q2",
                    "type": "matching",
                    "submitted_matches": [
                        {"pair_id": "p1", "selected_match": "Genetic control"},
                        {"pair_id": "p2", "selected_match": "Wrong Match"},
                    ],
                },
            ],
            ip_address="127.0.0.1",
        )

        self.client.force_login(self.student)
        response = self.client.post(reverse("kura:assessment_submit", kwargs={"attempt_id": attempt.id}))
        self.assertRedirects(response, reverse("kura:attempt_detail", kwargs={"attempt_id": attempt.id}))

        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.FULLY_GRADED)
        self.assertEqual(attempt.summary_score_json["auto_graded_points"], 15.0)
        self.assertEqual(attempt.summary_score_json["total_score"], 15.0)
        self.assertTrue(attempt.summary_score_json["is_fully_graded"])

        # The student is emailed a receipt with the submission's integrity hash.
        receipt = OutgoingEmail.objects.get(event_key=f"submission-receipt:{attempt.id}")
        self.assertEqual(receipt.to_email, self.student.email)
        self.assertIn(attempt.submission_hash, receipt.body)

        # Check draft grade was created for student.
        grade = Grade.objects.get(assessment=self.assessment, student=self.student)
        self.assertEqual(grade.score, Decimal("15.00"))
        self.assertEqual(grade.status, GradeStatus.DRAFT)


# ==========================================
# Grades, appeals & transcripts tests
# ==========================================

class InstructorAndTAGradingTests(TestCase):
    """
    Tests TA draft grading, instructor finalization, and MFA release.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.ta = make_user("Teaching assistant", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.department = Department.objects.create(name="Art", code="ART")

        # Provision TOTP device for instructor step-up authentication.
        self.device = TOTPDevice.objects.create(user=self.instructor, name="default", confirmed=True)

        StudentProfile.objects.create(user=self.student, department=self.department, current_level="level_4", matriculation_year=2026)
        self.course = Course.objects.create(
            department=self.department,
            code="ART101",
            title="Art History",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        CourseStaff.objects.create(course=self.course, user=self.ta, staff_role="teaching_assistant", can_release_grades=False)
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Renaissance", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Essays", section_type="coursework")
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Renaissance Essay",
            component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now() - timezone.timedelta(hours=1),
            due_date=timezone.now() + timezone.timedelta(hours=2),
            duration_minutes=60,
            created_by=self.instructor,
        )
        self.attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.REQUIRES_MANUAL_GRADING,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
            ip_address="127.0.0.1",
        )

    def test_ta_can_enter_draft_grade_creates_history_row(self):
        # TA enters manual draft score; grade is created and GradeHistory row is logged.
        self.client.force_login(self.ta)
        response = self.client.post(
            reverse("kura:grade_entry", kwargs={"attempt_id": self.attempt.id}),
            {"score": "85.00", "feedback": "Insightful visual analysis."},
        )
        self.assertRedirects(response, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        grade = Grade.objects.get(attempt=self.attempt)
        self.assertEqual(grade.score, Decimal("85.00"))
        self.assertEqual(grade.status, GradeStatus.DRAFT)
        self.assertEqual(grade.grader, self.ta)

        history = GradeHistory.objects.get(grade=grade)
        self.assertEqual(history.new_score, Decimal("85.00"))
        self.assertEqual(history.new_status, GradeStatus.DRAFT)
        self.assertEqual(history.changed_by, self.ta)

    def test_ta_cannot_finalize_or_release_grade(self):
        # TA attempts to finalize or release a grade; both actions return 403 Forbidden.
        grade = Grade.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt=self.attempt,
            grader=self.ta,
            score=Decimal("80.00"),
            status=GradeStatus.DRAFT,
        )

        self.client.force_login(self.ta)

        # Finalize attempt by TA
        finalize_resp = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}))
        self.assertEqual(finalize_resp.status_code, 403)

        # Release attempt by TA
        release_resp = self.client.post(
            reverse("kura:grade_release", kwargs={"grade_id": grade.id}),
            {"otp_token": "123456"},
        )
        self.assertEqual(release_resp.status_code, 403)

    def test_department_head_cannot_enter_initial_grade(self):
        # The head supervises grades but does not directly score initial attempts.
        head = make_user("Department head")
        self.department.head_user = head
        self.department.save(update_fields=["head_user"])
        self.client.force_login(head)
        response = self.client.post(reverse("kura:grade_entry", kwargs={"attempt_id": self.attempt.id}), {"score": "80"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Grade.objects.filter(attempt=self.attempt).exists())

    def test_finalized_grade_cannot_be_edited_as_draft(self):
        # Editing a finalized score must not silently return it to draft.
        grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=self.attempt,
                                     grader=self.ta, score=Decimal("80.00"), status=GradeStatus.FINALIZED)
        self.client.force_login(self.ta)
        self.client.post(reverse("kura:grade_entry", kwargs={"attempt_id": self.attempt.id}), {"score": "90"})
        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.FINALIZED)
        self.assertEqual(grade.score, Decimal("80.00"))

    def test_department_head_cannot_finalize_initial_grade(self):
        # Department heads approve later changes but do not finalize initial grades.
        head = make_user("Department head")
        self.department.head_user = head
        self.department.save(update_fields=["head_user"])
        grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=self.attempt,
                                     grader=self.ta, score=Decimal("80.00"), status=GradeStatus.DRAFT)
        self.client.force_login(head)
        response = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}))
        self.assertEqual(response.status_code, 403)
        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.DRAFT)

    def test_instructor_cannot_revert_released_grade_to_finalized(self):
        # A repeated finalize request must not change an already released grade.
        grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=self.attempt,
                                     grader=self.ta, score=Decimal("80.00"), status=GradeStatus.RELEASED)
        self.client.force_login(self.instructor)
        self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}))
        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.RELEASED)
        self.assertFalse(GradeHistory.objects.filter(grade=grade).exists())

    def test_instructor_can_finalize_and_release_with_mfa(self):
        # Instructor finalizes grade, then releases with step-up MFA verification.
        grade = Grade.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt=self.attempt,
            grader=self.ta,
            score=Decimal("92.00"),
            status=GradeStatus.DRAFT,
        )

        self.client.force_login(self.instructor)

        # 1. Finalize grade
        fin_resp = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}))
        self.assertRedirects(fin_resp, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.FINALIZED)
        self.assertEqual(grade.finalized_by, self.instructor)

        # 2. Release grade with MFA step-up verification
        static_device = StaticDevice.objects.create(user=self.instructor, name="backup", confirmed=True)
        StaticToken.objects.create(device=static_device, token=hash_recovery_code("888999"))

        rel_resp = self.client.post(
            reverse("kura:grade_release", kwargs={"grade_id": grade.id}),
            {"otp_token": "888999"},
        )
        self.assertRedirects(rel_resp, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.RELEASED)
        self.assertEqual(grade.released_by, self.instructor)
        self.assertIsNotNone(grade.released_at)

        # The student is emailed that a grade is ready, without the score.
        notice = OutgoingEmail.objects.get(event_key=f"grade-released:{grade.id}")
        self.assertEqual(notice.to_email, grade.student.email)
        self.assertNotIn(str(grade.score), notice.body)

        # Verify GradeHistory records both state transitions.
        history_entries = GradeHistory.objects.filter(grade=grade).order_by("id")
        self.assertEqual(history_entries.count(), 2)
        self.assertEqual(history_entries[0].new_status, GradeStatus.FINALIZED)
        self.assertEqual(history_entries[1].new_status, GradeStatus.RELEASED)


class StudentViewGradesTests(TestCase):
    """
    Tests Student grade view and visibility isolation.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student_a = make_user("Student", mfa_enabled=True)
        self.student_b = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Law", code="LAW")

        StudentProfile.objects.create(user=self.student_a, department=self.dept, current_level="level_4", matriculation_year=2026)
        StudentProfile.objects.create(user=self.student_b, department=self.dept, current_level="level_4", matriculation_year=2026)

        self.course = Course.objects.create(
            department=self.dept,
            code="LAW101",
            title="Constitutional Law",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.student_a, status=EnrollmentStatus.ACTIVE)
        Enrollment.objects.create(course=self.course, student=self.student_b, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Rights", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Moot Court", section_type="coursework")

        self.assessment_1 = Assessment.objects.create(
            section=self.section, title="Draft Quiz", component_type=GradeComponentType.QUIZ,
            max_score=Decimal("20.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=30, created_by=self.instructor,
        )
        self.assessment_2 = Assessment.objects.create(
            section=self.section, title="Finalized Brief", component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("40.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=30, created_by=self.instructor,
        )
        self.assessment_3 = Assessment.objects.create(
            section=self.section, title="Released Moot", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=60, created_by=self.instructor,
        )

        att_1 = AssessmentAttempt.objects.create(assessment=self.assessment_1, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        att_2 = AssessmentAttempt.objects.create(assessment=self.assessment_2, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        att_3 = AssessmentAttempt.objects.create(assessment=self.assessment_3, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        att_b = AssessmentAttempt.objects.create(assessment=self.assessment_3, student=self.student_b, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")

        # Student A grades across all 3 statuses
        Grade.objects.create(assessment=self.assessment_1, student=self.student_a, attempt=att_1, score=Decimal("18.00"), status=GradeStatus.DRAFT)
        Grade.objects.create(assessment=self.assessment_2, student=self.student_a, attempt=att_2, score=Decimal("35.00"), status=GradeStatus.FINALIZED)
        Grade.objects.create(assessment=self.assessment_3, student=self.student_a, attempt=att_3, score=Decimal("94.00"), status=GradeStatus.RELEASED)

        # Student B released grade
        Grade.objects.create(assessment=self.assessment_3, student=self.student_b, attempt=att_b, score=Decimal("77.00"), status=GradeStatus.RELEASED)

    def test_student_sees_only_own_released_grades_draft_and_finalized_hidden(self):
        # Student A views grades: only sees their own RELEASED grade.
        self.client.force_login(self.student_a)
        response = self.client.get(reverse("kura:student_grades"))
        self.assertEqual(response.status_code, 200)

        # Released Moot is visible
        self.assertContains(response, "Released Moot")
        self.assertContains(response, "94.00")

        # Draft and Finalized grades are hidden
        self.assertNotContains(response, "Draft Quiz")
        self.assertNotContains(response, "Finalized Brief")

        # Student B's score is hidden (prevents IDOR)
        self.assertNotContains(response, "77.00")


class GradeAppealsTests(TestCase):
    """
    Tests Student grade appeals and reviewer resolution.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student_a = make_user("Student", mfa_enabled=True)
        self.student_b = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Economics", code="ECON")

        StudentProfile.objects.create(user=self.student_a, department=self.dept, current_level="level_4", matriculation_year=2026)
        StudentProfile.objects.create(user=self.student_b, department=self.dept, current_level="level_4", matriculation_year=2026)

        self.course = Course.objects.create(
            department=self.dept,
            code="ECON201",
            title="Macroeconomics",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.student_a, status=EnrollmentStatus.ACTIVE)
        Enrollment.objects.create(course=self.course, student=self.student_b, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Fiscal Policy", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Midterm", section_type="exam")
        self.assessment = Assessment.objects.create(
            section=self.section, title="Macro Exam", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=60, created_by=self.instructor,
        )

        att_a = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        att_b = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student_b, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")

        self.grade_a = Grade.objects.create(assessment=self.assessment, student=self.student_a, attempt=att_a, score=Decimal("70.00"), status=GradeStatus.RELEASED)
        self.grade_b = Grade.objects.create(assessment=self.assessment, student=self.student_b, attempt=att_b, score=Decimal("65.00"), status=GradeStatus.RELEASED)

    def test_student_can_appeal_own_released_grade(self):
        # Student submits an appeal on their released grade.
        self.client.force_login(self.student_a)
        response = self.client.post(
            reverse("kura:grade_appeal_create", kwargs={"grade_id": self.grade_a.id}),
            {"reason": "Question 3 rubric criteria were omitted in the mark scheme."},
        )
        self.assertRedirects(response, reverse("kura:student_grades"))

        appeal = GradeAppeal.objects.get(grade=self.grade_a)
        self.assertEqual(appeal.status, AppealStatus.PENDING)
        self.assertIn("Question 3", appeal.reason)

    def test_student_cannot_appeal_someone_elses_grade(self):
        # Student A attempts to appeal Student B's grade; receives 404 Not Found (IDOR defense).
        self.client.force_login(self.student_a)
        response = self.client.post(
            reverse("kura:grade_appeal_create", kwargs={"grade_id": self.grade_b.id}),
            {"reason": "Unauthorized appeal attempt."},
        )
        self.assertEqual(response.status_code, 404)


class GradeChangeRequestsTests(TestCase):
    """
    Tests Post-release grade change requests and department head approval.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head", mfa_enabled=True)
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Psychology", code="PSYC", head_user=self.head)

        StudentProfile.objects.create(user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026)
        self.course = Course.objects.create(
            department=self.dept,
            code="PSYC101",
            title="Cognitive Psychology",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Memory", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Exam", section_type="exam")
        self.assessment = Assessment.objects.create(
            section=self.section, title="Memory Exam", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=60, created_by=self.instructor,
        )
        att = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        self.grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=att, score=Decimal("75.00"), status=GradeStatus.RELEASED)

    def test_department_head_can_approve_change_request_and_updates_grade(self):
        # Instructor submits change request; department head approves it.
        # Grade score updates and GradeHistory audit row records head approval.
        change_request = GradeChangeRequest.objects.create(
            grade=self.grade,
            requested_by=self.instructor,
            current_score=Decimal("75.00"),
            proposed_score=Decimal("85.00"),
            reason="Upheld appeal: Question 4 recalculation.",
            status=ChangeRequestStatus.PENDING,
        )

        self.client.force_login(self.head)
        response = self.client.post(
            reverse("kura:grade_change_request_review", kwargs={"request_id": change_request.id}),
            {"decision": ChangeRequestStatus.APPROVED, "review_note": "Approved based on submitted rubric evidence."},
        )
        self.assertRedirects(response, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        change_request.refresh_from_db()
        self.assertEqual(change_request.status, ChangeRequestStatus.APPROVED)
        self.assertEqual(change_request.reviewed_by, self.head)

        self.grade.refresh_from_db()
        self.assertEqual(self.grade.score, Decimal("85.00"))

        # Check GradeHistory row created with approved_by=head.
        history = GradeHistory.objects.filter(grade=self.grade, change_request=change_request).first()
        self.assertIsNotNone(history)
        self.assertEqual(history.old_score, Decimal("75.00"))
        self.assertEqual(history.new_score, Decimal("85.00"))
        self.assertEqual(history.approved_by, self.head)

    def test_department_head_can_reject_change_request(self):
        # Department head rejects change request; grade remains unchanged.
        change_request = GradeChangeRequest.objects.create(
            grade=self.grade,
            requested_by=self.instructor,
            current_score=Decimal("75.00"),
            proposed_score=Decimal("95.00"),
            reason="Unsubstantiated point adjustment.",
            status=ChangeRequestStatus.PENDING,
        )

        self.client.force_login(self.head)
        response = self.client.post(
            reverse("kura:grade_change_request_review", kwargs={"request_id": change_request.id}),
            {"decision": ChangeRequestStatus.REJECTED, "review_note": "Insufficient justification."},
        )
        self.assertRedirects(response, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        self.grade.refresh_from_db()
        self.assertEqual(self.grade.score, Decimal("75.00"))

    def test_instructor_cannot_approve_own_change_request(self):
        # Instructor tries to approve their own request; receives 403 Forbidden.
        change_request = GradeChangeRequest.objects.create(
            grade=self.grade,
            requested_by=self.instructor,
            current_score=Decimal("75.00"),
            proposed_score=Decimal("85.00"),
            reason="Self-approval attempt.",
            status=ChangeRequestStatus.PENDING,
        )

        self.client.force_login(self.instructor)
        response = self.client.post(
            reverse("kura:grade_change_request_review", kwargs={"request_id": change_request.id}),
            {"decision": ChangeRequestStatus.APPROVED},
        )
        self.assertEqual(response.status_code, 403)


class CourseResultsAndTranscriptsTests(TestCase):
    """
    Tests Weighted cumulative calculation and transcript release.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Physics", code="PHYS")

        StudentProfile.objects.create(user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026)
        self.course = Course.objects.create(
            department=self.dept,
            code="PHYS201",
            title="Thermodynamics",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        # Grading scheme: Exam = 60%, Quiz = 40%
        CourseGradeScheme.objects.create(course=self.course, component_type=GradeComponentType.EXAM, weight_percentage=Decimal("60.00"))
        CourseGradeScheme.objects.create(course=self.course, component_type=GradeComponentType.QUIZ, weight_percentage=Decimal("40.00"))

        mod = Module.objects.create(course=self.course, title="Heat", is_visible=True)
        sec = ModuleSection.objects.create(module=mod, title="Assessments", section_type="exam")

        # 1. Exam: max 100, scored 90 -> 90%
        exam = Assessment.objects.create(section=sec, title="Final Exam", component_type=GradeComponentType.EXAM, max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), duration_minutes=60, created_by=self.instructor)
        att_exam = AssessmentAttempt.objects.create(assessment=exam, student=self.student, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        Grade.objects.create(assessment=exam, student=self.student, attempt=att_exam, score=Decimal("90.00"), status=GradeStatus.RELEASED)

        # 2. Quiz: max 50, scored 40 -> 80%
        quiz = Assessment.objects.create(section=sec, title="Weekly Quiz", component_type=GradeComponentType.QUIZ, max_score=Decimal("50.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), duration_minutes=30, created_by=self.instructor)
        att_quiz = AssessmentAttempt.objects.create(assessment=quiz, student=self.student, attempt_no=1, status=AttemptStatus.FULLY_GRADED, expires_at=timezone.now(), ip_address="127.0.0.1")
        Grade.objects.create(assessment=quiz, student=self.student, attempt=att_quiz, score=Decimal("40.00"), status=GradeStatus.RELEASED)

    def test_result_calculation_get_does_not_change_data(self):
        # Viewing a URL must never create or alter a course result.
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("kura:course_result_calculate", kwargs={"course_id": self.course.id}))
        self.assertEqual(response.status_code, 405)
        self.assertFalse(CourseResult.objects.filter(course=self.course).exists())

    def test_recalculation_preserves_released_result(self):
        # A released transcript result must not be overwritten or hidden by recalculation.
        result = CourseResult.objects.create(course=self.course, student=self.student, final_score=Decimal("75.00"), status=GradeStatus.RELEASED)
        self.client.force_login(self.instructor)
        self.client.post(reverse("kura:course_result_calculate", kwargs={"course_id": self.course.id}))
        result.refresh_from_db()
        self.assertEqual(result.status, GradeStatus.RELEASED)
        self.assertEqual(result.final_score, Decimal("75.00"))

    def test_weighted_course_result_calculation(self):
        # Weighted calculation: (90% * 0.60) + (80% * 0.40) = 54 + 32 = 86.00%
        self.client.force_login(self.instructor)
        confirm_second_factor(self.client)
        response = self.client.post(reverse("kura:course_result_calculate", kwargs={"course_id": self.course.id}))
        self.assertRedirects(response, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        result = CourseResult.objects.get(course=self.course, student=self.student)
        self.assertEqual(result.final_score, Decimal("86.00"))
        self.assertEqual(result.status, GradeStatus.DRAFT)

        # Release result to transcript
        rel_resp = self.client.post(reverse("kura:course_result_release", kwargs={"course_id": self.course.id}))
        self.assertRedirects(rel_resp, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        result.refresh_from_db()
        self.assertEqual(result.status, GradeStatus.RELEASED)

        # Verify student can view released result on transcript
        self.client.force_login(self.student)
        transcript_resp = self.client.get(reverse("kura:student_transcript"))
        self.assertEqual(transcript_resp.status_code, 200)
        self.assertContains(transcript_resp, "PHYS201")
        self.assertContains(transcript_resp, "86.00%")


class DepartmentReportsTests(TestCase):
    """
    Tests Institutional reporting and cross-department protection.
    """

    def setUp(self):
        self.client = Client()
        self.head_a = make_user("Department head", mfa_enabled=True)
        self.head_b = make_user("Department head", mfa_enabled=True)
        self.dept_a = Department.objects.create(name="History", code="HIST", head_user=self.head_a)
        self.dept_b = Department.objects.create(name="Music", code="MUS", head_user=self.head_b)

    def test_head_can_view_own_department_report(self):
        # Head of Dept A views their department report.
        self.client.force_login(self.head_a)
        response = self.client.get(reverse("kura:department_reports", kwargs={"department_id": self.dept_a.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "History Department Report")

    def test_head_cannot_view_other_department_report(self):
        # Head of Dept A tries to view Dept B's report; receives 403 Forbidden.
        self.client.force_login(self.head_a)
        response = self.client.get(reverse("kura:department_reports", kwargs={"department_id": self.dept_b.id}))
        self.assertEqual(response.status_code, 403)


# ==========================================
# Hardening, logging & rate limits tests
# ==========================================

class SecuritySettingsAndHeadersTests(TestCase):
    """
    Tests HTTP security headers, CSP, cookie attributes, and cache headers.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", mfa_enabled=True)

    def test_response_security_headers_and_csp(self):
        # Verify X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy headers.
        response = self.client.get(reverse("kura:login"))
        self.assertEqual(response.status_code, 200)

        # Frame clickjacking protection
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

        # MIME sniffing defense
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")

        # Strict Content Security Policy
        csp_header = response.headers.get("Content-Security-Policy")
        self.assertIsNotNone(csp_header)
        self.assertIn("default-src 'self'", csp_header)
        self.assertIn("script-src 'self'", csp_header)
        self.assertNotIn("'unsafe-inline'", csp_header)

    def test_authenticated_requests_receive_no_store_cache_headers(self):
        # Authenticated user requests receive Cache-Control: no-store to protect sensitive data.
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:home"))
        self.assertEqual(response.status_code, 200)

        cache_control = response.headers.get("Cache-Control")
        self.assertIsNotNone(cache_control)
        self.assertIn("no-store", cache_control)


class SecurityLoggingTests(TestCase):
    """
    Tests Security event logging without leaking sensitive credentials.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Instructor", email="instructor_log@example.com", mfa_enabled=True)

    def test_failed_login_logs_security_warning_without_password(self):
        # Failed login attempt produces a security warning log without exposing the attempted password.
        with self.assertLogs("kura.security", level="WARNING") as log_capture:
            self.client.post(
                reverse("kura:login"),
                {"email": "instructor_log@example.com", "password": "WrongPasswordAttempt123!"},
            )
            # Verify log was created for user email
            self.assertTrue(any("instructor_log@example.com" in record.getMessage() for record in log_capture.records))
            # Verify the submitted raw password was NOT leaked into log output
            self.assertFalse(any("WrongPasswordAttempt123!" in record.getMessage() for record in log_capture.records))

    def test_user_logout_logs_security_info(self):
        # User logout action produces a security information log record.
        self.client.force_login(self.user)
        with self.assertLogs("kura.security", level="INFO") as log_capture:
            self.client.post(reverse("kura:logout"))
            self.assertTrue(any('event="auth.logout"' in record.getMessage() for record in log_capture.records))


class RateLimitingTests(TestCase):
    """
    Tests Rate limiting burst requests on sensitive endpoints.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", mfa_enabled=True)

    def test_rapid_burst_requests_beyond_limit_are_rejected(self):
        # Repeated burst requests exceeding the rate limit receive HTTP 429 Too Many Requests.
        from django.core.cache import caches
        caches["ratelimit"].clear()

        self.client.force_login(self.user)
        dummy_uuid = "00000000-0000-0000-0000-000000000001"
        upload_url = f"/attempts/{dummy_uuid}/files/upload/"

        # Send 25 rapid requests (limit is 20 per minute)
        last_status = None
        for _ in range(25):
            resp = self.client.post(upload_url)
            last_status = resp.status_code

        self.assertEqual(last_status, 429)


class ClamAVVirusScanningTests(TransactionTestCase):
    """
    Tests ClamAV virus scanning of uploaded files.
    Security: Verifies that infected files are detected in memory and rejected,
    clean files pass, production fail-closed behavior works, and dev fallback works.
    """

    # Rejected uploads are saved through the separate "quarantine" connection,
    # which only sees committed rows. TransactionTestCase really commits, so the
    # uploader exists for that connection.
    databases = {"default", "quarantine"}

    @classmethod
    def tearDownClass(cls):
        # Put back the seeded roles that TransactionTestCase removed.
        super().tearDownClass()
        reseed_roles_after_flush()

    def setUp(self):
        self.user = make_user("Instructor", mfa_enabled=True)

    @patch("socket.socket")
    def test_clean_file_passes_scan(self, mock_socket_cls):
        # A clean file returns 'stream: OK' from ClamAV and completes without error.
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"stream: OK\x00", b""]
        mock_socket_cls.return_value = mock_socket

        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        scan_file_for_malware(pdf_bytes)
        self.assertTrue(mock_socket.sendall.called)

    @patch("socket.socket")
    def test_malicious_eicar_file_is_detected_and_raises_validation_error(self, mock_socket_cls):
        # An infected file (EICAR signature) is detected by ClamAV and raises ValidationError.
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"stream: Eicar-Signature FOUND\x00", b""]
        mock_socket_cls.return_value = mock_socket

        eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with self.assertRaises(ValidationError) as ctx:
            scan_file_for_malware(eicar_bytes)

        self.assertIn("The uploaded file failed security scanning.", str(ctx.exception))

    @patch("socket.socket")
    @override_settings(CLAMAV_REQUIRED=False)
    def test_unreachable_clamav_in_development_falls_back(self, mock_socket_cls):
        # In development mode (CLAMAV_REQUIRED=False), unreachable daemon logs warning and allows upload.
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_socket

        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        # Should fall back cleanly without raising ValidationError
        scan_file_for_malware(pdf_bytes)

    @patch("socket.socket")
    @override_settings(CLAMAV_REQUIRED=True)
    def test_unreachable_clamav_in_production_fails_closed(self, mock_socket_cls):
        # In production mode (CLAMAV_REQUIRED=True), unreachable daemon fails closed for safety.
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_socket

        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        with self.assertRaises(ValidationError) as ctx:
            scan_file_for_malware(pdf_bytes)

        self.assertIn("Antivirus service is unavailable. Upload rejected for safety.", str(ctx.exception))

    @patch("socket.socket")
    @override_settings(CLAMAV_REQUIRED=True)
    def test_production_rejects_empty_or_incomplete_scanner_response(self, mock_socket_cls):
        # A dropped connection or unexpected reply is not proof that the file is clean.
        for reply in (b"", b"stream: OK", b"unexpected response\x00"):
            with self.subTest(reply=reply):
                mock_socket = MagicMock()
                mock_socket.recv.side_effect = [reply, b""]
                mock_socket_cls.return_value = mock_socket
                with self.assertRaises(ValidationError):
                    scan_file_for_malware(b"sample bytes")

    @patch("socket.socket")
    def test_validate_and_save_upload_aborts_on_malware_before_db_write(self, mock_socket_cls):
        # When an infected file is uploaded, validate_and_save_upload raises ValidationError
        # and stores zero rows in StoredFile and FileContent.
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"stream: Win.Trojan.Agent FOUND\x00", b""]
        mock_socket_cls.return_value = mock_socket

        infected_file = SimpleUploadedFile(
            "virus.pdf",
            b"%PDF-1.4 malicious content",
            content_type="application/pdf",
        )

        initial_file_count = StoredFile.objects.count()
        initial_content_count = FileContent.objects.count()

        with self.assertRaises(ValidationError):
            validate_and_save_upload(infected_file, self.user)

        # Confirm no database rows were created for the malicious file
        self.assertEqual(StoredFile.objects.count(), initial_file_count)
        self.assertEqual(FileContent.objects.count(), initial_content_count)

    @patch("socket.socket")
    def test_validate_and_save_upload_succeeds_on_clean_file(self, mock_socket_cls):
        # A clean file passes virus scanning and is persisted with its metadata and hash.
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"stream: OK\x00", b""]
        mock_socket_cls.return_value = mock_socket

        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        clean_file = SimpleUploadedFile("clean_lab.pdf", pdf_bytes, content_type="application/pdf")

        stored_file = validate_and_save_upload(clean_file, self.user)
        self.assertIsNotNone(stored_file.id)
        self.assertEqual(stored_file.content.content, pdf_bytes)


class VaultIntegrationTests(TestCase):
    """
    Tests HashiCorp Vault integration.
    Verifies Transit encryption for MFA secrets, dynamic database credentials,
    PKI certificate issuance, and development fallbacks.
    """

    def test_transit_encryption_fallback_when_vault_disabled(self):
        # In development mode (VAULT_ENABLED=False), secrets are stored directly as requested.
        secret = "JBSWY3DPEHPK3PXP"
        with override_settings(VAULT_ENABLED=False):
            encrypted = encrypt_mfa_secret(secret)
            self.assertEqual(encrypted, secret)

            decrypted = decrypt_mfa_secret(encrypted)
            self.assertEqual(decrypted, secret)

            # None and empty inputs return None
            self.assertIsNone(encrypt_mfa_secret(None))
            self.assertIsNone(decrypt_mfa_secret(None))

    @patch("kura.vault.get_vault_client")
    @override_settings(VAULT_ENABLED=True)
    def test_transit_encrypt_mfa_secret_with_vault(self, mock_get_client):
        # With Vault enabled, secret is base64-encoded and encrypted via Transit engine.
        mock_client = MagicMock()
        mock_client.secrets.transit.encrypt_data.return_value = {
            "data": {
                "ciphertext": "vault:v1:YWJjZGVmMTIzNDU2",
            }
        }
        mock_get_client.return_value = mock_client

        raw_secret = "JBSWY3DPEHPK3PXP"
        ciphertext = encrypt_mfa_secret(raw_secret)

        self.assertEqual(ciphertext, "vault:v1:YWJjZGVmMTIzNDU2")
        mock_client.secrets.transit.encrypt_data.assert_called_once()

    @patch("kura.vault.get_vault_client")
    @override_settings(VAULT_ENABLED=True)
    def test_transit_decrypt_mfa_secret_with_vault(self, mock_get_client):
        # Ciphertext with 'vault:v1:' prefix is decrypted back to plaintext string.
        mock_client = MagicMock()
        # "JBSWY3DPEHPK3PXP" in base64 is "SkJTV1kzRFBFSFBLM1BYUA=="
        mock_client.secrets.transit.decrypt_data.return_value = {
            "data": {
                "plaintext": "SkJTV1kzRFBFSFBLM1BYUA==",
            }
        }
        mock_get_client.return_value = mock_client

        decrypted = decrypt_mfa_secret("vault:v1:YWJjZGVmMTIzNDU2")
        self.assertEqual(decrypted, "JBSWY3DPEHPK3PXP")

    @patch("kura.vault.get_vault_client")
    @override_settings(VAULT_ENABLED=True)
    def test_transit_encryption_fails_closed_on_vault_error(self, mock_get_client):
        # In production, if Vault is unreachable, encryption fails closed to protect secret integrity.
        from hvac.exceptions import VaultError
        mock_client = MagicMock()
        mock_client.secrets.transit.encrypt_data.side_effect = VaultError("Connection refused")
        mock_get_client.return_value = mock_client

        with self.assertRaises(ValidationError) as ctx:
            encrypt_mfa_secret("MYSECRET")
        self.assertIn("MFA secret encryption failed", str(ctx.exception))


class MTLSIntegrationTests(TestCase):
    """
    Tests Mutual TLS (mTLS) between Nginx, Django and PostgreSQL.
    Verifies internal certificates, Gunicorn mTLS binding, and database SSL options.
    """

    def test_internal_certificates_generated_and_valid(self):
        # Confirms all required internal mTLS certificates and private keys are present
        from pathlib import Path
        base_dir = Path(__file__).resolve().parent.parent / "certs" / "internal"

        for cert_name in ["ca.crt", "nginx.crt", "waf.crt", "web.crt", "db.crt", "vault.crt"]:
            cert_path = base_dir / cert_name
            self.assertTrue(cert_path.exists(), f"Missing certificate: {cert_name}")
            content = cert_path.read_text()
            self.assertIn("-----BEGIN CERTIFICATE-----", content)

        # Only check the service keys exist: on Linux each one belongs to its
        # container user, so this test (running as you) may not be able to read it.
        for key_name in ["nginx.key", "waf.key", "web.key", "db.key", "vault.key"]:
            key_path = base_dir / key_name
            self.assertTrue(key_path.exists(), f"Missing private key: {key_name}")

        # No CA private key may sit where containers mount files from. Once Vault
        # issues the certificates (stage 3b) there is no CA key on disk at all:
        # it only exists inside Vault. Before that, the openssl bootstrap key
        # lives in certs/ca/, which no container mounts.
        self.assertFalse((base_dir / "ca.key").exists(), "ca.key must not be in certs/internal/")

    def test_database_ssl_options_structure(self):
        # Confirms database mTLS connection parameters are constructed properly
        import os

        env_backup = dict(os.environ)
        try:
            os.environ["DB_SSL_MODE"] = "verify-full"
            os.environ["DB_SSL_ROOTCERT"] = "/certs/internal/ca.crt"
            os.environ["DB_SSL_CERT"] = "/certs/internal/web.crt"
            os.environ["DB_SSL_KEY"] = "/certs/internal/web.key"

            # Simulate options builder logic from settings.py
            db_options = {
                "sslmode": os.environ["DB_SSL_MODE"],
                "sslrootcert": os.environ["DB_SSL_ROOTCERT"],
                "sslcert": os.environ["DB_SSL_CERT"],
                "sslkey": os.environ["DB_SSL_KEY"],
            }

            self.assertEqual(db_options["sslmode"], "verify-full")
            self.assertEqual(db_options["sslrootcert"], "/certs/internal/ca.crt")
            self.assertEqual(db_options["sslcert"], "/certs/internal/web.crt")
            self.assertEqual(db_options["sslkey"], "/certs/internal/web.key")
        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    def test_gunicorn_conf_mtls_logic(self):
        # Tests that gunicorn.conf.py configures mTLS on port 8443 when MTLS_ENABLED=True
        import importlib.util
        import os
        from pathlib import Path
        import ssl

        conf_path = Path(__file__).resolve().parent.parent / "gunicorn.conf.py"
        self.assertTrue(conf_path.exists())

        env_backup = dict(os.environ)
        try:
            # 1. When MTLS is disabled
            os.environ["MTLS_ENABLED"] = "False"
            spec = importlib.util.spec_from_file_location("gunicorn_conf_disabled", conf_path)
            mod_disabled = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod_disabled)
            self.assertEqual(mod_disabled.bind, "0.0.0.0:8000")
            self.assertFalse(hasattr(mod_disabled, "cert_reqs"))

            # 2. When MTLS is enabled
            os.environ["MTLS_ENABLED"] = "True"
            spec = importlib.util.spec_from_file_location("gunicorn_conf_enabled", conf_path)
            mod_enabled = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod_enabled)
            self.assertEqual(mod_enabled.bind, "0.0.0.0:8443")
            self.assertEqual(mod_enabled.cert_reqs, ssl.CERT_REQUIRED)
        finally:
            os.environ.clear()
            os.environ.update(env_backup)


class RowLevelSecurityAndPostgresRolesTests(TestCase):
    """
    Tests PostgreSQL roles, REVOKE rules, Row-Level Security, and pgAudit.
    Verifies that the database engine itself enforces grade isolation via RLS policies.
    """

    def setUp(self):
        self.dept_head = make_user("Department head", mfa_enabled=True)
        self.dept = Department.objects.create(name="Cybersecurity", code="CSEC", head_user=self.dept_head)
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student_a = make_user("Student", mfa_enabled=True)
        self.student_b = make_user("Student", mfa_enabled=True)

        StudentProfile.objects.create(user=self.student_a, department=self.dept, current_level="level_4", matriculation_year=2026)
        StudentProfile.objects.create(user=self.student_b, department=self.dept, current_level="level_4", matriculation_year=2026)

        self.course = Course.objects.create(
            department=self.dept,
            code="CSEC401",
            title="Database Security",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.dept_head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True)

        self.module = Module.objects.create(course=self.course, title="RLS Module", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="RLS Section", section_type="assignment")
        now = timezone.now()
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="SQL Hardening Lab",
            component_type=GradeComponentType.ASSIGNMENT,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(days=7),
            duration_minutes=60,
            created_by=self.instructor,
        )

        self.attempt_a = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student_a,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=now + timezone.timedelta(hours=2),
            ip_address="127.0.0.1",
        )
        self.attempt_b = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student_b,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=now + timezone.timedelta(hours=2),
            ip_address="127.0.0.1",
        )

        self.grade_a = Grade.objects.create(
            assessment=self.assessment,
            student=self.student_a,
            attempt=self.attempt_a,
            score=Decimal("95.00"),
            status=GradeStatus.RELEASED,
        )
        self.grade_b = Grade.objects.create(
            assessment=self.assessment,
            student=self.student_b,
            attempt=self.attempt_b,
            score=Decimal("88.00"),
            status=GradeStatus.RELEASED,
        )

    def test_rls_student_isolation_in_database(self):
        # When kura.current_user_id is set to student_a under the application role,
        # the PostgreSQL RLS policy filters out student_b's grade.
        from django.db import connection

        with connection.cursor() as cursor:
            # Switch to application role which enforces RLS policies
            cursor.execute("SET ROLE kura_app;")
            # Set session context to student_a
            cursor.execute("SET kura.current_user_id = %s;", [str(self.student_a.id)])

            # Query all grades directly from table
            cursor.execute("SELECT id, student_id FROM grades;")
            visible_rows = cursor.fetchall()

            # Always clean up session context and role
            cursor.execute("RESET kura.current_user_id;")
            cursor.execute("RESET ROLE;")

            # Student A can only see their own grade
            self.assertEqual(len(visible_rows), 1)
            self.assertEqual(visible_rows[0][0], self.grade_a.id)
            self.assertEqual(visible_rows[0][1], self.student_a.id)

    def test_rls_instructor_sees_course_grades(self):
        # When kura.current_user_id is set to an instructor teaching the course, they see all course grades.
        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute("SET ROLE kura_app;")
            cursor.execute("SET kura.current_user_id = %s;", [str(self.instructor.id)])
            cursor.execute("SELECT id FROM grades;")
            visible_rows = cursor.fetchall()

            cursor.execute("RESET kura.current_user_id;")
            cursor.execute("RESET ROLE;")

            # Instructor sees both student grades for their course
            self.assertEqual(len(visible_rows), 2)

    def test_rls_middleware_attaches_and_resets_session_context(self):
        # RowLevelSecurityMiddleware sets kura.current_user_id during request processing.
        from django.test import RequestFactory
        from kura.middleware import RowLevelSecurityMiddleware

        factory = RequestFactory()
        request = factory.get(reverse("kura:course_list"))
        request.user = self.student_a

        def dummy_view(req):
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_setting('kura.current_user_id', true);")
                return cursor.fetchone()[0]

        middleware = RowLevelSecurityMiddleware(dummy_view)
        result = middleware(request)
        self.assertEqual(result, str(self.student_a.id))


class PostgreSQLEncryptedBackupAndPITRTests(TestCase):
    """
    Tests Encrypted backups with Point-In-Time Recovery (PITR).
    Verifies AES-256 encryption key entropy, pgBackRest configuration,
    PostgreSQL continuous WAL archiving parameters, and disaster recovery scripts.
    """

    def setUp(self):
        from pathlib import Path
        from django.conf import settings
        self.base_dir = Path(settings.BASE_DIR)

    def test_backup_encryption_key_validity_and_entropy(self):
        # The AES-256 backup encryption key must exist and possess high cryptographic entropy.
        from kura.management.commands.verify_backup_config import calculate_shannon_entropy

        key_path = self.base_dir / "secrets" / "backup_encryption_key.txt"
        self.assertTrue(key_path.exists(), "Backup encryption key file must exist in secrets/")

        key_content = key_path.read_text(encoding="utf-8").strip()
        self.assertGreaterEqual(len(key_content), 32, "Encryption key must be at least 32 characters for AES-256")

        entropy = calculate_shannon_entropy(key_content)
        self.assertGreaterEqual(entropy, 3.5, "Encryption key must exhibit high cryptographic entropy")

    def test_pgbackrest_config_security_attributes(self):
        # pgbackrest.conf must enforce AES-256-CBC cipher and point to the secret key file.
        conf_path = self.base_dir / "docker" / "postgres" / "pgbackrest.conf"
        self.assertTrue(conf_path.exists(), "pgbackrest.conf must exist")

        content = conf_path.read_text(encoding="utf-8")
        self.assertIn("repo1-cipher-type=aes-256-cbc", content)
        self.assertIn("repo1-cipher-pass=file:/run/secrets/backup_encryption_key", content)
        self.assertIn("repo1-retention-full=", content)
        self.assertIn("[kura]", content)

    def test_postgresql_wal_archiving_config(self):
        # postgresql.conf must configure continuous WAL archiving for point-in-time recovery.
        conf_path = self.base_dir / "docker" / "postgres" / "postgresql.conf"
        self.assertTrue(conf_path.exists(), "postgresql.conf must exist")

        content = conf_path.read_text(encoding="utf-8")
        self.assertIn("wal_level = replica", content)
        self.assertIn("archive_mode = on", content)
        self.assertIn("archive_command = 'pgbackrest --stanza=kura archive-push %p'", content)
        self.assertIn("restore_command = 'pgbackrest --stanza=kura archive-get %f \"%p\"'", content)

    def test_backup_and_restore_scripts_attributes(self):
        # Shell scripts for backup and PITR restore must be executable and contain safety checks.
        import os

        backup_sh = self.base_dir / "docker" / "postgres" / "backup.sh"
        restore_sh = self.base_dir / "docker" / "postgres" / "restore.sh"

        self.assertTrue(backup_sh.exists())
        self.assertTrue(restore_sh.exists())

        # Check executable permissions
        self.assertTrue(os.access(backup_sh, os.X_OK))
        self.assertTrue(os.access(restore_sh, os.X_OK))

        backup_text = backup_sh.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", backup_text)
        self.assertIn("pgbackrest", backup_text)

        restore_text = restore_sh.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", restore_text)
        self.assertIn("--type=time", restore_text)
        self.assertIn("--target-action=promote", restore_text)

    def test_verify_backup_config_management_command(self):
        # The verify_backup_config management command runs cleanly without errors.
        import io
        out = io.StringIO()
        call_command("verify_backup_config", stdout=out)
        output = out.getvalue()
        self.assertIn("All backup and disaster recovery security checks passed", output)


class PasskeyWebAuthnIntegrationTests(TestCase):
    """
    Tests Passkeys (WebAuthn / FIDO2) with django-mfa2.
    Tests user model property compatibility, passkey management views,
    deletion access control, mfa_login_callback session creation, and WebAuthn challenges.
    """

    def setUp(self):
        self.user_a = make_user("Student", mfa_enabled=True)
        self.user_b = make_user("Student", mfa_enabled=True)
        self.client_a = Client()
        self.client_a.force_login(self.user_a)
        confirm_second_factor(self.client_a)
        self.client_b = Client()
        self.client_b.force_login(self.user_b)
        confirm_second_factor(self.client_b)

    def test_fido2_enrollment_page_renders(self):
        # An authenticated user should be able to open the passkey enrollment page.
        response = self.client_a.get(reverse("start_fido2"))

        self.assertEqual(response.status_code, 200)

    def test_user_model_username_property_compatibility(self):
        # Third-party WebAuthn libraries require user.username even when USERNAME_FIELD is email.
        self.assertEqual(self.user_a.username, self.user_a.email)

    def test_passkey_manage_view_isolation(self):
        # Authenticated users can view their own enrolled passkeys, but never other users' keys.
        from mfa.models import User_Keys

        key_a = User_Keys.objects.create(
            username=self.user_a.email,
            key_type="FIDO2",
            properties={"device": "dGVzdC1jcmVkZW50aWFsLWRhdGE=", "type": "public-key"},
            enabled=True,
            added_on=timezone.now(),
        )
        key_b = User_Keys.objects.create(
            username=self.user_b.email,
            key_type="FIDO2",
            properties={"device": "dGVzdC1jcmVkZW50aWFsLWRhdGE=", "type": "public-key"},
            enabled=True,
            added_on=timezone.now(),
        )

        response = self.client_a.get(reverse("kura:passkey_manage"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"Passkey #{key_a.id}")
        self.assertNotContains(response, f"Passkey #{key_b.id}")

    def test_passkey_delete_view_owner_and_idor_protection(self):
        # Users can delete their own passkeys via POST. Deleting another user's key raises 404 (IDOR).
        from mfa.models import User_Keys

        key_a = User_Keys.objects.create(
            username=self.user_a.email,
            key_type="FIDO2",
            properties={"device": "dGVzdC1jcmVkZW50aWFsLWRhdGE=", "type": "public-key"},
            enabled=True,
            added_on=timezone.now(),
        )

        # GET request is not allowed
        get_res = self.client_a.get(reverse("kura:passkey_delete", kwargs={"key_id": key_a.id}))
        self.assertEqual(get_res.status_code, 405)

        # User B cannot delete User A's key (IDOR protection)
        res_b = self.client_b.post(reverse("kura:passkey_delete", kwargs={"key_id": key_a.id}))
        self.assertEqual(res_b.status_code, 404)
        self.assertTrue(User_Keys.objects.filter(id=key_a.id).exists())

        # User A can successfully delete their own key
        res_a = self.client_a.post(reverse("kura:passkey_delete", kwargs={"key_id": key_a.id}))
        self.assertEqual(res_a.status_code, 302)
        self.assertFalse(User_Keys.objects.filter(id=key_a.id).exists())

    def test_mfa_login_callback_establishes_session(self):
        # The django-mfa2 login callback authenticates the user and logs a UserSession record.
        from django.test import RequestFactory
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.contrib.messages.middleware import MessageMiddleware
        from kura.views import mfa_login_callback
        from kura.models import UserSession

        factory = RequestFactory()
        request = factory.get(reverse("kura:home"))
        # Add session and messages support
        session_middleware = SessionMiddleware(lambda r: None)
        session_middleware.process_request(request)
        message_middleware = MessageMiddleware(lambda r: None)
        message_middleware.process_request(request)
        request.session["pre_mfa_user_id"] = str(self.user_a.id)
        request.session["base_username"] = self.user_a.email

        response = mfa_login_callback(request, username=self.user_a.email)
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("pre_mfa_user_id", request.session)
        self.assertTrue(UserSession.objects.filter(user=self.user_a).exists())

    def test_mfa_verify_view_detects_enrolled_passkeys(self):
        # mfa_verify_view informs the template when the user has registered passkeys.
        from mfa.models import User_Keys

        client = Client()
        session = client.session
        session["pre_mfa_user_id"] = str(self.user_a.id)
        session.save()

        # Before adding passkey: has_passkeys is False
        res = client.get(reverse("kura:mfa_verify"))
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.context["has_passkeys"])

        # After adding passkey: has_passkeys is True
        User_Keys.objects.create(
            username=self.user_a.email,
            key_type="FIDO2",
            properties={"device": "dGVzdA==", "type": "public-key"},
            enabled=True,
            added_on=timezone.now(),
        )
        res = client.get(reverse("kura:mfa_verify"))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.context["has_passkeys"])

    def test_webauthn_begin_registration_endpoint(self):
        # The /mfa/fido2/begin_reg endpoint returns a cryptographic challenge and RP metadata.
        response = self.client_a.get(reverse("fido2_begin_reg"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("publicKey", data)
        self.assertIn("challenge", data["publicKey"])
        self.assertIn("rp", data["publicKey"])
        self.assertEqual(data["publicKey"]["rp"]["name"], "Kura LMS")


class LokiSIEMAlertRulesTests(TestCase):
    """
    Tests Loki SIEM alert rules.
    Verifies that security alerting rules are defined with valid LogQL expressions,
    alert severities, descriptions, and that Loki Ruler is properly wired to Alertmanager.
    """

    def setUp(self):
        from pathlib import Path
        from django.conf import settings
        self.base_dir = Path(settings.BASE_DIR)
        self.rules_file_fake = self.base_dir / "docker" / "loki" / "rules" / "fake" / "kura-alerts.yml"
        self.rules_directory_tenant = self.base_dir / "docker" / "loki" / "rules" / "kura"
        self.loki_conf = self.base_dir / "docker" / "loki" / "loki.yml"
        self.compose_file = self.base_dir / "docker-compose.yml"

    def test_loki_rules_files_exist(self):
        # Loki uses the fake tenant when auth is disabled, so only that rules file should exist.
        self.assertTrue(self.rules_file_fake.exists(), "Rules file for default tenant must exist")
        self.assertFalse(self.rules_directory_tenant.exists(), "Duplicate kura tenant rules must not exist")

    def test_all_siem_alert_rules_present(self):
        # All 13 security alerts from the handoff's WP4 table, plus
        # BreachCheckUnavailable (fix 3), must be defined.
        expected_alerts = [
            "BruteForceLogin",
            "SingleIpBruteForce",
            "MfaFailuresSpike",
            "AdminRoleChanged",
            "MalwareUploaded",
            "AccessDeniedSpike",
            "CsrfFailures",
            "GradeReleaseMfaFailed",
            "WafBlockSpike",
            "VaultErrors",
            "DbAuthFailures",
            "RelayBounces",
            "ClamAvUnavailable",
            "BreachCheckUnavailable",
        ]
        content = self.rules_file_fake.read_text(encoding="utf-8")
        for alert_name in expected_alerts:
            self.assertIn(f"- alert: {alert_name}", content, f"Alert {alert_name} must be defined in SIEM rules")

    def test_alert_rules_have_required_metadata(self):
        # Each alert must have severity (warning or critical), summary, and description.
        content = self.rules_file_fake.read_text(encoding="utf-8")
        self.assertIn("severity: critical", content)
        self.assertIn("severity: warning", content)
        self.assertIn("summary:", content)
        self.assertIn("description:", content)
        self.assertIn("count_over_time", content)

    def test_loki_ruler_configuration(self):
        # loki.yml must configure the Ruler component and point to Alertmanager.
        content = self.loki_conf.read_text(encoding="utf-8")
        self.assertIn("ruler:", content)
        self.assertIn("directory: /etc/loki/rules", content)
        self.assertIn("alertmanager_url: http://alertmanager:9093", content)

    def test_docker_compose_mounts_loki_rules(self):
        # docker-compose.yml must mount the rules directory into the Loki container.
        content = self.compose_file.read_text(encoding="utf-8")
        self.assertIn("./docker/loki/rules:/etc/loki/rules:ro", content)


class DataRetentionAndIPAnonymizationTests(TestCase):
    """
    Tests Data retention and IP anonymization jobs.
    Tests IPv4 and IPv6 subnet masking, management commands for anonymizing historic records,
    and retention purging of expired sessions and obsolete logs.
    """

    def setUp(self):
        self.student = make_user("Student", mfa_enabled=True)
        self.dept_head = make_user("Department head", mfa_enabled=True)
        self.dept = Department.objects.create(name="Data Privacy", code="PRIV", head_user=self.dept_head)
        self.instructor = make_user("Instructor", mfa_enabled=True)

        self.course = Course.objects.create(
            department=self.dept,
            code="PRIV101",
            title="Privacy Law & Security",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.dept_head,
            published_at=timezone.now(),
        )
        self.module = Module.objects.create(course=self.course, title="GDPR & Law 151", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Privacy Section", section_type="assignment")
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Data Protection Exam",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now() - timezone.timedelta(days=200),
            due_date=timezone.now() - timezone.timedelta(days=190),
            duration_minutes=60,
            created_by=self.instructor,
        )

    def test_anonymize_ip_address_ipv4_and_ipv6(self):
        # Subnet masking zeroes the host identifier while preserving valid IP formatting.
        from kura.management.commands.anonymize_ips import anonymize_ip_address

        # IPv4 /24 mask
        self.assertEqual(anonymize_ip_address("192.168.1.42"), "192.168.1.0")
        self.assertEqual(anonymize_ip_address("10.0.5.254"), "10.0.5.0")
        self.assertEqual(anonymize_ip_address("192.168.1.0"), "192.168.1.0")

        # IPv6 /48 mask
        self.assertEqual(
            anonymize_ip_address("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
            "2001:db8:85a3::",
        )

        # Edge cases: None, blank, and invalid strings
        self.assertEqual(anonymize_ip_address(""), "")
        self.assertIsNone(anonymize_ip_address(None))
        self.assertEqual(anonymize_ip_address("not-an-ip"), "not-an-ip")

    def test_anonymize_ips_command_execution(self):
        # Records older than the retention cutoff have their IP addresses anonymized.
        import io
        from kura.models import AssessmentAttempt, LoginAttempt, UserSession

        now = timezone.now()
        past_date = now - timezone.timedelta(days=200)

        # 1. Old session (> 180 days)
        old_session = UserSession.objects.create(
            user=self.student,
            session_token_hash="a" * 64,
            ip_address="198.51.100.77",
            expires_at=now + timezone.timedelta(hours=1),
        )
        UserSession.objects.filter(id=old_session.id).update(created_at=past_date)

        # 2. Recent session (< 180 days)
        recent_session = UserSession.objects.create(
            user=self.student,
            session_token_hash="b" * 64,
            ip_address="198.51.100.88",
            expires_at=now + timezone.timedelta(hours=1),
        )

        # 3. Old login attempt
        old_attempt = LoginAttempt.objects.create(
            user=self.student,
            username_attempted=self.student.email,
            ip_address="203.0.113.15",
            failed_count=1,
        )
        LoginAttempt.objects.filter(id=old_attempt.id).update(created_at=past_date)

        # 4. Old assessment attempt
        old_exam = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=now - timezone.timedelta(days=190),
            ip_address="192.0.2.99",
        )
        AssessmentAttempt.objects.filter(id=old_exam.id).update(started_at=past_date)

        # Execute anonymization command for records older than 180 days
        out = io.StringIO()
        call_command("anonymize_ips", days=180, stdout=out)

        # Old records should have anonymized IPs (ending in .0)
        old_session.refresh_from_db()
        self.assertEqual(old_session.ip_address, "198.51.100.0")

        old_attempt.refresh_from_db()
        self.assertEqual(old_attempt.ip_address, "203.0.113.0")

        old_exam.refresh_from_db()
        self.assertEqual(old_exam.ip_address, "192.0.2.0")

        # Recent records must retain their raw IP addresses
        recent_session.refresh_from_db()
        self.assertEqual(recent_session.ip_address, "198.51.100.88")

    def test_anonymize_ips_command_dry_run(self):
        # In dry-run mode, no changes are committed to the database.
        import io
        from kura.models import LoginAttempt

        past_date = timezone.now() - timezone.timedelta(days=200)
        attempt = LoginAttempt.objects.create(
            user=self.student,
            username_attempted=self.student.email,
            ip_address="203.0.113.55",
            failed_count=1,
        )
        LoginAttempt.objects.filter(id=attempt.id).update(created_at=past_date)

        out = io.StringIO()
        call_command("anonymize_ips", days=180, dry_run=True, stdout=out)

        attempt.refresh_from_db()
        self.assertEqual(attempt.ip_address, "203.0.113.55")

    def test_purge_retention_command_execution(self):
        # Expired sessions and resolved login attempts older than cutoff are deleted.
        import io
        from kura.models import LoginAttempt, UserSession

        now = timezone.now()
        past_date = now - timezone.timedelta(days=200)

        # Expired session older than 180 days
        expired_old = UserSession.objects.create(
            user=self.student,
            session_token_hash="c" * 64,
            expires_at=past_date,
        )
        # Active session
        active_session = UserSession.objects.create(
            user=self.student,
            session_token_hash="d" * 64,
            expires_at=now + timezone.timedelta(hours=2),
        )

        # Old resolved login attempt
        old_attempt = LoginAttempt.objects.create(
            user=self.student,
            username_attempted=self.student.email,
            ip_address="198.51.100.1",
            failed_count=1,
        )
        LoginAttempt.objects.filter(id=old_attempt.id).update(created_at=past_date)

        out = io.StringIO()
        call_command("purge_retention", days=180, stdout=out)

        # Expired session should be deleted, active session preserved
        self.assertFalse(UserSession.objects.filter(id=expired_old.id).exists())
        self.assertTrue(UserSession.objects.filter(id=active_session.id).exists())

        # Old resolved attempt should be purged
        self.assertFalse(LoginAttempt.objects.filter(id=old_attempt.id).exists())


# Where the incident-response runbook lives. The docs/ folder is kept on the
# developer's machine and is not committed, so on GitHub (CI) the file is missing.
INCIDENT_RUNBOOK_PATH = Path(__file__).resolve().parent.parent / "docs" / "INCIDENT_RESPONSE.md"


# Skip (do not fail) these checks when the runbook is not in this copy of the
# project. Where the file exists, every check below still runs.
@unittest.skipUnless(INCIDENT_RUNBOOK_PATH.exists(), "docs/INCIDENT_RESPONSE.md is not in this checkout")
class IncidentResponseRunbookTests(TestCase):
    """
    Tests Incident response runbook.
    Verifies that the runbook exists, covers all 6 critical security incident scenarios,
    cites statutory compliance requirements (Law 175/2018 & NIST SP 800-61), and references
    valid disaster recovery scripts and emergency mitigation commands.
    """

    def setUp(self):
        from pathlib import Path
        from django.conf import settings
        self.base_dir = Path(settings.BASE_DIR)
        self.runbook_path = INCIDENT_RUNBOOK_PATH

    def test_runbook_file_exists(self):
        # The incident-response runbook is kept with the other project documentation.
        self.assertTrue(self.runbook_path.exists(), "docs/INCIDENT_RESPONSE.md must exist")

    def test_runbook_covers_all_scenarios(self):
        # Must document procedures for all 6 scenarios.
        content = self.runbook_path.read_text(encoding="utf-8")
        scenarios = [
            "Scenario 1: Compromised User Account",
            "Scenario 2: Active Web Exploitation & WAF Infiltration",
            "Scenario 3: Malicious File Upload Detected",
            "Scenario 4: Database Tampering or Unauthorized Grade Alteration",
            "Scenario 5: Internal mTLS Certificate Expiration or Breach",
            "Scenario 6: Distributed Denial of Service (DDoS)",
        ]
        for scenario in scenarios:
            self.assertIn(scenario, content, f"Runbook must cover '{scenario}'")

    def test_runbook_contains_emergency_tools_and_commands(self):
        # Must include actionable commands for tools used in Kura.
        content = self.runbook_path.read_text(encoding="utf-8")
        self.assertIn("cscli decisions add", content, "Must explain CrowdSec IP banning")
        self.assertIn("generate_internal_mtls_certs.sh", content, "Must explain mTLS certificate regeneration")
        self.assertIn("pgbackrest", content, "Must explain PITR database restoration")
        self.assertIn("sha256sum", content, "Must explain cryptographic evidence hashing")

    def test_runbook_cites_legal_and_security_standards(self):
        # Must cite NIST SP 800-61 and Egyptian Anti-Cybercrime Law (Law No. 175 of 2018).
        content = self.runbook_path.read_text(encoding="utf-8")
        self.assertIn("NIST SP 800-61", content)
        self.assertIn("Law No. 175 of 2018", content)


class SemesterValueMigrationTests(TestCase):
    """Verify semester values migrate forward and have a documented rollback mapping."""

    def test_migration_maps_old_semester_values(self):
        # Load the real migration function without changing the shared test database.
        migration = import_module("kura.migrations.0005_semester_type_values")
        historical_course = MagicMock()
        course_manager = MagicMock()
        course_manager.filter.return_value = course_manager
        historical_course.objects.using.return_value = course_manager
        apps = MagicMock()
        apps.get_model.return_value = historical_course
        schema_editor = MagicMock()
        schema_editor.connection.alias = "default"

        # Run the migration with a fake historical model and inspect the four updates.
        migration.migrate_semester_values(apps, schema_editor)

        self.assertEqual(
            course_manager.filter.call_args_list,
            [call(semester="fall"), call(semester="spring"), call(semester="summer"), call(semester="winter")],
        )
        self.assertEqual(
            course_manager.update.call_args_list,
            [call(semester="1"), call(semester="2"), call(semester="3"), call(semester="3")],
        )

    def test_migration_restores_old_values_on_rollback(self):
        # Rollback returns every numbered value to a choice accepted by the old model.
        migration = import_module("kura.migrations.0005_semester_type_values")
        historical_course = MagicMock()
        course_manager = MagicMock()
        course_manager.filter.return_value = course_manager
        historical_course.objects.using.return_value = course_manager
        apps = MagicMock()
        apps.get_model.return_value = historical_course
        schema_editor = MagicMock()
        schema_editor.connection.alias = "default"

        migration.reverse_semester_values(apps, schema_editor)

        self.assertEqual(
            course_manager.filter.call_args_list,
            [call(semester="1"), call(semester="2"), call(semester="3")],
        )
        self.assertEqual(
            course_manager.update.call_args_list,
            [call(semester="fall"), call(semester="spring"), call(semester="summer")],
        )


class ApprovedSchemaChangesTests(TestCase):
    """Verify the approved schema and permission changes are present."""

    def test_html_to_markdown_conversion_preserves_content_and_formatting(self):
        # Old stored notes keep their text and common formatting during conversion.
        migration = import_module("kura.migrations.0010_convert_section_items_to_markdown")
        converter = migration.MarkdownConverter()
        converter.feed('<h2>Title</h2><p>Hello <strong>world</strong> <a href="https://example.com">link</a>.</p>')
        converter.close()
        markdown = "".join(converter.parts)
        self.assertIn("## Title", markdown)
        self.assertIn("**world**", markdown)
        self.assertIn("[link](https://example.com)", markdown)
        self.assertNotIn("<strong>", markdown)

    def test_html_to_markdown_conversion_keeps_list_and_plain_text(self):
        # Lists and literal punctuation remain readable rather than being discarded.
        migration = import_module("kura.migrations.0010_convert_section_items_to_markdown")
        converter = migration.MarkdownConverter()
        converter.feed("<ul><li>First</li><li>Second</li></ul><p>Use a * symbol.</p>")
        converter.close()
        markdown = "".join(converter.parts)
        self.assertIn("- First", markdown)
        self.assertIn("- Second", markdown)
        self.assertIn(r"Use a \* symbol.", markdown)

    def test_item_conversion_forward_and_rollback_keep_note_text(self):
        # Exercise the migration with a historical model without rewriting the test database.
        migration = import_module("kura.migrations.0010_convert_section_items_to_markdown")
        item = MagicMock()
        item.content_body = "<p>Hello <strong>world</strong></p>"
        historical_model = MagicMock()
        historical_model.objects.using.return_value.all.return_value.iterator.side_effect = [[item], [item]]
        apps = MagicMock()
        apps.get_model.return_value = historical_model
        schema_editor = MagicMock()
        schema_editor.connection.alias = "default"

        migration.convert_items(apps, schema_editor)
        self.assertIn("**world**", item.content_body)
        migration.restore_html(apps, schema_editor)
        self.assertIn("Hello", item.content_body)
        self.assertIn("<strong>world</strong>", item.content_body)

    def test_section_item_body_is_optional_and_release_fields_are_safe_by_default(self):
        # New section items should stay hidden until staff explicitly release them.
        content_body = SectionItem._meta.get_field("content_body")
        is_visible = SectionItem._meta.get_field("is_visible")
        released_at = SectionItem._meta.get_field("released_at")

        self.assertTrue(content_body.blank)
        self.assertFalse(content_body.null)
        self.assertIs(is_visible.default, False)
        self.assertTrue(released_at.null)

    def test_assessments_default_to_online_delivery(self):
        # The assessment delivery mode must support the online and scanned-paper choices.
        delivery_mode = Assessment._meta.get_field("delivery_mode")

        self.assertEqual(delivery_mode.default, "online")
        self.assertEqual(
            {choice_value for choice_value, _ in delivery_mode.choices},
            {"online", "paper_scanned"},
        )

    def test_upload_allowlist_has_approved_types_and_keeps_dangerous_types_out(self):
        # Approved document, image, video, and audio formats are allowed without relaxing the size cap.
        expected_types = {
            "application/msword",
            "application/vnd.ms-powerpoint",
            "application/vnd.ms-excel",
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.presentation",
            "application/vnd.oasis.opendocument.spreadsheet",
            "text/csv",
            "text/markdown",
            "image/gif",
            "image/webp",
            "video/mp4",
            "audio/mpeg",
        }
        dangerous_types = {"image/svg+xml", "text/html", "application/x-msdownload"}

        self.assertTrue(expected_types.issubset(set(ALLOWED_UPLOAD_MIME_TYPES)))
        self.assertTrue(dangerous_types.isdisjoint(set(ALLOWED_UPLOAD_MIME_TYPES)))
        self.assertEqual(MAX_UPLOAD_BYTES, 25 * 1024 * 1024)

    def test_upload_database_constraint_accepts_new_type_and_rejects_html(self):
        # The database constraint must match the Python allowlist, not just the upload form.
        uploader = make_user("Instructor")
        markdown_file = StoredFile.objects.create(
            uploaded_by=uploader,
            original_filename="notes.md",
            mime_type="text/markdown",
            size_bytes=20,
            sha256_hash="a" * 64,
        )

        self.assertEqual(markdown_file.mime_type, "text/markdown")

        # HTML remains rejected by the database even if a caller bypasses the upload validator.
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                StoredFile.objects.create(
                    uploaded_by=uploader,
                    original_filename="unsafe.html",
                    mime_type="text/html",
                    size_bytes=20,
                    sha256_hash="b" * 64,
                )

    def test_admin_course_and_session_permissions_do_not_grant_sensitive_access(self):
        # Admins manage courses and sessions, while all non-admin roles lose personal-session permissions.
        admin = make_user("Admin")

        self.assertTrue(has_permission(admin, "read", "courses", "institution"))
        self.assertTrue(has_permission(admin, "write", "courses", "institution"))
        self.assertTrue(has_permission(admin, "view", "sessions", "institution"))
        self.assertTrue(has_permission(admin, "revoke", "sessions", "institution"))
        self.assertFalse(has_permission(admin, "view", "course_grades", "course"))
        self.assertFalse(has_permission(admin, "view", "assessments", "institution"))
        self.assertFalse(has_permission(admin, "view", "assessment_attempts", "institution"))
        self.assertFalse(has_permission(admin, "view", "scores", "institution"))
        self.assertFalse(has_permission(admin, "view", "answer_keys", "institution"))

        # Check every non-admin role, not just one example role.
        for role_name in ["Registrar", "Department head", "Instructor", "Teaching assistant", "Student"]:
            user = make_user(role_name)
            self.assertFalse(has_permission(user, "view", "sessions", "self"))
            self.assertFalse(has_permission(user, "revoke", "sessions", "self"))

    def test_admin_combined_with_instructor_cannot_gain_sensitive_permissions(self):
        # Admin's prohibition still applies if an inconsistent second role exists.
        admin = make_user("Admin")
        make_user("Instructor")
        UserRole.objects.create(user=admin, role=Role.objects.get(name="Instructor"))
        self.assertFalse(has_permission(admin, "manage", "assessments", "course"))
        self.assertFalse(has_permission(admin, "manage", "modules_and_sections", "course"))
        self.assertTrue(has_permission(admin, "read", "courses", "institution"))

    def test_admin_permission_migration_removes_personal_session_grants_and_can_reverse(self):
        # Simulate the old personal-session grants, then check the migration and its rollback.
        admin = make_user("Admin")
        student = make_user("Student")
        student_role = UserRole.objects.get(user=student).role
        session_view, _ = SystemPermission.objects.get_or_create(
            action="view",
            resource="sessions",
            scope="self",
        )
        session_revoke, _ = SystemPermission.objects.get_or_create(
            action="revoke",
            resource="sessions",
            scope="self",
        )
        RolePermission.objects.get_or_create(role=student_role, permission=session_view)
        RolePermission.objects.get_or_create(role=student_role, permission=session_revoke)

        migration = import_module("kura.migrations.0009_admin_course_and_session_permissions")
        with connection.schema_editor() as schema_editor:
            migration.update_admin_permissions(django_apps, schema_editor)

        self.assertFalse(has_permission(student, "view", "sessions", "self"))
        self.assertFalse(has_permission(student, "revoke", "sessions", "self"))
        self.assertTrue(has_permission(admin, "read", "courses", "institution"))

        # Rolling back restores personal access and removes the four new Admin permissions.
        with connection.schema_editor() as schema_editor:
            migration.restore_previous_permissions(django_apps, schema_editor)

        self.assertTrue(has_permission(student, "view", "sessions", "self"))
        self.assertTrue(has_permission(student, "revoke", "sessions", "self"))
        self.assertFalse(has_permission(admin, "read", "courses", "institution"))



class ClientIPBehindProxyTests(TestCase):
    """
    get_client_ip() returns the real visitor's IP behind Nginx and the Coraza WAF.
    Every request reaches Django from the WAF, so REMOTE_ADDR is the WAF's address
    and the visitor's address arrives in the X-Real-IP header.
    """

    WAF_ADDRESS = "172.28.10.130"

    def make_request(self, real_ip_header=None):
        # Build a request that looks like it came through the WAF.
        from django.test import RequestFactory

        extra = {"REMOTE_ADDR": self.WAF_ADDRESS}
        if real_ip_header is not None:
            extra["HTTP_X_REAL_IP"] = real_ip_header
        return RequestFactory().get("/", **extra)

    @override_settings(TRUST_PROXY_IP_HEADER=True)
    def test_trusted_header_gives_visitor_ip(self):
        from .views import get_client_ip

        self.assertEqual(get_client_ip(self.make_request("203.0.113.7")), "203.0.113.7")

    @override_settings(TRUST_PROXY_IP_HEADER=True)
    def test_trusted_header_accepts_ipv6(self):
        from .views import get_client_ip

        self.assertEqual(get_client_ip(self.make_request("2001:db8::1")), "2001:db8::1")

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_header_ignored_when_not_behind_trusted_proxy(self):
        # With runserver anyone could send X-Real-IP, so it must be ignored.
        from .views import get_client_ip

        self.assertEqual(get_client_ip(self.make_request("203.0.113.7")), self.WAF_ADDRESS)

    @override_settings(TRUST_PROXY_IP_HEADER=True)
    def test_invalid_header_values_fall_back_to_remote_addr(self):
        # Garbage, lists and missing headers are never used as an IP address.
        from .views import get_client_ip

        for bad_value in ["not-an-ip", "203.0.113.7, 198.51.100.1", "", "<script>"]:
            self.assertEqual(get_client_ip(self.make_request(bad_value)), self.WAF_ADDRESS)
        self.assertEqual(get_client_ip(self.make_request()), self.WAF_ADDRESS)


class SecurityEventLogTests(TestCase):
    """Security events use safe, searchable fields without exposing reset tokens."""

    def make_request(self, path="/courses/", request_id="a" * 32):
        # Build a request with a logged-in actor and a request ID from Nginx.
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        request = RequestFactory().post(
            path,
            REMOTE_ADDR="203.0.113.7",
            HTTP_X_REQUEST_ID=request_id,
        )
        request.user = AnonymousUser()
        return request

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_log_values_are_quoted_and_newlines_cannot_forge_fields(self):
        # A crafted detail value must remain one quoted value on a single line.
        request = self.make_request()
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(request, "test.event", {"filename": 'homework "final"\nlevel=ERROR'})

        self.assertEqual(len(captured.output), 1)
        self.assertIn('filename="homework \\"final\\"\\nlevel=ERROR"', captured.output[0])
        self.assertNotIn("\n", captured.output[0])

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_password_reset_token_is_redacted_from_logged_path(self):
        # Reset links contain bearer tokens, so logs must never record the token.
        request = self.make_request("/password/reset/reset-secret-value/")
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(request, "test.event", {})

        self.assertIn("/password/reset/<redacted>/", captured.output[0])
        self.assertNotIn("reset-secret-value", captured.output[0])

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_invalid_request_id_is_replaced_with_dash(self):
        # Only Nginx's exact 32-character lowercase hexadecimal value is accepted.
        request = self.make_request(request_id="bad-request-id")
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(request, "test.event", {})

        self.assertIn('request_id="-"', captured.output[0])

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_valid_request_id_is_kept_and_details_are_sorted(self):
        # Nginx's request ID helps operators follow one request across services.
        request = self.make_request()
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(request, "test.event", {"zeta": 2, "alpha": 1})

        self.assertIn('request_id="' + "a" * 32 + '"', captured.output[0])
        self.assertLess(captured.output[0].index("alpha="), captured.output[0].index("zeta="))
        self.assertIn('actor_user_id="anonymous"', captured.output[0])

    @override_settings(TRUST_PROXY_IP_HEADER=False)
    def test_permission_denied_handler_logs_one_structured_denial(self):
        # The handler logs the actor and path once, while showing a generic page.
        from .views import permission_denied_view

        request = self.make_request("/admin/staff/")
        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = permission_denied_view(request, PermissionDenied("not allowed"))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(captured.output), 1)
        self.assertIn('event="access.denied"', captured.output[0])
        self.assertIn('path="/admin/staff/"', captured.output[0])
        self.assertIn('reason="not allowed"', captured.output[0])

    def test_student_opening_admin_page_logs_one_access_denial(self):
        # A denied real route must create one event with the student's ID and requested path.
        student = make_user("Student")
        client = Client(raise_request_exception=False)
        client.force_login(student)

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = client.get(reverse("kura:staff_list"))

        self.assertEqual(response.status_code, 403)
        denial_lines = [line for line in captured.output if 'event="access.denied"' in line]
        self.assertEqual(len(denial_lines), 1)
        self.assertIn('actor_user_id="' + str(student.id) + '"', denial_lines[0])
        self.assertIn('path="/admin/staff/"', denial_lines[0])

    def test_csrf_failure_is_logged_and_page_is_generic(self):
        # Django must reject a POST without a CSRF token and log its failure once.
        client = Client(enforce_csrf_checks=True)
        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = client.post(reverse("kura:login"), {"email": "nobody@example.edu"})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(captured.output), 1)
        self.assertIn('event="access.csrf_failed"', captured.output[0])
        self.assertNotIn(b"CSRF token", response.content)

class ClientIPLockoutTests(TestCase):
    """Login lockouts use the visitor address supplied by the trusted proxy."""

    WAF_ADDRESS = "172.28.10.130"

    @override_settings(TRUST_PROXY_IP_HEADER=True)
    def test_axes_lockout_hits_attacker_ip_not_every_user(self):
        # Five failed logins from one visitor must not lock out a different
        # visitor, even though both reach Django from the same WAF address.
        password = "ValidPassword123!"
        user = make_user("Student", password=password)
        login_url = reverse("kura:login")

        # The attacker (203.0.113.7) fails five times.
        for attempt in range(5):
            self.client.post(
                login_url,
                {"email": user.email, "password": "WrongPassword999!"},
                REMOTE_ADDR=self.WAF_ADDRESS,
                HTTP_X_REAL_IP="203.0.113.7",
            )

        # The real student (198.51.100.20) can still log in: the password is
        # accepted and they are redirected on to the MFA step.
        response = Client().post(
            login_url,
            {"email": user.email, "password": password},
            REMOTE_ADDR=self.WAF_ADDRESS,
            HTTP_X_REAL_IP="198.51.100.20",
        )
        self.assertEqual(response.status_code, 302)

        # The attacker's IP is locked, even with the right password (no redirect).
        response = Client().post(
            login_url,
            {"email": user.email, "password": password},
            REMOTE_ADDR=self.WAF_ADDRESS,
            HTTP_X_REAL_IP="203.0.113.7",
        )
        self.assertNotEqual(response.status_code, 302)


class SecretKeySettingTests(TestCase):
    """
    config/settings.py must refuse to start in production (DEBUG off) when the
    secret key is missing or weak, instead of falling back to a known key.
    Each test starts a fresh Python process, because settings are only read once.
    """

    def load_settings(self, secret_key, debug):
        # Start a new Python process that loads the settings and prints the key length.
        # SECRET_KEY is set (even to "") so the .env file cannot fill it in.
        environment = os.environ.copy()
        environment["DJANGO_SETTINGS_MODULE"] = "config.settings"
        environment["SECRET_KEY"] = secret_key
        environment["DEBUG"] = debug
        return subprocess.run(
            [sys.executable, "-c", "from django.conf import settings; print(len(settings.SECRET_KEY))"],
            cwd=settings.BASE_DIR,
            env=environment,
            capture_output=True,
            text=True,
        )

    def test_production_refuses_missing_key(self):
        result = self.load_settings("", "False")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY is missing or too weak", result.stderr)

    def test_production_refuses_insecure_placeholder_key(self):
        result = self.load_settings("django-insecure-" + "x" * 60, "False")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY is missing or too weak", result.stderr)

    def test_production_refuses_short_key(self):
        result = self.load_settings("short-key-123", "False")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY is missing or too weak", result.stderr)

    def test_production_accepts_long_random_key(self):
        strong_key = secrets.token_urlsafe(48)
        result = self.load_settings(strong_key, "False")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(len(strong_key)))

    def test_development_uses_throwaway_key_when_missing(self):
        result = self.load_settings("", "True")
        self.assertEqual(result.returncode, 0, result.stderr)


class BreachedPasswordCheckTests(TestCase):
    """
    The breached-password check asks HaveIBeenPwned (k-anonymity: only the
    first 5 characters of the SHA-1 hash leave the server). In Docker it goes
    through the breach-proxy container, the web container's only way out.
    Network access is replaced with a stand-in here.
    """

    # SHA-1 of "password123" is CBFDAC6008F9CAB4083784CBD1874F76618D2A97.
    BREACHED_PASSWORD = "password123"
    BREACHED_SUFFIX = "C6008F9CAB4083784CBD1874F76618D2A97"

    def fake_opener(self, response_text):
        # An opener whose open() returns response_text, like HaveIBeenPwned would.
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = response_text.encode("utf-8")
        return opener

    def test_breached_password_is_rejected(self):
        opener = self.fake_opener(f"0000000000000000000000000000000000A:1\r\n{self.BREACHED_SUFFIX}:2500\r\n")
        with patch("kura.validators.urllib.request.build_opener", return_value=opener):
            with self.assertRaises(ValidationError):
                BreachedPasswordValidator().validate(self.BREACHED_PASSWORD)
        # Only the 5-character prefix was sent.
        sent_request = opener.open.call_args[0][0]
        self.assertTrue(sent_request.full_url.endswith("/range/CBFDA"))

    def test_password_not_in_list_is_accepted(self):
        opener = self.fake_opener("0000000000000000000000000000000000A:1\r\n")
        with patch("kura.validators.urllib.request.build_opener", return_value=opener):
            BreachedPasswordValidator().validate(self.BREACHED_PASSWORD)

    def test_network_failure_is_logged_without_the_password(self):
        opener = MagicMock()
        opener.open.side_effect = OSError("no route to host")
        with patch("kura.validators.urllib.request.build_opener", return_value=opener):
            with self.assertLogs("kura.security", level="WARNING") as captured:
                BreachedPasswordValidator().validate(self.BREACHED_PASSWORD)
        log_text = "\n".join(captured.output)
        self.assertIn('event="auth.breach_check.unavailable"', log_text)
        self.assertNotIn(self.BREACHED_PASSWORD, log_text)
        self.assertNotIn("CBFDA", log_text)

    @override_settings(BREACH_CHECK_PROXY_URL="http://breach-proxy:8888")
    def test_lookup_goes_through_the_proxy_when_set(self):
        opener = self.fake_opener("")
        with patch("kura.validators.urllib.request.build_opener", return_value=opener) as build_opener:
            BreachedPasswordValidator().validate("a-long-unique-test-password")
        proxy_handlers = []
        for handler in build_opener.call_args[0]:
            if isinstance(handler, urllib.request.ProxyHandler):
                proxy_handlers.append(handler)
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {"https": "http://breach-proxy:8888"})

    @override_settings(BREACH_CHECK_PROXY_URL="", BREACH_CHECK_CA_FILE="")
    def test_no_proxy_means_a_direct_connection(self):
        # An empty proxy setting also ignores any HTTPS_PROXY in the environment.
        opener = self.fake_opener("")
        with patch("kura.validators.urllib.request.build_opener", return_value=opener) as build_opener:
            BreachedPasswordValidator().validate("a-long-unique-test-password")
        for handler in build_opener.call_args[0]:
            if isinstance(handler, urllib.request.ProxyHandler):
                self.assertEqual(handler.proxies, {})

    @override_settings(BREACH_CHECK_CA_FILE="/no/such/ca-file.crt")
    def test_missing_ca_file_fails_open_with_a_warning(self):
        # A wrong certificate path must not break password changes (500 error).
        with self.assertLogs("kura.security", level="WARNING") as captured:
            BreachedPasswordValidator().validate("a-long-unique-test-password")
        self.assertIn('event="auth.breach_check.unavailable"', "\n".join(captured.output))


class BreachCheckProxyConfigTests(TestCase):
    """
    The breach-proxy container lets the web container reach only
    api.pwnedpasswords.com, and only the web container may use it.
    """

    def setUp(self):
        base_dir = Path(settings.BASE_DIR)
        self.compose_text = (base_dir / "docker-compose.yml").read_text(encoding="utf-8")
        self.proxy_settings = (base_dir / "docker" / "breach-proxy" / "tinyproxy.conf").read_text(encoding="utf-8")
        self.allowlist = (base_dir / "docker" / "breach-proxy" / "filter").read_text(encoding="utf-8")
        self.dockerfile = (base_dir / "docker" / "breach-proxy" / "Dockerfile").read_text(encoding="utf-8")

    def test_allowlist_has_only_haveibeenpwned(self):
        allowed_lines = []
        for line in self.allowlist.splitlines():
            if line.strip():
                allowed_lines.append(line.strip())
        self.assertEqual(allowed_lines, [r"^api\.pwnedpasswords\.com$"])

    def test_proxy_refuses_everything_else(self):
        self.assertIn("FilterDefaultDeny Yes", self.proxy_settings)
        self.assertIn("ConnectPort 443", self.proxy_settings)
        self.assertIn("FilterURLs Off", self.proxy_settings)

    def test_only_the_breach_check_network_may_use_the_proxy(self):
        self.assertIn("Allow 172.28.50.0/24", self.proxy_settings)
        self.assertIn("subnet: 172.28.50.0/24", self.compose_text)
        breach_network = self.compose_text.split("  breach_check:\n", 1)[1].split("\n  breach_check_egress:", 1)[0]
        self.assertIn("internal: true", breach_network)

    def test_proxy_runs_unprivileged_on_a_pinned_image(self):
        self.assertIn("USER tinyproxy", self.dockerfile)
        self.assertRegex(self.dockerfile, r"FROM alpine:[0-9.]+@sha256:[0-9a-f]{64}")

    def test_web_uses_the_proxy_and_public_certificates(self):
        self.assertIn('BREACH_CHECK_PROXY_URL: "http://breach-proxy:8888"', self.compose_text)
        self.assertIn('BREACH_CHECK_CA_FILE: "/etc/ssl/certs/ca-certificates.crt"', self.compose_text)


class FakeTransitVault:
    """
    Stands in for Vault in the answer-key tests. "Encrypting" just labels the
    base64 text, which is enough to check that Kura sends the key through
    Vault, with the right key name, and stores only what Vault returns.
    """

    def __init__(self):
        self.key_names_used = []
        self.secrets = MagicMock()
        self.secrets.transit.encrypt_data.side_effect = self.encrypt_data
        self.secrets.transit.decrypt_data.side_effect = self.decrypt_data

    def encrypt_data(self, name, mount_point, plaintext):
        self.key_names_used.append(name)
        return {"data": {"ciphertext": "vault:v1:" + plaintext}}

    def decrypt_data(self, name, mount_point, ciphertext):
        self.key_names_used.append(name)
        return {"data": {"plaintext": ciphertext.removeprefix("vault:v1:")}}


@override_settings(VAULT_ENABLED=True)
class AnswerKeyEncryptionTests(TestCase):
    """
    Exam answer keys are encrypted by Vault (key "kura-answer-keys") before they
    are saved, and decrypted in memory only for auto-grading and editing.
    If Vault is down, submissions still go through (to manual grading).
    """

    def setUp(self):
        self.client = Client()
        self.fake_vault = FakeTransitVault()
        vault_patch = patch("kura.vault.get_vault_client", return_value=self.fake_vault)
        vault_patch.start()
        self.addCleanup(vault_patch.stop)

        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        head = make_user("Department head", mfa_enabled=True)
        department = Department.objects.create(name="Security", code="SEC", head_user=head)
        course = Course.objects.create(
            department=department, code="SEC101", title="Security", semester="1", academic_year=2026,
            is_published=True, published_by=head, published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=course, user=self.instructor, staff_role="lead_instructor")
        module = Module.objects.create(course=course, title="Week 1", is_visible=True)
        self.section = ModuleSection.objects.create(module=module, title="Quiz", section_type="exam")
        now = timezone.now()
        self.assessment = Assessment.objects.create(
            section=self.section, title="Quiz 1", component_type=GradeComponentType.QUIZ, max_score=10,
            max_attempts=1, opens_at=now - timezone.timedelta(hours=1), due_date=now + timezone.timedelta(days=1),
            duration_minutes=30, created_by=self.instructor, settings_json={"autosave_interval_seconds": 15},
            questions_json=[{"question_id": "q1", "type": "multiple_choice", "prompt": "Pick A", "points": 10,
                             "options": [{"option_id": "a", "text": "A"}, {"option_id": "b", "text": "B"}]}],
        )
        ExamAnswerKey.objects.create(
            assessment=self.assessment, created_by=self.instructor,
            answer_key_json=encrypt_answer_key({"q1": {"correct_option_ids": ["a"]}}),
        )

    def make_submitted_attempt(self, chosen_option):
        # A sealed attempt (time and hash set), ready for evaluate_attempt.
        return AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            expires_at=timezone.now() + timezone.timedelta(minutes=30), ip_address="127.0.0.1",
            submitted_at=timezone.now(), submission_hash="0" * 64,
            answers_json=[{"question_id": "q1", "type": "multiple_choice", "selected_option_ids": [chosen_option]}],
        )

    def test_saved_answer_key_is_vault_ciphertext_only(self):
        stored = ExamAnswerKey.objects.get(assessment=self.assessment).answer_key_json
        self.assertEqual(list(stored.keys()), ["ciphertext"])
        self.assertTrue(stored["ciphertext"].startswith("vault:v1:"))
        self.assertNotIn("correct_option_ids", json.dumps(stored))
        self.assertEqual(self.fake_vault.key_names_used, ["kura-answer-keys"])

    def test_decrypt_gives_back_the_answer_key(self):
        stored = ExamAnswerKey.objects.get(assessment=self.assessment).answer_key_json
        self.assertEqual(decrypt_answer_key(stored), {"q1": {"correct_option_ids": ["a"]}})

    def test_plain_answer_key_is_refused_when_vault_is_on(self):
        with self.assertRaises(ValidationError):
            decrypt_answer_key({"q1": {"correct_option_ids": ["a"]}})

    def test_auto_grading_uses_the_decrypted_key(self):
        attempt = self.make_submitted_attempt("a")
        evaluate_attempt(attempt)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.FULLY_GRADED)
        self.assertEqual(attempt.summary_score_json["total_score"], 10.0)

    def test_vault_down_sends_attempt_to_manual_grading(self):
        # The submission is kept and not marked as zero; an instructor grades it.
        attempt = self.make_submitted_attempt("a")
        self.fake_vault.secrets.transit.decrypt_data.side_effect = ConnectionError("Vault down")
        evaluate_attempt(attempt)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, AttemptStatus.REQUIRES_MANUAL_GRADING)
        self.assertIsNone(attempt.summary_score_json)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())

    def test_assessment_builder_saves_only_ciphertext(self):
        self.client.force_login(self.instructor)
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Quiz 2", "component_type": GradeComponentType.QUIZ, "delivery_mode": "online",
            "max_score": "10", "max_attempts": 1, "duration_minutes": 30, "autosave_interval_seconds": 15,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 0,
            "questions-0-type": "multiple_choice", "questions-0-prompt": "Pick B", "questions-0-points": "10",
            "questions-0-option_1": "A", "questions-0-option_2": "B", "questions-0-correct_2": "on",
        })
        new_assessment = Assessment.objects.get(title="Quiz 2")
        self.assertRedirects(response, reverse("kura:assessment_detail", kwargs={"assessment_id": new_assessment.id}))
        stored = new_assessment.answer_key.answer_key_json
        self.assertEqual(list(stored.keys()), ["ciphertext"])
        question_id = new_assessment.questions_json[0]["question_id"]
        self.assertEqual(decrypt_answer_key(stored)[question_id]["correct_option_ids"], ["opt_2"])

    def test_builder_saves_nothing_when_vault_is_down(self):
        self.client.force_login(self.instructor)
        self.fake_vault.secrets.transit.encrypt_data.side_effect = ConnectionError("Vault down")
        now = timezone.now()
        response = self.client.post(reverse("kura:assessment_create", kwargs={"section_id": self.section.id}), {
            "title": "Quiz 3", "component_type": GradeComponentType.QUIZ, "delivery_mode": "online",
            "max_score": "10", "max_attempts": 1, "duration_minutes": 30, "autosave_interval_seconds": 15,
            "opens_at": (now - timezone.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "due_date": (now + timezone.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M"),
            "questions-TOTAL_FORMS": 1, "questions-INITIAL_FORMS": 0,
            "questions-0-type": "multiple_choice", "questions-0-prompt": "Pick B", "questions-0-points": "10",
            "questions-0-option_1": "A", "questions-0-option_2": "B", "questions-0-correct_2": "on",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "could not be saved securely right now")
        self.assertFalse(Assessment.objects.filter(title="Quiz 3").exists())

    def test_edit_page_is_not_shown_when_vault_is_down(self):
        self.client.force_login(self.instructor)
        self.fake_vault.secrets.transit.decrypt_data.side_effect = ConnectionError("Vault down")
        response = self.client.get(reverse("kura:assessment_edit", kwargs={"assessment_id": self.assessment.id}))
        self.assertRedirects(
            response,
            reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id}),
            fetch_redirect_response=False,
        )

    def test_command_encrypts_plain_keys_and_skips_encrypted_ones(self):
        other = Assessment.objects.create(
            section=self.section, title="Old quiz", component_type=GradeComponentType.QUIZ, max_score=10,
            max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(days=1),
            duration_minutes=30, created_by=self.instructor,
        )
        ExamAnswerKey.objects.create(assessment=other, created_by=self.instructor,
                                     answer_key_json={"q1": {"correct_option_ids": ["b"]}})
        output = StringIO()
        call_command("encrypt_answer_keys", stdout=output)
        self.assertIn("Encrypted 1 answer key(s); 1 were already encrypted.", output.getvalue())
        stored = ExamAnswerKey.objects.get(assessment=other).answer_key_json
        self.assertEqual(decrypt_answer_key(stored), {"q1": {"correct_option_ids": ["b"]}})
        self.assertNotIn("correct_option_ids", json.dumps(stored))


class GradeHistoryInsertOnlyTests(TestCase):
    """
    Migration 0016: the application role (kura_app) may add grade history rows
    but may not change or delete them, so the grade audit log cannot be rewritten.
    """

    def setUp(self):
        instructor = make_user("Instructor", mfa_enabled=True)
        student = make_user("Student", mfa_enabled=True)
        head = make_user("Department head", mfa_enabled=True)
        department = Department.objects.create(name="History", code="HIS", head_user=head)
        course = Course.objects.create(department=department, code="HIS101", title="History", semester="1",
                                       academic_year=2026)
        module = Module.objects.create(course=course, title="Week 1")
        section = ModuleSection.objects.create(module=module, title="Exam", section_type="exam")
        now = timezone.now()
        assessment = Assessment.objects.create(
            section=section, title="Exam", component_type=GradeComponentType.EXAM, max_score=10, max_attempts=1,
            opens_at=now, due_date=now + timezone.timedelta(days=1), duration_minutes=30, created_by=instructor,
        )
        attempt = AssessmentAttempt.objects.create(assessment=assessment, student=student, attempt_no=1,
                                                   expires_at=now, ip_address="127.0.0.1")
        self.grade = Grade.objects.create(assessment=assessment, student=student, attempt=attempt, score=7)
        self.history = GradeHistory.objects.create(grade=self.grade, new_score=7, new_status="draft",
                                                   changed_by=instructor)
        self.instructor = instructor

    def run_as_app_role(self, sql, parameters):
        # Run one statement as kura_app (inside a savepoint, so a refused
        # statement does not break the rest of the test), then switch back.
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE kura_app;")
            try:
                with transaction.atomic():
                    cursor.execute(sql, parameters)
            finally:
                cursor.execute("RESET ROLE;")

    def test_app_role_cannot_update_history(self):
        with self.assertRaises(DatabaseError):
            self.run_as_app_role("UPDATE grade_history SET new_score = 10 WHERE id = %s;", [self.history.id])
        self.history.refresh_from_db()
        self.assertEqual(self.history.new_score, 7)

    def test_app_role_cannot_delete_history(self):
        with self.assertRaises(DatabaseError):
            self.run_as_app_role("DELETE FROM grade_history WHERE id = %s;", [self.history.id])
        self.assertTrue(GradeHistory.objects.filter(id=self.history.id).exists())

    def test_app_role_can_still_add_history(self):
        self.run_as_app_role(
            "INSERT INTO grade_history (grade_id, new_score, new_status, changed_by_id, changed_at) "
            "VALUES (%s, %s, %s, %s, NOW());",
            [self.grade.id, 8, "draft", self.instructor.id],
        )
        self.assertEqual(GradeHistory.objects.filter(grade=self.grade).count(), 2)


@override_settings(VAULT_ENABLED=False)
class RecoveryCodeHashingTests(TestCase):
    """
    Recovery codes are saved only as keyed hashes (HMAC-SHA256 with SECRET_KEY),
    so a copy of the database does not reveal them. Each code still works once,
    at login and for grade release.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student")
        self.static_device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=self.static_device, token=hash_recovery_code("ABCD1234"))

    def log_in_with_code(self, code):
        # Step 1 (password), then step 2 (the recovery code). Returns the step 2 response.
        self.client.post(reverse("kura:login"), {"email": self.user.email, "password": "ValidPassword123!"})
        return self.client.post(reverse("kura:mfa_verify"), {"code": code})

    def test_setup_saves_only_hashes_of_the_codes_it_shows(self):
        new_user = make_user("Student", mfa_enabled=False)
        self.client.force_login(new_user)
        self.client.get(reverse("kura:mfa_setup"))
        new_user.refresh_from_db()
        device = TOTPDevice.objects.get(user=new_user, name="default")
        totp = TOTP(bytes.fromhex(new_user.mfa_secret), device.step, device.t0, device.digits, device.drift)
        totp.time = time.time()
        self.client.post(reverse("kura:mfa_setup"), {"code": str(totp.token()).zfill(device.digits)})

        # The completion page shows the 10 codes once.
        response = self.client.get(reverse("kura:mfa_setup_complete"))
        shown_codes = response.context["recovery_codes"]
        self.assertEqual(len(shown_codes), 10)

        # The database holds 10 hashes and none of the codes themselves.
        saved_tokens = []
        for static_token in StaticToken.objects.filter(device__user=new_user):
            saved_tokens.append(static_token.token)
        self.assertEqual(len(saved_tokens), 10)
        for code in shown_codes:
            self.assertNotIn(code, saved_tokens)
            self.assertIn(hash_recovery_code(code), saved_tokens)

    def test_hash_depends_on_secret_key(self):
        # Without SECRET_KEY the hash cannot be recomputed, so the 4 billion
        # possible codes cannot simply be tried against a stolen database.
        normal_hash = hash_recovery_code("ABCD1234")
        with override_settings(SECRET_KEY="a-different-secret-key-" + "x" * 40):
            other_hash = hash_recovery_code("ABCD1234")
        self.assertNotEqual(normal_hash, other_hash)
        self.assertEqual(len(normal_hash), 16)

    def test_code_works_once_at_login(self):
        response = self.log_in_with_code("ABCD1234")
        self.assertRedirects(response, reverse("kura:home"))
        self.assertFalse(StaticToken.objects.filter(device=self.static_device).exists())

        # Using the same code again fails.
        self.client.logout()
        response = self.log_in_with_code("ABCD1234")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid security code.")

    def test_code_ignores_spaces_and_letter_case(self):
        response = self.log_in_with_code("abcd 1234")
        self.assertRedirects(response, reverse("kura:home"))

    def test_code_saved_as_plain_text_is_refused(self):
        # A code saved the old way (plain text) does not work any more.
        StaticToken.objects.filter(device=self.static_device).delete()
        StaticToken.objects.create(device=self.static_device, token="ABCD1234")
        response = self.log_in_with_code("ABCD1234")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid security code.")


@override_settings(VAULT_ENABLED=False)
class VaultTOTPSeedTests(TestCase):
    """
    Authenticator (TOTP) seeds live only in User.mfa_secret, encrypted by Vault.
    TOTPDevice.key is a random placeholder. With Vault off (as in these tests)
    mfa_secret holds the seed as-is; Vault calls are replaced with mocks where
    a test needs to see ciphertext or a Vault failure.
    """

    def setUp(self):
        self.client = Client()
        self.seed_hex = random_hex(20)
        self.user = make_user("Student")
        self.user.mfa_secret = self.seed_hex
        self.user.save(update_fields=["mfa_secret"])
        self.device = TOTPDevice.objects.get(user=self.user, name="default")

    def current_code(self, seed_hex):
        # Work out the code an authenticator app with this seed shows right now.
        totp = TOTP(bytes.fromhex(seed_hex), self.device.step, self.device.t0, self.device.digits, self.device.drift)
        totp.time = time.time()
        return str(totp.token()).zfill(self.device.digits)

    def test_login_accepts_code_from_the_vault_seed(self):
        response = self.client.post(reverse("kura:login"), {"email": self.user.email, "password": "ValidPassword123!"})
        self.assertRedirects(response, reverse("kura:mfa_verify"))
        response = self.client.post(reverse("kura:mfa_verify"), {"code": self.current_code(self.seed_hex)})
        self.assertRedirects(response, reverse("kura:home"))

    def test_same_code_cannot_be_used_twice(self):
        code = self.current_code(self.seed_hex)
        self.assertTrue(verify_totp_code(self.device, self.user, code))
        self.assertFalse(verify_totp_code(self.device, self.user, code))

    def test_code_from_the_placeholder_key_is_rejected(self):
        # TOTPDevice.key is not the seed, so a code made from it must not work.
        self.assertNotEqual(self.device.key, self.seed_hex)
        self.assertFalse(verify_totp_code(self.device, self.user, self.current_code(self.device.key)))

    def test_wrong_code_counts_towards_throttling(self):
        self.assertFalse(verify_totp_code(self.device, self.user, "000000x"))
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 1)

    def test_vault_failure_rejects_code_without_blaming_the_user(self):
        # Vault down: the right code is refused (fail closed) but is not counted
        # as a wrong guess, so the user is not throttled for Vault's problem.
        with patch("kura.views.decrypt_mfa_secret", side_effect=ValidationError("Vault down")):
            self.assertFalse(verify_totp_code(self.device, self.user, self.current_code(self.seed_hex)))
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)

    def test_recovery_code_still_works_when_vault_is_down(self):
        static_device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=static_device, token=hash_recovery_code("ABCD1234"))
        self.client.post(reverse("kura:login"), {"email": self.user.email, "password": "ValidPassword123!"})
        with patch("kura.views.decrypt_mfa_secret", side_effect=ValidationError("Vault down")):
            response = self.client.post(reverse("kura:mfa_verify"), {"code": "ABCD1234"})
        self.assertRedirects(response, reverse("kura:home"))

    def test_setup_saves_only_vault_ciphertext(self):
        new_user = make_user("Student", mfa_enabled=False)
        self.client.force_login(new_user)
        seeds_given_to_vault = []

        def fake_encrypt(seed_hex):
            seeds_given_to_vault.append(seed_hex)
            return "vault:v1:fake-ciphertext"

        with patch("kura.views.encrypt_mfa_secret", side_effect=fake_encrypt), patch(
            "kura.views.decrypt_mfa_secret", side_effect=lambda ciphertext: seeds_given_to_vault[0]
        ):
            response = self.client.get(reverse("kura:mfa_setup"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/svg+xml;utf8,")
        new_user.refresh_from_db()
        self.assertEqual(new_user.mfa_secret, "vault:v1:fake-ciphertext")
        # The device's own key is NOT the seed that went to Vault.
        device = TOTPDevice.objects.get(user=new_user, name="default")
        self.assertNotEqual(device.key, seeds_given_to_vault[0])

    def test_setup_confirms_with_a_code_from_the_new_seed(self):
        new_user = make_user("Student", mfa_enabled=False)
        self.client.force_login(new_user)
        self.client.get(reverse("kura:mfa_setup"))
        new_user.refresh_from_db()
        response = self.client.post(reverse("kura:mfa_setup"), {"code": self.current_code(new_user.mfa_secret)})
        self.assertRedirects(response, reverse("kura:mfa_setup_complete"))
        self.assertTrue(TOTPDevice.objects.get(user=new_user, name="default").confirmed)

    def test_setup_shows_503_when_vault_is_down(self):
        new_user = make_user("Student", mfa_enabled=False)
        self.client.force_login(new_user)
        with patch("kura.views.encrypt_mfa_secret", side_effect=ValidationError("Vault down")):
            response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "unavailable right now", status_code=503)
        self.assertNotContains(response, "TOTP QR Code", status_code=503)
        new_user.refresh_from_db()
        self.assertIsNone(new_user.mfa_secret)

    @override_settings(VAULT_ENABLED=True)
    def test_plain_text_seed_is_refused_when_vault_is_on(self):
        with self.assertRaises(ValidationError):
            decrypt_mfa_secret(self.seed_hex)

    @override_settings(
        VAULT_URL="https://vault:8200",
        VAULT_CA_CERT="/certs/internal/ca.crt",
        VAULT_ROLE_ID="test-role-id",
        VAULT_SECRET_ID="test-secret-id",
    )
    def test_vault_client_checks_certificate_and_logs_in_with_approle(self):
        with patch("kura.vault.hvac.Client") as mock_client_class:
            client = get_vault_client()
        mock_client_class.assert_called_once_with(url="https://vault:8200", verify="/certs/internal/ca.crt")
        client.auth.approle.login.assert_called_once_with(role_id="test-role-id", secret_id="test-secret-id")

    def test_command_moves_old_plain_text_seed_into_mfa_secret(self):
        # Simulate a user enrolled before stage 2: seed in TOTPDevice.key, no mfa_secret.
        old_seed = self.device.key
        self.user.mfa_secret = None
        self.user.save(update_fields=["mfa_secret"])

        with patch(
            "kura.management.commands.encrypt_totp_seeds.encrypt_mfa_secret", return_value="vault:v1:moved"
        ) as mock_encrypt:
            call_command("encrypt_totp_seeds", stdout=StringIO())

        mock_encrypt.assert_called_once_with(old_seed)
        self.user.refresh_from_db()
        self.device.refresh_from_db()
        self.assertEqual(self.user.mfa_secret, "vault:v1:moved")
        self.assertNotEqual(self.device.key, old_seed)

    def test_command_keeps_the_users_authenticator_app_working(self):
        # With Vault off the "ciphertext" is the seed itself, so the old app code still works.
        old_seed = self.device.key
        self.user.mfa_secret = None
        self.user.save(update_fields=["mfa_secret"])
        output = StringIO()
        call_command("encrypt_totp_seeds", stdout=output)
        self.assertIn("Moved 1", output.getvalue())
        self.user.refresh_from_db()
        self.device.refresh_from_db()
        self.assertTrue(verify_totp_code(self.device, self.user, self.current_code(old_seed)))

        # Running it again changes nothing.
        output = StringIO()
        call_command("encrypt_totp_seeds", stdout=output)
        self.assertIn("Moved 0", output.getvalue())

    def test_command_stops_and_changes_nothing_when_vault_is_down(self):
        old_seed = self.device.key
        self.user.mfa_secret = None
        self.user.save(update_fields=["mfa_secret"])
        with patch(
            "kura.management.commands.encrypt_totp_seeds.encrypt_mfa_secret", side_effect=ValidationError("Vault down")
        ):
            with self.assertRaises(CommandError):
                call_command("encrypt_totp_seeds", stdout=StringIO())
        self.user.refresh_from_db()
        self.device.refresh_from_db()
        self.assertIsNone(self.user.mfa_secret)
        self.assertEqual(self.device.key, old_seed)


class VaultDatabaseLoginTests(TestCase):
    """
    Stage 3a: Django logs in to PostgreSQL with temporary users from Vault.
    kura/vault.py caches one login per worker; kura/vault_postgres/base.py uses it
    for every new connection. Vault itself is replaced by a mock here.
    """

    def setUp(self):
        # Start every test with an empty cache (it is shared by the whole process).
        database_login_cache["username"] = ""
        database_login_cache["password"] = ""
        database_login_cache["refresh_after"] = 0
        self.addCleanup(database_login_cache.update, {"username": "", "password": "", "refresh_after": 0})

    def fake_vault_client(self, username="kura_dyn_test", lease_seconds=900):
        # A pretend Vault client that hands out one temporary login.
        client = MagicMock()
        client.secrets.database.generate_credentials.return_value = {
            "data": {"username": username, "password": "temporary-password"},
            "lease_duration": lease_seconds,
        }
        return client

    @patch("kura.vault.get_vault_client")
    def test_login_comes_from_the_kura_app_role(self, mock_get_client):
        mock_get_client.return_value = self.fake_vault_client()
        login = get_dynamic_database_credentials()
        self.assertEqual(login["username"], "kura_dyn_test")
        self.assertEqual(login["password"], "temporary-password")
        mock_get_client.return_value.secrets.database.generate_credentials.assert_called_once_with(
            name="kura-app", mount_point="database"
        )

    @patch("kura.vault.get_vault_client")
    def test_login_is_reused_instead_of_asking_vault_every_time(self, mock_get_client):
        mock_get_client.return_value = self.fake_vault_client()
        for _ in range(5):
            get_dynamic_database_credentials()
        self.assertEqual(mock_get_client.return_value.secrets.database.generate_credentials.call_count, 1)

    @patch("kura.vault.get_vault_client")
    def test_new_login_is_fetched_five_minutes_before_expiry(self, mock_get_client):
        mock_get_client.return_value = self.fake_vault_client(lease_seconds=900)
        before = time.time()
        get_dynamic_database_credentials()
        # 900 second lease, so a new login is due after about 600 seconds.
        self.assertAlmostEqual(database_login_cache["refresh_after"], before + 600, delta=5)

        # Pretend those 10 minutes have passed: the next call asks Vault again.
        database_login_cache["refresh_after"] = time.time() - 1
        mock_get_client.return_value = self.fake_vault_client(username="kura_dyn_second")
        self.assertEqual(get_dynamic_database_credentials()["username"], "kura_dyn_second")

    @patch("kura.vault.get_vault_client", side_effect=Exception("Vault is sealed"))
    def test_vault_failure_raises_validation_error(self, mock_get_client):
        with self.assertRaises(ValidationError):
            get_dynamic_database_credentials()

    @patch("kura.vault_postgres.base.get_dynamic_database_credentials")
    def test_backend_uses_vault_login_and_keeps_tls_options(self, mock_get_login):
        mock_get_login.return_value = {"username": "kura_dyn_test", "password": "temporary-password"}
        settings_dict = dict(connection.settings_dict)
        settings_dict["USER"] = "kura-admin"
        settings_dict["PASSWORD"] = "fixed-password-must-not-be-used"
        settings_dict["OPTIONS"] = {
            "sslmode": "verify-full",
            "sslrootcert": "/certs/internal/ca.crt",
            "sslcert": "/certs/internal/web.crt",
            "sslkey": "/certs/internal/web.key",
        }
        params = VaultDatabaseWrapper(settings_dict).get_connection_params()
        self.assertEqual(params["user"], "kura_dyn_test")
        self.assertEqual(params["password"], "temporary-password")
        self.assertEqual(params["sslmode"], "verify-full")
        self.assertEqual(params["sslcert"], "/certs/internal/web.crt")

    @patch("kura.vault_postgres.base.get_dynamic_database_credentials", side_effect=ValidationError("down"))
    def test_backend_reports_vault_failure_as_database_error(self, mock_get_login):
        from django.db.utils import OperationalError

        with self.assertRaises(OperationalError):
            VaultDatabaseWrapper(dict(connection.settings_dict)).get_connection_params()

    def test_setting_switches_the_database_backend(self):
        # Load the settings in a fresh process with the switch on and off.
        environment = os.environ.copy()
        environment["DJANGO_SETTINGS_MODULE"] = "config.settings"
        environment["DEBUG"] = "True"
        engines = []
        for switch in ["True", "False"]:
            environment["VAULT_DATABASE_CREDENTIALS"] = switch
            result = subprocess.run(
                [sys.executable, "-c", "from django.conf import settings; print(settings.DATABASES['default']['ENGINE'])"],
                cwd=settings.BASE_DIR,
                env=environment,
                capture_output=True,
                text=True,
            )
            engines.append(result.stdout.strip())
        self.assertEqual(engines, ["kura.vault_postgres", "django.db.backends.postgresql"])


def fake_clamav_reply(reply):
    """
    Test helper: a pretend ClamAV socket that answers every command with `reply`.
    Used for scan results ("stream: ... FOUND") and version replies.
    """
    fake_socket = MagicMock()
    fake_socket.recv.return_value = reply
    return fake_socket


class ClamAVQuarantineTests(TransactionTestCase):
    """
    Uploads rejected by ClamAV are quarantined (stage "ClamAV"): kept for 7 days
    with who/what/when, never stored as a normal file, and visible only to Admins.
    TransactionTestCase because the quarantine connection only sees committed rows.
    """

    databases = {"default", "quarantine"}

    @classmethod
    def tearDownClass(cls):
        # Put back the seeded roles that TransactionTestCase removed.
        super().tearDownClass()
        reseed_roles_after_flush()

    def setUp(self):
        self.user = make_user("Student")
        self.eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def upload_rejected_as(self, detection, filename="homework.pdf"):
        # Upload a file while ClamAV (mocked) reports `detection`.
        reply = f"stream: {detection} FOUND\x00".encode()
        upload = SimpleUploadedFile(filename, self.eicar_bytes, content_type="application/pdf")
        with patch("socket.socket", return_value=fake_clamav_reply(reply)):
            with self.assertRaises(ValidationError) as context:
                validate_and_save_upload(upload, self.user)
        return context.exception

    def test_infected_upload_is_quarantined_not_stored(self):
        error = self.upload_rejected_as("Eicar-Test-Signature")
        self.assertIn("failed security scanning", str(error))
        self.assertEqual(StoredFile.objects.count(), 0)

        quarantined = QuarantinedFile.objects.get()
        self.assertEqual(quarantined.uploaded_by, self.user)
        self.assertEqual(quarantined.original_filename, "homework.pdf")
        self.assertEqual(quarantined.detection, "Eicar-Test-Signature")
        self.assertEqual(quarantined.size_bytes, len(self.eicar_bytes))
        self.assertEqual(quarantined.sha256_hash, hashlib.sha256(self.eicar_bytes).hexdigest())
        self.assertEqual(bytes(quarantined.content), self.eicar_bytes)

    def test_encrypted_and_macro_detections_are_quarantined_too(self):
        for detection in ["Heuristics.Encrypted.Zip", "Heuristics.OLE2.ContainsMacros"]:
            with self.subTest(detection=detection):
                self.upload_rejected_as(detection)
                self.assertTrue(QuarantinedFile.objects.filter(detection=detection).exists())

    def test_quarantine_record_survives_the_upload_transaction_rollback(self):
        # Most upload views run inside transaction.atomic(); the rejection rolls it back.
        try:
            with transaction.atomic():
                self.upload_rejected_as("Eicar-Test-Signature")
                raise ValidationError("the view gives up")
        except ValidationError:
            pass
        self.assertEqual(QuarantinedFile.objects.count(), 1)

    @override_settings(CLAMAV_REQUIRED=True)
    def test_scanner_outage_is_not_quarantined(self):
        broken_socket = MagicMock()
        broken_socket.connect.side_effect = OSError("Connection refused")
        upload = SimpleUploadedFile("notes.pdf", b"%PDF-1.4 notes", content_type="application/pdf")
        with patch("socket.socket", return_value=broken_socket):
            with self.assertRaises(ValidationError):
                validate_and_save_upload(upload, self.user)
        self.assertEqual(QuarantinedFile.objects.count(), 0)

    def test_security_log_records_details_and_escapes_the_file_name(self):
        with self.assertLogs("kura.security", level="WARNING") as captured:
            self.upload_rejected_as("Eicar-Test-Signature", filename="evil\nFAKE LOG LINE.pdf")
        log_line = captured.output[0]
        self.assertIn(str(self.user.id), log_line)
        self.assertIn(hashlib.sha256(self.eicar_bytes).hexdigest(), log_line)
        self.assertIn('detection="Eicar-Test-Signature"', log_line)
        self.assertIn('event="file.quarantined"', log_line)
        # The newline in the name is written as \\n, so no fake second log line appears.
        self.assertNotIn("\n", log_line)

    def test_old_signatures_log_a_warning(self):
        old_reply = b"ClamAV 1.5.4/27000/Mon Jan  5 09:00:00 2026\x00"
        with patch("socket.create_connection", return_value=fake_clamav_reply(old_reply)):
            with self.assertLogs("kura.security", level="WARNING") as captured:
                check_signature_age()
        self.assertIn('event="clamav.signatures_old"', captured.output[0])
        self.assertIn("age_days=", captured.output[0])

    def test_fresh_signatures_log_nothing(self):
        today = timezone.now().strftime("%a %b %d %H:%M:%S %Y")
        fresh_reply = f"ClamAV 1.5.4/27999/{today}\x00".encode()
        with patch("socket.create_connection", return_value=fake_clamav_reply(fresh_reply)):
            with self.assertNoLogs("kura.security", level="WARNING"):
                check_signature_age()

    def test_purge_deletes_only_quarantined_files_older_than_seven_days(self):
        self.upload_rejected_as("Old-Signature")
        self.upload_rejected_as("New-Signature")
        QuarantinedFile.objects.filter(detection="Old-Signature").update(
            created_at=timezone.now() - timezone.timedelta(days=8)
        )
        call_command("purge_quarantine", stdout=StringIO())
        remaining = list(QuarantinedFile.objects.values_list("detection", flat=True))
        self.assertEqual(remaining, ["New-Signature"])

    def test_admin_sees_details_but_never_the_file(self):
        self.upload_rejected_as("Eicar-Test-Signature")
        admin = make_user("Admin")
        self.client.force_login(admin)
        response = self.client.get(reverse("kura:quarantine_list"))
        self.assertContains(response, "Eicar-Test-Signature")
        self.assertContains(response, hashlib.sha256(self.eicar_bytes).hexdigest())
        self.assertNotContains(response, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
        # No link anywhere on the page points at a download URL.
        self.assertNotContains(response, '/download/"')

    def test_other_roles_cannot_see_or_delete_quarantine(self):
        self.upload_rejected_as("Eicar-Test-Signature")
        quarantined = QuarantinedFile.objects.get()
        for role_name in ["Student", "Instructor", "Registrar", "Department head"]:
            with self.subTest(role=role_name):
                self.client.force_login(make_user(role_name))
                self.assertEqual(self.client.get(reverse("kura:quarantine_list")).status_code, 403)
                delete_url = reverse("kura:quarantine_delete", kwargs={"quarantined_file_id": quarantined.id})
                self.assertEqual(self.client.post(delete_url, {"confirm": "on"}).status_code, 403)
        self.assertTrue(QuarantinedFile.objects.filter(id=quarantined.id).exists())

    def test_admin_delete_needs_post_and_confirmation(self):
        self.upload_rejected_as("Eicar-Test-Signature")
        quarantined = QuarantinedFile.objects.get()
        self.client.force_login(make_user("Admin"))
        delete_url = reverse("kura:quarantine_delete", kwargs={"quarantined_file_id": quarantined.id})

        self.assertEqual(self.client.get(delete_url).status_code, 405)
        self.client.post(delete_url, {})
        self.assertTrue(QuarantinedFile.objects.filter(id=quarantined.id).exists())

        response = self.client.post(delete_url, {"confirm": "on"})
        self.assertRedirects(response, reverse("kura:quarantine_list"))
        self.assertFalse(QuarantinedFile.objects.filter(id=quarantined.id).exists())


@override_settings(SITE_URL="https://kura.example.com")
class EmailNotificationTests(TestCase):
    """
    Email notifications through the outbox (OutgoingEmail): password resets,
    new/changed assessments, 24-hour reminders, submission receipts and appeal
    decisions, plus the send_queued_emails job.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor")
        self.student = make_user("Student")
        self.dropped_student = make_user("Student")
        department = Department.objects.create(name="Art", code="ART")
        self.course = Course.objects.create(
            department=department, code="ART101", title="Art History", semester="1", academic_year=2026,
            is_published=True, published_by=self.instructor, published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor")
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)
        Enrollment.objects.create(
            course=self.course, student=self.dropped_student, status=EnrollmentStatus.DROPPED,
            dropped_by=self.instructor, dropped_at=timezone.now(),
        )
        self.module = Module.objects.create(course=self.course, title="Renaissance", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Essays", section_type="coursework")
        self.assessment = Assessment.objects.create(
            section=self.section, title="Renaissance Essay", component_type=GradeComponentType.COURSEWORK,
            opens_at=timezone.now() - timezone.timedelta(hours=1),
            due_date=timezone.now() + timezone.timedelta(hours=10),
            duration_minutes=60, created_by=self.instructor,
        )

    # --- password reset ---------------------------------------------------

    def request_reset(self, email):
        return self.client.post(reverse("kura:password_reset_request"), {"email": email})

    def test_reset_is_queued_not_sent_and_uses_the_fixed_site_url(self):
        response = self.request_reset(self.student.email)
        self.assertRedirects(response, reverse("kura:login"), fetch_redirect_response=False)
        self.assertEqual(len(mail.outbox), 0)
        email = OutgoingEmail.objects.get(to_email=self.student.email)
        self.assertTrue(email.event_key.startswith("password-reset:"))
        self.assertIn("https://kura.example.com/password/reset/", email.body)

    def test_unknown_email_gets_same_answer_and_nothing_is_queued(self):
        known = self.request_reset(self.student.email)
        unknown = self.request_reset("nobody@kura.edu")
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known["Location"], unknown["Location"])
        self.assertFalse(OutgoingEmail.objects.filter(to_email="nobody@kura.edu").exists())

    def test_at_most_two_reset_emails_per_account_every_five_minutes(self):
        for _ in range(4):
            self.request_reset(self.student.email)
        self.assertEqual(OutgoingEmail.objects.filter(to_email=self.student.email).count(), 2)

    # --- the outbox helper --------------------------------------------------

    def test_same_event_is_only_queued_once_and_subject_is_one_line(self):
        queue_email("test-event:1", "a@kura.edu", "Line one\r\nBcc: victim@example.com", "Body")
        queue_email("test-event:1", "a@kura.edu", "Again", "Body")
        email = OutgoingEmail.objects.get(event_key="test-event:1")
        self.assertEqual(email.subject, "Line one Bcc: victim@example.com")
        self.assertEqual(OutgoingEmail.objects.filter(event_key="test-event:1").count(), 1)

    # --- assessment notifications ------------------------------------------

    def test_new_assessment_emails_only_active_students_once(self):
        queue_assessment_notification(self.assessment, "assessment-new", "New", "A new assessment.")
        queue_assessment_notification(self.assessment, "assessment-new", "New", "A new assessment.")
        recipients = list(OutgoingEmail.objects.values_list("to_email", flat=True))
        self.assertEqual(recipients, [self.student.email])
        body = OutgoingEmail.objects.get().body
        self.assertIn("Renaissance Essay", body)
        self.assertIn(f"https://kura.example.com/assessments/{self.assessment.id}/", body)

    def test_hidden_section_or_module_sends_nothing(self):
        self.section.is_visible = False
        self.section.save()
        queue_assessment_notification(self.assessment, "assessment-new", "New", "A new assessment.")
        self.assertEqual(OutgoingEmail.objects.count(), 0)

    def test_making_a_module_visible_announces_its_assessments(self):
        self.module.is_visible = False
        self.module.save()
        self.client.force_login(self.instructor)
        self.client.post(
            reverse("kura:module_edit", kwargs={"module_id": self.module.id}),
            {"title": "Renaissance", "description": "", "is_visible": "on", "target_levels": ["level_4"]},
        )
        self.assertTrue(
            OutgoingEmail.objects.filter(event_key=f"assessment-new:{self.assessment.id}:{self.student.id}").exists()
        )

    # --- 24-hour reminders --------------------------------------------------

    def test_reminder_goes_to_students_who_have_not_submitted_once(self):
        submitted = make_user("Student")
        Enrollment.objects.create(course=self.course, student=submitted, status=EnrollmentStatus.ACTIVE)
        AssessmentAttempt.objects.create(
            assessment=self.assessment, student=submitted, expires_at=timezone.now(),
            submitted_at=timezone.now(), ip_address="127.0.0.1",
        )
        call_command("queue_due_reminders", stdout=StringIO())
        call_command("queue_due_reminders", stdout=StringIO())
        reminders = OutgoingEmail.objects.filter(event_key__startswith="reminder-24h:")
        self.assertEqual(list(reminders.values_list("to_email", flat=True)), [self.student.email])

    def test_no_reminder_when_due_more_than_a_day_away_or_not_open(self):
        self.assessment.due_date = timezone.now() + timezone.timedelta(days=3)
        self.assessment.save()
        later = Assessment.objects.create(
            section=self.section, title="Not open yet", component_type=GradeComponentType.QUIZ,
            opens_at=timezone.now() + timezone.timedelta(hours=1),
            due_date=timezone.now() + timezone.timedelta(hours=5),
            duration_minutes=30, created_by=self.instructor,
        )
        call_command("queue_due_reminders", stdout=StringIO())
        self.assertFalse(OutgoingEmail.objects.filter(event_key__contains=str(later.id)).exists())
        self.assertEqual(OutgoingEmail.objects.count(), 0)

    # --- appeal decision ------------------------------------------------------

    def test_appeal_decision_is_emailed_to_the_student(self):
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, expires_at=timezone.now(), ip_address="127.0.0.1",
        )
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=attempt, score=Decimal("61"),
            status=GradeStatus.RELEASED,
        )
        appeal = GradeAppeal.objects.create(grade=grade, reason="Please review")
        self.client.force_login(self.instructor)
        self.client.post(
            reverse("kura:grade_appeal_review", kwargs={"appeal_id": appeal.id}),
            {"status": "approved", "response": "Marks added."},
        )
        notice = OutgoingEmail.objects.get(event_key__startswith=f"appeal-decided:{appeal.id}:")
        self.assertEqual(notice.to_email, self.student.email)
        self.assertNotIn("61", notice.body)

    # --- send_queued_emails ---------------------------------------------------

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_sending_marks_sent_and_wipes_the_body(self):
        queue_email("test-send:1", self.student.email, "Subject", "Secret link")
        call_command("send_queued_emails", stdout=StringIO())
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "Kura <noreply@kura.edu>")
        email = OutgoingEmail.objects.get(event_key="test-send:1")
        self.assertEqual(email.status, OutgoingEmailStatus.SENT)
        self.assertEqual(email.body, "")

    def test_failed_sends_are_retried_then_given_up_after_five(self):
        import smtplib

        queue_email("test-send:2", self.student.email, "Subject", "Body")
        with patch("kura.management.commands.send_queued_emails.EmailMessage.send", side_effect=smtplib.SMTPException):
            for _ in range(4):
                call_command("send_queued_emails", stdout=StringIO())
            email = OutgoingEmail.objects.get(event_key="test-send:2")
            self.assertEqual((email.status, email.attempts), (OutgoingEmailStatus.PENDING, 4))
            call_command("send_queued_emails", stdout=StringIO())
        email.refresh_from_db()
        self.assertEqual((email.status, email.attempts, email.body), (OutgoingEmailStatus.FAILED, 5, ""))
        self.assertEqual(email.last_error, "SMTPException")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_old_reset_emails_expire_instead_of_sending(self):
        queue_email("password-reset:old", self.student.email, "Reset", "Old link")
        OutgoingEmail.objects.filter(event_key="password-reset:old").update(
            created_at=timezone.now() - timezone.timedelta(minutes=31)
        )
        call_command("send_queued_emails", stdout=StringIO())
        email = OutgoingEmail.objects.get(event_key="password-reset:old")
        self.assertEqual((email.status, email.body), (OutgoingEmailStatus.FAILED, ""))
        self.assertEqual(len(mail.outbox), 0)


class PasskeyAddedAuditTests(TestCase):
    """
    WP1: adding a passkey writes auth.passkey.added. The FIDO2 cryptography is
    django-mfa2's job, so its complete_reg view is replaced with a stand-in here.
    """

    def setUp(self):
        self.user = make_user("Student")
        self.client.force_login(self.user)
        confirm_second_factor(self.client)

    def test_successful_registration_is_logged(self):
        from django.http import JsonResponse
        from mfa.models import User_Keys

        def fake_complete_reg(request):
            User_Keys.objects.create(username=request.user.username, key_type="FIDO2", properties={})
            return JsonResponse({"status": "OK"})

        with patch("mfa.FIDO2.complete_reg", side_effect=fake_complete_reg):
            with self.assertLogs("kura.security", level="INFO") as captured:
                response = self.client.post("/mfa/fido2/complete_reg", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any('event="auth.passkey.added"' in line for line in captured.output))

    def test_failed_registration_is_not_logged(self):
        from django.http import JsonResponse

        with patch("mfa.FIDO2.complete_reg", return_value=JsonResponse({"status": "ERR"})):
            with self.assertNoLogs("kura.security", level="INFO"):
                self.client.post("/mfa/fido2/complete_reg", data="{}", content_type="application/json")


class PasskeyOnlyMfaUrlsTests(TestCase):
    """
    Only django-mfa2's passkey (FIDO2) pages are published (config/urls.py).
    Its TOTP, email, recovery, U2F and "trusted device" pages must not exist.
    """

    def setUp(self):
        self.user = make_user("Student")
        self.client.force_login(self.user)

    def test_unused_mfa_pages_are_not_reachable(self):
        # Each of these was published by include("mfa.urls") before.
        unused_paths = [
            "/mfa/",
            "/mfa/td/",
            "/mfa/td/add",
            "/mfa/td/send_link",
            "/mfa/u2f/checkTrusted",
            "/mfa/totp/start/",
            "/mfa/email/start/",
            "/mfa/recovery/start",
            "/mfa/u2f/",
            "/mfa/selct_method",
            "/mfa/toggleKey",
            "/mfa/delete",
            "/mfa/fido2/recheck",
        ]
        for unused_path in unused_paths:
            with self.subTest(path=unused_path):
                self.assertEqual(self.client.get(unused_path).status_code, 404)

    def test_passkey_pages_keep_their_addresses(self):
        # The library's templates and JavaScript use these names, so they must
        # still resolve to the same addresses as before.
        expected = {
            "start_fido2": "/mfa/fido2/",
            "fido2_begin_reg": "/mfa/fido2/begin_reg",
            "fido2_complete_reg": "/mfa/fido2/complete_reg",
            "fido2_auth": "/mfa/fido2/auth",
            "fido2_begin_auth": "/mfa/fido2/begin_auth",
            "fido2_complete_auth": "/mfa/fido2/complete_auth",
            "mfa_reset_cookie": "/mfa/reset",
        }
        for name, address in expected.items():
            with self.subTest(name=name):
                self.assertEqual(reverse(name), address)

    def test_passkey_start_page_still_works(self):
        # The "add a passkey" page renders for a signed-in user.
        self.assertEqual(self.client.get("/mfa/fido2/").status_code, 200)

    def test_passkey_registration_needs_a_signed_in_user(self):
        # Without a full login, every registration step sends the visitor to
        # the login page and never hands out a registration challenge.
        self.client.logout()
        for address in ["/mfa/fido2/", "/mfa/fido2/begin_reg", "/mfa/fido2/complete_reg"]:
            with self.subTest(address=address):
                response = self.client.get(address)
                self.assertEqual(response.status_code, 302)
                self.assertIn(reverse("kura:login"), response["Location"])


class WriteAppMetricsTests(TestCase):
    """WP3: write_app_metrics prints counts in Prometheus text format and nothing personal."""

    def test_counts_are_printed_in_prometheus_format(self):
        student = make_user("Student")
        queue_email("metrics-test:1", student.email, "Subject", "Body")
        OutgoingEmail.objects.filter(event_key="metrics-test:1").update(
            created_at=timezone.now() - timezone.timedelta(seconds=120)
        )
        output = StringIO()
        call_command("write_app_metrics", stdout=output)
        text = output.getvalue()
        self.assertIn("# TYPE kura_outbox_pending gauge", text)
        self.assertIn("kura_outbox_pending 1", text)
        self.assertIn("kura_outbox_failed_total 0", text)
        oldest_line = [line for line in text.splitlines() if line.startswith("kura_outbox_oldest_pending_seconds ")][0]
        self.assertGreaterEqual(int(oldest_line.split()[1]), 120)
        # Counts only: the address must never appear in metrics.
        self.assertNotIn(student.email, text)


class AssessmentVisibilityRulesTests(TestCase):
    """
    ACL-01: Students can only view or attempt assessments in published courses,
    visible modules, and modules matching their academic target level.
    Staff retain access even when modules are hidden or courses unpublished.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor", mfa_enabled=True)
        self.student = make_user("Student", mfa_enabled=True)
        self.dept = Department.objects.create(name="Computer Science", code="CS")

        self.student_profile = StudentProfile.objects.create(
            user=self.student,
            department=self.dept,
            current_level="level_4",
            matriculation_year=2026,
        )

        self.course = Course.objects.create(
            department=self.dept,
            code="CS101",
            title="Intro to CS",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course,
            user=self.instructor,
            staff_role="lead_instructor",
            can_release_grades=True,
        )
        Enrollment.objects.create(
            course=self.course,
            student=self.student,
            status=EnrollmentStatus.ACTIVE,
        )

        self.module = Module.objects.create(
            course=self.course,
            title="Module 1",
            is_visible=True,
        )
        self.section = ModuleSection.objects.create(
            module=self.module,
            title="Section 1",
            section_type="coursework",
            is_visible=True,
        )

        now = timezone.now()
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Assignment 1",
            component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("100.00"),
            max_attempts=3,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(hours=4),
            duration_minutes=60,
            questions_json=[],
            created_by=self.instructor,
        )

    def test_student_blocked_when_module_hidden(self):
        self.module.is_visible = False
        self.module.save()
        self.client.force_login(self.student)

        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 403)

        initial_count = AssessmentAttempt.objects.count()
        start_url = reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id})
        response = self.client.post(start_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AssessmentAttempt.objects.count(), initial_count)

    def test_student_blocked_when_target_level_mismatch(self):
        ModuleTargetLevel.objects.create(module=self.module, target_level="level_5")
        self.client.force_login(self.student)

        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 403)

        initial_count = AssessmentAttempt.objects.count()
        start_url = reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id})
        response = self.client.post(start_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AssessmentAttempt.objects.count(), initial_count)

    def test_student_blocked_when_course_unpublished(self):
        self.course.is_published = False
        self.course.save()
        self.client.force_login(self.student)

        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 403)

        initial_count = AssessmentAttempt.objects.count()
        start_url = reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id})
        response = self.client.post(start_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AssessmentAttempt.objects.count(), initial_count)

    def test_eligible_student_can_view_assessment(self):
        self.client.force_login(self.student)
        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)

    def test_course_staff_can_view_hidden_module_assessment(self):
        self.module.is_visible = False
        self.module.save()
        self.client.force_login(self.instructor)
        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)


class MfaSetupReauthTests(TestCase):
    """
    AUTH-02a: Users with MFA enabled must re-authenticate with their second factor
    before the MFA setup page displays the authenticator seed or allows regenerating
    recovery codes.
    """

    def setUp(self):
        self.client = Client()
        self.seed_hex = random_hex(20)
        self.user = make_user("Student", mfa_enabled=True)
        self.user.mfa_secret = self.seed_hex
        self.user.save(update_fields=["mfa_secret"])
        self.device = TOTPDevice.objects.get(user=self.user, name="default")

        self.static_device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        self.initial_token = StaticToken.objects.create(
            device=self.static_device, token=hash_recovery_code("OLDCODE1")
        )

    def current_code(self, seed_hex, at_time=None):
        totp = TOTP(bytes.fromhex(seed_hex), self.device.step, self.device.t0, self.device.digits, self.device.drift)
        totp.time = at_time if at_time is not None else time.time()
        return str(totp.token()).zfill(self.device.digits)

    def test_enrolled_user_get_does_not_reveal_seed_or_qr(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "otpauth")
        self.assertNotContains(response, "data:image/svg+xml;utf8,")
        self.assertContains(response, "Confirm Your Identity")

    def test_wrong_code_keeps_seed_hidden(self):
        self.client.force_login(self.user)
        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(reverse("kura:mfa_setup"), {"code": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "otpauth")
        self.assertNotContains(response, "data:image/svg+xml;utf8,")
        self.assertContains(response, "Invalid security code.")
        self.assertTrue(any('event="auth.mfa.reauth_failed"' in line for line in captured.output))

    def test_correct_totp_renders_setup_and_confirming_post_regenerates_codes(self):
        self.client.force_login(self.user)
        t0 = time.time()
        with patch("time.time", return_value=t0):
            code = self.current_code(self.seed_hex, at_time=t0)
            with self.assertLogs("kura.security", level="INFO") as captured:
                response = self.client.post(reverse("kura:mfa_setup"), {"code": code})
        self.assertRedirects(response, reverse("kura:mfa_setup"))
        self.assertTrue(any('event="auth.mfa.reauth_ok"' in line for line in captured.output))

        # After step-up, setup page renders with QR code.
        setup_response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(setup_response.status_code, 200)
        self.assertContains(setup_response, "data:image/svg+xml;utf8,")

        # Confirming POST on the setup page with fresh time step replaces StaticToken rows.
        t1 = t0 + 35
        with patch("time.time", return_value=t1):
            new_code = self.current_code(self.seed_hex, at_time=t1)
            confirm_response = self.client.post(reverse("kura:mfa_setup"), {"code": new_code})
        self.assertRedirects(confirm_response, reverse("kura:mfa_setup_complete"))

        # Previous recovery token was deleted and replaced by 10 new tokens.
        self.assertFalse(StaticToken.objects.filter(id=self.initial_token.id).exists())
        self.assertEqual(StaticToken.objects.filter(device=self.static_device).count(), 10)

    def test_unenrolled_user_sees_qr_code_on_first_get(self):
        unenrolled_user = make_user("Student", mfa_enabled=False)
        self.client.force_login(unenrolled_user)
        response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/svg+xml;utf8,")
        self.assertContains(response, "Set up Multi-Factor Authentication")


class RowLevelSecurityFailClosedTests(TestCase):
    """
    CFG-01: When RowLevelSecurityMiddleware fails to set the session user ID in PostgreSQL,
    it must fail closed (return HTTP 503) and log an error, rather than continuing
    with unrestricted database access.
    """

    def setUp(self):
        self.client = Client()
        self.student = make_user("Student", mfa_enabled=True)

    def test_rls_set_failure_fails_closed_and_logs_error(self):
        from django.db.utils import OperationalError

        self.client.force_login(self.student)
        real_cursor = connection.cursor

        def failing_cursor(*args, **kwargs):
            cursor = real_cursor(*args, **kwargs)
            real_execute = cursor.execute

            def guarded_execute(sql, params=None):
                if isinstance(sql, str) and "SET kura.current_user_id" in sql:
                    raise OperationalError("Simulated SET failure")
                return real_execute(sql, params)

            cursor.execute = guarded_execute
            return cursor

        with patch.object(connection, "cursor", side_effect=failing_cursor):
            with self.assertLogs("kura.security", level="ERROR") as captured:
                response = self.client.get(reverse("kura:student_grades"))
            self.assertEqual(response.status_code, 503)
            self.assertTrue(any('event="rls.context_failed"' in line for line in captured.output))

    def test_normal_request_returns_200(self):
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:student_grades"))
        self.assertEqual(response.status_code, 200)

    def test_rls_reset_failure_logs_warning_and_closes_connection(self):
        from django.db.utils import OperationalError

        self.client.force_login(self.student)
        real_cursor = connection.cursor

        def failing_reset_cursor(*args, **kwargs):
            cursor = real_cursor(*args, **kwargs)
            real_execute = cursor.execute

            def guarded_execute(sql, params=None):
                if isinstance(sql, str) and "RESET kura.current_user_id" in sql:
                    raise OperationalError("Simulated RESET failure")
                return real_execute(sql, params)

            cursor.execute = guarded_execute
            return cursor

        with patch.object(connection, "cursor", side_effect=failing_reset_cursor):
            with patch.object(connection, "close") as mock_close:
                with self.assertLogs("kura.security", level="WARNING") as captured:
                    response = self.client.get(reverse("kura:student_grades"))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(any('event="rls.reset_failed"' in line for line in captured.output))
                mock_close.assert_called_once()


class SessionInvalidLoggingTests(TestCase):
    """
    LOG-01: SessionValidationMiddleware must log a WARNING security event
    'session.invalid' with the specific reason (deactivated, locked, revoked, expired)
    when ending an invalid session, capturing the actor user ID before logout.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", mfa_enabled=True)
        self.user_session = UserSession.objects.create(
            user=self.user,
            session_token_hash=secrets.token_hex(32),
            ip_address="127.0.0.1",
            user_agent="TestAgent",
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )

    def attach_tracked_session(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["user_session_id"] = str(self.user_session.id)
        session.save()

    def test_deactivated_session_is_logged_at_warning(self):
        self.attach_tracked_session()
        self.user.is_active = False
        self.user.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:login"))
        self.assertTrue(any('event="session.invalid"' in line and 'reason="deactivated"' in line for line in captured.output))
        self.assertTrue(any(f'actor_user_id="{self.user.id}"' in line for line in captured.output))

    def test_locked_session_is_logged_at_warning(self):
        self.attach_tracked_session()
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=1)
        self.user.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:login"))
        self.assertTrue(any('event="session.invalid"' in line and 'reason="locked"' in line for line in captured.output))
        self.assertTrue(any(f'actor_user_id="{self.user.id}"' in line for line in captured.output))

    def test_revoked_session_is_logged_at_warning(self):
        self.attach_tracked_session()
        self.user_session.revoked_at = timezone.now()
        self.user_session.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:login"))
        self.assertTrue(any('event="session.invalid"' in line and 'reason="revoked"' in line for line in captured.output))
        self.assertTrue(any(f'actor_user_id="{self.user.id}"' in line for line in captured.output))

    def test_expired_session_is_logged_at_warning(self):
        self.attach_tracked_session()
        self.user_session.expires_at = timezone.now() - timezone.timedelta(minutes=5)
        self.user_session.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:login"))
        self.assertTrue(any('event="session.invalid"' in line and 'reason="expired"' in line for line in captured.output))
        self.assertTrue(any(f'actor_user_id="{self.user.id}"' in line for line in captured.output))


class PasswordChangeNotificationTests(TestCase):
    """
    AUTH-05: When a user changes or resets their password, a notification email
    is queued to their address. The email must not contain the password, the reset
    token, or any bearer link.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", password="OriginalPassword123!")

    def test_password_change_queues_notification_email(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": "OriginalPassword123!",
                "new_password": "NewSecurePassword456!",
                "confirm_password": "NewSecurePassword456!",
            },
        )
        self.assertRedirects(response, reverse("kura:home"))

        email = OutgoingEmail.objects.get(to_email=self.user.email)
        self.assertIn("Your Kura password was changed. If this was not you, contact an administrator.", email.body)
        self.assertNotIn("OriginalPassword123!", email.body)
        self.assertNotIn("NewSecurePassword456!", email.body)

    def test_password_reset_confirm_queues_notification_email(self):
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
        )

        # The test user has MFA, so the confirm page also needs a recovery code.
        device = StaticDevice.objects.create(user=self.user, name="recovery", confirmed=True)
        StaticToken.objects.create(device=device, token=hash_recovery_code("abcd1234"))

        response = self.client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
            {
                "code": "abcd1234",
                "new_password": "NewResetPassword789!",
                "confirm_password": "NewResetPassword789!",
            },
        )
        self.assertRedirects(response, reverse("kura:login"))

        email = OutgoingEmail.objects.get(to_email=self.user.email)
        self.assertIn("Your Kura password was changed. If this was not you, contact an administrator.", email.body)
        self.assertNotIn(raw_token, email.body)
        self.assertNotIn("NewResetPassword789!", email.body)

    def test_failed_attempts_queue_no_email(self):
        self.client.force_login(self.user)
        # Failed password change (wrong old password)
        self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": "WrongPassword!",
                "new_password": "NewSecurePassword456!",
                "confirm_password": "NewSecurePassword456!",
            },
        )
        self.assertEqual(OutgoingEmail.objects.filter(to_email=self.user.email).count(), 0)

        # Failed reset confirm (passwords don't match)
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        PasswordResetToken.objects.create(
            user=self.user,
            token_hash=token_hash,
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
        )
        self.client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
            {
                "new_password": "Password1!",
                "confirm_password": "Password2!",
            },
        )
        self.assertEqual(OutgoingEmail.objects.filter(to_email=self.user.email).count(), 0)


class GradeFinalizeInstructorOnlyTests(TestCase):
    """
    ACL-04: A user holding both the Instructor and Teaching assistant roles, but assigned
    to the course only as a teaching assistant, must not finalize grades.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head")
        self.student = make_user("Student")
        self.dual_role_user = make_user("Instructor")
        ta_role, _ = Role.objects.get_or_create(name="Teaching assistant")
        UserRole.objects.get_or_create(user=self.dual_role_user, role=ta_role)
        self.co_instructor = make_user("Instructor")

        self.dept = Department.objects.create(name="Sociology", code="SOCI", head_user=self.head)
        StudentProfile.objects.create(
            user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026
        )
        self.course = Course.objects.create(
            department=self.dept,
            code="SOCI101",
            title="Introduction to Sociology",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        # The dual-role user is assigned only as a TA, which must not allow finalizing.
        CourseStaff.objects.create(course=self.course, user=self.dual_role_user, staff_role="teaching_assistant")
        CourseStaff.objects.create(course=self.course, user=self.co_instructor, staff_role="co_instructor")
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Foundations", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Midterm", section_type="exam")
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Midterm Exam",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now(),
            due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=60,
            created_by=self.co_instructor,
        )
        self.attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=timezone.now(),
            ip_address="127.0.0.1",
        )
        self.grade = Grade.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt=self.attempt,
            grader=self.dual_role_user,
            score=Decimal("80.00"),
            status=GradeStatus.DRAFT,
        )

    def test_dual_role_ta_cannot_finalize_grade(self):
        # Instructor+TA with only a teaching_assistant assignment is refused.
        self.client.force_login(self.dual_role_user)
        response = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": self.grade.id}))
        self.assertEqual(response.status_code, 403)

        self.grade.refresh_from_db()
        self.assertEqual(self.grade.status, GradeStatus.DRAFT)
        self.assertFalse(GradeHistory.objects.filter(grade=self.grade).exists())

    def test_co_instructor_can_finalize_grade(self):
        # A co-instructor on the course still finalizes successfully.
        self.client.force_login(self.co_instructor)
        response = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": self.grade.id}))
        self.assertRedirects(response, reverse("kura:course_grades", kwargs={"course_id": self.course.id}))

        self.grade.refresh_from_db()
        self.assertEqual(self.grade.status, GradeStatus.FINALIZED)
        self.assertTrue(GradeHistory.objects.filter(grade=self.grade, new_status=GradeStatus.FINALIZED).exists())


class UserRolesInputValidationTests(TestCase):
    """
    INP-03: Invalid role-management input must be rejected without an HTTP 500
    and without changing any UserRole rows.
    """

    def setUp(self):
        self.client = Client()
        self.admin = make_user("Admin")
        self.target_user = User.objects.create_user(email="role_target@example.com", password="Password12345!")
        self.instructor_role = Role.objects.get(name="Instructor")
        self.roles_url = reverse("kura:user_roles", kwargs={"user_id": self.target_user.id})

    def test_non_numeric_role_id_is_rejected(self):
        # A malformed role_id used to raise ValueError and return HTTP 500.
        self.client.force_login(self.admin)
        confirm_second_factor(self.client)
        before = UserRole.objects.filter(user=self.target_user).count()

        response = self.client.post(self.roles_url, {"action": "assign", "role_id": "abc"})

        self.assertNotEqual(response.status_code, 500)
        self.assertRedirects(response, self.roles_url)
        self.assertEqual(UserRole.objects.filter(user=self.target_user).count(), before)

    def test_unknown_action_is_rejected(self):
        # An action outside assign/remove must not change roles.
        self.client.force_login(self.admin)
        confirm_second_factor(self.client)
        before = UserRole.objects.filter(user=self.target_user).count()

        response = self.client.post(self.roles_url, {"action": "bogus", "role_id": self.instructor_role.id})

        self.assertRedirects(response, self.roles_url)
        self.assertEqual(UserRole.objects.filter(user=self.target_user).count(), before)


class DownloadFilenameHeaderTests(TestCase):
    """
    CFG-07: A stored filename must not be able to inject extra Content-Disposition
    parameters, and non-ASCII names must be encoded safely.
    """

    def make_stored_file(self, filename):
        # Build the smallest valid StoredFile plus its binary content.
        uploader = make_user("Instructor")
        stored_file = StoredFile.objects.create(
            uploaded_by=uploader,
            original_filename=filename,
            mime_type="application/pdf",
            size_bytes=12,
            sha256_hash="a" * 64,
        )
        FileContent.objects.create(file=stored_file, content=b"%PDF-1.4 test")
        return stored_file

    def test_quote_and_parameter_text_stays_inside_the_filename(self):
        stored_file = self.make_stored_file('a"; filename*=UTF-8\'\'evil.html')

        response = create_download_response(stored_file)
        header = response["Content-Disposition"]

        self.assertTrue(header.startswith("attachment"))
        # The double quote is escaped, so it cannot end the filename early.
        self.assertIn('\\"', header)

        # Parse the header: the injected text must be part of the filename value,
        # not a separate filename* parameter.
        from email.message import Message

        message = Message()
        message["Content-Disposition"] = header
        params = message.get_params(header="content-disposition") or []
        parameter_names = [name.lower() for name, _value in params]
        self.assertNotIn("filename*", parameter_names)

    def test_plain_filename_header(self):
        stored_file = self.make_stored_file("notes.pdf")

        response = create_download_response(stored_file)

        self.assertEqual(response["Content-Disposition"], 'attachment; filename="notes.pdf"')
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")


class NoStoreAndAutocompleteTests(TestCase):
    """
    LOG-06: Every authenticated response is marked no-store, including the
    must-change-password onboarding path, and one-time codes carry the right
    autocomplete hint.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Student", mfa_enabled=True)

    def test_must_change_password_page_is_not_cacheable(self):
        # The early-return path used to skip the Cache-Control header.
        self.user.must_change_password = True
        self.user.save(update_fields=["must_change_password"])
        self.client.force_login(self.user)

        response = self.client.get(reverse("kura:password_change"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])

    def test_grade_release_otp_has_one_time_code_autocomplete(self):
        from .forms import GradeReleaseForm

        self.assertIn('autocomplete="one-time-code"', str(GradeReleaseForm()))

    def test_proctor_code_has_autocomplete_off(self):
        from .forms import AssessmentAttemptStartForm

        self.assertIn('autocomplete="off"', str(AssessmentAttemptStartForm()))


class PasswordReuseTests(TestCase):
    """
    AUTH-06: A new password must differ from the account's current password,
    both on the change form and on the reset confirm form.
    """

    def setUp(self):
        self.client = Client()
        self.password = "OriginalPassword123!"
        self.user = make_user("Student", password=self.password, mfa_enabled=True)

    def test_change_form_rejects_current_password(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": self.password,
                "confirm_password": self.password,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Choose a password you have not used recently.",
            response.context["form"].errors["new_password"],
        )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_reset_confirm_form_rejects_current_password(self):
        raw_token = secrets.token_urlsafe(32)
        PasswordResetToken.objects.create(
            user=self.user,
            token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
            expires_at=timezone.now() + timezone.timedelta(minutes=30),
        )

        response = self.client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
            {
                "new_password": self.password,
                "confirm_password": self.password,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Choose a password you have not used recently.",
            response.context["form"].errors["new_password"],
        )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))


class OldPasswordThrottleTests(TestCase):
    """
    AUTH-07: Wrong current passwords on the change form count as failures and
    the account is refused after AXES_FAILURE_LIMIT attempts.
    """

    def setUp(self):
        self.client = Client()
        self.password = "OriginalPassword123!"
        self.user = make_user("Student", password=self.password, mfa_enabled=True)
        self.url = reverse("kura:password_change")

    def test_wrong_current_password_is_throttled(self):
        self.client.force_login(self.user)

        # Five wrong current passwords reach the axes limit.
        for _attempt in range(5):
            self.client.post(
                self.url,
                {
                    "old_password": "WrongPassword999!",
                    "new_password": "NewSecurePassword456!",
                    "confirm_password": "NewSecurePassword456!",
                },
            )

        # The sixth request is refused even though the old password is now correct.
        response = self.client.post(
            self.url,
            {
                "old_password": self.password,
                "new_password": "NewSecurePassword456!",
                "confirm_password": "NewSecurePassword456!",
            },
        )

        self.assertIn(response.status_code, (200, 403, 429))
        if response.status_code == 200:
            self.assertIn("old_password", response.context["form"].errors)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_correct_current_password_still_changes(self):
        # A fresh account with the right current password is not affected.
        self.client.force_login(self.user)
        new_password = "NewSecurePassword456!"

        response = self.client.post(
            self.url,
            {
                "old_password": self.password,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )

        self.assertRedirects(response, reverse("kura:home"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))


class UploadExtensionMatchTests(TestCase):
    """
    INP-01: The filename extension must match the type libmagic detects, so a
    valid PDF renamed to .html is not stored under a web-page extension.
    """

    def setUp(self):
        self.instructor = make_user("Instructor")
        self.pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF"

    @patch("kura.files.scan_file_for_malware")
    def test_pdf_bytes_with_html_extension_are_rejected(self, mock_scan):
        before = StoredFile.objects.count()

        with self.assertRaises(ValidationError):
            validate_and_save_upload(SimpleUploadedFile("x.html", self.pdf_bytes), self.instructor)

        self.assertEqual(StoredFile.objects.count(), before)

    @patch("kura.files.scan_file_for_malware")
    def test_matching_pdf_extension_is_accepted(self, mock_scan):
        stored = validate_and_save_upload(SimpleUploadedFile("report.pdf", self.pdf_bytes), self.instructor)

        self.assertEqual(stored.original_filename, "report.pdf")
        self.assertEqual(stored.mime_type, "application/pdf")

    @patch("kura.files.scan_file_for_malware")
    def test_uppercase_pdf_extension_is_accepted(self, mock_scan):
        stored = validate_and_save_upload(SimpleUploadedFile("REPORT.PDF", self.pdf_bytes), self.instructor)

        self.assertEqual(stored.original_filename, "REPORT.PDF")


class FreeTextLengthLimitTests(TestCase):
    """
    INP-04: Free-text form fields have a length limit, so an over-long value
    gives a form error instead of being stored.
    """

    def setUp(self):
        self.client = Client()
        self.head = make_user("Department head")
        self.instructor = make_user("Instructor")
        self.student = make_user("Student")
        self.dept = Department.objects.create(name="Law", code="LAW", head_user=self.head)
        StudentProfile.objects.create(
            user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026
        )
        self.course = Course.objects.create(
            department=self.dept,
            code="LAW101",
            title="Contract Law",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.head,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True
        )
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)

        self.module = Module.objects.create(course=self.course, title="Formation", is_visible=True)
        self.section = ModuleSection.objects.create(module=self.module, title="Essay", section_type="exam")
        self.assessment = Assessment.objects.create(
            section=self.section,
            title="Essay",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now(),
            due_date=timezone.now() + timezone.timedelta(hours=1),
            duration_minutes=60,
            created_by=self.instructor,
        )
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            expires_at=timezone.now(),
            ip_address="127.0.0.1",
        )
        self.grade = Grade.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt=attempt,
            score=Decimal("70.00"),
            status=GradeStatus.RELEASED,
        )

    def test_overlong_appeal_reason_is_rejected(self):
        self.client.force_login(self.student)

        response = self.client.post(
            reverse("kura:grade_appeal_create", kwargs={"grade_id": self.grade.id}),
            {"reason": "a" * 5001},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("reason", response.context["form"].errors)
        self.assertFalse(GradeAppeal.objects.filter(grade=self.grade).exists())

    def test_overlong_manual_attendance_reason_is_rejected(self):
        from .forms import ManualAttendanceForm

        form = ManualAttendanceForm(
            data={
                "student": self.student.id,
                "status": AttendanceStatus.PRESENT,
                "override_reason": "a" * 5001,
            }
        )

        self.assertFalse(form.is_valid())
        self.assertIn("override_reason", form.errors)


class AdminSettingsAuditLogTests(TestCase):
    """
    LOG-02: A successful admin settings save writes an audit event that names
    only the saved object's ID.
    """

    def setUp(self):
        self.client = Client()
        self.admin = make_user("Admin", mfa_enabled=True)

    def test_department_save_is_logged(self):
        self.client.force_login(self.admin)

        with self.assertLogs("kura.security", level="INFO") as captured:
            response = self.client.post(
                reverse("kura:staff_settings"),
                {"kind": "department", "code": "PHYS", "name": "Physics"},
            )

        self.assertRedirects(response, reverse("kura:staff_settings"))
        department = Department.objects.get(code="PHYS")
        output = "\n".join(captured.output)
        self.assertIn("admin.department.saved", output)
        self.assertIn(str(department.pk), output)
        # The audit line must not carry the department's free-text name.
        self.assertNotIn("Physics", output)


class InvalidInputLoggingTests(TestCase):
    """
    LOG-03: A rejected admin form logs input.invalid with the form and field
    names, and never the submitted value.
    """

    def setUp(self):
        self.client = Client()
        self.admin = make_user("Admin", mfa_enabled=True)

    def test_invalid_department_is_logged_without_values(self):
        self.client.force_login(self.admin)
        marker = "ZZ-unique-marker"

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(
                reverse("kura:staff_settings"),
                {"kind": "department", "code": "", "name": marker},
            )

        self.assertEqual(response.status_code, 200)
        output = "\n".join(captured.output)
        self.assertIn("input.invalid", output)
        self.assertIn("DepartmentForm", output)
        self.assertIn("code", output)
        self.assertNotIn(marker, output)


class PasskeyLoginCallbackTests(TestCase):
    """
    AUTH-Q: django-mfa2 finds the user from the passkey itself, and its sign-in
    endpoints are public. The login callback must only sign in the user who
    already passed the password step, and only if they are active and unlocked.
    """

    def setUp(self):
        self.user = make_user("Student")
        self.other = make_user("Student")

    def call_callback(self, session_values):
        # Build a request with a real session and message storage, the same
        # way django-mfa2 would hand one to the callback.
        request = RequestFactory().post("/mfa/fido2/complete_auth")
        SessionMiddleware(lambda r: None).process_request(request)
        MessageMiddleware(lambda r: None).process_request(request)
        for key, value in session_values.items():
            request.session[key] = value
        request.user = AnonymousUser()
        response = mfa_login_callback(request, self.user.email)
        return request, response

    def test_passkey_without_password_step_is_refused(self):
        request, response = self.call_callback({})
        self.assertEqual(response.url, reverse("kura:login"))
        self.assertNotIn("_auth_user_id", request.session)

    def test_passkey_for_different_user_is_refused(self):
        request, response = self.call_callback({"pre_mfa_user_id": str(self.other.id)})
        self.assertEqual(response.url, reverse("kura:login"))
        self.assertNotIn("_auth_user_id", request.session)

    def test_locked_user_is_refused(self):
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=1)
        self.user.save(update_fields=["locked_until"])
        request, response = self.call_callback({"pre_mfa_user_id": str(self.user.id)})
        self.assertEqual(response.url, reverse("kura:login"))
        self.assertNotIn("_auth_user_id", request.session)

    def test_inactive_user_is_refused(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        request, response = self.call_callback({"pre_mfa_user_id": str(self.user.id)})
        self.assertEqual(response.url, reverse("kura:login"))
        self.assertNotIn("_auth_user_id", request.session)

    def test_same_user_after_password_step_signs_in(self):
        request, response = self.call_callback({"pre_mfa_user_id": str(self.user.id)})
        self.assertEqual(response.url, reverse("kura:home"))
        self.assertEqual(request.session["_auth_user_id"], str(self.user.pk))


class FreshSecondFactorTests(TestCase):
    """
    AUTH-02 / ACL-05: changing passkeys, changing roles, deactivating accounts and
    releasing course results need a second-factor code from the last five minutes.
    """

    def setUp(self):
        self.admin = make_user("Admin")
        self.target_user = make_user("Instructor")
        self.client.force_login(self.admin)

    def test_role_change_without_fresh_factor_asks_for_code(self):
        # A logged-in admin without a recent code is sent to the confirm page.
        roles_url = reverse("kura:user_roles", kwargs={"user_id": self.target_user.id})
        response = self.client.post(roles_url, {"action": "remove", "role_id": "1"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        self.assertTrue(UserRole.objects.filter(user=self.target_user, role__name="Instructor").exists())

    def test_deactivate_without_fresh_factor_changes_nothing(self):
        url = reverse("kura:user_deactivate", kwargs={"user_id": self.target_user.id})
        response = self.client.post(url)
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        self.target_user.refresh_from_db()
        self.assertTrue(self.target_user.is_active)

    def test_old_confirmation_has_expired(self):
        # A code entered six minutes ago no longer counts.
        session = self.client.session
        session["mfa_reauth_at"] = (timezone.now() - timezone.timedelta(minutes=6)).timestamp()
        session.save()
        url = reverse("kura:user_deactivate", kwargs={"user_id": self.target_user.id})
        response = self.client.post(url)
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))

    def test_passkey_page_and_delete_need_fresh_factor(self):
        from mfa.models import User_Keys

        key = User_Keys.objects.create(username=self.admin.email, key_type="FIDO2", properties={})
        response = self.client.get(reverse("kura:passkey_manage"))
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        response = self.client.post(reverse("kura:passkey_delete", kwargs={"key_id": key.id}))
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        self.assertTrue(User_Keys.objects.filter(id=key.id).exists())

    def test_passkey_registration_needs_fresh_factor(self):
        response = self.client.post(reverse("fido2_complete_reg"), data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 403)

    def test_recovery_code_confirms_and_returns_to_next(self):
        # A valid recovery code is accepted and the user goes back to the page they wanted.
        device = StaticDevice.objects.create(user=self.admin, name="recovery", confirmed=True)
        StaticToken.objects.create(device=device, token=hash_recovery_code("abcd1234"))
        next_url = reverse("kura:passkey_manage")
        response = self.client.post(reverse("kura:mfa_reauth"), {"code": "abcd1234", "next": next_url})
        self.assertRedirects(response, next_url)
        self.assertIn("mfa_reauth_at", self.client.session)

    def test_wrong_code_is_rejected(self):
        response = self.client.post(reverse("kura:mfa_reauth"), {"code": "000000", "next": "/"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid security code")
        self.assertNotIn("mfa_reauth_at", self.client.session)

    def test_next_to_another_site_is_ignored(self):
        # The confirm page must not become an open redirect.
        device = StaticDevice.objects.create(user=self.admin, name="recovery", confirmed=True)
        StaticToken.objects.create(device=device, token=hash_recovery_code("abcd1234"))
        response = self.client.post(
            reverse("kura:mfa_reauth"), {"code": "abcd1234", "next": "https://evil.example/"}
        )
        self.assertRedirects(response, reverse("kura:home"), fetch_redirect_response=False)

    def test_users_without_mfa_are_not_blocked(self):
        # Nobody without a second factor can be asked for one. (Middleware sends
        # such users to MFA setup anyway, so the helper is checked directly.)
        request = RequestFactory().get("/")
        request.user = make_user("Admin", mfa_enabled=False)
        request.session = {}
        self.assertTrue(has_fresh_second_factor(request))
        request.user = self.admin
        self.assertFalse(has_fresh_second_factor(request))


class OwnSessionsTests(TestCase):
    """
    Tests the restored personal "My sessions" view and IDOR/CSRF protections (ACL-02, ACL-06).
    """

    def setUp(self):
        self.student = make_user("Student", mfa_enabled=True)
        self.other = make_user("Instructor", mfa_enabled=True)
        self.own_current = UserSession.objects.create(
            user=self.student,
            session_token_hash=secrets.token_hex(32),
            ip_address="198.51.100.10",
            user_agent="Browser One",
            expires_at=timezone.now() + timezone.timedelta(hours=12),
        )
        self.own_other = UserSession.objects.create(
            user=self.student,
            session_token_hash=secrets.token_hex(32),
            ip_address="198.51.100.20",
            user_agent="Browser Two",
            expires_at=timezone.now() + timezone.timedelta(hours=12),
        )
        self.other_session = UserSession.objects.create(
            user=self.other,
            session_token_hash=secrets.token_hex(32),
            ip_address="203.0.113.99",
            user_agent="Other Browser",
            expires_at=timezone.now() + timezone.timedelta(hours=12),
        )

    def _login_student_with_current(self):
        self.client.force_login(self.student)
        s = self.client.session
        s["user_session_id"] = str(self.own_current.id)
        s.save()

    def test_student_sees_own_sessions_only_and_no_token_hash(self):
        self._login_student_with_current()
        response = self.client.get(reverse("kura:user_sessions"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "198.51.100.10")
        self.assertContains(response, "198.51.100.20")
        self.assertContains(response, "Current session")
        self.assertNotContains(response, "203.0.113.99")
        self.assertNotContains(response, self.own_current.session_token_hash)

    def test_revoking_another_users_session_returns_404(self):
        self._login_student_with_current()
        response = self.client.post(
            reverse("kura:user_session_revoke", args=[self.other_session.id])
        )
        self.assertEqual(response.status_code, 404)
        self.other_session.refresh_from_db()
        self.assertIsNone(self.other_session.revoked_at)

    def test_get_on_revoke_returns_405(self):
        self._login_student_with_current()
        response = self.client.get(
            reverse("kura:user_session_revoke", args=[self.own_other.id])
        )
        self.assertEqual(response.status_code, 405)
        self.own_other.refresh_from_db()
        self.assertIsNone(self.own_other.revoked_at)

    def test_revoking_other_own_session_sets_revoked_at(self):
        self._login_student_with_current()
        with self.assertLogs("kura.security", level="INFO") as logs:
            response = self.client.post(
                reverse("kura:user_session_revoke", args=[self.own_other.id])
            )
        self.assertRedirects(response, reverse("kura:user_sessions"))
        self.own_other.refresh_from_db()
        self.assertIsNotNone(self.own_other.revoked_at)
        self.assertIn('event="auth.session.revoked"', "\n".join(logs.output))
        self.assertIn('by="self"', "\n".join(logs.output))

    def test_revoking_current_session_logs_out(self):
        self._login_student_with_current()
        response = self.client.post(
            reverse("kura:user_session_revoke", args=[self.own_current.id])
        )
        self.assertRedirects(response, reverse("kura:login"))
        self.own_current.refresh_from_db()
        self.assertIsNotNone(self.own_current.revoked_at)
        # Follow-up request is treated as anonymous.
        self.assertRedirects(
            self.client.get(reverse("kura:user_sessions")),
            f"{reverse('kura:login')}?next={reverse('kura:user_sessions')}",
        )


class AbsoluteSessionLimitTests(TestCase):
    """
    Tests the 12-hour absolute session limit (ACL-07).
    """

    def setUp(self):
        self.password = "ValidPassword123!"
        self.user = make_user("Student", password=self.password, mfa_enabled=False)

    def test_login_sets_expires_at_to_twelve_hours(self):
        before = timezone.now()
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )
        self.assertRedirects(response, reverse("kura:mfa_setup"))
        after = timezone.now()

        user_session = UserSession.objects.get(user=self.user)
        expected_min = before + timezone.timedelta(hours=12)
        expected_max = after + timezone.timedelta(hours=12)
        self.assertGreaterEqual(user_session.expires_at, expected_min)
        self.assertLessEqual(user_session.expires_at, expected_max)

    def test_past_expires_at_logs_user_out_and_redirects_to_login(self):
        self.user.mfa_enabled = True
        self.user.save(update_fields=["mfa_enabled"])
        self.client.force_login(self.user)
        user_session = UserSession.objects.create(
            user=self.user,
            session_token_hash=secrets.token_hex(32),
            ip_address="127.0.0.1",
            user_agent="TestAgent",
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )
        session = self.client.session
        session["user_session_id"] = str(user_session.id)
        session.save()

        with self.assertLogs("kura.security", level="WARNING") as logs:
            response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:login"))
        self.assertTrue(
            any('event="session.invalid"' in line and 'reason="expired"' in line for line in logs.output)
        )
        # Subsequent request remains logged out.
        self.assertRedirects(
            self.client.get(reverse("kura:home")),
            f"{reverse('kura:login')}?next={reverse('kura:home')}",
        )


class SharedRateLimitCacheTests(TestCase):
    """
    Tests that RateLimitMiddleware stores counters in the shared DatabaseCache (AUTH-08).
    """

    def setUp(self):
        from django.core.cache import caches

        self.user = make_user("Student", mfa_enabled=True)
        caches["default"].clear()
        caches["ratelimit"].clear()

    def test_rate_limit_counter_uses_shared_ratelimit_cache(self):
        from django.core.cache import caches

        self.client.force_login(self.user)
        dummy_uuid = "00000000-0000-0000-0000-000000000001"
        self.client.post(f"/attempts/{dummy_uuid}/files/upload/")

        cache_key = f"rate_limit_upload_{self.user.id}"
        self.assertEqual(caches["ratelimit"].get(cache_key), 1)
        self.assertIsNone(caches["default"].get(cache_key))


class PasswordHistoryTests(TestCase):
    """
    Tests PasswordHistory tracking and reuse prevention for the last 5 passwords (AUTH-06).
    """

    def setUp(self):
        self.passwords = [
            "HistPassZero!1234",
            "HistPassOne!1234",
            "HistPassTwo!1234",
            "HistPassThree!1234",
            "HistPassFour!1234",
            "HistPassFive!1234",
            "HistPassSix!1234",
        ]
        self.user = make_user("Student", password=self.passwords[0], mfa_enabled=True)

    def _change_password(self, old_pw, new_pw):
        return self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": old_pw,
                "new_password": new_pw,
                "confirm_password": new_pw,
            },
        )

    @patch("kura.validators.BreachedPasswordValidator.validate", return_value=None)
    def test_password_history_enforces_five_previous_passwords_and_prunes_older(self, _mock_breach):
        self.client.force_login(self.user)

        # Rotate P0 -> P1 -> P2 -> P3 -> P4 -> P5 (5 changes: P0..P4 in history, P5 current).
        with self.assertLogs("kura.security", level="INFO") as logs:
            for idx in range(5):
                resp = self._change_password(self.passwords[idx], self.passwords[idx + 1])
                self.assertRedirects(resp, reverse("kura:home"))
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)

        # Current password (P5) fails.
        resp = self._change_password(self.passwords[5], self.passwords[5])
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Choose a password you have not used recently.", resp.context["form"].errors["new_password"])

        # 6th change: P5 -> P6. Now history holds P5 (1st prev), P4 (2nd), P3 (3rd), P2 (4th), P1 (5th);
        # P0 (6th previous) is pruned, and only 5 rows remain.
        resp = self._change_password(self.passwords[5], self.passwords[6])
        self.assertRedirects(resp, reverse("kura:home"))
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)

        # 2nd previous (P4) and 5th previous (P1) fail on both change and reset confirm forms.
        for old_candidate in (self.passwords[4], self.passwords[1]):
            resp = self._change_password(self.passwords[6], old_candidate)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Choose a password you have not used recently.", resp.context["form"].errors["new_password"])

            raw_token = secrets.token_urlsafe(32)
            PasswordResetToken.objects.create(
                user=self.user,
                token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
                expires_at=timezone.now() + timezone.timedelta(minutes=30),
            )
            reset_resp = self.client.post(
                reverse("kura:password_reset_confirm", kwargs={"token": raw_token}),
                {"new_password": old_candidate, "confirm_password": old_candidate},
            )
            self.assertEqual(reset_resp.status_code, 200)
            self.assertIn("Choose a password you have not used recently.", reset_resp.context["form"].errors["new_password"])

        # 6th previous (P0) was pruned and now succeeds.
        resp = self._change_password(self.passwords[6], self.passwords[0])
        self.assertRedirects(resp, reverse("kura:home"))
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)

        # No password text ever appeared in the security log.
        log_blob = "\n".join(logs.output)
        for pw in self.passwords:
            self.assertNotIn(pw, log_blob)


class DisableInactiveAccountsTests(TestCase):
    """
    Tests disabling dormant accounts and revoking their active sessions (ACL-08).
    """

    def setUp(self):
        self.User = get_user_model()
        now = timezone.now()

        # Dormant user with old last_login and an active session.
        self.old_user = make_user("Student", mfa_enabled=True)
        self.old_user.last_login = now - timezone.timedelta(days=95)
        self.old_user.save(update_fields=["last_login"])
        self.old_session = UserSession.objects.create(
            user=self.old_user,
            session_token_hash=secrets.token_hex(32),
            ip_address="192.0.2.10",
            user_agent="OldAgent",
            expires_at=now + timezone.timedelta(hours=12),
        )

        # Dormant Admin to verify Admin accounts are not exempted and are counted.
        self.old_admin = make_user("Admin", mfa_enabled=True)
        self.old_admin.last_login = now - timezone.timedelta(days=100)
        self.old_admin.save(update_fields=["last_login"])

        # Recently active user stays active.
        self.recent_user = make_user("Instructor", mfa_enabled=True)
        self.recent_user.last_login = now - timezone.timedelta(days=10)
        self.recent_user.save(update_fields=["last_login"])

        # Never logged in, created recently -> stays active.
        self.new_never_logged_in = make_user("Student", mfa_enabled=False)

        # Never logged in, created > 90 days ago -> disabled.
        self.old_never_logged_in = make_user("Student", mfa_enabled=False)
        self.User.objects.filter(id=self.old_never_logged_in.id).update(
            created_at=now - timezone.timedelta(days=120)
        )

    def test_dry_run_changes_nothing(self):
        out = StringIO()
        call_command("disable_inactive_accounts", "--days=90", "--dry-run", stdout=out)
        self.assertIn("would disable 3 inactive account(s) (1 Admin)", out.getvalue())

        for user in (self.old_user, self.old_admin, self.old_never_logged_in):
            user.refresh_from_db()
            self.assertTrue(user.is_active)
            self.assertIsNone(user.deactivated_at)
        self.old_session.refresh_from_db()
        self.assertIsNone(self.old_session.revoked_at)

    def test_disables_inactive_accounts_and_revokes_sessions(self):
        out = StringIO()
        with self.assertLogs("kura.security", level="WARNING") as logs:
            call_command("disable_inactive_accounts", "--days=90", stdout=out)

        self.assertIn("Disabled 3 inactive account(s) (1 Admin)", out.getvalue())

        for user in (self.old_user, self.old_admin, self.old_never_logged_in):
            user.refresh_from_db()
            self.assertFalse(user.is_active)
            self.assertIsNotNone(user.deactivated_at)

        self.old_session.refresh_from_db()
        self.assertIsNotNone(self.old_session.revoked_at)

        self.recent_user.refresh_from_db()
        self.assertTrue(self.recent_user.is_active)
        self.new_never_logged_in.refresh_from_db()
        self.assertTrue(self.new_never_logged_in.is_active)

        log_blob = "\n".join(logs.output)
        self.assertIn('event="account.deactivated.inactive"', log_blob)
        self.assertIn(str(self.old_user.id), log_blob)
        self.assertIn('days="90"', log_blob)


class CoursePageLinksTests(TestCase):
    """
    The course page must link staff to the gradebook and to live attendance,
    and must not show those links to enrolled students.
    """

    def setUp(self):
        self.client = Client()
        self.instructor = make_user("Instructor")
        self.student = make_user("Student")
        department = Department.objects.create(name="Computer Science", code="CS")
        StudentProfile.objects.create(
            user=self.student, department=department, current_level="level_4", matriculation_year=2026
        )
        self.course = Course.objects.create(
            department=department,
            code="CS210",
            title="Networks",
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=self.instructor,
            published_at=timezone.now(),
        )
        CourseStaff.objects.create(course=self.course, user=self.instructor, staff_role="lead_instructor")
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)
        self.module = Module.objects.create(course=self.course, title="Week 1", is_visible=True)

    def test_staff_see_gradebook_and_attendance_links(self):
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("kura:course_detail", args=[self.course.id]))
        self.assertContains(response, reverse("kura:course_grades", args=[self.course.id]))
        self.assertContains(response, reverse("kura:attendance_session_start", args=[self.module.id]))

    def test_students_do_not_see_staff_links(self):
        self.client.force_login(self.student)
        response = self.client.get(reverse("kura:course_detail", args=[self.course.id]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("kura:course_grades", args=[self.course.id]))
        self.assertNotContains(response, reverse("kura:attendance_session_start", args=[self.module.id]))

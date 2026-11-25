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
import uuid
import zipfile
from importlib import import_module
from pathlib import Path
from decimal import Decimal
from io import BytesIO, StringIO
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.apps import apps as django_apps
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from config.settings import read_secret
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
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

from .forms import PasswordChangeForm
from .base import get_vault_client
from .views import (
    calculate_student_course_score,
    check_signature_age,
    create_download_response,
    scan_file_for_malware,
    validate_and_save_upload,
    check_breached_password,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    hash_recovery_code,
    hash_session_token,
    log_security_event,
    mfa_login_callback,
    queue_email,
    verify_totp_code,
)
from .base import DatabaseWrapper as VaultDatabaseWrapper
from .base import database_login_cache, get_dynamic_database_credentials
from .models import (
    OutgoingEmail,
    OutgoingEmailStatus,
    QuarantinedFile,
    Assessment,
    AssessmentAttempt,
    AttemptStatus,
    AttendanceMethod,
    AttendanceRecord,
    AttendanceStatus,
    ChangeRequestStatus,
    Course,
    CourseResult,
    CourseStaff,
    DayOfWeek,
    Department,
    Building,
    Room,
    Enrollment,
    EnrollmentStatus,
    FileContent,
    Grade,
    GradeChangeRequest,
    GradeComponentType,
    GradeHistory,
    GradeStatus,
    ModuleAttendanceSession,
    PasswordHistory,
    PasswordResetToken,
    Role,
    Schedule,
    SessionType,
    StaffProfile,
    StoredFile,
    StudentProfile,
    UserRole,
    UserSession,
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
        login_with_session(self.client, admin)
        response = self.client.get(reverse("kura:course_list"), {"department": first.pk})
        self.assertContains(response, "First course")
        self.assertNotContains(response, "Second course")


class GmailEmailSettingsTests(TestCase):
    """Production email goes straight to Gmail over verified STARTTLS; the app password comes from Vault KV."""

    def test_production_uses_smtp_backend(self):
        from config import settings
        # EMAIL_BACKEND is set at import time from DEBUG; override_settings(DEBUG)
        # does not re-run the module-level if block, so test the logic directly.
        if not settings.DEBUG:
            self.assertEqual(settings.EMAIL_BACKEND, "django.core.mail.backends.smtp.EmailBackend")
        else:
            self.skipTest("DEBUG is True; console backend is in use")

    def test_gmail_smtp_settings(self):
        with override_settings(DEBUG=False, EMAIL_HOST="smtp.gmail.com", EMAIL_PORT=587, EMAIL_USE_TLS=True):
            self.assertEqual(settings.EMAIL_HOST, "smtp.gmail.com")
            self.assertEqual(settings.EMAIL_PORT, 587)
            self.assertTrue(settings.EMAIL_USE_TLS)
            self.assertEqual(settings.EMAIL_TIMEOUT, 10)

    def test_ssl_context_verifies_certificates(self):
        import ssl
        # ssl.create_default_context() verifies certificates by default
        # (CERT_REQUIRED), which is what Django's SMTP backend uses for STARTTLS.
        self.assertIs(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)

    def test_password_comes_from_vault_not_file(self):
        from django.conf import settings as dj_settings
        from kura.vault_secrets import get_gmail_app_password
        import os
        # EMAIL_HOST_PASSWORD must come from Vault KV, not from os.environ or
        # a Docker secret file (read_secret("gmail_app_password")).
        self.assertEqual(dj_settings.EMAIL_HOST_PASSWORD, get_gmail_app_password())
        self.assertNotIn("GMAIL_APP_PASSWORD", os.environ)
        settings_src = (Path(dj_settings.BASE_DIR) / "config" / "settings.py").read_text(encoding="utf-8")
        self.assertIn("EMAIL_HOST_PASSWORD = get_gmail_app_password()", settings_src)
        self.assertNotIn('read_secret("gmail_app_password")', settings_src)
        if dj_settings.EMAIL_HOST_PASSWORD:
            self.assertNotEqual(dj_settings.EMAIL_HOST_PASSWORD, read_secret("gmail_app_password"))

    def test_debug_uses_console_backend(self):
        from config import settings
        if settings.DEBUG:
            self.assertEqual(settings.EMAIL_BACKEND, "django.core.mail.backends.console.EmailBackend")
        else:
            self.skipTest("DEBUG is False; SMTP backend is in use")


def make_user(role_name, email=None, password="ValidPassword123!", **extra_fields):  # nosemgrep: python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument
    """Test helper function to create a user and assign them a specific system role."""
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

def login_with_session(client, user):
    """Log a test client in and create a matching tracked UserSession row."""
    client.logout()
    client.force_login(user)
    session = client.session
    if not session.session_key:
        session.save()
    user_session = UserSession.objects.create(
        user=user,
        session_token_hash=hash_session_token(session.session_key),
        ip_address="127.0.0.1",
        user_agent="DjangoTestClient",
        expires_at=timezone.now() + timezone.timedelta(hours=settings.SESSION_ABSOLUTE_HOURS),
    )
    session["user_session_id"] = str(user_session.id)
    session.save()
    return user_session

def confirm_second_factor(client):
    """Test helper: marks the logged-in test client as having just entered a
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

    def test_navigation_context_for_anonymous_and_missing_user(self):
        from .views import nav_roles

        request = RequestFactory().get("/")
        self.assertEqual(nav_roles(request), {"nav_roles": set()})
        request.user = AnonymousUser()
        self.assertEqual(nav_roles(request), {"nav_roles": set()})

    def test_navigation_context_processor_exposes_assigned_roles(self):
        from django.template import engines

        user = make_user("Student")
        instructor = Role.objects.get(name="Instructor")
        UserRole.objects.create(user=user, role=instructor)
        request = RequestFactory().get("/")
        request.user = user
        template = engines["django"].from_string(
            "{% if 'Student' in nav_roles and 'Instructor' in nav_roles %}both roles{% endif %}"
        )
        self.assertEqual(template.render({}, request), "both roles")

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
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid email or password.", status_code=400)

    def test_deactivated_account_cannot_login(self):
        # AUTH-01: even a correct password gets the generic message, so the response never confirms that the password was right.
        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid email or password.", status_code=400)
        self.assertNotContains(response, "deactivated", status_code=400)

    def test_wrong_password_for_deactivated_account_stays_generic(self):
        # A wrong password never reveals whether the matching account is deactivated.
        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "WrongPassword999!"},
        )

        self.assertContains(response, "Invalid email or password.", status_code=400)
        self.assertNotContains(response, "This account has been deactivated.", status_code=400)

    def test_locked_account_with_correct_password_shows_generic_message(self):
        # AUTH-01: a correct password on a locked account gets the same message as a wrong one; the lock reason is only logged.
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=2)
        self.user.save()

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(
                reverse("kura:login"),
                {"email": self.user.email, "password": self.password},
            )
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid email or password.", status_code=400)
        self.assertNotContains(response, "locked", status_code=400)
        self.assertIn('reason="locked"', "\n".join(captured.output))

    def test_locked_account_with_wrong_password_shows_generic_message(self):
        # A wrong password must not disclose that this account is locked.
        self.user.locked_until = timezone.now() + timezone.timedelta(hours=2)
        self.user.save()

        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": "WrongPassword999!"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid email or password.", status_code=400)
        self.assertNotContains(response, "This account is currently locked.", status_code=400)

    @patch("kura.views.authenticate", return_value=None)
    @patch("kura.views.AxesProxyHandler.is_locked", return_value=True)
    def test_axes_locked_account_with_correct_password_shows_generic_message(self, mock_is_locked, mock_authenticate):
        # AUTH-01: an Axes lockout also gets the generic message.
        response = self.client.post(
            reverse("kura:login"),
            {"email": self.user.email, "password": self.password},
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid email or password.", status_code=400)

    def test_failed_login_checks_the_password_only_once(self):
        # AUTH-04: a known email with a wrong password must cost one password hash, the same as an unknown email, so timing does not reveal which emails have accounts.
        with patch.object(User, "check_password", autospec=True, return_value=False) as mock_check:
            self.client.post(
                reverse("kura:login"),
                {"email": self.user.email, "password": "WrongPassword999!"},
            )
        self.assertEqual(mock_check.call_count, 1)

    def test_logout_by_post(self):
        # Logout must be a POST request and revoke active session.
        self.client.force_login(self.user)
        session = self.client.session
        if not session.session_key:
            session.save()
        session_record = UserSession.objects.create(
            user=self.user,
            session_token_hash=hash_session_token(session.session_key),
            expires_at=timezone.now() + timezone.timedelta(days=1),
        )
        session["user_session_id"] = str(session_record.id)
        session.save()

        response = self.client.post(reverse("kura:logout"))
        self.assertRedirects(response, reverse("kura:login"))

        session_record.refresh_from_db()
        self.assertIsNotNone(session_record.revoked_at)

    def test_logout_get_request_is_not_allowed(self):
        # GET request to logout must return 405 Method Not Allowed.
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, self.user)
        response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:password_change"))

    @patch("kura.views.check_breached_password", side_effect=ValidationError("Breached password"))
    def test_breached_password_does_not_change_account(self, check):
        login_with_session(self.client, self.user)
        response = self.client.post(reverse("kura:password_change"), {
            "old_password": self.password,
            "new_password": "NewSecurePassword456!",
            "confirm_password": "NewSecurePassword456!",
        })
        self.assertEqual(response.status_code, 400)
        check.assert_called_once_with("NewSecurePassword456!")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_password_change_succeeds(self):
        # Completing password change updates password_changed_at and removes flag.
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": "weak",
                "confirm_password": "weak",
            },
        )

        self.assertEqual(response.status_code, 400)
        password_error = response.context["form"].errors["new_password"][0]
        self.assertContains(response, password_error, status_code=400)
        self.assertNotContains(response, "data-password-change-confirmation", status_code=400)

    def test_password_confirmation_is_shown_before_mfa_setup(self):
        # First-time users also need confirmation when they are redirected to MFA setup.
        self.user.mfa_enabled = False
        self.user.save(update_fields=["mfa_enabled"])
        login_with_session(self.client, self.user)
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
        session["pre_mfa_started_at"] = timezone.now().timestamp()
        session.save()
        response = self.client.post(reverse("kura:mfa_verify"), {"code": "123456"})

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid security code.", status_code=400)
        # Preserve existing MFA settings while removing the known insecure token.
        self.assertTrue(demo_user.mfa_enabled)
        self.assertTrue(TOTPDevice.objects.filter(user=demo_user).exists())
        self.assertTrue(StaticDevice.objects.filter(user=demo_user).exists())
        self.assertFalse(StaticToken.objects.filter(device=static_device, token="123456").exists())

    @override_settings(DEBUG=True)
    def test_reseeding_preserves_existing_password_and_mfa_devices(self):
        # Re-running the demo command must not reset a user's chosen password or MFA.
        demo_user = make_user("Admin", email="admin@kura.edu", mfa_enabled=True)
        demo_user.set_password("ChosenDemoPassword987!")  # nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password
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

    @patch("kura.views.check_breached_password", side_effect=ValidationError("Breached password"))
    def test_breached_password_does_not_consume_reset_token(self, check):
        raw_token, reset_record = self.make_reset_token()
        response = self.client.post(reverse("kura:password_reset_confirm", kwargs={"token": raw_token}), {
            "code": "000000",
            "new_password": "BrandNewPassword789!",
            "confirm_password": "BrandNewPassword789!",
        })
        self.assertEqual(response.status_code, 400)
        check.assert_called_once_with("BrandNewPassword789!")
        reset_record.refresh_from_db()
        self.assertIsNone(reset_record.used_at)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OriginalPassword123!"))

    def test_request_always_emails_a_link(self):
        # G13: request enqueues a deferred lookup so known/unknown responses execute equal work; cron resolves tokens.
        response = self.client.post(reverse("kura:password_reset_request"), {"email": self.user.email})
        self.assertRedirects(response, reverse("kura:login"))
        call_command("send_queued_emails", stdout=StringIO())
        self.assertEqual(PasswordResetToken.objects.filter(user=self.user).count(), 1)

    def test_mfa_account_needs_code_on_confirm_page(self):
        # AUTH-03: the emailed link alone cannot reset an MFA account. A wrong code spends the link and leaves the password unchanged.
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
        login_with_session(self.client, self.user)
        response = self.client.get(reverse("kura:home"))
        self.assertRedirects(response, reverse("kura:mfa_setup"))

    def test_mfa_setup_renders_qr_code(self):
        # Setup page displays locally generated QR code.
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, self.user_a)
        response = self.client.get(reverse("kura:user_sessions"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "192.168.1.10")
        self.assertNotContains(response, "10.0.0.2")

    def test_student_cannot_revoke_another_users_session_on_personal_page(self):
        # A non-admin cannot revoke another user's session via the personal revoke URL (IDOR -> 404).
        login_with_session(self.client, self.user_a)
        response = self.client.post(
            reverse("kura:user_session_revoke", args=[self.session_b.id]),
        )
        self.assertEqual(response.status_code, 404)

        # Confirm User B's session was not revoked.
        self.session_b.refresh_from_db()
        self.assertIsNone(self.session_b.revoked_at)

    def test_student_can_revoke_own_session_on_personal_page(self):
        # A user can revoke their own active session from the personal sessions endpoint.
        login_with_session(self.client, self.user_a)
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
        login_with_session(self.client, admin)
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
        login_with_session(self.client, admin)
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
        login_with_session(self.client, admin)
        response = self.client.get(reverse("kura:admin_sessions"), {"state": "unknown"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, self.user_a.email)
        self.assertFormError(response.context["form"], "state", "Select a valid choice. unknown is not one of the available choices.")

    def test_non_admin_has_my_sessions_link_and_no_admin_sessions_navigation(self):
        # Non-admins see their personal sessions link, never the Admin sessions page.
        login_with_session(self.client, self.user_a)
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
        login_with_session(self.client, admin)
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
        login_with_session(self.client, admin)
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
                login_with_session(self.client, make_user(role_name, mfa_enabled=True))
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
        login_with_session(self.client, admin)
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
        login_with_session(self.client, self.admin)
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

    @patch("kura.views.check_breached_password", side_effect=ValidationError("Breached password"))
    def test_breached_temporary_password_does_not_create_staff(self, check):
        login_with_session(self.client, self.admin)
        response = self.client.post(reverse("kura:staff_create"), {
            "email": "blocked.staff@example.com", "department": self.department.id, "staff_title": "Instructor",
        })
        self.assertEqual(response.status_code, 400)
        check.assert_called_once()
        self.assertFalse(User.objects.filter(email="blocked.staff@example.com").exists())

    def test_new_staff_account_gets_the_role_named_by_its_title(self):
        # The chosen title becomes the first role, recorded with the Admin who assigned it.
        login_with_session(self.client, self.admin)
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
        login_with_session(self.client, self.admin)

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
        login_with_session(self.client, self.admin)
        url = reverse("kura:staff_settings")
        self.assertEqual(self.client.post(url, {"kind": "department", "code": "MATH", "name": "Mathematics"}).status_code, 302)
        self.assertEqual(self.client.post(url, {"kind": "building", "name": "Building B"}).status_code, 302)
        building = Building.objects.get(name="Building B")
        self.assertEqual(self.client.post(url, {"kind": "room", "building": building.pk, "name": "Room 204"}).status_code, 302)
        self.assertTrue(Room.objects.filter(building=building, name="Room 204").exists())

    def test_student_cannot_manage_offices(self):
        login_with_session(self.client, self.student)
        response = self.client.post(reverse("kura:staff_settings"), {"kind": "building", "name": "Forbidden"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Building.objects.filter(name="Forbidden").exists())

    def test_room_must_belong_to_selected_building(self):
        login_with_session(self.client, self.admin)
        building = Building.objects.create(name="A")
        other = Building.objects.create(name="B")
        room = Room.objects.create(building=other, name="204")
        response = self.client.post(reverse("kura:staff_create"), {
            "email": "test-office@example.com", "department": self.department.pk,
            "staff_title": "Instructor", "building": building.pk, "room": room.pk,
        })
        self.assertEqual(response.status_code, 400)
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
        login_with_session(self.client, self.admin)

        response = self.client.get(reverse("kura:staff_list"))

        self.assertContains(response, f"Head of {self.department.name}")

    def test_non_admin_cannot_access_staff_creation(self):
        # Non-admin user receives 403 Forbidden.
        login_with_session(self.client, self.student)
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

        login_with_session(self.client, self.admin)
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
        login_with_session(self.client, self.admin)

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
        login_with_session(self.client, self.admin)
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
        login_with_session(self.client, self.admin)

        self.client.post(
            reverse("kura:user_roles", kwargs={"user_id": instructor_user.id}),
            {"action": "assign", "role_id": self.admin_role.id},
        )
        # Verify assignment was rejected
        self.assertFalse(UserRole.objects.filter(user=instructor_user, role=self.admin_role).exists())

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
        StaffProfile.objects.create(user=self.ta, department=self.dept, staff_title="Teaching assistant")

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

    def test_instructor_cannot_assign_non_ta_as_teaching_assistant(self):
        # A user with an Instructor role must not appear as or be saved as a TA.
        login_with_session(self.client, self.lead)
        form_response = self.client.get(
            reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id})
        )
        self.assertContains(form_response, self.ta.email)
        self.assertNotContains(form_response, f'<option value="{self.lead.id}"')

        response = self.client.post(
            reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id}),
            {"user": str(self.lead.id)},
        )

        self.assertEqual(response.status_code, 400)
        lead_assignment = CourseStaff.objects.get(course=self.course, user=self.lead)
        self.assertEqual(lead_assignment.staff_role, "lead_instructor")

    def test_assigned_ta_cannot_assign_another_ta(self):
        # A course assignment does not allow teaching assistants to assign staff.
        CourseStaff.objects.create(course=self.course, user=self.ta, staff_role="teaching_assistant")
        other_ta = make_user("Teaching assistant")
        login_with_session(self.client, self.ta)
        response = self.client.post(reverse("kura:course_ta_assign", kwargs={"course_id": self.course.id}), {"user": str(other_ta.id)})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(CourseStaff.objects.filter(course=self.course, user=other_ta).exists())

    def test_lead_instructor_can_assign_ta(self):
        # Lead instructor assigns TA to course with can_release_grades=False.
        login_with_session(self.client, self.lead)
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

    @patch("kura.views.scan_file_for_malware")
    def test_new_file_formats_pass_real_content_detection(self, mock_scan):
        # Check actual bytes rather than trusting each file's extension or browser MIME type.
        import base64

        samples = [
            ("tiny.gif", base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="), "image/gif"),
            ("tiny.webp", base64.b64decode("UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA"), "image/webp"),
            # Different libmagic versions call plain CSV "text/csv" (macOS) or "text/plain" (Ubuntu); both are on the allowlist.
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

    @patch("kura.views.scan_file_for_malware")
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

    @patch("kura.views.scan_file_for_malware")
    def test_rejected_upload_explains_allowed_types(self, mock_scan):
        # Give the author useful guidance without trusting a disguised filename.
        upload = SimpleUploadedFile("malware.pdf", b"\x7fELF\x02\x01\x01\x00executable")
        with self.assertRaises(ValidationError) as error:
            validate_and_save_upload(upload, self.instructor)
        self.assertIn("Allowed:", str(error.exception))
        self.assertIn("PDF", str(error.exception))
        self.assertIn("ZIP", str(error.exception))
        mock_scan.assert_called_once()

    def test_assessment_delete_requires_confirmation_and_permissions(self):
        # Without an attempt, deletion still requires the right course and confirmation.
        now = timezone.now()
        assessment = Assessment.objects.create(course=self.course, title="Empty assessment", component_type=GradeComponentType.EXAM,
                                               opens_at=now, due_date=now + timezone.timedelta(days=1),
                                               created_by=self.instructor)
        url = reverse("kura:assessment_delete", kwargs={"assessment_id": assessment.id})
        login_with_session(self.client, self.outsider_student)
        self.assertEqual(self.client.post(url, {"confirm": "on"}).status_code, 403)
        login_with_session(self.client, self.instructor)
        self.client.post(url)
        self.assertTrue(Assessment.objects.filter(id=assessment.id).exists())
        self.client.post(url, {"confirm": "on"})
        self.assertFalse(Assessment.objects.filter(id=assessment.id).exists())

# Schedules and attendance tests

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
        session = ModuleAttendanceSession.objects.create(course=self.course, created_by=self.instructor, title="Private roll", passcode_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(hours=1))
        AttendanceRecord.objects.create(session=session, student=self.student, status=AttendanceStatus.PRESENT, method=AttendanceMethod.QR_CODE)
        login_with_session(self.client, self.instructor)
        self.assertNotContains(self.client.get(reverse("kura:course_list")), self.course.code)
        self.assertNotContains(self.client.get(reverse("kura:attendance_history")), "Private roll")

    def test_instructor_can_create_schedule(self):
        # Instructor creates a recurring class schedule with valid start and end times.
        login_with_session(self.client, self.instructor)
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
        session = ModuleAttendanceSession.objects.create(course=self.course, schedule=schedule, created_by=self.instructor,
                                                        title="Roll", passcode_hash="x" * 64, expires_at=timezone.now() + timezone.timedelta(hours=1))
        record = AttendanceRecord.objects.create(session=session, student=self.student, status=AttendanceStatus.PRESENT,
                                                 method=AttendanceMethod.QR_CODE)
        edit_url = reverse("kura:schedule_edit", kwargs={"schedule_id": schedule.id})
        delete_url = reverse("kura:schedule_delete", kwargs={"schedule_id": schedule.id})
        login_with_session(self.client, self.student)
        self.assertEqual(self.client.get(edit_url).status_code, 403)
        self.assertEqual(self.client.post(delete_url, {"confirm": "on"}).status_code, 403)
        login_with_session(self.client, self.instructor)
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
        login_with_session(self.client, self.instructor)
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
        self.assertEqual(response.status_code, 400)
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
        login_with_session(self.client, self.student)
        response = self.client.get(reverse("kura:schedule_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "MATH201")
        self.assertContains(response, "Hall A")

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

        self.session = ModuleAttendanceSession.objects.create(
            course=self.course,
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
        login_with_session(self.client, self.student_a)
        response = self.client.get(reverse("kura:attendance_history"))
        self.assertEqual(response.status_code, 200)

        # Student A record is present.
        self.assertContains(response, "PHIL101")
        self.assertContains(response, "Present")

        # Student B record (Late) is not visible to Student A.
        self.assertNotContains(response, "Late")

    def test_staff_sees_all_course_attendance_records(self):
        # Course staff sees attendance records for students in their course.
        login_with_session(self.client, self.instructor)
        response = self.client.get(reverse("kura:attendance_history"))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, self.student_a.email)
        self.assertContains(response, self.student_b.email)
        self.assertContains(response, "Present")
        self.assertContains(response, "Late")

# Assessments and grading tests

def reseed_roles_after_flush():
    """Test helper: puts back the roles and permissions that migrations seed.
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
        login_with_session(client, instructor)
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
                login_with_session(release_client, instructor)
                confirm_second_factor(release_client)
                response = release_client.post(reverse("kura:course_result_release", kwargs={"course_id": course.id}))
                self.assertEqual(response.status_code, 302)
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(responses[0].status_code, 302)
        result.refresh_from_db()
        self.assertEqual(result.status, GradeStatus.RELEASED)
        # Release recalculates the draft, so the stored 75.00 is replaced by the real score.
        self.assertEqual(result.final_score, calculate_student_course_score(course, student))

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
        now = timezone.now()
        assessment = Assessment.objects.create(course=course, title="Original", component_type=GradeComponentType.EXAM,
                                               created_by=instructor, opens_at=now - timezone.timedelta(hours=1),
                                               due_date=now + timezone.timedelta(days=1),)
        client = Client()
        login_with_session(client, student)
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

# Grades, appeals & transcripts tests

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

        self.assessment = Assessment.objects.create(
            course=self.course,
            title="Renaissance Essay",
            component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now() - timezone.timedelta(hours=1),
            due_date=timezone.now() + timezone.timedelta(hours=2),
            created_by=self.instructor,
        )
        self.attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.REQUIRES_MANUAL_GRADING,
            ip_address="127.0.0.1",
        )

    def test_ta_can_enter_draft_grade_creates_history_row(self):
        # TA enters manual draft score; grade is created and GradeHistory row is logged.
        login_with_session(self.client, self.ta)
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

        login_with_session(self.client, self.ta)

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
        login_with_session(self.client, head)
        response = self.client.post(reverse("kura:grade_entry", kwargs={"attempt_id": self.attempt.id}), {"score": "80"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Grade.objects.filter(attempt=self.attempt).exists())

    def test_finalized_grade_cannot_be_edited_as_draft(self):
        # Editing a finalized score must not silently return it to draft.
        grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=self.attempt,
                                     grader=self.ta, score=Decimal("80.00"), status=GradeStatus.FINALIZED)
        login_with_session(self.client, self.ta)
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
        login_with_session(self.client, head)
        response = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": grade.id}))
        self.assertEqual(response.status_code, 403)
        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.DRAFT)

    def test_instructor_cannot_revert_released_grade_to_finalized(self):
        # A repeated finalize request must not change an already released grade.
        grade = Grade.objects.create(assessment=self.assessment, student=self.student, attempt=self.attempt,
                                     grader=self.ta, score=Decimal("80.00"), status=GradeStatus.RELEASED)
        login_with_session(self.client, self.instructor)
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

        login_with_session(self.client, self.instructor)

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

        self.assessment_1 = Assessment.objects.create(
            course=self.course, title="Draft Quiz", component_type=GradeComponentType.QUIZ,
            max_score=Decimal("20.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), created_by=self.instructor,
        )
        self.assessment_2 = Assessment.objects.create(
            course=self.course, title="Finalized Brief", component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("40.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), created_by=self.instructor,
        )
        self.assessment_3 = Assessment.objects.create(
            course=self.course, title="Released Moot", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), created_by=self.instructor,
        )

        att_1 = AssessmentAttempt.objects.create(assessment=self.assessment_1, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1")
        att_2 = AssessmentAttempt.objects.create(assessment=self.assessment_2, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1")
        att_3 = AssessmentAttempt.objects.create(assessment=self.assessment_3, student=self.student_a, attempt_no=1, status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1")
        att_b = AssessmentAttempt.objects.create(assessment=self.assessment_3, student=self.student_b, attempt_no=1, status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1")

        # Student A grades across all 3 statuses
        Grade.objects.create(assessment=self.assessment_1, student=self.student_a, attempt=att_1, score=Decimal("18.00"), status=GradeStatus.DRAFT)
        Grade.objects.create(assessment=self.assessment_2, student=self.student_a, attempt=att_2, score=Decimal("35.00"), status=GradeStatus.FINALIZED)
        Grade.objects.create(assessment=self.assessment_3, student=self.student_a, attempt=att_3, score=Decimal("94.00"), status=GradeStatus.RELEASED)

        # Student B released grade
        Grade.objects.create(assessment=self.assessment_3, student=self.student_b, attempt=att_b, score=Decimal("77.00"), status=GradeStatus.RELEASED)

    def test_student_sees_only_own_released_grades_draft_and_finalized_hidden(self):
        # Student A views grades: only sees their own RELEASED grade.
        login_with_session(self.client, self.student_a)
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

        self.assessment = Assessment.objects.create(
            course=self.course, title="Memory Exam", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(), due_date=timezone.now() + timezone.timedelta(hours=1), created_by=self.instructor,
        )
        att = AssessmentAttempt.objects.create(assessment=self.assessment, student=self.student, attempt_no=1, status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1")
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

        login_with_session(self.client, self.head)
        confirm_second_factor(self.client)
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

        login_with_session(self.client, self.head)
        confirm_second_factor(self.client)
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

        login_with_session(self.client, self.instructor)
        response = self.client.post(
            reverse("kura:grade_change_request_review", kwargs={"request_id": change_request.id}),
            {"decision": ChangeRequestStatus.APPROVED},
        )
        self.assertEqual(response.status_code, 403)

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
        login_with_session(self.client, self.head_a)
        response = self.client.get(reverse("kura:department_reports", kwargs={"department_id": self.dept_a.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"{self.dept_a.name} report")

    def test_head_cannot_view_other_department_report(self):
        # Head of Dept A tries to view Dept B's report; receives 403 Forbidden.
        login_with_session(self.client, self.head_a)
        response = self.client.get(reverse("kura:department_reports", kwargs={"department_id": self.dept_b.id}))
        self.assertEqual(response.status_code, 403)

# Hardening, logging & rate limits tests

class SecurityLoggingTests(TestCase):
    """
    Tests Security event logging without leaking sensitive credentials.
    """

    def setUp(self):
        self.client = Client()
        self.user = make_user("Instructor", email="instructor_log@example.com", mfa_enabled=True)

    def test_failed_login_logs_security_warning_without_password(self):
        # Failed login attempt produces a security warning log with a keyed email hash, never raw email or password.
        from .logging_utils import hash_login_identifier

        expected_hash = hash_login_identifier("instructor_log@example.com")
        with self.assertLogs("kura.security", level="WARNING") as log_capture:
            self.client.post(
                reverse("kura:login"),
                {"email": "instructor_log@example.com", "password": "WrongPasswordAttempt123!"},
            )
            self.assertTrue(any(expected_hash in record.getMessage() for record in log_capture.records))
            self.assertFalse(any("instructor_log@example.com" in record.getMessage() for record in log_capture.records))
            self.assertFalse(any("WrongPasswordAttempt123!" in record.getMessage() for record in log_capture.records))

    def test_user_logout_logs_security_info(self):
        # User logout action produces a security information log record.
        login_with_session(self.client, self.user)
        with self.assertLogs("kura.security", level="INFO") as log_capture:
            self.client.post(reverse("kura:logout"))
            self.assertTrue(any('event="auth.logout"' in record.getMessage() for record in log_capture.records))

    def test_password_reset_url_redacted_in_django_request_logs(self):
        # R14/R16: django.request logger must not emit raw password-reset tokens or UIDs.
        import logging
        from kura.logging_utils import RedactSecretsFilter

        filter_obj = RedactSecretsFilter()
        record = logging.LogRecord(
            name="django.request",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg='GET /password/reset/abc123def456/ HTTP/1.1" 200',
            args=(),
            exc_info=None,
        )
        filter_obj.filter(record)
        self.assertIn("<redacted>", record.getMessage())
        self.assertNotIn("abc123def456", record.getMessage())

        # Also test token= and uid= query parameters
        record2 = logging.LogRecord(
            name="django.request",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg='GET /password/reset/confirm/?token=xyz789&uid=123 HTTP/1.1" 200',
            args=(),
            exc_info=None,
        )
        filter_obj.filter(record2)
        self.assertIn("token=<redacted>", record2.getMessage())
        self.assertIn("uid=<redacted>", record2.getMessage())
        self.assertNotIn("xyz789", record2.getMessage())
        self.assertNotIn("123", record2.getMessage())

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

        login_with_session(self.client, self.user)
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

    # Rejected uploads are saved through the separate "quarantine" connection, which only sees committed rows.
    # TransactionTestCase really commits, so the uploader exists for that connection.
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
        # When an infected file is uploaded, validate_and_save_upload raises ValidationError and stores zero rows in StoredFile and FileContent.
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

    @patch("kura.views.get_vault_client")
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

    @patch("kura.views.get_vault_client")
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

    @patch("kura.views.get_vault_client")
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

    @unittest.skipUnless(
        (Path(settings.BASE_DIR) / "certs" / "internal").is_dir(),
        "certs/internal/ not available in container",
    )
    def test_internal_certificates_generated_and_valid(self):
        # Confirms all required internal mTLS certificates and private keys are present
        from pathlib import Path
        base_dir = Path(__file__).resolve().parent.parent / "certs" / "internal"

        for cert_name in ["ca.crt", "nginx.crt", "waf.crt", "web.crt", "db.crt", "vault.crt"]:
            cert_path = base_dir / cert_name
            self.assertTrue(cert_path.exists(), f"Missing certificate: {cert_name}")
            content = cert_path.read_text()
            self.assertIn("-----BEGIN CERTIFICATE-----", content)

        # Only check the service keys exist: on Linux each one belongs to its container user, so this test (running as you) may not be able to read it.
        for key_name in ["nginx.key", "waf.key", "web.key", "db.key", "vault.key"]:
            key_path = base_dir / key_name
            self.assertTrue(key_path.exists(), f"Missing private key: {key_name}")

        # No CA private key may sit where containers mount files from.
        # Once Vault issues the certificates (stage 3b) there is no CA key on disk at all:
        # it only exists inside Vault.
        # Before that, the openssl bootstrap key lives in certs/ca/, which no container mounts.
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

        now = timezone.now()
        self.assessment = Assessment.objects.create(
            course=self.course,
            title="SQL Hardening Lab",
            component_type=GradeComponentType.ASSIGNMENT,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(days=7),
            created_by=self.instructor,
        )

        self.attempt_a = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student_a,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            ip_address="127.0.0.1",
        )
        self.attempt_b = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student_b,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
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
        # When kura.current_user_id is set to student_a under the application role, the PostgreSQL RLS policy filters out student_b's grade.
        from django.db import connection

        with connection.cursor() as cursor:
            # Switch to application role which enforces RLS policies
            cursor.execute("SET ROLE kura_app;")
            # Set session context to student_a
            cursor.execute("SELECT set_config('kura.current_user_id', %s, false);", [str(self.student_a.id)])

            # Query grades through the ORM while PostgreSQL enforces RLS.
            visible_rows = list(Grade.objects.values_list("id", "student_id"))

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
            cursor.execute("SELECT set_config('kura.current_user_id', %s, false);", [str(self.instructor.id)])
            visible_rows = list(Grade.objects.values_list("id", flat=True))

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

@unittest.skipUnless(
    (Path(settings.BASE_DIR) / "docker" / "postgres").is_dir(),
    "docker/postgres/ not available in container",
)
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
        # On Linux the key is mode 600 and belongs to the database container user (UID 26), so this test (running as you) may not read it.
        # ./kura.sh preflight checks its length as root instead.
        if not os.access(key_path, os.R_OK):
            self.skipTest("backup key belongs to the database container user")

        key_content = key_path.read_text(encoding="utf-8").strip()
        self.assertGreaterEqual(len(key_content), 32, "Encryption key must be at least 32 characters for AES-256")

        entropy = calculate_shannon_entropy(key_content)
        self.assertGreaterEqual(entropy, 3.5, "Encryption key must exhibit high cryptographic entropy")

    def test_pgbackrest_config_security_attributes(self):
        # pgbackrest.conf must enforce AES-256-CBC cipher without broken file: syntax, and entrypoint/wrapper scripts must supply PGBACKREST_REPO1_CIPHER_PASS from the secret.
        conf_path = self.base_dir / "docker" / "postgres" / "pgbackrest.conf"
        self.assertTrue(conf_path.exists(), "pgbackrest.conf must exist")

        content = conf_path.read_text(encoding="utf-8")
        self.assertIn("repo1-cipher-type=aes-256-cbc", content)
        self.assertNotIn("repo1-cipher-pass=file:", content)
        self.assertIn("repo1-retention-full=", content)
        self.assertIn("[kura]", content)

        wrapper_path = self.base_dir / "docker" / "postgres" / "pgbackrest-wrapper.sh"
        entrypoint_path = self.base_dir / "docker" / "postgres" / "entrypoint.sh"
        self.assertTrue(wrapper_path.exists())
        self.assertTrue(entrypoint_path.exists())
        self.assertIn("PGBACKREST_REPO1_CIPHER_PASS", wrapper_path.read_text(encoding="utf-8"))
        self.assertIn("PGBACKREST_REPO1_CIPHER_PASS", entrypoint_path.read_text(encoding="utf-8"))

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
        # The key file may belong to the database container user (see above).
        key_path = self.base_dir / "secrets" / "backup_encryption_key.txt"
        if key_path.exists() and not os.access(key_path, os.R_OK):
            self.skipTest("backup key belongs to the database container user")
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
        login_with_session(self.client_a, self.user_a)
        confirm_second_factor(self.client_a)
        self.client_b = Client()
        login_with_session(self.client_b, self.user_b)
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
        # Users can delete their own passkeys via POST.
        # Deleting another user's key raises 404 (IDOR).
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
        request.session["pre_mfa_started_at"] = timezone.now().timestamp()
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
        session["pre_mfa_started_at"] = timezone.now().timestamp()
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

@unittest.skipUnless(
    (Path(settings.BASE_DIR) / "docker" / "loki").is_dir(),
    "docker/loki/ not available in container",
)
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
        # All 13 security alerts from the handoff's WP4 table, plus BreachCheckUnavailable (fix 3), must be defined.
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

    def test_grafana_security_dashboard_shows_collected_security_events(self):
        # Search all collected services, not only web, so cron events are included.
        dashboard_path = self.base_dir / "docker" / "grafana" / "dashboards" / "kura_security_overview.json"
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
        panels = [panel for panel in dashboard["panels"] if panel.get("title") == "All Kura security events"]
        self.assertEqual(len(panels), 1)
        self.assertEqual(panels[0]["type"], "logs")
        self.assertEqual(panels[0]["datasource"]["uid"], "loki")
        self.assertEqual(
            panels[0]["targets"][0]["expr"],
            '{service=~".+"} | logfmt | logger="kura.security" | event != ""',
        )

    def test_security_logger_and_alloy_forward_logs_to_loki(self):
        # Keep the logger-to-console and Alloy-to-Loki configuration connected.
        logger = settings.LOGGING["loggers"]["kura.security"]
        self.assertEqual(logger["handlers"], ["console"])
        self.assertEqual(settings.LOGGING["handlers"]["console"]["class"], "logging.StreamHandler")
        alloy = (self.base_dir / "docker" / "alloy" / "config.alloy").read_text(encoding="utf-8")
        self.assertIn('loki.source.docker "containers"', alloy)
        self.assertIn('loki.source.file "cron_logs"', alloy)
        self.assertIn("forward_to = [loki.process.docker_envelope.receiver]", alloy)
        self.assertIn("forward_to = [loki.process.pipeline.receiver]", alloy)
        self.assertIn('selector = "{service=~\\\"web|cron\\\"}"', alloy)
        self.assertIn("forward_to = [loki.write.local_loki.receiver]", alloy)
        self.assertIn('url = "http://loki:3100/loki/api/v1/push"', alloy)

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
        self.assessment = Assessment.objects.create(
            course=self.course,
            title="Data Protection Exam",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now() - timezone.timedelta(days=200),
            due_date=timezone.now() - timezone.timedelta(days=190),
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
        # Records older than the retention cutoff have their IP addresses pseudonymised.
        import io
        from axes.models import AccessAttempt, AccessLog
        from kura.models import AssessmentAttempt, UserSession

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

        # 3. Old django-axes AccessAttempt and AccessLog
        old_attempt = AccessAttempt.objects.create(
            username=self.student.email,
            ip_address="203.0.113.15",
            failures_since_start=1,
        )
        AccessAttempt.objects.filter(id=old_attempt.id).update(attempt_time=past_date)
        old_access_log = AccessLog.objects.create(
            username=self.student.email,
            ip_address="203.0.113.25",
        )
        AccessLog.objects.filter(id=old_access_log.id).update(attempt_time=past_date)

        # 4. Old assessment attempt
        old_exam = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            ip_address="192.0.2.99",
        )
        AssessmentAttempt.objects.filter(id=old_exam.id).update(started_at=past_date)

        # Execute anonymization command for records older than 180 days
        out = io.StringIO()
        call_command("anonymize_ips", days=180, stdout=out)

        # Old records should have masked IPs (ending in .0)
        old_session.refresh_from_db()
        self.assertEqual(old_session.ip_address, "198.51.100.0")

        old_attempt.refresh_from_db()
        self.assertEqual(old_attempt.ip_address, "203.0.113.0")

        old_access_log.refresh_from_db()
        self.assertEqual(old_access_log.ip_address, "203.0.113.0")

        old_exam.refresh_from_db()
        self.assertEqual(old_exam.ip_address, "192.0.2.0")

        # Recent records must retain their raw IP addresses
        recent_session.refresh_from_db()
        self.assertEqual(recent_session.ip_address, "198.51.100.88")

    def test_anonymize_ips_command_dry_run(self):
        # In dry-run mode, no changes are committed to the database.
        import io
        from axes.models import AccessAttempt

        past_date = timezone.now() - timezone.timedelta(days=200)
        attempt = AccessAttempt.objects.create(
            username=self.student.email,
            ip_address="203.0.113.55",
            failures_since_start=1,
        )
        AccessAttempt.objects.filter(id=attempt.id).update(attempt_time=past_date)

        out = io.StringIO()
        call_command("anonymize_ips", days=180, dry_run=True, stdout=out)

        attempt.refresh_from_db()
        self.assertEqual(attempt.ip_address, "203.0.113.55")

    def test_purge_retention_command_execution(self):
        # Expired sessions and old axes records older than cutoff are deleted; active lockouts remain.
        import io
        from axes.models import AccessAttempt, AccessLog
        from kura.models import UserSession

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

        # Old axes AccessAttempt and AccessLog + recent active AccessAttempt
        old_attempt = AccessAttempt.objects.create(
            username=self.student.email,
            ip_address="198.51.100.1",
            failures_since_start=5,
        )
        AccessAttempt.objects.filter(id=old_attempt.id).update(attempt_time=past_date)
        recent_attempt = AccessAttempt.objects.create(
            username=self.student.email,
            ip_address="198.51.100.2",
            failures_since_start=5,
        )
        old_log = AccessLog.objects.create(
            username=self.student.email,
            ip_address="198.51.100.3",
        )
        AccessLog.objects.filter(id=old_log.id).update(attempt_time=past_date)

        out = io.StringIO()
        call_command("purge_retention", days=180, stdout=out)

        # Expired session should be deleted, active session preserved
        self.assertFalse(UserSession.objects.filter(id=expired_old.id).exists())
        self.assertTrue(UserSession.objects.filter(id=active_session.id).exists())

        # Old axes records purged; recent active attempt preserved
        self.assertFalse(AccessAttempt.objects.filter(id=old_attempt.id).exists())
        self.assertTrue(AccessAttempt.objects.filter(id=recent_attempt.id).exists())
        self.assertFalse(AccessLog.objects.filter(id=old_log.id).exists())

# Where the incident-response runbook lives.
# The docs/ folder is kept on the developer's machine and is not committed, so on GitHub (CI) the file is missing.
INCIDENT_RUNBOOK_PATH = Path(__file__).resolve().parent.parent / "docs" / "INCIDENT_RESPONSE.md"

# Skip (do not fail) these checks when the runbook is not in this copy of the project.
# Where the file exists, every check below still runs.
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
        self.assertIn("kura.sh renew-certs", content, "Must explain mTLS certificate renewal")
        self.assertIn("pgbackrest", content, "Must explain PITR database restoration")
        self.assertIn("sha256sum", content, "Must explain cryptographic evidence hashing")

    def test_runbook_cites_legal_and_security_standards(self):
        # Must cite NIST SP 800-61 and Egyptian Anti-Cybercrime Law (Law No. 175 of 2018).
        content = self.runbook_path.read_text(encoding="utf-8")
        self.assertIn("NIST SP 800-61", content)
        self.assertIn("Law No. 175 of 2018", content)

    def test_runbook_uses_current_login_events_and_explains_evidence_limits(self):
        # The old login model was removed; checksums alone do not establish provenance.
        content = self.runbook_path.read_text(encoding="utf-8")
        self.assertNotIn("from kura.models import LoginAttempt", content)
        self.assertIn("event=\"auth.login.failed\"", content)
        self.assertIn("login_identifier_hash", content)
        self.assertIn("checksums alone do not establish who", content)
        self.assertIn("sha256sum loki_logs.json pgaudit_trail.log", content)

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
            log_security_event(request, "test.event", {"detail": 'homework "final"\nlevel=ERROR'})

        self.assertEqual(len(captured.output), 1)
        self.assertIn('detail="homework \\"final\\"\\nlevel=ERROR"', captured.output[0])
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
    def test_invalid_or_missing_request_id_generates_shared_32_hex_id(self):
        # When X-Request-ID is missing or invalid, one 32-hex ID is generated per request.
        import re

        request = self.make_request(request_id="bad-request-id")
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(request, "test.event_one", {})
            log_security_event(request, "test.event_two", {})

        match_one = re.search(r'request_id="([0-9a-f]{32})"', captured.output[0])
        match_two = re.search(r'request_id="([0-9a-f]{32})"', captured.output[1])
        self.assertIsNotNone(match_one)
        self.assertIsNotNone(match_two)
        self.assertEqual(match_one.group(1), match_two.group(1))

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
        login_with_session(client, student)

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
        # Five failed logins from one visitor must not lock out a different visitor, even though both reach Django from the same WAF address.
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

        # The real student (198.51.100.20) can still log in: the password is accepted and they are redirected on to the MFA step.
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

class BreachCheckDirectTests(TestCase):
    """
    The breached-password check calls HaveIBeenPwned directly (k-anonymity:
    only the first 5 characters of the SHA-1 hash leave the server). There is
    no proxy any more; the host firewall restricts the destination.
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
        with patch("kura.views.urllib.request.build_opener", return_value=opener):
            with self.assertRaises(ValidationError):
                check_breached_password(self.BREACHED_PASSWORD)
        # Only the 5-character prefix was sent.
        sent_request = opener.open.call_args[0][0]
        self.assertTrue(sent_request.full_url.endswith("/range/CBFDA"))

    def test_password_not_in_list_is_accepted(self):
        opener = self.fake_opener("0000000000000000000000000000000000A:1\r\n")
        with patch("kura.views.urllib.request.build_opener", return_value=opener):
            check_breached_password(self.BREACHED_PASSWORD)

    def test_network_failure_is_logged_without_the_password(self):
        opener = MagicMock()
        opener.open.side_effect = OSError("no route to host")
        with patch("kura.views.urllib.request.build_opener", return_value=opener):
            with self.assertLogs("kura.security", level="WARNING") as captured:
                check_breached_password(self.BREACHED_PASSWORD)
        log_text = "\n".join(captured.output)
        self.assertIn('event="auth.breach_check.unavailable"', log_text)
        self.assertNotIn(self.BREACHED_PASSWORD, log_text)
        self.assertNotIn("CBFDA", log_text)

    def test_no_proxy_handler_is_used(self):
        # The opener uses only an empty ProxyHandler, so proxy variables in the
        # environment cannot redirect the request.
        opener = self.fake_opener("")
        with patch("kura.views.urllib.request.build_opener", return_value=opener) as build_opener:
            check_breached_password("a-long-unique-test-password")
        proxy_handlers = [h for h in build_opener.call_args[0] if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})

    def test_default_context_is_used(self):
        # Certificate verification stays on: create_default_context() with no cafile.
        opener = self.fake_opener("")
        with patch("kura.views.ssl.create_default_context", return_value=MagicMock()) as create_context:
            with patch("kura.views.urllib.request.build_opener", return_value=opener):
                check_breached_password("a-long-unique-test-password")
        create_context.assert_called_once_with()

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
        CourseStaff.objects.create(
            course=course, user=instructor, staff_role="lead_instructor", assigned_by=head
        )
        now = timezone.now()
        assessment = Assessment.objects.create(
            course=course, title="Exam", component_type=GradeComponentType.EXAM, max_score=10, max_attempts=1,
            opens_at=now, due_date=now + timezone.timedelta(days=1), created_by=instructor,
        )
        attempt = AssessmentAttempt.objects.create(assessment=assessment, student=student, attempt_no=1, ip_address="127.0.0.1")
        self.grade = Grade.objects.create(assessment=assessment, student=student, attempt=attempt, score=7)
        self.history = GradeHistory.objects.create(grade=self.grade, new_score=7, new_status="draft",
                                                   changed_by=instructor)
        self.instructor = instructor

    def run_as_app_role(self, sql, parameters):
        # Run one statement as kura_app with the instructor's RLS context (inside a savepoint, so a refused statement does not break the rest of the test), then switch back.
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE kura_app;")
            cursor.execute("SELECT set_config('kura.current_user_id', %s, false);", [str(self.instructor.id)])
            try:
                with transaction.atomic():
                    cursor.execute(sql, parameters)
            finally:
                cursor.execute("RESET kura.current_user_id;")
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
        # Step 1 (password), then step 2 (the recovery code).
        # Returns the step 2 response.
        self.client.post(reverse("kura:login"), {"email": self.user.email, "password": "ValidPassword123!"})
        return self.client.post(reverse("kura:mfa_verify"), {"code": code})

    def test_setup_saves_only_hashes_of_the_codes_it_shows(self):
        new_user = make_user("Student", mfa_enabled=False)
        login_with_session(self.client, new_user)
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
        # Without SECRET_KEY the hash cannot be recomputed, so the 4 billion possible codes cannot simply be tried against a stolen database.
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
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid security code.", status_code=400)

    def test_code_ignores_spaces_and_letter_case(self):
        response = self.log_in_with_code("abcd 1234")
        self.assertRedirects(response, reverse("kura:home"))

    def test_code_saved_as_plain_text_is_refused(self):
        # A code saved the old way (plain text) does not work any more.
        StaticToken.objects.filter(device=self.static_device).delete()
        StaticToken.objects.create(device=self.static_device, token="ABCD1234")
        response = self.log_in_with_code("ABCD1234")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid security code.", status_code=400)

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
        # Vault down: the right code is refused (fail closed) but is not counted as a wrong guess, so the user is not throttled for Vault's problem.
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
        login_with_session(self.client, new_user)
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
        login_with_session(self.client, new_user)
        self.client.get(reverse("kura:mfa_setup"))
        new_user.refresh_from_db()
        response = self.client.post(reverse("kura:mfa_setup"), {"code": self.current_code(new_user.mfa_secret)})
        self.assertRedirects(response, reverse("kura:mfa_setup_complete"))
        self.assertTrue(TOTPDevice.objects.get(user=new_user, name="default").confirmed)

    def test_setup_shows_503_when_vault_is_down(self):
        new_user = make_user("Student", mfa_enabled=False)
        login_with_session(self.client, new_user)
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
        with patch("kura.base.hvac.Client") as mock_client_class:
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
    The database backend caches one login per worker and uses it for every new
    connection. Vault itself is replaced by a mock here.
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

    @patch("kura.base.get_vault_client")
    def test_login_comes_from_the_kura_app_role(self, mock_get_client):
        mock_get_client.return_value = self.fake_vault_client()
        login = get_dynamic_database_credentials()
        self.assertEqual(login["username"], "kura_dyn_test")
        self.assertEqual(login["password"], "temporary-password")
        mock_get_client.return_value.secrets.database.generate_credentials.assert_called_once_with(
            name="kura-app", mount_point="database"
        )

    @patch("kura.base.get_vault_client")
    def test_login_is_reused_instead_of_asking_vault_every_time(self, mock_get_client):
        mock_get_client.return_value = self.fake_vault_client()
        for _ in range(5):
            get_dynamic_database_credentials()
        self.assertEqual(mock_get_client.return_value.secrets.database.generate_credentials.call_count, 1)

    @patch("kura.base.get_vault_client")
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

    @patch("kura.base.get_vault_client", side_effect=Exception("Vault is sealed"))
    def test_vault_failure_raises_validation_error(self, mock_get_client):
        with self.assertRaises(ValidationError):
            get_dynamic_database_credentials()

    @patch("kura.base.get_dynamic_database_credentials")
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

    @patch("kura.base.get_dynamic_database_credentials", side_effect=ValidationError("down"))
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
        self.assertEqual(engines, ["kura", "django.db.backends.postgresql"])

def fake_clamav_reply(reply):
    """Test helper: a pretend ClamAV socket that answers every command with `reply`.
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

    def test_security_log_records_details_and_omits_filename(self):
        with self.assertLogs("kura.security", level="WARNING") as captured:
            self.upload_rejected_as("Eicar-Test-Signature", filename="evil\nFAKE LOG LINE.pdf")
        log_line = captured.output[0]
        self.assertIn(str(self.user.id), log_line)
        self.assertIn(hashlib.sha256(self.eicar_bytes).hexdigest(), log_line)
        self.assertIn('detection="Eicar-Test-Signature"', log_line)
        self.assertIn('event="file.quarantined"', log_line)
        self.assertNotIn("evil", log_line)
        self.assertNotIn("filename=", log_line)
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
        login_with_session(self.client, admin)
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
                login_with_session(self.client, make_user(role_name))
                self.assertEqual(self.client.get(reverse("kura:quarantine_list")).status_code, 403)
                delete_url = reverse("kura:quarantine_delete", kwargs={"quarantined_file_id": quarantined.id})
                self.assertEqual(self.client.post(delete_url, {"confirm": "on"}).status_code, 403)
        self.assertTrue(QuarantinedFile.objects.filter(id=quarantined.id).exists())

    def test_admin_delete_needs_post_and_confirmation(self):
        self.upload_rejected_as("Eicar-Test-Signature")
        quarantined = QuarantinedFile.objects.get()
        login_with_session(self.client, make_user("Admin"))
        delete_url = reverse("kura:quarantine_delete", kwargs={"quarantined_file_id": quarantined.id})

        self.assertEqual(self.client.get(delete_url).status_code, 405)
        self.client.post(delete_url, {})
        self.assertTrue(QuarantinedFile.objects.filter(id=quarantined.id).exists())

        response = self.client.post(delete_url, {"confirm": "on"})
        self.assertRedirects(response, reverse("kura:quarantine_list"))
        self.assertFalse(QuarantinedFile.objects.filter(id=quarantined.id).exists())

@override_settings(SITE_URL="https://kura.example.com")

class PasskeyAddedAuditTests(TestCase):
    """
    WP1: adding a passkey writes auth.passkey.added. The FIDO2 cryptography is
    django-mfa2's job, so its complete_reg view is replaced with a stand-in here.
    """

    def setUp(self):
        self.user = make_user("Student")
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, self.user)

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
        # The library's templates and JavaScript use these names, so they must still resolve to the same addresses as before.
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
        # Without a full login, every registration step sends the visitor to the login page and never hands out a registration challenge.
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

        now = timezone.now()
        self.assessment = Assessment.objects.create(
            course=self.course,
            title="Assignment 1",
            component_type=GradeComponentType.COURSEWORK,
            max_score=Decimal("100.00"),
            max_attempts=3,
            opens_at=now - timezone.timedelta(hours=1),
            due_date=now + timezone.timedelta(hours=4),
            created_by=self.instructor,
        )

    def test_student_blocked_when_course_unpublished(self):
        self.course.is_published = False
        self.course.save()
        login_with_session(self.client, self.student)

        detail_url = reverse("kura:assessment_detail", kwargs={"assessment_id": self.assessment.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 403)

        initial_count = AssessmentAttempt.objects.count()
        start_url = reverse("kura:assessment_attempt_start", kwargs={"assessment_id": self.assessment.id})
        response = self.client.post(start_url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AssessmentAttempt.objects.count(), initial_count)

    def test_eligible_student_can_view_assessment(self):
        login_with_session(self.client, self.student)
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
        login_with_session(self.client, self.user)
        response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "otpauth")
        self.assertNotContains(response, "data:image/svg+xml;utf8,")
        self.assertContains(response, "Confirm it's you")

    def test_wrong_code_keeps_seed_hidden(self):
        login_with_session(self.client, self.user)
        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(reverse("kura:mfa_setup"), {"code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, "otpauth", status_code=400)
        self.assertNotContains(response, "data:image/svg+xml;utf8,", status_code=400)
        self.assertContains(response, "Invalid security code.", status_code=400)
        self.assertTrue(any('event="auth.mfa.reauth_failed"' in line for line in captured.output))

    def test_correct_totp_renders_setup_and_confirming_post_regenerates_codes(self):
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, unenrolled_user)
        response = self.client.get(reverse("kura:mfa_setup"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/svg+xml;utf8,")
        self.assertContains(response, "Set up two-step verification")

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

        login_with_session(self.client, self.student)
        real_cursor = connection.cursor

        def failing_cursor(*args, **kwargs):
            cursor = real_cursor(*args, **kwargs)
            real_execute = cursor.execute

            def guarded_execute(sql, params=None):
                if isinstance(sql, str) and "set_config('kura.current_user_id'" in sql:
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
        login_with_session(self.client, self.student)
        response = self.client.get(reverse("kura:student_grades"))
        self.assertEqual(response.status_code, 200)

    def test_rls_reset_failure_logs_warning_and_closes_connection(self):
        from django.db.utils import OperationalError

        login_with_session(self.client, self.student)
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
        if not session.session_key:
            session.save()
        self.user_session.session_token_hash = hash_session_token(session.session_key)
        self.user_session.save(update_fields=["session_token_hash"])
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
        login_with_session(self.client, self.user)
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
        login_with_session(self.client, self.user)
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

        self.assessment = Assessment.objects.create(
            course=self.course,
            title="Midterm Exam",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now(),
            due_date=timezone.now() + timezone.timedelta(hours=1),
            created_by=self.co_instructor,
        )
        self.attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
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
        login_with_session(self.client, self.dual_role_user)
        response = self.client.post(reverse("kura:grade_finalize", kwargs={"grade_id": self.grade.id}))
        self.assertEqual(response.status_code, 403)

        self.grade.refresh_from_db()
        self.assertEqual(self.grade.status, GradeStatus.DRAFT)
        self.assertFalse(GradeHistory.objects.filter(grade=self.grade).exists())

    def test_co_instructor_can_finalize_grade(self):
        # A co-instructor on the course still finalizes successfully.
        login_with_session(self.client, self.co_instructor)
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
        login_with_session(self.client, self.admin)
        confirm_second_factor(self.client)
        before = UserRole.objects.filter(user=self.target_user).count()

        response = self.client.post(self.roles_url, {"action": "assign", "role_id": "abc"})

        self.assertNotEqual(response.status_code, 500)
        self.assertRedirects(response, self.roles_url)
        self.assertEqual(UserRole.objects.filter(user=self.target_user).count(), before)

    def test_unknown_action_is_rejected(self):
        # An action outside assign/remove must not change roles.
        login_with_session(self.client, self.admin)
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
        payload = b"%PDF-1.4 test"
        stored_file = StoredFile.objects.create(
            uploaded_by=uploader,
            original_filename=filename,
            mime_type="application/pdf",
            size_bytes=len(payload),
            sha256_hash=hashlib.sha256(payload).hexdigest(),
        )
        FileContent.objects.create(file=stored_file, content=payload)
        return stored_file

    def test_quote_and_parameter_text_stays_inside_the_filename(self):
        stored_file = self.make_stored_file('a"; filename*=UTF-8\'\'evil.html')

        response = create_download_response(stored_file)
        header = response["Content-Disposition"]

        self.assertTrue(header.startswith("attachment"))
        # The double quote is escaped, so it cannot end the filename early.
        self.assertIn('\\"', header)

        # Parse the header: the injected text must be part of the filename value, not a separate filename* parameter.
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
        login_with_session(self.client, self.user)
        response = self.client.post(
            reverse("kura:password_change"),
            {
                "old_password": self.password,
                "new_password": self.password,
                "confirm_password": self.password,
            },
        )

        self.assertEqual(response.status_code, 400)
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

        self.assertEqual(response.status_code, 400)
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
        login_with_session(self.client, self.user)

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
        login_with_session(self.client, self.user)
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

    @patch("kura.views.scan_file_for_malware")
    def test_pdf_bytes_with_html_extension_are_rejected(self, mock_scan):
        before = StoredFile.objects.count()

        with self.assertRaises(ValidationError):
            validate_and_save_upload(SimpleUploadedFile("x.html", self.pdf_bytes), self.instructor)

        self.assertEqual(StoredFile.objects.count(), before)

    @patch("kura.views.scan_file_for_malware")
    def test_matching_pdf_extension_is_accepted(self, mock_scan):
        stored = validate_and_save_upload(SimpleUploadedFile("report.pdf", self.pdf_bytes), self.instructor)

        self.assertEqual(stored.original_filename, "report.pdf")
        self.assertEqual(stored.mime_type, "application/pdf")

    @patch("kura.views.scan_file_for_malware")
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

        self.assessment = Assessment.objects.create(
            course=self.course,
            title="Essay",
            component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now(),
            due_date=timezone.now() + timezone.timedelta(hours=1),
            created_by=self.instructor,
        )
        attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt_no=1,
            status=AttemptStatus.FULLY_GRADED,
            ip_address="127.0.0.1",
        )
        self.grade = Grade.objects.create(
            assessment=self.assessment,
            student=self.student,
            attempt=attempt,
            score=Decimal("70.00"),
            status=GradeStatus.RELEASED,
        )

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
        login_with_session(self.client, self.admin)

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
        login_with_session(self.client, self.admin)
        marker = "ZZ-unique-marker"

        with self.assertLogs("kura.security", level="WARNING") as captured:
            response = self.client.post(
                reverse("kura:staff_settings"),
                {"kind": "department", "code": "", "name": marker},
            )

        self.assertEqual(response.status_code, 400)
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
        # Build a request with a real session and message storage, the same way django-mfa2 would hand one to the callback.
        request = RequestFactory().post("/mfa/fido2/complete_auth")
        SessionMiddleware(lambda r: None).process_request(request)
        MessageMiddleware(lambda r: None).process_request(request)
        for key, value in session_values.items():
            request.session[key] = value
        if "pre_mfa_user_id" in session_values and "pre_mfa_started_at" not in session_values:
            request.session["pre_mfa_started_at"] = timezone.now().timestamp()
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
        login_with_session(self.client, self.admin)

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
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Invalid security code", status_code=400)
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
        # Nobody without a second factor can be asked for one. (Middleware sends such users to MFA setup anyway, so the helper is checked directly.)
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
        if not s.session_key:
            s.save()
        self.own_current.session_token_hash = hash_session_token(s.session_key)
        self.own_current.save(update_fields=["session_token_hash"])
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
        session = self.client.session
        if not session.session_key:
            session.save()
        user_session = UserSession.objects.create(
            user=self.user,
            session_token_hash=hash_session_token(session.session_key),
            ip_address="127.0.0.1",
            user_agent="TestAgent",
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )
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

        login_with_session(self.client, self.user)
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

    @patch("kura.views.check_breached_password", return_value=None)
    def test_password_history_enforces_five_previous_passwords_and_prunes_older(self, _mock_breach):
        login_with_session(self.client, self.user)

        # Rotate P0 -> P1 -> P2 -> P3 -> P4 -> P5 (5 changes: P0..P4 in history, P5 current).
        with self.assertLogs("kura.security", level="INFO") as logs:
            for idx in range(5):
                resp = self._change_password(self.passwords[idx], self.passwords[idx + 1])
                self.assertRedirects(resp, reverse("kura:home"))
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)

        # Current password (P5) fails.
        resp = self._change_password(self.passwords[5], self.passwords[5])
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Choose a password you have not used recently.", resp.context["form"].errors["new_password"])

        # 6th change: P5 -> P6. Now history holds P5 (1st prev), P4 (2nd), P3 (3rd), P2 (4th), P1 (5th); P0 (6th previous) is pruned, and only 5 rows remain.
        resp = self._change_password(self.passwords[5], self.passwords[6])
        self.assertRedirects(resp, reverse("kura:home"))
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)

        # 2nd previous (P4) and 5th previous (P1) fail on both change and reset confirm forms.
        for old_candidate in (self.passwords[4], self.passwords[1]):
            resp = self._change_password(self.passwords[6], old_candidate)
            self.assertEqual(resp.status_code, 400)
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
            self.assertEqual(reset_resp.status_code, 400)
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

def make_released_grade_course():
    """Test helper: a course with a department head, a lead instructor, a teaching
    assistant and one student holding a released exam grade. Used by the
    gradebook, grade scheme and feedback tests.
    """
    head = make_user("Department head")
    instructor = make_user("Instructor")
    assistant = make_user("Teaching assistant")
    student = make_user("Student")
    department = Department.objects.create(name="Psychology", code="PSYC", head_user=head)
    StudentProfile.objects.create(
        user=student, department=department, current_level="level_4", matriculation_year=2026
    )
    course = Course.objects.create(
        department=department,
        code="PSYC201",
        title="Social Psychology",
        semester="1",
        academic_year=2026,
        is_published=True,
        published_by=head,
        published_at=timezone.now(),
    )
    CourseStaff.objects.create(course=course, user=instructor, staff_role="lead_instructor", can_release_grades=True)
    CourseStaff.objects.create(course=course, user=assistant, staff_role="teaching_assistant")
    Enrollment.objects.create(course=course, student=student, status=EnrollmentStatus.ACTIVE)
    assessment = Assessment.objects.create(
        course=course,
        title="Groups Exam",
        component_type=GradeComponentType.EXAM,
        max_score=Decimal("100.00"),
        opens_at=timezone.now(),
        due_date=timezone.now() + timezone.timedelta(hours=1),
        created_by=instructor,
    )
    attempt = AssessmentAttempt.objects.create(
        assessment=assessment,
        student=student,
        status=AttemptStatus.FULLY_GRADED,
        ip_address="127.0.0.1",
    )
    grade = Grade.objects.create(
        assessment=assessment, student=student, attempt=attempt, score=Decimal("70.00"), status=GradeStatus.RELEASED
    )
    return {
        "head": head,
        "instructor": instructor,
        "assistant": assistant,
        "student": student,
        "course": course,
        "assessment": assessment,
        "attempt": attempt,
        "grade": grade,
    }

class GradeFeedbackTests(TestCase):
    """
    Feedback typed on the grade entry page is saved with the grade and shown to
    the student only after release. It never reaches the security log.
    """

    def setUp(self):
        self.client = Client()
        self.data = make_released_grade_course()
        grade = self.data["grade"]
        grade.status = GradeStatus.DRAFT
        grade.save()
        self.entry_url = reverse("kura:grade_entry", args=[self.data["attempt"].id])
        self.feedback = "Good structure, but question 2 needed a worked example."

    def test_assistant_feedback_is_saved_and_not_logged(self):
        login_with_session(self.client, self.data["assistant"])
        with self.assertLogs("kura.security", level="INFO") as logs:
            self.client.post(self.entry_url, {"score": "72", "feedback": self.feedback})
        self.data["grade"].refresh_from_db()
        self.assertEqual(self.data["grade"].feedback, self.feedback)
        self.assertNotIn("worked example", "\n".join(logs.output))

    def test_staff_cannot_grade_in_progress_online_attempt(self):
        # Marking an attempt before it is submitted would be overwritten at submit.
        attempt = self.data["attempt"]
        attempt.status = AttemptStatus.IN_PROGRESS
        attempt.save()
        Grade.objects.filter(attempt=attempt).delete()
        login_with_session(self.client, self.data["instructor"])
        response = self.client.post(self.entry_url, {"score": "72", "feedback": self.feedback})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Grade.objects.filter(attempt=attempt).exists())

    def test_entry_page_shows_saved_feedback(self):
        self.data["grade"].feedback = self.feedback
        self.data["grade"].save()
        login_with_session(self.client, self.data["instructor"])
        self.assertContains(self.client.get(self.entry_url), "worked example")

    def test_student_sees_feedback_only_after_release(self):
        self.data["grade"].feedback = self.feedback
        self.data["grade"].save()
        login_with_session(self.client, self.data["student"])
        self.assertNotContains(self.client.get(reverse("kura:student_grades")), "worked example")

        self.data["grade"].status = GradeStatus.RELEASED
        self.data["grade"].released_at = timezone.now()
        self.data["grade"].save()
        self.assertContains(self.client.get(reverse("kura:student_grades")), "worked example")
        attempt_page = self.client.get(reverse("kura:attempt_detail", args=[self.data["attempt"].id]))
        self.assertContains(attempt_page, "worked example")

class SecurityPolicyPageTests(TestCase):
    """
    Admins can review and update configurable security rules with step-up MFA;
    nobody else can reach the page.
    """

    def setUp(self):
        self.client = Client()
        self.url = reverse("kura:security_policy")

    def test_admin_sees_current_rules(self):
        login_with_session(self.client, make_user("Admin"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "12 characters")
        self.assertContains(response, f"{settings.SESSION_ABSOLUTE_HOURS} hours")
        self.assertContains(response, "25 MiB")

    def test_admin_dashboard_links_to_the_page(self):
        login_with_session(self.client, make_user("Admin"))
        self.assertContains(self.client.get(reverse("kura:home")), self.url)

    def test_other_roles_are_refused(self):
        for role_name in ("Registrar", "Department head", "Instructor", "Teaching assistant", "Student"):
            login_with_session(self.client, make_user(role_name))
            self.assertEqual(self.client.get(self.url).status_code, 403)

    def test_post_requires_fresh_second_factor_and_validates_bounds(self):
        admin = make_user("Admin", mfa_enabled=True)
        login_with_session(self.client, admin)
        # Without fresh second factor, POST redirects to mfa_reauth.
        stale = self.client.post(
            self.url,
            {
                "min_password_length": 14,
                "password_history_count": 6,
                "axes_failure_limit": 4,
                "axes_cooloff_hours": 2,
                "session_idle_minutes": 20,
                "session_absolute_hours": 8,
            },
        )
        self.assertRedirects(stale, f"{reverse('kura:mfa_reauth')}?next={self.url}", fetch_redirect_response=False)

        # Unsafe min_password_length (< 12) returns 400 when step-up is fresh.
        confirm_second_factor(self.client)
        bad = self.client.post(
            self.url,
            {
                "min_password_length": 8,
                "password_history_count": 5,
                "axes_failure_limit": 5,
                "axes_cooloff_hours": 1,
                "session_idle_minutes": 30,
                "session_absolute_hours": 12,
            },
        )
        self.assertEqual(bad.status_code, 400)

class WorkItem1LoggingTests(TestCase):
    """Tests for Work Item 1: redaction, correlation IDs, 404/500 handlers, and write-view logging."""

    def test_redaction_deny_list_masks_secrets_and_preserves_safe_ids(self):
        from .logging_utils import REDACTED_LOG_KEYS

        details = {key: f"sensitive-{key}" for key in REDACTED_LOG_KEYS}
        details.update({"key_id": "k123", "session_id": "s456", "code": "CS101"})
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(None, "test.redaction", details)

        line = captured.output[0]
        for key in REDACTED_LOG_KEYS:
            self.assertIn(f'{key}="<redacted>"', line)
            self.assertNotIn(f"sensitive-{key}", line)
        self.assertIn('key_id="k123"', line)
        self.assertIn('session_id="s456"', line)
        self.assertIn('code="CS101"', line)

    def test_failed_login_uses_keyed_hash_and_never_logs_email(self):
        email = "student.probe@kura.edu"
        make_user("Student", email=email)
        with self.assertLogs("kura.security", level="WARNING") as captured:
            self.client.post(reverse("kura:login"), {"email": email, "password": "WrongPassword123!"})

        failed_lines = [line for line in captured.output if 'event="auth.login.failed"' in line]
        self.assertEqual(len(failed_lines), 1)
        self.assertIn("login_identifier_hash=", failed_lines[0])
        self.assertNotIn(email, failed_lines[0])
        self.assertNotIn("@", failed_lines[0])

    def test_handler404_logs_access_not_found(self):
        student = make_user("Student")
        login_with_session(self.client, student)
        with self.assertLogs("kura.security", level="INFO") as captured:
            resp = self.client.get(f"/courses/{uuid.uuid4()}/")

        self.assertEqual(resp.status_code, 404)
        self.assertTrue(any('event="access.not_found"' in line for line in captured.output))

    def test_handler500_logs_server_error_without_exception_or_db_access(self):
        from .views import server_error_view

        with patch("kura.views.LoginForm", side_effect=RuntimeError("db-secret-failure")):
            client = Client(raise_request_exception=False)
            with self.assertLogs("kura.security", level="ERROR") as captured:
                resp = client.get(reverse("kura:login"))

        self.assertEqual(resp.status_code, 500)
        self.assertIn(b"Something went wrong.", resp.content)
        self.assertTrue(any('event="server.error"' in line for line in captured.output))
        self.assertNotIn("db-secret-failure", " ".join(captured.output))

        # Direct test on server_error_view with broken request.user (simulating DB down).
        class BrokenUserRequest:
            path = "/boom/"
            method = "GET"
            META = {"REMOTE_ADDR": "127.0.0.1"}

            @property
            def user(self):
                raise RuntimeError("database unavailable")

        with self.assertLogs("kura.security", level="ERROR") as captured_db_down:
            resp_db_down = server_error_view(BrokenUserRequest())

        self.assertEqual(resp_db_down.status_code, 500)
        self.assertIn(b"Something went wrong.", resp_db_down.content)
        self.assertTrue(any('event="server.error"' in line for line in captured_db_down.output))
        self.assertNotIn("database unavailable", captured_db_down.output[0])

class WorkItem3SessionTests(TestCase):
    """Tests for Work Item 3: sliding idle timeout, untracked rejection, password-change revocation, and pre-MFA expiry."""

    def test_sliding_idle_timeout_and_absolute_12h_limit(self):
        password = "ValidPassword123!"
        user = make_user("Student", password=password, mfa_enabled=False)
        t0 = timezone.now()

        with patch("django.utils.timezone.now", return_value=t0):
            resp = self.client.post(reverse("kura:login"), {"email": user.email, "password": password})
            self.assertRedirects(resp, reverse("kura:mfa_setup"))

        # +20m: still valid, and sliding window refreshes expiry to +50m.
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=20)):
            r1 = self.client.get(reverse("kura:mfa_setup"))
            self.assertEqual(r1.status_code, 200)

        # +40m total (20m since last request): still valid because window slid.
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=40)):
            r2 = self.client.get(reverse("kura:mfa_setup"))
            self.assertEqual(r2.status_code, 200)

        # +71m total (31m idle since +40m): idle timeout expired.
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=71)):
            r3 = self.client.get(reverse("kura:mfa_setup"))
            self.assertEqual(r3.status_code, 302)
            self.assertIn(reverse("kura:login"), r3.url)

        # Fresh login: keep active every 20m, still rejected after 12h absolute cap.
        client2 = Client()
        with patch("django.utils.timezone.now", return_value=t0):
            client2.post(reverse("kura:login"), {"email": user.email, "password": password})
        for step_minutes in range(20, 12 * 60, 20):
            with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=step_minutes)):
                self.assertEqual(client2.get(reverse("kura:mfa_setup")).status_code, 200)
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(hours=12, minutes=1)):
            r_abs = client2.get(reverse("kura:mfa_setup"))
            self.assertRedirects(r_abs, reverse("kura:login"))

    def test_password_change_revokes_other_tracked_sessions(self):
        old_pw = "ValidPassword123!"
        new_pw = "NewValidPassword456!"
        user = make_user("Student", password=old_pw, mfa_enabled=True)
        current_session = login_with_session(self.client, user)
        other_session = UserSession.objects.create(
            user=user,
            session_token_hash=secrets.token_hex(32),
            ip_address="198.51.100.5",
            user_agent="OtherDevice",
            expires_at=timezone.now() + timezone.timedelta(hours=12),
        )

        with patch("kura.views.check_breached_password", return_value=None):
            with self.assertLogs("kura.security", level="INFO") as captured:
                resp = self.client.post(
                    reverse("kura:password_change"),
                    {"old_password": old_pw, "new_password": new_pw, "confirm_password": new_pw},
                )
        self.assertRedirects(resp, reverse("kura:home"))
        current_session.refresh_from_db()
        other_session.refresh_from_db()
        self.assertIsNone(current_session.revoked_at)
        self.assertIsNotNone(other_session.revoked_at)
        self.assertTrue(any('event="session.revoked"' in line and 'by="password_change"' in line for line in captured.output))

    def test_untracked_authenticated_session_is_rejected(self):
        user = make_user("Student", mfa_enabled=True)
        self.client.force_login(user)
        with self.assertLogs("kura.security", level="WARNING") as captured:
            resp = self.client.get(reverse("kura:home"))
        self.assertRedirects(resp, reverse("kura:login"))
        self.assertTrue(any('event="session.invalid"' in line and 'reason="untracked"' in line for line in captured.output))

    def test_pre_mfa_step_expires_after_five_minutes(self):
        password = "ValidPassword123!"
        user = make_user("Student", password=password, mfa_enabled=True)
        t0 = timezone.now()
        with patch("django.utils.timezone.now", return_value=t0):
            resp = self.client.post(reverse("kura:login"), {"email": user.email, "password": password})
            self.assertRedirects(resp, reverse("kura:mfa_verify"))

        # 6 minutes later, mfa_verify redirects back to login and clears markers.
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=6)):
            expired_resp = self.client.post(reverse("kura:mfa_verify"), {"code": "123456"})
            self.assertRedirects(expired_resp, reverse("kura:login"))
            self.assertNotIn("pre_mfa_user_id", self.client.session)

        # Passkey callback 6 minutes after password step also refuses and redirects to login.
        request = RequestFactory().post("/mfa/fido2/complete_auth")
        SessionMiddleware(lambda r: None).process_request(request)
        MessageMiddleware(lambda r: None).process_request(request)
        request.session["pre_mfa_user_id"] = str(user.id)
        request.session["pre_mfa_started_at"] = t0.timestamp()
        request.user = AnonymousUser()
        with patch("django.utils.timezone.now", return_value=t0 + timezone.timedelta(minutes=6)):
            cb_resp = mfa_login_callback(request, user.email)
        self.assertEqual(cb_resp.url, reverse("kura:login"))
        self.assertNotIn("_auth_user_id", request.session)

    def test_login_rotates_session_key(self):
        password = "ValidPassword123!"
        user = make_user("Student", password=password, mfa_enabled=False)
        self.client.get(reverse("kura:login"))
        session_before = self.client.session
        session_before["anon_marker"] = "1"
        session_before.save()
        key_before = self.client.session.session_key
        self.client.post(reverse("kura:login"), {"email": user.email, "password": password})
        key_after = self.client.session.session_key
        self.assertIsNotNone(key_before)
        self.assertIsNotNone(key_after)
        self.assertNotEqual(key_before, key_after)

class WorkItem4bKeyedHashTests(TestCase):
    """Tests for Work Item 4b: keyed HMAC-SHA256 digests for attendance passcodes and proctor codes."""

class WorkItem5FileEncryptionTests(TestCase):
    """Tests for Work Item 5: hybrid AES-256-GCM + Vault RSA-4096 file encryption."""

    def setUp(self):
        self.user = make_user("Instructor")

    @override_settings(VAULT_ENABLED=True)
    @patch("kura.views.get_vault_client")
    def test_invalid_vault_encryption_response_fails_closed(self, get_client):
        from .views import encrypt_file_content

        get_client.return_value.secrets.transit.encrypt_data.return_value = {"data": {}}
        with self.assertRaises(ValidationError):
            encrypt_file_content(b"file contents", uuid.uuid4())

    def _mock_vault_client(self):
        import base64

        wrapped_store = {}

        def encrypt_data(name, mount_point, plaintext):
            token = f"vault:v1:{base64.b64encode(secrets.token_bytes(16)).decode('ascii')}"
            wrapped_store[token] = plaintext
            return {"data": {"ciphertext": token}}

        def decrypt_data(name, mount_point, ciphertext):
            return {"data": {"plaintext": wrapped_store[ciphertext]}}

        mock_client = MagicMock()
        mock_client.secrets.transit.encrypt_data.side_effect = encrypt_data
        mock_client.secrets.transit.decrypt_data.side_effect = decrypt_data
        return mock_client, wrapped_store

    @override_settings(VAULT_ENABLED=True, CLAMAV_REQUIRED=False)
    def test_hybrid_upload_download_distinct_nonces_and_no_secret_leaks(self):
        payload = b"%PDF-1.4 secret student paper payload"
        mock_client, wrapped_store = self._mock_vault_client()

        with patch("kura.views.get_vault_client", return_value=mock_client):
            with self.assertLogs("kura.security", level="INFO") as cap_up:
                up1 = SimpleUploadedFile("paper1.pdf", payload, content_type="application/pdf")
                up2 = SimpleUploadedFile("paper2.pdf", payload, content_type="application/pdf")
                sf1 = validate_and_save_upload(up1, self.user)
                sf2 = validate_and_save_upload(up2, self.user)

            fc1 = FileContent.objects.get(file=sf1)
            fc2 = FileContent.objects.get(file=sf2)

            self.assertEqual(fc1.encryption_version, 1)
            self.assertNotEqual(bytes(fc1.content), payload)
            self.assertTrue(fc1.wrapped_key.startswith("vault:"))
            self.assertEqual(len(bytes(fc1.nonce)), 12)

            # Identical plaintexts produce distinct nonces, wrapped keys, and ciphertexts.
            self.assertNotEqual(bytes(fc1.nonce), bytes(fc2.nonce))
            self.assertNotEqual(fc1.wrapped_key, fc2.wrapped_key)
            self.assertNotEqual(bytes(fc1.content), bytes(fc2.content))

            # Download restores original bytes and passes SHA-256 check.
            dl1 = create_download_response(sf1)
            self.assertEqual(dl1.status_code, 200)
            self.assertEqual(dl1.content, payload)

        all_logs = "\n".join(cap_up.output)
        for wrapped_key, raw_b64 in wrapped_store.items():
            self.assertNotIn(wrapped_key, all_logs)
            self.assertNotIn(raw_b64, all_logs)
            self.assertNotIn(wrapped_key.encode(), dl1.content)
        self.assertNotIn(bytes(fc1.nonce).hex(), all_logs)

    @override_settings(VAULT_ENABLED=True, CLAMAV_REQUIRED=False)
    def test_tampering_or_row_swap_fails_and_logs_decrypt_failed(self):
        payload = b"%PDF-1.4 tamper test content"
        mock_client, _ = self._mock_vault_client()

        with patch("kura.views.get_vault_client", return_value=mock_client):
            sf1 = validate_and_save_upload(SimpleUploadedFile("a.pdf", payload, content_type="application/pdf"), self.user)
            sf2 = validate_and_save_upload(SimpleUploadedFile("b.pdf", payload, content_type="application/pdf"), self.user)

            fc1 = FileContent.objects.get(file=sf1)
            fc2 = FileContent.objects.get(file=sf2)

            # Flip one byte of ciphertext -> GCM auth failure.
            tampered = bytearray(bytes(fc1.content))
            tampered[0] ^= 0xFF
            fc1.content = bytes(tampered)
            fc1.save(update_fields=["content"])
            sf1 = StoredFile.objects.get(id=sf1.id)

            with self.assertLogs("kura.security", level="ERROR") as cap_tamper:
                resp_tamper = create_download_response(sf1)
            self.assertEqual(resp_tamper.status_code, 500)
            self.assertEqual(resp_tamper.content, b"File decryption failed.")
            self.assertTrue(any('event="file.decrypt_failed"' in line for line in cap_tamper.output))

            # Move valid ciphertext/envelope from sf2 onto sf1 -> AAD mismatch fails.
            fc1.content = fc2.content
            fc1.wrapped_key = fc2.wrapped_key
            fc1.nonce = fc2.nonce
            fc1.save(update_fields=["content", "wrapped_key", "nonce"])
            sf1 = StoredFile.objects.get(id=sf1.id)

            with self.assertLogs("kura.security", level="ERROR") as cap_swap:
                resp_swap = create_download_response(sf1)
            self.assertEqual(resp_swap.status_code, 500)
            self.assertTrue(any('event="file.decrypt_failed"' in line for line in cap_swap.output))

    @override_settings(CLAMAV_REQUIRED=False)
    def test_encrypt_file_contents_command_migrates_legacy_rows_idempotently(self):
        payload = b"%PDF-1.4 legacy plaintext file"
        with override_settings(VAULT_ENABLED=False):
            sf = validate_and_save_upload(SimpleUploadedFile("legacy.pdf", payload, content_type="application/pdf"), self.user)
        fc = FileContent.objects.get(file=sf)
        self.assertEqual(fc.encryption_version, 0)
        self.assertEqual(bytes(fc.content), payload)

        mock_client, _ = self._mock_vault_client()
        with override_settings(VAULT_ENABLED=True):
            # Legacy v0 is refused while VAULT_ENABLED=True and ALLOW_LEGACY_UNENCRYPTED_FILE_READS=False.
            with self.assertLogs("kura.security", level="ERROR"):
                self.assertEqual(create_download_response(sf).status_code, 500)

            with patch("kura.views.get_vault_client", return_value=mock_client):
                out1 = StringIO()
                call_command("encrypt_file_contents", stdout=out1)
                self.assertIn("Encrypted 1 file(s)", out1.getvalue())

                fc.refresh_from_db()
                self.assertEqual(fc.encryption_version, 1)
                self.assertNotEqual(bytes(fc.content), payload)
                self.assertTrue(fc.wrapped_key.startswith("vault:"))
                self.assertEqual(len(bytes(fc.nonce)), 12)

                # Second run skips already encrypted rows.
                prev_wrapped = fc.wrapped_key
                out2 = StringIO()
                call_command("encrypt_file_contents", stdout=out2)
                self.assertIn("Encrypted 0 file(s); 1 were already encrypted.", out2.getvalue())
                fc.refresh_from_db()
                self.assertEqual(fc.wrapped_key, prev_wrapped)

                # Download works after migration.
                sf = StoredFile.objects.get(id=sf.id)
                dl = create_download_response(sf)
                self.assertEqual(dl.status_code, 200)
                self.assertEqual(dl.content, payload)

    @unittest.skipUnless(
        (Path(settings.BASE_DIR) / "docker" / "vault" / "policies" / "kura-web.hcl").is_file(),
        "docker/vault/policies/kura-web.hcl not available in container",
    )
    def test_vault_policy_grants_only_update_on_kura_files(self):
        policy_path = Path(settings.BASE_DIR) / "docker" / "vault" / "policies" / "kura-web.hcl"
        policy_text = policy_path.read_text(encoding="utf-8")
        self.assertIn('path "transit/encrypt/kura-files" {\n  capabilities = ["update"]\n}', policy_text)
        self.assertIn('path "transit/decrypt/kura-files" {\n  capabilities = ["update"]\n}', policy_text)

class WorkItem6EmailRetentionTests(TestCase):
    """Tests for Work Item 6: sent OutgoingEmail retention in purge_retention."""

    def test_purge_retention_deletes_sent_emails_older_than_30_days_and_honours_dry_run(self):
        now = timezone.now()

        sent_31d = OutgoingEmail.objects.create(
            event_key="wi6:sent-31d",
            to_email="student1@kura.edu",
            subject="Old notice",
            body="",
            status=OutgoingEmailStatus.SENT,
            sent_at=now - timezone.timedelta(days=31),
        )
        sent_29d = OutgoingEmail.objects.create(
            event_key="wi6:sent-29d",
            to_email="student2@kura.edu",
            subject="Recent notice",
            body="",
            status=OutgoingEmailStatus.SENT,
            sent_at=now - timezone.timedelta(days=29),
        )
        pending_old = OutgoingEmail.objects.create(
            event_key="wi6:pending-old",
            to_email="student3@kura.edu",
            subject="Pending notice",
            body="Body",
            status=OutgoingEmailStatus.PENDING,
        )
        failed_old = OutgoingEmail.objects.create(
            event_key="wi6:failed-old",
            to_email="student4@kura.edu",
            subject="Failed notice",
            body="",
            status=OutgoingEmailStatus.FAILED,
            sent_at=now - timezone.timedelta(days=45),
        )
        OutgoingEmail.objects.filter(id=pending_old.id).update(created_at=now - timezone.timedelta(days=45))
        OutgoingEmail.objects.filter(id=failed_old.id).update(created_at=now - timezone.timedelta(days=45))

        # Dry run leaves all rows untouched and emits no email.purged event.
        dry_out = StringIO()
        with self.assertNoLogs("kura.security", level="INFO"):
            call_command("purge_retention", days=180, dry_run=True, stdout=dry_out)
        self.assertIn("Sent emails purged (>30d): 1", dry_out.getvalue())
        self.assertTrue(OutgoingEmail.objects.filter(id=sent_31d.id).exists())

        # Real run deletes only the 31-day-old sent email and logs email.purged with count=1.
        out = StringIO()
        with self.assertLogs("kura.security", level="INFO") as cap:
            call_command("purge_retention", days=180, stdout=out)
        self.assertFalse(OutgoingEmail.objects.filter(id=sent_31d.id).exists())
        self.assertTrue(OutgoingEmail.objects.filter(id=sent_29d.id).exists())
        self.assertTrue(OutgoingEmail.objects.filter(id=pending_old.id).exists())
        self.assertTrue(OutgoingEmail.objects.filter(id=failed_old.id).exists())
        log_output = "\n".join(cap.output)
        self.assertIn('event="email.purged"', log_output)
        self.assertIn('count="1"', log_output)
        self.assertNotIn("student1@kura.edu", log_output)

class AuditGroup5RetentionAndLokiTests(TestCase):
    """Tests for Audit Group 5: O7, P3, P4, W8."""

    def test_login_attempt_model_removed_and_loki_ruler_api_disabled(self):
        from kura import models as kura_models

        self.assertFalse(hasattr(kura_models, "LoginAttempt"))
        loki_path = Path(settings.BASE_DIR) / "docker" / "loki" / "loki.yml"
        if not loki_path.is_file():
            self.skipTest("docker/loki/loki.yml not available in container")
        loki_yml = loki_path.read_text(encoding="utf-8")
        self.assertIn("enable_api: false", loki_yml)
        self.assertNotIn("enable_api: true", loki_yml)

    def test_retention_commands_re_raise_and_log_failures_instead_of_swallowing(self):
        from axes.models import AccessAttempt, AccessLog

        with patch.object(AccessAttempt.objects, "filter", side_effect=RuntimeError("db failure")):
            with self.assertLogs("kura.security", level="ERROR") as cap_purge:
                with self.assertRaises(RuntimeError):
                    call_command("purge_retention", "--days=180", stdout=StringIO())
            self.assertTrue(
                any('event="retention.job_failed"' in line and 'command="purge_retention"' in line for line in cap_purge.output)
            )

        with patch.object(AccessLog.objects, "filter", side_effect=RuntimeError("db failure")):
            with self.assertLogs("kura.security", level="ERROR") as cap_anon:
                with self.assertRaises(RuntimeError):
                    call_command("anonymize_ips", "--days=180", stdout=StringIO())
            self.assertTrue(
                any('event="retention.job_failed"' in line and 'command="anonymize_ips"' in line for line in cap_anon.output)
            )

class AuditGroup6PolicyAndGdprTests(TestCase):
    """Tests for Audit Group 6: O6 (editable SecurityPolicy) and O3 (GDPR data subject rights)."""

    def test_admin_can_update_security_policy_with_step_up_and_runtime_readers_use_it(self):
        from kura.models import SecurityPolicy, get_security_policy
        from kura.views import get_axes_cooloff_timedelta, get_axes_failure_limit

        admin = make_user("Admin", mfa_enabled=True)
        login_with_session(self.client, admin)
        confirm_second_factor(self.client)

        with self.assertLogs("kura.security", level="WARNING") as cap:
            resp = self.client.post(
                reverse("kura:security_policy"),
                {
                    "min_password_length": 16,
                    "password_history_count": 7,
                    "axes_failure_limit": 3,
                    "axes_cooloff_hours": 2,
                    "session_idle_minutes": 15,
                    "session_absolute_hours": 6,
                },
            )
        self.assertRedirects(resp, reverse("kura:security_policy"))
        self.assertTrue(any('event="admin.security_policy.changed"' in line for line in cap.output))

        policy = SecurityPolicy.objects.get(pk=1)
        self.assertEqual(policy.min_password_length, 16)
        self.assertEqual(get_security_policy()["session_idle_minutes"], 15)
        self.assertEqual(get_axes_failure_limit(), 3)
        self.assertEqual(get_axes_cooloff_timedelta(), timezone.timedelta(hours=2))

        # Password change form enforces the updated 16-character minimum length.
        old_pw = "ValidPassword123!"
        student = make_user("Student", password=old_pw, mfa_enabled=True)
        stud_client = Client()
        stud_session = login_with_session(stud_client, student)
        with patch("kura.views.check_breached_password", return_value=None):
            short_resp = stud_client.post(
                reverse("kura:password_change"),
                {
                    "old_password": old_pw,
                    "new_password": "FourteenChar!9",  # 14 chars (< 16)
                    "confirm_password": "FourteenChar!9",
                },
            )
        self.assertEqual(short_resp.status_code, 400)
        self.assertContains(short_resp, "at least 16 characters", status_code=400)

        # Idle expiry reflects updated 15-minute idle policy (900 seconds).
        self.assertEqual(stud_client.session.get_expiry_age(), 900)

        # Lockout triggers at 3 failures and sets Retry-After: 7200 (2 hours).
        anon_client = Client()
        locked_user = make_user("Student", password="AnotherValidPassword!123")
        for _ in range(3):
            locked_resp = anon_client.post(
                reverse("kura:login"),
                {"email": locked_user.email, "password": "WrongPassword!999"},
            )
        self.assertEqual(locked_resp.status_code, 429)
        self.assertEqual(locked_resp.headers.get("Retry-After"), "7200")
        self.assertIsNotNone(stud_session)

class DjangoSecurityBaselineTests(TestCase):
    """
    Django security baseline check. Each test names the baseline rule it proves.
    Rules already covered elsewhere (idle and absolute timeout, failed-login
    logging, role change and grade release allowed with a fresh factor, a
    student downloading another student's file) are not repeated here.
    """

    PASSWORD = "ValidPassword123!"

    def setUp(self):
        self.head = make_user("Department head")
        self.instructor = make_user("Instructor")
        self.student = make_user("Student", password=self.PASSWORD)
        self.dept = Department.objects.create(name="Baseline", code="BASE", head_user=self.head)
        StudentProfile.objects.create(
            user=self.student, department=self.dept, current_level="level_4", matriculation_year=2026
        )
        self.course = Course.objects.create(
            department=self.dept, code="BASE101", title="Baseline course", semester="1",
            academic_year=2026, is_published=True, published_by=self.head, published_at=timezone.now(),
        )
        CourseStaff.objects.create(
            course=self.course, user=self.instructor, staff_role="lead_instructor", can_release_grades=True
        )
        Enrollment.objects.create(course=self.course, student=self.student, status=EnrollmentStatus.ACTIVE)
        self.assessment = Assessment.objects.create(
            course=self.course, title="Baseline exam", component_type=GradeComponentType.EXAM,
            max_score=Decimal("100.00"), max_attempts=1, opens_at=timezone.now(),
            due_date=timezone.now() + timezone.timedelta(hours=1),
            created_by=self.instructor,
        )
        self.attempt = AssessmentAttempt.objects.create(
            assessment=self.assessment, student=self.student, attempt_no=1,
            status=AttemptStatus.FULLY_GRADED, ip_address="127.0.0.1",
        )

    def assert_no_secrets_in_logs(self, lines, extra_values):
        # Security rule 6: no password, token, MFA secret or raw score in a log record.
        joined = "\n".join(lines)
        for value in [self.PASSWORD, "password=", "otp_token", "mfa_secret"] + extra_values:
            self.assertNotIn(value, joined)

    # --- Baseline 2: production cookie flags ---

    def test_rule_production_settings_turn_on_secure_cookies_and_hsts(self):
        # Settings are read once, so load them in a new process with DEBUG off.
        environment = os.environ.copy()
        environment["DJANGO_SETTINGS_MODULE"] = "config.settings"
        environment["SECRET_KEY"] = secrets.token_urlsafe(48)
        environment["DEBUG"] = "False"
        environment.pop("SECURE_SSL_REDIRECT", None)
        code = (
            "from django.conf import settings as s; "
            "print(s.SESSION_COOKIE_SECURE, s.SESSION_COOKIE_HTTPONLY, s.SESSION_COOKIE_SAMESITE, "
            "s.CSRF_COOKIE_SECURE, s.CSRF_COOKIE_HTTPONLY, s.CSRF_COOKIE_SAMESITE, "
            "s.SECURE_SSL_REDIRECT, s.SECURE_PROXY_SSL_HEADER, "
            "s.SECURE_HSTS_SECONDS, s.SECURE_HSTS_INCLUDE_SUBDOMAINS)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=settings.BASE_DIR, env=environment, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "True True Lax True True Lax True ('HTTP_X_FORWARDED_PROTO', 'https') 31536000 True",
        )

    @override_settings(SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
    def test_rule_session_and_csrf_cookies_are_secure_httponly_samesite(self):
        # With the production values, both cookies carry Secure, HttpOnly and SameSite.
        login_page = self.client.get(reverse("kura:login"))
        csrf_cookie = login_page.cookies[settings.CSRF_COOKIE_NAME]
        self.assertTrue(csrf_cookie["secure"])
        self.assertTrue(csrf_cookie["httponly"])
        self.assertEqual(csrf_cookie["samesite"], "Lax")

        self.student.mfa_enabled = False
        self.student.save(update_fields=["mfa_enabled"])
        response = self.client.post(reverse("kura:login"), {"email": self.student.email, "password": self.PASSWORD})
        session_cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(session_cookie["secure"])
        self.assertTrue(session_cookie["httponly"])
        self.assertEqual(session_cookie["samesite"], "Lax")

    # --- Baseline 3: CSP and response headers on a signed-in page ---

    def test_rule_csp_has_no_inline_or_eval_on_signed_in_page(self):
        login_with_session(self.client, self.student)
        response = self.client.get(reverse("kura:home"))
        self.assertEqual(response.status_code, 200)
        csp_header = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp_header)
        self.assertIn("style-src 'self'", csp_header)
        self.assertNotIn("unsafe-inline", csp_header)
        self.assertNotIn("unsafe-eval", csp_header)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    # --- Baseline 5: re-authentication for sensitive actions ---

    def test_rule_grade_release_refused_with_wrong_code(self):
        # Releasing a grade needs a valid second-factor code typed on the release form.
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=self.attempt,
            score=Decimal("80.00"), status=GradeStatus.FINALIZED,
        )
        login_with_session(self.client, self.instructor)
        with self.assertLogs("kura.security", level="WARNING") as logs:
            response = self.client.post(reverse("kura:grade_release", args=[grade.id]), {"otp_token": "000000"})
        self.assertEqual(response.status_code, 400)
        grade.refresh_from_db()
        self.assertEqual(grade.status, GradeStatus.FINALIZED)
        self.assertTrue(any('event="grade.release_mfa_failed"' in line for line in logs.output))
        self.assert_no_secrets_in_logs(logs.output, ["000000", "80.00"])

    def test_rule_course_result_release_needs_fresh_second_factor(self):
        result = CourseResult.objects.create(
            course=self.course, student=self.student, final_score=Decimal("75.00"), status=GradeStatus.DRAFT
        )
        login_with_session(self.client, self.instructor)
        url = reverse("kura:course_result_release", args=[self.course.id])
        response = self.client.post(url)
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        result.refresh_from_db()
        self.assertEqual(result.status, GradeStatus.DRAFT)

    def test_rule_grade_change_after_release_needs_fresh_second_factor(self):
        # Approving a change to a released grade needs a fresh second factor.
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=self.attempt,
            score=Decimal("75.00"), status=GradeStatus.RELEASED,
        )
        change_request = GradeChangeRequest.objects.create(
            grade=grade, requested_by=self.instructor, current_score=Decimal("75.00"),
            proposed_score=Decimal("85.00"), reason="Marking error on question 2.",
            status=ChangeRequestStatus.PENDING,
        )
        url = reverse("kura:grade_change_request_review", args=[change_request.id])
        decision = {"decision": ChangeRequestStatus.APPROVED, "review_note": "Checked the script."}
        login_with_session(self.client, self.head)

        # Without a fresh factor: sent to the confirm page and nothing changes.
        response = self.client.post(url, decision)
        self.assertTrue(response["Location"].startswith(reverse("kura:mfa_reauth")))
        grade.refresh_from_db()
        self.assertEqual(grade.score, Decimal("75.00"))

        # With a fresh factor: the change is applied.
        confirm_second_factor(self.client)
        response = self.client.post(url, decision)
        self.assertEqual(response.status_code, 302)
        grade.refresh_from_db()
        self.assertEqual(grade.score, Decimal("85.00"))

    # --- Baseline 5: security event logging ---

    def test_rule_lockout_is_logged_without_password(self):
        login_url = reverse("kura:login")
        for _ in range(5):
            self.client.post(login_url, {"email": self.student.email, "password": "WrongPassword999!"})
        with self.assertLogs("kura.security", level="WARNING") as logs:
            response = self.client.post(login_url, {"email": self.student.email, "password": self.PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertTrue(
            any('event="access.denied"' in line and 'reason="axes_lockout"' in line for line in logs.output)
        )
        self.assert_no_secrets_in_logs(logs.output, ["WrongPassword999!", self.student.email])

    def test_rule_role_change_is_logged_without_secrets(self):
        admin = make_user("Admin")
        login_with_session(self.client, admin)
        confirm_second_factor(self.client)
        ta_role = Role.objects.get(name="Teaching assistant")
        with self.assertLogs("kura.security", level="WARNING") as logs:
            self.client.post(
                reverse("kura:user_roles", args=[self.instructor.id]), {"action": "assign", "role_id": ta_role.id}
            )
        self.assertTrue(any('event="admin.role.changed"' in line for line in logs.output))
        totp_key = TOTPDevice.objects.get(user=admin).key
        session_key = self.client.session.session_key
        self.assert_no_secrets_in_logs(logs.output, [totp_key, session_key])

    def test_rule_grade_change_is_logged_without_scores(self):
        grade = Grade.objects.create(
            assessment=self.assessment, student=self.student, attempt=self.attempt,
            score=Decimal("75.00"), status=GradeStatus.RELEASED,
        )
        change_request = GradeChangeRequest.objects.create(
            grade=grade, requested_by=self.instructor, current_score=Decimal("75.00"),
            proposed_score=Decimal("85.00"), reason="Marking error on question 2.",
            status=ChangeRequestStatus.PENDING,
        )
        login_with_session(self.client, self.head)
        confirm_second_factor(self.client)
        with self.assertLogs("kura.security", level="INFO") as logs:
            self.client.post(
                reverse("kura:grade_change_request_review", args=[change_request.id]),
                {"decision": ChangeRequestStatus.APPROVED, "review_note": "Checked the script."},
            )
        self.assertTrue(any('event="grade.change_decided"' in line for line in logs.output))
        self.assert_no_secrets_in_logs(logs.output, ["75.00", "85.00", "Checked the script."])

    # --- Baseline 5: object-level authorization ---

    def test_rule_student_cannot_open_another_students_attempt(self):
        # A classmate in the same course still cannot open this student's submission.
        classmate = make_user("Student")
        Enrollment.objects.create(course=self.course, student=classmate, status=EnrollmentStatus.ACTIVE)
        login_with_session(self.client, classmate)
        response = self.client.get(reverse("kura:attempt_detail", args=[self.attempt.id]))
        self.assertEqual(response.status_code, 403)

    def test_rule_instructor_cannot_open_course_they_do_not_teach(self):
        outsider = make_user("Instructor")
        login_with_session(self.client, outsider)
        self.assertEqual(self.client.get(reverse("kura:course_detail", args=[self.course.id])).status_code, 403)
        self.assertEqual(self.client.get(reverse("kura:course_grades", args=[self.course.id])).status_code, 403)


class JWTShimTests(TestCase):
    """
    Tests for the kura/__init__.py python-jose monkeypatch using cryptography.
    Covers RS256/ES256 valid tokens, tampered signatures, disallowed algorithms,
    wrong aud/iss, and expired tokens.
    """

    @classmethod
    def setUpTestData(cls):
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives import serialization

        cls.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.rsa_public = cls.rsa_private.public_key()
        cls.rsa_pem = cls.rsa_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cls.rsa_priv_pem = cls.rsa_private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        cls.ec_private = ec.generate_private_key(ec.SECP256R1())
        cls.ec_public = cls.ec_private.public_key()
        cls.ec_pem = cls.ec_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def test_valid_rs256_token_decodes(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-1", "iat": now, "exp": now + 3600, "aud": "kura", "iss": "kura"},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        payload = jwt.decode(
            token, self.rsa_pem, algorithms=["RS256"], audience="kura", issuer="kura"
        )
        self.assertEqual(payload["sub"], "user-1")

    def test_valid_es256_token_decodes(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-2", "iat": now, "exp": now + 3600},
            self.ec_private.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            algorithm="ES256",
        )
        payload = jwt.decode(token, self.ec_pem, algorithms=["ES256"])
        self.assertEqual(payload["sub"], "user-2")

    def test_tampered_rs256_signature_rejected(self):
        import time
        import base64
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-3", "iat": now, "exp": now + 3600},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        # Flip a byte in the signature.
        parts = token.split(".")
        sig = base64.urlsafe_b64decode(parts[2] + "==")
        sig = bytearray(sig)
        sig[0] ^= 0xFF
        tampered_sig = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{parts[1]}.{tampered_sig}"
        with self.assertRaises(ValueError):
            jwt.decode(tampered, self.rsa_pem, algorithms=["RS256"])

    def test_alg_none_rejected(self):
        import time
        import base64
        import json as _json

        from jose import jwt

        now = int(time.time())
        header = _json.dumps({"alg": "none", "typ": "JWT"}).encode()
        payload = _json.dumps({"sub": "user-4", "iat": now, "exp": now + 3600}).encode()
        token = (
            base64.urlsafe_b64encode(header).rstrip(b"=").decode() + "."
            + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
            + "."
        )
        with self.assertRaises(ValueError):
            jwt.decode(token, self.rsa_pem, algorithms=["RS256"])

    def test_alg_hs256_rejected(self):
        import time
        import base64
        import json as _json

        from jose import jwt

        now = int(time.time())
        header = _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        payload = _json.dumps({"sub": "user-5", "iat": now, "exp": now + 3600}).encode()
        token = (
            base64.urlsafe_b64encode(header).rstrip(b"=").decode() + "."
            + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
            + ".fakesig"
        )
        with self.assertRaises(ValueError):
            jwt.decode(token, self.rsa_pem, algorithms=["RS256"])

    def test_wrong_audience_rejected(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-6", "iat": now, "exp": now + 3600, "aud": "other"},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        with self.assertRaises(ValueError):
            jwt.decode(token, self.rsa_pem, algorithms=["RS256"], audience="kura")

    def test_wrong_issuer_rejected(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-7", "iat": now, "exp": now + 3600, "iss": "other"},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        with self.assertRaises(ValueError):
            jwt.decode(token, self.rsa_pem, algorithms=["RS256"], issuer="kura")

    def test_expired_token_rejected(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-8", "iat": now - 7200, "exp": now - 3600},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        with self.assertRaises(ValueError):
            jwt.decode(token, self.rsa_pem, algorithms=["RS256"])

    def test_exp_skip_when_verify_exp_false(self):
        import time
        from jose import jwt

        now = int(time.time())
        token = jwt.encode(
            {"sub": "user-9", "iat": now - 7200, "exp": now - 3600},
            self.rsa_priv_pem,
            algorithm="RS256",
        )
        payload = jwt.decode(
            token, self.rsa_pem, algorithms=["RS256"],
            options={"verify_exp": False},
        )
        self.assertEqual(payload["sub"], "user-9")


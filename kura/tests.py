import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import zipfile
from importlib import import_module
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
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from unittest.mock import MagicMock, call, patch

from .files import validate_and_save_upload
from .forms import PasswordChangeForm
from .views import log_security_event
from .models import (
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
    can_release_grades,
    has_permission,
    has_role,
    is_course_staff,
    is_department_head,
    is_enrolled,
    is_lead_instructor,
)

User = get_user_model()


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
        from django.core.cache import cache
        cache.clear()

        self.client.force_login(self.user)
        dummy_uuid = "00000000-0000-0000-0000-000000000001"
        upload_url = f"/attempts/{dummy_uuid}/files/upload/"

        # Send 25 rapid requests (limit is 20 per minute)
        last_status = None
        for _ in range(25):
            resp = self.client.post(upload_url)
            last_status = resp.status_code

        self.assertEqual(last_status, 429)


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

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

from .files import check_signature_age, scan_file_for_malware, validate_and_save_upload
from .forms import PasswordChangeForm
from .vault import (
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    get_dynamic_database_credentials,
    get_vault_client,
)
from .views import log_security_event, queue_assessment_notification, queue_email, verify_totp_code
from .vault import database_login_cache
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
        self.assertIn('event=file.quarantined', log_line)
        # The newline in the name is written as \\n, so no fake second log line appears.
        self.assertNotIn("\n", log_line)

    def test_old_signatures_log_a_warning(self):
        old_reply = b"ClamAV 1.5.4/27000/Mon Jan  5 09:00:00 2026\x00"
        with patch("socket.create_connection", return_value=fake_clamav_reply(old_reply)):
            with self.assertLogs("kura.security", level="WARNING") as captured:
                check_signature_age()
        self.assertIn("event=clamav.signatures_old", captured.output[0])
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

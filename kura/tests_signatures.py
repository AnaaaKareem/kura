"""Tests for G05 cryptographic non-repudiation signatures and verification."""

import base64
import datetime
from decimal import Decimal
from io import StringIO
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command
from django.db import DatabaseError, connection, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from kura.models import (
    Assessment,
    AssessmentAttempt,
    AttemptFile,
    Course,
    CourseStaff,
    CourseStaffRole,
    Department,
    Enrollment,
    FileContent,
    Grade,
    GradeChangeRequest,
    GradeComponentType,
    GradeStatus,
    SemesterType,
    StoredFile,
    UserSession,
)
from kura.signing import (
    build_grade_payload,
    build_submission_payload,
    canonical_payload,
    public_key_pem,
    sign_payload,
    verify_payload,
)
from kura.tests import make_user
from kura.views import hash_session_token


class ReceiptSignatureTests(TestCase):
    """Verify receipt signing, trigger immutability, Vault path, and tamper detection."""

    def _authenticate(self, user, fresh_mfa=True):
        client = Client()
        client.force_login(user)
        session = client.session
        now = timezone.now()
        session["mfa_verified_at"] = now.timestamp() if fresh_mfa else (now.timestamp() - 7200)
        session["session_started_at"] = now.timestamp()
        session.save()
        user_session = UserSession.objects.create(
            user=user,
            session_token_hash=hash_session_token(session.session_key),
            expires_at=now + datetime.timedelta(hours=1),
            ip_address="127.0.0.1",
            user_agent="testclient",
        )
        session["user_session_id"] = str(user_session.id)
        session.save()
        return client

    def _create_submitted_attempt(self):
        head = make_user("Department head")
        instructor = make_user("Instructor")
        student = make_user("Student")
        now = timezone.now()
        dept = Department.objects.create(code="SIG", name="Signature Dept", head_user=head)
        course = Course.objects.create(
            department=dept,
            code="SIG101",
            title="Crypto Signatures",
            semester=SemesterType.SEMESTER_1,
            academic_year=2026,
            is_published=True,
            published_by=head,
            published_at=now,
        )
        CourseStaff.objects.create(
            course=course,
            user=instructor,
            staff_role=CourseStaffRole.LEAD_INSTRUCTOR,
            can_release_grades=True,
        )
        Enrollment.objects.create(course=course, student=student)
        assessment = Assessment.objects.create(
            course=course,
            title="Signed Assignment",
            component_type=GradeComponentType.ASSIGNMENT,
            max_score=Decimal("100.00"),
            max_attempts=1,
            opens_at=timezone.now() - datetime.timedelta(hours=1),
            due_date=timezone.now() + datetime.timedelta(hours=2),
            created_by=instructor,
        )
        attempt = AssessmentAttempt.objects.create(
            assessment=assessment,
            student=student,
            attempt_no=1,
            ip_address="127.0.0.1",
        )
        sf = StoredFile.objects.create(
            uploaded_by=student,
            original_filename="answer.pdf",
            mime_type="application/pdf",
            size_bytes=128,
            sha256_hash="a" * 64,
        )
        FileContent.objects.create(file=sf, content=b"%PDF-1.4\n%test\n")
        AttemptFile.objects.create(attempt=attempt, file=sf)
        client = self._authenticate(student)
        resp = client.post(reverse("kura:assessment_submit", args=[attempt.id]))
        self.assertEqual(resp.status_code, 302)
        attempt.refresh_from_db()
        return head, instructor, student, course, assessment, attempt

    def test_g05_submit_creates_verifiable_signature_and_blocks_trigger_edit(self):
        """Plan ID: G05 | Risk ID: R13
        Submitting an attempt writes a dev signature, displays valid on attempt_detail,
        passes verify_signatures, and trigger blocks overwriting submission_signature.
        """
        _head, _instructor, student, _course, _assessment, attempt = self._create_submitted_attempt()
        self.assertTrue(attempt.submission_signature.startswith("dev:v1:"))
        self.assertTrue(verify_payload(build_submission_payload(attempt), attempt.submission_signature))

        client = self._authenticate(student)
        detail = client.get(reverse("kura:attempt_detail", args=[attempt.id]))
        self.assertEqual(detail.status_code, 200)
        self.assertContains(detail, "Signature: valid (key version 1)")

        out = StringIO()
        call_command("verify_signatures", stdout=out)
        self.assertIn(f"ATTEMPT  {attempt.id}  OK", out.getvalue())

        # Database trigger must refuse mutating submission_signature once set.
        with self.assertRaises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE assessment_attempts SET submission_signature = 'forged' WHERE id = %s",
                    [str(attempt.id)],
                )

    @override_settings(VAULT_ENABLED=True)
    def test_g05_dev_signature_rejected_when_vault_enabled_and_vault_mocked(self):
        """Plan ID: G05 | Risk ID: R13
        When VAULT_ENABLED=True, dev: signatures are rejected, Vault Transit sign/verify
        calls work via hvac client, and Vault outages fail closed with ValidationError.
        """
        payload = canonical_payload("submission", {"attempt_id": "abc", "submission_hash": "0" * 64})
        self.assertFalse(verify_payload(payload, "dev:v1:AAAA"))

        mock_client = MagicMock()
        mock_client.secrets.transit.sign_data.return_value = {"data": {"signature": "vault:v2:MEUCIQDto=="}}
        mock_client.secrets.transit.verify_signed_data.return_value = {"data": {"valid": True}}
        mock_client.secrets.transit.read_key.return_value = {
            "data": {
                "latest_version": 2,
                "keys": {"2": {"public_key": "-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n"}},
            }
        }
        with patch("kura.signing.get_vault_client", return_value=mock_client):
            sig = sign_payload(payload)
            self.assertEqual(sig, "vault:v2:MEUCIQDto==")
            self.assertTrue(verify_payload(payload, sig))
            pem = public_key_pem()
            self.assertIn("BEGIN PUBLIC KEY", pem)

        mock_failing = MagicMock()
        mock_failing.secrets.transit.sign_data.side_effect = RuntimeError("vault sealed")
        with (
            patch("kura.signing.get_vault_client", return_value=mock_failing),
            self.assertLogs("kura.security", level="ERROR"),
        ):
            with self.assertRaises(ValidationError):
                sign_payload(payload)

    def test_g05_grade_finalize_release_and_change_signatures(self):
        """Plan ID: G05 | Risk ID: R13
        Finalizing, releasing, and approving a grade change request all write verifiable
        signatures that pass verify_signatures.
        """
        head, instructor, student, _course, assessment, attempt = self._create_submitted_attempt()
        grade = Grade.objects.create(
            assessment=assessment,
            student=student,
            attempt=attempt,
            grader=instructor,
            score=Decimal("82.00"),
            status=GradeStatus.DRAFT,
        )

        inst_client = self._authenticate(instructor)
        resp_fin = inst_client.post(reverse("kura:grade_finalize", args=[grade.id]))
        self.assertEqual(resp_fin.status_code, 302)
        grade.refresh_from_db()
        self.assertTrue(grade.finalization_signature.startswith("dev:v1:"))
        self.assertTrue(
            verify_payload(
                build_grade_payload(
                    grade,
                    status=GradeStatus.FINALIZED,
                    actor_id=instructor.id,
                    at=grade.finalized_at,
                ),
                grade.finalization_signature,
            )
        )

        with patch("kura.views.verify_second_factor", return_value="totp"):
            resp_rel = inst_client.post(reverse("kura:grade_release", args=[grade.id]), {"otp_token": "123456"})
        self.assertEqual(resp_rel.status_code, 302)
        grade.refresh_from_db()
        self.assertTrue(grade.release_signature.startswith("dev:v1:"))

        change_req = GradeChangeRequest.objects.create(
            grade=grade,
            requested_by=instructor,
            current_score=grade.score,
            proposed_score=Decimal("88.50"),
            reason="Re-marked question 2.",
        )
        head_client = self._authenticate(head)
        resp_chg = head_client.post(
            reverse("kura:grade_change_request_review", args=[change_req.id]),
            {"decision": "approved", "review_note": "Approved after review."},
        )
        self.assertEqual(resp_chg.status_code, 302)

        out = StringIO()
        call_command("verify_signatures", stdout=out)
        self.assertIn(f"GRADE    {grade.id}  OK", out.getvalue())

    def test_g05_public_key_endpoint_anonymous_and_cacheable(self):
        """Plan ID: G05 | Risk ID: R13
        /.well-known/kura-receipts.pem is accessible anonymously on GET with PEM content type
        and Cache-Control: public, max-age=3600, and rejects POST with 405.
        """
        anon = Client()
        resp = anon.get(reverse("kura:receipts_public_key"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/x-pem-file")
        self.assertEqual(resp["Cache-Control"], "public, max-age=3600")
        self.assertIn(b"-----BEGIN PUBLIC KEY-----", resp.content)

        self.assertEqual(anon.post(reverse("kura:receipts_public_key")).status_code, 405)

        # Authenticated user with onboarding incomplete must still receive cacheable public PEM.
        pending_user = make_user("Student", mfa_enabled=False)
        pending_client = self._authenticate(pending_user)
        resp_auth = pending_client.get(reverse("kura:receipts_public_key"))
        self.assertEqual(resp_auth.status_code, 200)
        self.assertEqual(resp_auth["Cache-Control"], "public, max-age=3600")


class ReceiptTamperDetectionTests(TransactionTestCase):
    """TransactionTestCase so ALTER TABLE DISABLE TRIGGER runs without pending outer triggers."""

    def test_g05_tampered_row_detected_by_verify_signatures(self):
        """Plan ID: G05 | Risk ID: R13
        Bypassing the trigger to alter submitted_at causes verify_signatures to exit non-zero
        and log integrity.signature_failed at ERROR level.
        """
        helper = ReceiptSignatureTests()
        _head, _instructor, _student, _course, _assessment, attempt = helper._create_submitted_attempt()
        tampered_time = attempt.submitted_at - datetime.timedelta(minutes=5)
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE assessment_attempts DISABLE TRIGGER submission_hash_immutable")
            try:
                cursor.execute(
                    "UPDATE assessment_attempts SET submitted_at = %s WHERE id = %s",
                    [tampered_time, str(attempt.id)],
                )
            finally:
                cursor.execute("ALTER TABLE assessment_attempts ENABLE TRIGGER submission_hash_immutable")

        with self.assertLogs("kura.security", level="ERROR") as captured:
            with self.assertRaises(CommandError):
                call_command("verify_signatures", stdout=StringIO(), stderr=StringIO())
        self.assertTrue(any('event="integrity.signature_failed"' in r.getMessage() for r in captured.records))

    def test_g05_forged_signature_wrong_key_and_tampered_payload_rejected(self):
        """Plan ID: G05, T15 | Risk ID: R13
        Verify both a signature forged with a different private key and a tampered submission
        payload are rejected by verify_payload, the attempt_detail receipt view, and verify_signatures.
        """
        helper = ReceiptSignatureTests()
        _head, _instructor, student, _course, _assessment, attempt = helper._create_submitted_attempt()
        original_sig = attempt.submission_signature

        # Positive control: valid receipt renders valid on the receipt view and passes verify_signatures.
        student_client = helper._authenticate(student)
        ok_resp = student_client.get(reverse("kura:attempt_detail", args=[attempt.id]))
        self.assertEqual(ok_resp.status_code, 200)
        self.assertTrue(ok_resp.context["signature_valid"])
        self.assertContains(ok_resp, "Signature: valid")

        # Negative control 1: signature over the exact payload created by an unauthorized keypair must fail.
        rogue_key = Ed25519PrivateKey.generate()
        rogue_sig_bytes = rogue_key.sign(build_submission_payload(attempt))
        forged_sig = "dev:v1:" + base64.b64encode(rogue_sig_bytes).decode("ascii")
        self.assertFalse(verify_payload(build_submission_payload(attempt), forged_sig))

        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE assessment_attempts DISABLE TRIGGER submission_hash_immutable")
            try:
                cursor.execute(
                    "UPDATE assessment_attempts SET submission_signature = %s WHERE id = %s",
                    [forged_sig, str(attempt.id)],
                )
            finally:
                cursor.execute("ALTER TABLE assessment_attempts ENABLE TRIGGER submission_hash_immutable")

        forged_resp = student_client.get(reverse("kura:attempt_detail", args=[attempt.id]))
        self.assertEqual(forged_resp.status_code, 200)
        self.assertFalse(forged_resp.context["signature_valid"])
        self.assertContains(forged_resp, "Signature: INVALID")
        self.assertNotContains(forged_resp, "Signature: valid")

        with self.assertLogs("kura.security", level="ERROR") as cap_forged:
            with self.assertRaises(CommandError):
                call_command("verify_signatures", stdout=StringIO(), stderr=StringIO())
        self.assertTrue(any('event="integrity.signature_failed"' in r.getMessage() for r in cap_forged.records))

        # Negative control 2: restore valid signature, then tamper the stored file hash so payload check fails.
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE assessment_attempts DISABLE TRIGGER submission_hash_immutable")
            try:
                cursor.execute(
                    "UPDATE assessment_attempts SET submission_signature = %s WHERE id = %s",
                    [original_sig, str(attempt.id)],
                )
            finally:
                cursor.execute("ALTER TABLE assessment_attempts ENABLE TRIGGER submission_hash_immutable")
            cursor.execute(
                "UPDATE stored_files SET sha256_hash = %s WHERE uploaded_by_id = %s",
                ["b" * 64, str(student.id)],
            )

        tampered_resp = student_client.get(reverse("kura:attempt_detail", args=[attempt.id]))
        self.assertEqual(tampered_resp.status_code, 200)
        self.assertFalse(tampered_resp.context["signature_valid"])
        self.assertContains(tampered_resp, "Signature: INVALID")

        with self.assertLogs("kura.security", level="ERROR"):
            with self.assertRaises(CommandError):
                call_command("verify_signatures", stdout=StringIO(), stderr=StringIO())

    def test_g05_replayed_signature_across_records_and_after_change_rejected(self):
        """Plan ID: G05, T15 | Risk ID: R13
        Verify a genuine signature cannot be replayed onto another submission record (even with identical
        file bytes) or retained after a signed grade record's score is altered.
        """
        helper = ReceiptSignatureTests()
        _head, instructor, student_a, course, assessment, attempt_a = helper._create_submitted_attempt()

        # Create a second student attempt on the same assessment with identical file SHA-256.
        student_b = make_user("Student")
        Enrollment.objects.create(course=course, student=student_b)
        attempt_b = AssessmentAttempt.objects.create(
            assessment=assessment,
            student=student_b,
            attempt_no=1,
            ip_address="127.0.0.1",
        )
        sf_b = StoredFile.objects.create(
            uploaded_by=student_b,
            original_filename="answer.pdf",
            mime_type="application/pdf",
            size_bytes=128,
            sha256_hash="a" * 64,
        )
        FileContent.objects.create(file=sf_b, content=b"%PDF-1.4\n%test\n")
        AttemptFile.objects.create(attempt=attempt_b, file=sf_b)
        client_b = helper._authenticate(student_b)
        resp_sub_b = client_b.post(reverse("kura:assessment_submit", args=[attempt_b.id]))
        self.assertEqual(resp_sub_b.status_code, 302)
        attempt_b.refresh_from_db()
        original_sig_b = attempt_b.submission_signature

        # Replay case 1: transplant attempt_a's valid signature onto attempt_b.
        self.assertFalse(verify_payload(build_submission_payload(attempt_b), attempt_a.submission_signature))
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE assessment_attempts DISABLE TRIGGER submission_hash_immutable")
            try:
                cursor.execute(
                    "UPDATE assessment_attempts SET submission_signature = %s WHERE id = %s",
                    [attempt_a.submission_signature, str(attempt_b.id)],
                )
            finally:
                cursor.execute("ALTER TABLE assessment_attempts ENABLE TRIGGER submission_hash_immutable")

        replay_resp = client_b.get(reverse("kura:attempt_detail", args=[attempt_b.id]))
        self.assertEqual(replay_resp.status_code, 200)
        self.assertFalse(replay_resp.context["signature_valid"])
        self.assertContains(replay_resp, "Signature: INVALID")

        out_replay = StringIO()
        with self.assertLogs("kura.security", level="ERROR"):
            with self.assertRaises(CommandError):
                call_command("verify_signatures", stdout=out_replay, stderr=StringIO())
        self.assertIn(f"ATTEMPT  {attempt_a.id}  OK", out_replay.getvalue())
        self.assertIn(f"ATTEMPT  {attempt_b.id}  FAIL", out_replay.getvalue())

        # Restore attempt_b's legitimate signature before testing post-mutation replay on a finalized grade.
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE assessment_attempts DISABLE TRIGGER submission_hash_immutable")
            try:
                cursor.execute(
                    "UPDATE assessment_attempts SET submission_signature = %s WHERE id = %s",
                    [original_sig_b, str(attempt_b.id)],
                )
            finally:
                cursor.execute("ALTER TABLE assessment_attempts ENABLE TRIGGER submission_hash_immutable")

        grade = Grade.objects.create(
            assessment=assessment,
            student=student_a,
            attempt=attempt_a,
            grader=instructor,
            score=Decimal("75.00"),
            status=GradeStatus.DRAFT,
        )
        inst_client = helper._authenticate(instructor)
        self.assertEqual(inst_client.post(reverse("kura:grade_finalize", args=[grade.id])).status_code, 302)
        grade.refresh_from_db()

        out_ok = StringIO()
        call_command("verify_signatures", stdout=out_ok)
        self.assertIn(f"GRADE    {grade.id}  OK", out_ok.getvalue())

        # Replay case 2: mutate finalized grade score while retaining its previously valid signature.
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE grade_history DISABLE TRIGGER ALL")
            try:
                cursor.execute(
                    "UPDATE grades SET score = %s WHERE id = %s",
                    [Decimal("99.00"), str(grade.id)],
                )
                cursor.execute(
                    "UPDATE grade_history SET new_score = %s WHERE grade_id = %s",
                    [Decimal("99.00"), str(grade.id)],
                )
            finally:
                cursor.execute("ALTER TABLE grade_history ENABLE TRIGGER ALL")

        out_grade_replay = StringIO()
        with self.assertLogs("kura.security", level="ERROR"):
            with self.assertRaises(CommandError):
                call_command("verify_signatures", stdout=out_grade_replay, stderr=StringIO())
        self.assertIn(f"GRADE    {grade.id}  FAIL", out_grade_replay.getvalue())

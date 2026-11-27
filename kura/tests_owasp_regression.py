"""Automated OWASP Top 10 (2025) defensive regression tests for Kura LMS.

Covers attack classes from security_concepts_reference.md sections 3.2 to 3.4
that are not already exhaustively covered by existing test suites:
- XSS output encoding & Content-Security-Policy (A05)
- Path traversal on download/upload routes and filename sanitisation (A01)
- CORS untrusted-origin handling on HTML and JSON endpoints (A02)
- Vertical privilege escalation across all dynamically discovered admin/registrar/staff routes (A01)
- HTTP method enforcement (GET/PUT/PATCH/DELETE -> 405) & CSRF enforcement (403) (A01/A05)
- Hidden-field and parameter tampering / mass-assignment resistance (A01/A05)
- Resource exhaustion: upload size limit, pagination cap, login rate limit (429) (A04/A07)
- Error-handling leakage with DEBUG=False on 403, 404, and forced 500 (A10)
- XXE attack-surface guard confirming no XML parser is used in Kura runtime code (A05)

Existing tests referenced (not duplicated):
- CSP no-inline/eval check: kura/tests.py::SecurityPolicyRulesTests.test_rule_csp_has_no_inline_or_eval_on_signed_in_page
- 91-route anonymous & CSRF baseline: kura/tests_security_routes.py::SecurityRouteAuthorizationMatrixTests.test_all_90_routes_anonymous_and_csrf_matrix
- Representative CLS-03..CLS-08 access matrix: kura/tests_security_routes.py::SecurityRouteAuthorizationMatrixTests.test_cls_03_to_cls_08_positive_and_cross_scope_negative_matrix
- Direct /media/ bypass: kura/tests_security_leads_part1.py::SecurityLeadsPart1Tests.test_lead_04_media_url_bypass_serves_no_content_and_returns_404
- Burst upload/search rate limit: kura/tests.py::RateLimitingTests.test_rapid_burst_requests_beyond_limit_are_rejected
- Handler 404/500 logging: kura/tests.py::AuditLoggingTests.test_handler404_logs_access_not_found & test_handler500_logs_server_error_without_exception_or_db_access
"""

import ast
import os
import re
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from axes.models import AccessAttempt
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import URLPattern, reverse
from django.utils.html import escape as html_escape

from . import urls as kura_urls
from .models import (
    MAX_UPLOAD_BYTES,
    AcademicLevel,
    Assessment,
    AttemptStatus,
    Course,
    CourseFile,
    Enrollment,
    EnrollmentStatus,
    FileContent,
    GradeStatus,
    QuarantinedFile,
    Schedule,
    StaffProfile,
    StoredFile,
    User,
    UserRole,
    UserSession,
)
from .tests_security_fixtures import build_security_fixture_set, create_authenticated_client
from .views import sanitize_filename, validate_and_save_upload

# Standard OWASP XSS test payloads covering script tags, event handlers, and javascript: URIs.
XSS_SCRIPT_PAYLOAD = "<script>alert('xss')</script>"
XSS_IMG_PAYLOAD = '<img src=x onerror=alert(1)>'
XSS_LINK_PAYLOAD = '<a href="javascript:alert(1)">click</a>'
XSS_MARKDOWN_PAYLOAD = '[click](javascript:alert(1)) <img src=x onerror=alert(1)>'

# Minimal valid PDF bytes recognized by python-magic as application/pdf.
MINIMAL_PDF_BYTES = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


class XSSOutputEncodingRegressionTests(TestCase):
    """Verify HTML output encoding, absence of unsafe template rendering, and CSP headers."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student_client, _ = create_authenticated_client(self.fx["users"]["student_1"])
        self.instructor_client, _ = create_authenticated_client(self.fx["users"]["instructor_a"])
        self.head_client, _ = create_authenticated_client(self.fx["users"]["head_a"])
        self.registrar_client, _ = create_authenticated_client(self.fx["users"]["registrar"])

    def _assert_escaped_and_not_raw(self, response, payload, label):
        body = response.content.decode("utf-8")
        # Django's autoescaping must neutralize every raw HTML tag and attribute payload.
        self.assertNotIn(payload, body, f"Raw XSS payload leaked in {label}")
        self.assertIn(html_escape(payload), body, f"Escaped payload missing in {label}")

    def test_course_title_and_description_escape_xss_payloads(self):
        """Course title and description must render only HTML-escaped text, never raw tags."""
        course = self.fx["courses"]["course_a1"]
        for payload in (XSS_SCRIPT_PAYLOAD, XSS_IMG_PAYLOAD, XSS_LINK_PAYLOAD):
            course.title = f"Course {payload}"
            course.description = f"Desc {payload} {XSS_MARKDOWN_PAYLOAD}"
            course.save(update_fields=["title", "description"])

            resp = self.student_client.get(reverse("kura:course_detail", kwargs={"course_id": course.id}))
            self.assertEqual(resp.status_code, 200)
            self._assert_escaped_and_not_raw(resp, payload, "course_detail")
            body = resp.content.decode("utf-8")
            self.assertNotIn('<a href="javascript:', body)
            self.assertNotIn("<img src=x onerror=", body)

    def test_assessment_description_and_no_unsafe_markdown_rendering(self):
        """Assessment descriptions escape HTML/Markdown XSS and no template uses |safe or autoescape off.

        Note: SectionItem (rich Markdown) was removed in migration 0029_strip_to_security_core.
        All remaining text fields are rendered as Django auto-escaped plain text.
        """
        assessment = self.fx["objects"]["assessment_open"]
        assessment.description = f"{XSS_SCRIPT_PAYLOAD} {XSS_IMG_PAYLOAD} {XSS_LINK_PAYLOAD} {XSS_MARKDOWN_PAYLOAD}"
        assessment.save(update_fields=["description"])

        resp = self.student_client.get(reverse("kura:assessment_detail", kwargs={"assessment_id": assessment.id}))
        self.assertEqual(resp.status_code, 200)
        for payload in (XSS_SCRIPT_PAYLOAD, XSS_IMG_PAYLOAD, XSS_LINK_PAYLOAD):
            self._assert_escaped_and_not_raw(resp, payload, "assessment_detail")
        body = resp.content.decode("utf-8")
        self.assertNotIn('<a href="javascript:', body)
        self.assertNotIn("<img src=x onerror=", body)

        # Static guard: verify no Kura HTML template bypasses Django auto-escaping.
        templates_dir = Path(settings.BASE_DIR) / "kura" / "templates"
        unsafe_pattern = re.compile(r"\|\s*safe\b|\bautoescape\s+off\b")
        for tpl in templates_dir.rglob("*.html"):
            content = tpl.read_text(encoding="utf-8")
            self.assertIsNone(
                unsafe_pattern.search(content),
                f"Unsafe template rendering found in {tpl.relative_to(settings.BASE_DIR)}",
            )

    def test_grade_feedback_escapes_xss_payloads(self):
        """Released grade feedback must be HTML-escaped on both student and staff grade views."""
        grade = self.fx["objects"]["grade_released"]
        grade.feedback = f"Feedback: {XSS_SCRIPT_PAYLOAD} {XSS_IMG_PAYLOAD} {XSS_LINK_PAYLOAD}"
        grade.save(update_fields=["feedback"])

        student_resp = self.student_client.get(reverse("kura:student_grades"))
        self.assertEqual(student_resp.status_code, 200)
        for payload in (XSS_SCRIPT_PAYLOAD, XSS_IMG_PAYLOAD, XSS_LINK_PAYLOAD):
            self._assert_escaped_and_not_raw(student_resp, payload, "student_grades")

        # Staff grade entry view also renders draft feedback inside a textarea; verify escaping there too.
        attempt = self.fx["objects"]["attempt_submitted"]
        attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
        attempt.save(update_fields=["status"])
        draft_grade = self.fx["objects"]["grade_draft"]
        draft_grade.feedback = f"Draft: {XSS_SCRIPT_PAYLOAD} {XSS_IMG_PAYLOAD} {XSS_LINK_PAYLOAD}"
        draft_grade.save(update_fields=["feedback"])

        staff_resp = self.instructor_client.get(
            reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id})
        )
        self.assertEqual(staff_resp.status_code, 200)
        for payload in (XSS_SCRIPT_PAYLOAD, XSS_IMG_PAYLOAD, XSS_LINK_PAYLOAD):
            self._assert_escaped_and_not_raw(staff_resp, payload, "grade_entry")

    def test_profile_name_escapes_xss_payloads(self):
        """User profile first_name and last_name must be HTML-escaped on profile and dashboard pages."""
        student = self.fx["users"]["student_1"]
        student.first_name = XSS_SCRIPT_PAYLOAD
        student.last_name = XSS_IMG_PAYLOAD
        student.save(update_fields=["first_name", "last_name"])

        profile_resp = self.registrar_client.get(
            reverse("kura:student_profile", kwargs={"student_id": student.id})
        )
        self.assertEqual(profile_resp.status_code, 200)
        self._assert_escaped_and_not_raw(profile_resp, XSS_SCRIPT_PAYLOAD, "student_profile.first_name")
        self._assert_escaped_and_not_raw(profile_resp, XSS_IMG_PAYLOAD, "student_profile.last_name")

        home_resp = self.student_client.get(reverse("kura:home"))
        self.assertEqual(home_resp.status_code, 200)
        self.assertNotIn(XSS_SCRIPT_PAYLOAD, home_resp.content.decode("utf-8"))
        self.assertNotIn(XSS_IMG_PAYLOAD, home_resp.content.decode("utf-8"))

    def test_grade_change_appeal_reason_escapes_xss_payloads(self):
        """Grade change request (appeal) reason must be HTML-escaped on the review page."""
        change_req = self.fx["objects"]["change_request_pending"]
        change_req.reason = f"Appeal: {XSS_SCRIPT_PAYLOAD} {XSS_IMG_PAYLOAD} {XSS_LINK_PAYLOAD}"
        change_req.save(update_fields=["reason"])

        resp = self.head_client.get(
            reverse("kura:grade_change_request_review", kwargs={"request_id": change_req.id})
        )
        self.assertEqual(resp.status_code, 200)
        for payload in (XSS_SCRIPT_PAYLOAD, XSS_IMG_PAYLOAD, XSS_LINK_PAYLOAD):
            self._assert_escaped_and_not_raw(resp, payload, "grade_change_request_review")

    def test_csp_header_present_on_html_responses(self):
        """HTML responses must include a strict Content-Security-Policy header."""
        anon = Client()
        for label, client, url in (
            ("login", anon, reverse("kura:login")),
            ("home", self.student_client, reverse("kura:home")),
            (
                "course_detail",
                self.student_client,
                reverse("kura:course_detail", kwargs={"course_id": self.fx["courses"]["course_a1"].id}),
            ),
        ):
            with self.subTest(page=label):
                resp = client.get(url)
                self.assertEqual(resp.status_code, 200)
                csp = resp.get("Content-Security-Policy", "")
                self.assertTrue(csp, f"Missing Content-Security-Policy header on {label}")
                self.assertIn("default-src 'self'", csp)
                self.assertIn("script-src 'self'", csp)
                self.assertNotIn("'unsafe-inline'", csp)
                self.assertNotIn("'unsafe-eval'", csp)


class PathTraversalRegressionTests(TestCase):
    """Verify path traversal resistance on download/upload routes and filename sanitisation."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.instructor_client, _ = create_authenticated_client(self.fx["users"]["instructor_a"])
        self.student_client, _ = create_authenticated_client(self.fx["users"]["student_1"])
        self.course = self.fx["courses"]["course_a1"]
        self.assessment = self.fx["objects"]["assessment_open"]
        self.attempt = self.fx["objects"]["attempt_in_progress"]

    def test_download_and_upload_routes_reject_traversal_ids_and_paths(self):
        """Plain, URL-encoded, and double-encoded traversal segments must return 400 or 404."""
        traversal_tokens = (
            "../../etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "..%2f..%2fetc%2fpasswd",
        )
        for token in traversal_tokens:
            download_paths = (
                f"/courses/{self.course.id}/files/{token}/download/",
                f"/courses/{token}/files/{self.fx['objects']['sf_course'].id}/download/",
                f"/assessments/{self.assessment.id}/files/{token}/download/",
                f"/attempts/{self.attempt.id}/files/{token}/download/",
                f"/media/{token}",
            )
            for path in download_paths:
                with self.subTest(method="GET", path=path):
                    resp = self.instructor_client.get(path)
                    self.assertIn(resp.status_code, (400, 404))
                    self.assertNotIn(b"root:x:0:0:", resp.content)

            upload_paths = (
                f"/courses/{token}/files/upload/",
                f"/assessments/{token}/files/upload/",
                f"/attempts/{token}/files/upload/",
            )
            for path in upload_paths:
                with self.subTest(method="POST", path=path):
                    resp = self.instructor_client.post(path, data={})
                    self.assertIn(resp.status_code, (400, 404))
                    self.assertNotIn(b"root:x:0:0:", resp.content)

    @patch("kura.views.scan_file_for_malware")
    def test_upload_with_traversal_filename_is_sanitized_and_stored_by_uuid(self, mock_scan):
        """Uploading a file whose name contains ../ must strip traversal paths and store by UUID in DB."""
        mock_scan.return_value = None
        malicious_names = (
            "../../../etc/passwd.pdf",
            "..\\..\\windows\\system32\\notes.pdf",
            "subdir/%2e%2e/report.pdf",
        )
        upload_url = reverse("kura:course_file_upload", kwargs={"course_id": self.course.id})

        for raw_name in malicious_names:
            with self.subTest(filename=raw_name):
                uploaded = SimpleUploadedFile(raw_name, MINIMAL_PDF_BYTES, content_type="application/pdf")
                before_ids = set(StoredFile.objects.values_list("id", flat=True))
                resp = self.instructor_client.post(
                    upload_url,
                    data={"title": "Traversal Test", "file": uploaded, "is_visible": "on"},
                )
                self.assertEqual(resp.status_code, 302)

                new_files = list(StoredFile.objects.exclude(id__in=before_ids))
                self.assertEqual(len(new_files), 1)
                sf = new_files[0]

                # Stored filename must contain no path separators or traversal sequences.
                self.assertNotIn("..", sf.original_filename)
                self.assertNotIn("/", sf.original_filename)
                self.assertNotIn("\\", sf.original_filename)
                # Content is stored in PostgreSQL keyed by UUID, not written under media storage.
                self.assertTrue(FileContent.objects.filter(file_id=sf.id).exists())

                dl_url = reverse(
                    "kura:file_download", kwargs={"course_id": self.course.id, "file_id": sf.id}
                )
                dl_resp = self.instructor_client.get(dl_url)
                self.assertEqual(dl_resp.status_code, 200)
                disposition = dl_resp.get("Content-Disposition", "")
                self.assertIn("attachment", disposition)
                self.assertNotIn("..", disposition)
                self.assertNotIn("/", disposition)

        # Direct unit assertion on sanitize_filename with traversal inputs.
        self.assertEqual(sanitize_filename("../../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\secret.txt"), "secret.txt")


class CORSRegressionTests(TestCase):
    """Verify untrusted Origin headers are never reflected or granted wildcard/credentialed CORS."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student_client, _ = create_authenticated_client(self.fx["users"]["student_1"])
        self.admin_client, _ = create_authenticated_client(self.fx["users"]["admin"])

    def _assert_no_untrusted_cors(self, response, label):
        acao = response.get("Access-Control-Allow-Origin")
        acac = response.get("Access-Control-Allow-Credentials")
        self.assertNotEqual(acao, "*", f"Wildcard ACAO present on {label}")
        self.assertNotEqual(acao, "https://evil.example", f"Untrusted origin reflected on {label}")
        self.assertIsNone(acao, f"Unexpected ACAO header on {label}: {acao}")
        self.assertIsNone(acac, f"Unexpected ACAC header on {label}: {acac}")

    def test_untrusted_origin_rejected_on_authenticated_html_and_json_endpoints(self):
        """Authenticated HTML pages and JSON endpoints must never emit permissive CORS headers."""
        headers = {
            "HTTP_ORIGIN": "https://evil.example",
            "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
        }
        targets = (
            ("home_html", self.student_client, reverse("kura:home")),
            (
                "course_detail_html",
                self.student_client,
                reverse("kura:course_detail", kwargs={"course_id": self.fx["courses"]["course_a1"].id}),
            ),
            ("admin_users_html", self.admin_client, reverse("kura:admin_users")),
            # JSON endpoint: GDPR self-service data export returns application/json.
            ("privacy_export_json", self.student_client, reverse("kura:privacy_export")),
            # Public key endpoint.
            ("receipts_pem", self.student_client, reverse("kura:receipts_public_key")),
        )
        for label, client, url in targets:
            with self.subTest(endpoint=label, method="GET"):
                resp = client.get(url, **headers)
                self._assert_no_untrusted_cors(resp, f"GET {label}")
            with self.subTest(endpoint=label, method="OPTIONS"):
                resp = client.options(url, **headers)
                self._assert_no_untrusted_cors(resp, f"OPTIONS {label}")


class VerticalPrivilegeEscalationRegressionTests(TestCase):
    """Verify Student, TA, and Instructor cannot access any admin, registrar, or higher-privilege route.

    Admin and registrar route lists are dynamically generated from kura/urls.py so newly added
    routes are tested automatically without manual list maintenance.
    """

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student_client, _ = create_authenticated_client(self.fx["users"]["student_1"])
        self.ta_client, _ = create_authenticated_client(self.fx["users"]["ta_a"])
        self.instructor_client, _ = create_authenticated_client(self.fx["users"]["instructor_a"])

    def _kwargs_for_pattern(self, pattern_str):
        """Map URL path converter parameter names to real fixture object IDs."""
        objs = self.fx["objects"]
        courses = self.fx["courses"]
        depts = self.fx["departments"]
        users = self.fx["users"]
        param_map = {
            "user_id": users["student_2"].id,
            "student_id": users["student_1"].id,
            "quarantined_file_id": objs["quarantined_file"].id,
            "enrollment_id": objs["enrollment_a1"].id,
            "course_id": courses["course_a1"].id,
            "course_file_id": objs["course_file_visible"].id,
            "file_id": objs["sf_course"].id,
            "schedule_id": objs["schedule_a1"].id,
            "session_id": objs["attendance_session"].id,
            "assessment_id": objs["assessment_open"].id,
            "attempt_id": objs["attempt_submitted"].id,
            "grade_id": objs["grade_draft"].id,
            "request_id": objs["change_request_pending"].id,
            "department_id": depts["dept_a"].id,
            "key_id": objs["passkey_stu1"].id,
            "token": "synthetic-reset-token",
        }
        names = re.findall(r"<[^:>]+:([^>]+)>", pattern_str)
        return {name: param_map[name] for name in names}

    def _discover_routes_by_prefix(self, prefixes):
        """Dynamically enumerate all named URLPatterns in kura/urls.py matching any prefix."""
        discovered = []
        for entry in kura_urls.urlpatterns:
            if not isinstance(entry, URLPattern) or not entry.name:
                continue
            route_str = str(entry.pattern)
            if any(route_str.startswith(p) for p in prefixes):
                kwargs = self._kwargs_for_pattern(route_str)
                discovered.append((f"kura:{entry.name}", reverse(f"kura:{entry.name}", kwargs=kwargs)))
        return discovered

    def test_student_ta_and_instructor_blocked_from_all_admin_and_registrar_routes(self):
        """Every /admin/ and /registrar/ route in kura/urls.py must deny Student, TA, and Instructor."""
        privileged_routes = self._discover_routes_by_prefix(("admin/", "registrar/"))
        # Sanity check: ensure dynamic discovery actually found the admin and registrar routes.
        self.assertGreaterEqual(len(privileged_routes), 18)

        target_user = self.fx["users"]["student_2"]
        enrollment = self.fx["objects"]["enrollment_a1"]
        quarantined_count_before = QuarantinedFile.objects.count()
        user_count_before = User.objects.count()
        course_count_before = Course.objects.count()
        enrollment_status_before = enrollment.status
        target_active_before = target_user.is_active
        target_locked_before = target_user.locked_until
        login_url = reverse("kura:login")

        for role_label, client in (
            ("student", self.student_client),
            ("ta", self.ta_client),
            ("instructor", self.instructor_client),
        ):
            for route_name, url in privileged_routes:
                for method in ("GET", "POST"):
                    with self.subTest(role=role_label, route=route_name, method=method):
                        resp = client.get(url) if method == "GET" else client.post(url, data={})
                        # Some POST-only views check method (405) before role (403); GET on them is still denied.
                        if method == "GET" and resp.status_code == 405:
                            continue
                        if resp.status_code == 302:
                            self.assertIn(login_url, resp["Location"])
                        else:
                            self.assertEqual(resp.status_code, 403)

        # Assert zero state changes occurred across all denied requests.
        target_user.refresh_from_db()
        enrollment.refresh_from_db()
        self.assertEqual(QuarantinedFile.objects.count(), quarantined_count_before)
        self.assertEqual(User.objects.count(), user_count_before)
        self.assertEqual(Course.objects.count(), course_count_before)
        self.assertEqual(enrollment.status, enrollment_status_before)
        self.assertEqual(target_user.is_active, target_active_before)
        self.assertEqual(target_user.locked_until, target_locked_before)

    def test_student_and_ta_blocked_from_staff_and_head_only_routes(self):
        """Students cannot access staff-only routes; TAs and Instructors cannot access head-only routes."""
        course = self.fx["courses"]["course_a1"]
        objs = self.fx["objects"]
        dept_a = self.fx["departments"]["dept_a"]

        staff_only_routes = [
            ("kura:course_create", reverse("kura:course_create"), "POST"),
            ("kura:course_publish_toggle", reverse("kura:course_publish_toggle", kwargs={"course_id": course.id}), "POST"),
            ("kura:course_staff_assign", reverse("kura:course_staff_assign", kwargs={"course_id": course.id}), "GET"),
            ("kura:course_ta_assign", reverse("kura:course_ta_assign", kwargs={"course_id": course.id}), "GET"),
            ("kura:course_file_upload", reverse("kura:course_file_upload", kwargs={"course_id": course.id}), "POST"),
            ("kura:course_file_delete", reverse("kura:course_file_delete", kwargs={"course_file_id": objs["course_file_visible"].id}), "POST"),
            ("kura:schedule_create", reverse("kura:schedule_create", kwargs={"course_id": course.id}), "GET"),
            ("kura:schedule_delete", reverse("kura:schedule_delete", kwargs={"schedule_id": objs["schedule_a1"].id}), "POST"),
            ("kura:attendance_session_start", reverse("kura:attendance_session_start", kwargs={"course_id": course.id}), "GET"),
            ("kura:attendance_session_close", reverse("kura:attendance_session_close", kwargs={"session_id": objs["attendance_session"].id}), "POST"),
            ("kura:assessment_create", reverse("kura:assessment_create", kwargs={"course_id": course.id}), "GET"),
            ("kura:assessment_delete", reverse("kura:assessment_delete", kwargs={"assessment_id": objs["assessment_open"].id}), "POST"),
            ("kura:course_grades", reverse("kura:course_grades", kwargs={"course_id": course.id}), "GET"),
            ("kura:grade_entry", reverse("kura:grade_entry", kwargs={"attempt_id": objs["attempt_submitted"].id}), "GET"),
            ("kura:grade_finalize", reverse("kura:grade_finalize", kwargs={"grade_id": objs["grade_draft"].id}), "POST"),
            ("kura:grade_release", reverse("kura:grade_release", kwargs={"grade_id": objs["grade_finalized"].id}), "GET"),
            ("kura:grade_change_request_review", reverse("kura:grade_change_request_review", kwargs={"request_id": objs["change_request_pending"].id}), "GET"),
            ("kura:course_result_calculate", reverse("kura:course_result_calculate", kwargs={"course_id": course.id}), "POST"),
            ("kura:course_result_release", reverse("kura:course_result_release", kwargs={"course_id": course.id}), "POST"),
            ("kura:department_reports", reverse("kura:department_reports", kwargs={"department_id": dept_a.id}), "GET"),
        ]
        for route_name, url, method in staff_only_routes:
            with self.subTest(role="student", route=route_name):
                resp = self.student_client.get(url) if method == "GET" else self.student_client.post(url, data={})
                self.assertEqual(resp.status_code, 403)

        # TA cannot finalize/release grades, publish courses, or view department reports.
        ta_forbidden = [
            ("kura:grade_finalize", reverse("kura:grade_finalize", kwargs={"grade_id": objs["grade_draft"].id}), "POST"),
            ("kura:grade_release", reverse("kura:grade_release", kwargs={"grade_id": objs["grade_finalized"].id}), "POST"),
            ("kura:course_result_release", reverse("kura:course_result_release", kwargs={"course_id": course.id}), "POST"),
            ("kura:course_publish_toggle", reverse("kura:course_publish_toggle", kwargs={"course_id": course.id}), "POST"),
            ("kura:department_reports", reverse("kura:department_reports", kwargs={"department_id": dept_a.id}), "GET"),
        ]
        for route_name, url, method in ta_forbidden:
            with self.subTest(role="ta", route=route_name):
                resp = self.ta_client.get(url) if method == "GET" else self.ta_client.post(url, data={})
                self.assertEqual(resp.status_code, 403)

        # Instructor cannot publish courses, assign instructors, review appeals, or view department reports.
        instructor_forbidden = [
            ("kura:course_publish_toggle", reverse("kura:course_publish_toggle", kwargs={"course_id": course.id}), "POST"),
            ("kura:course_staff_assign", reverse("kura:course_staff_assign", kwargs={"course_id": course.id}), "GET"),
            ("kura:grade_change_request_review", reverse("kura:grade_change_request_review", kwargs={"request_id": objs["change_request_pending"].id}), "GET"),
            ("kura:department_reports", reverse("kura:department_reports", kwargs={"department_id": dept_a.id}), "GET"),
        ]
        for route_name, url, method in instructor_forbidden:
            with self.subTest(role="instructor", route=route_name):
                resp = self.instructor_client.get(url) if method == "GET" else self.instructor_client.post(url, data={})
                self.assertEqual(resp.status_code, 403)

        # Verify course publish state and draft grade remained untouched.
        course.refresh_from_db()
        objs["grade_draft"].refresh_from_db()
        self.assertTrue(course.is_published)
        self.assertEqual(objs["grade_draft"].status, GradeStatus.DRAFT)


class HTTPMethodEnforcementRegressionTests(TestCase):
    """Verify state-changing POST-only views reject GET/PUT/PATCH/DELETE with 405 and missing CSRF with 403."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.clients = {
            role: create_authenticated_client(self.fx["users"][role], fresh_mfa=True)[0]
            for role in ("admin", "registrar", "head_a", "instructor_a", "student_1")
        }
        self.csrf_clients = {
            role: create_authenticated_client(
                self.fx["users"][role], fresh_mfa=True, enforce_csrf_checks=True
            )[0]
            for role in ("admin", "registrar", "head_a", "instructor_a", "student_1")
        }
        _, self.student_other_session = create_authenticated_client(
            self.fx["users"]["student_1"], ip_address="198.51.100.55"
        )

    def _state_changing_post_only_routes(self):
        objs = self.fx["objects"]
        course = self.fx["courses"]["course_a1"]
        return [
            # delete
            ("passkey_delete", "student_1", reverse("kura:passkey_delete", kwargs={"key_id": objs["passkey_stu1"].id})),
            ("quarantine_delete", "admin", reverse("kura:quarantine_delete", kwargs={"quarantined_file_id": objs["quarantined_file"].id})),
            ("course_file_delete", "instructor_a", reverse("kura:course_file_delete", kwargs={"course_file_id": objs["course_file_visible"].id})),
            ("schedule_delete", "instructor_a", reverse("kura:schedule_delete", kwargs={"schedule_id": objs["schedule_a1"].id})),
            ("assessment_delete", "instructor_a", reverse("kura:assessment_delete", kwargs={"assessment_id": objs["assessment_open"].id})),
            (
                "assessment_attempt_file_delete",
                "student_1",
                reverse(
                    "kura:assessment_attempt_file_delete",
                    kwargs={"attempt_id": objs["attempt_in_progress"].id, "file_id": objs["sf_attempt"].id},
                ),
            ),
            # drop
            ("enrollment_drop", "registrar", reverse("kura:enrollment_drop", kwargs={"enrollment_id": objs["enrollment_a1"].id})),
            # lock
            ("user_lock_toggle", "admin", reverse("kura:user_lock_toggle", kwargs={"user_id": self.fx["users"]["student_2"].id})),
            # revoke
            ("user_session_revoke", "student_1", reverse("kura:user_session_revoke", kwargs={"session_id": self.student_other_session.id})),
            ("admin_sessions_revoke", "admin", reverse("kura:admin_sessions_revoke")),
            # publish
            ("course_publish_toggle", "head_a", reverse("kura:course_publish_toggle", kwargs={"course_id": course.id})),
            # grade / results
            ("grade_finalize", "instructor_a", reverse("kura:grade_finalize", kwargs={"grade_id": objs["grade_draft"].id})),
            ("course_result_calculate", "instructor_a", reverse("kura:course_result_calculate", kwargs={"course_id": course.id})),
            ("course_result_release", "instructor_a", reverse("kura:course_result_release", kwargs={"course_id": course.id})),
            # upload
            ("course_file_upload", "instructor_a", reverse("kura:course_file_upload", kwargs={"course_id": course.id})),
            ("assessment_file_upload", "instructor_a", reverse("kura:assessment_file_upload", kwargs={"assessment_id": objs["assessment_open"].id})),
            ("assessment_attempt_file_upload", "student_1", reverse("kura:assessment_attempt_file_upload", kwargs={"attempt_id": objs["attempt_in_progress"].id})),
        ]

    def test_post_only_state_changing_views_reject_get_put_patch_delete_with_405(self):
        """GET, PUT, PATCH, and DELETE on POST-only state-changing views must return 405 with zero mutation."""
        objs = self.fx["objects"]
        course = self.fx["courses"]["course_a1"]
        target_user = self.fx["users"]["student_2"]

        quarantine_before = QuarantinedFile.objects.count()
        course_files_before = CourseFile.objects.count()
        schedules_before = Schedule.objects.count()
        assessments_before = Assessment.objects.count()

        for label, actor_key, url in self._state_changing_post_only_routes():
            client = self.clients[actor_key]
            for method_name in ("get", "put", "patch", "delete"):
                with self.subTest(route=label, method=method_name.upper()):
                    resp = getattr(client, method_name)(url)
                    self.assertEqual(resp.status_code, 405, f"{method_name.upper()} {label} returned {resp.status_code}")

        # Verify no state changed across any target model.
        self.assertEqual(QuarantinedFile.objects.count(), quarantine_before)
        self.assertEqual(CourseFile.objects.count(), course_files_before)
        self.assertEqual(Schedule.objects.count(), schedules_before)
        self.assertEqual(Assessment.objects.count(), assessments_before)
        objs["enrollment_a1"].refresh_from_db()
        self.assertEqual(objs["enrollment_a1"].status, EnrollmentStatus.ACTIVE)
        target_user.refresh_from_db()
        self.assertIsNone(target_user.locked_until)
        self.student_other_session.refresh_from_db()
        self.assertIsNone(self.student_other_session.revoked_at)
        course.refresh_from_db()
        self.assertTrue(course.is_published)
        objs["grade_draft"].refresh_from_db()
        self.assertEqual(objs["grade_draft"].status, GradeStatus.DRAFT)

    def test_state_changing_views_reject_post_without_csrf_token_with_403(self):
        """POST without a CSRF token must return 403 Forbidden with enforce_csrf_checks=True."""
        for label, actor_key, url in self._state_changing_post_only_routes():
            csrf_client = self.csrf_clients[actor_key]
            with self.subTest(route=label):
                resp = csrf_client.post(url, data={})
                self.assertEqual(resp.status_code, 403, f"CSRF-less POST to {label} returned {resp.status_code}")


class ParameterTamperingRegressionTests(TestCase):
    """Verify forms ignore or reject tampered privilege, ownership, cross-course, and out-of-range fields."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.registrar_client, _ = create_authenticated_client(self.fx["users"]["registrar"])
        self.head_client, _ = create_authenticated_client(self.fx["users"]["head_a"])
        self.instructor_client, _ = create_authenticated_client(self.fx["users"]["instructor_a"])

    def test_student_create_ignores_tampered_admin_role_and_staff_flags(self):
        """Injecting role=Admin, is_staff=True, or is_superuser=True into student_create must not elevate privileges."""
        resp = self.registrar_client.post(
            reverse("kura:student_create"),
            data={
                "email": "tampered_student@kura.edu",
                "first_name": "Tamper",
                "last_name": "Test",
                "department": self.fx["departments"]["dept_a"].id,
                "current_level": AcademicLevel.YEAR_1,
                "matriculation_year": "2026",
                # Tampered privilege fields:
                "role": "Admin",
                "roles": ["Admin"],
                "is_staff": "true",
                "is_superuser": "true",
            },
        )
        self.assertEqual(resp.status_code, 302)
        created = User.objects.get(email="tampered_student@kura.edu")
        assigned_roles = set(UserRole.objects.filter(user=created).values_list("role__name", flat=True))
        self.assertEqual(assigned_roles, {"Student"})
        self.assertFalse(getattr(created, "is_staff", False))
        self.assertFalse(getattr(created, "is_superuser", False))
        self.assertFalse(StaffProfile.objects.filter(user=created).exists())

    def test_enrollment_create_rejects_unpublished_course_and_non_student_user(self):
        """Tampering course to an unpublished course or student to an instructor must be rejected."""
        before_count = Enrollment.objects.count()
        # 1. Unpublished course ID (course_a2)
        resp_unpub = self.registrar_client.post(
            reverse("kura:enrollment_create"),
            data={
                "course": self.fx["courses"]["course_a2"].id,
                "student": self.fx["users"]["student_unenrolled"].id,
                "status": EnrollmentStatus.ACTIVE,
            },
        )
        self.assertEqual(resp_unpub.status_code, 400)

        # 2. Non-student user ID (instructor_a)
        resp_non_stu = self.registrar_client.post(
            reverse("kura:enrollment_create"),
            data={
                "course": self.fx["courses"]["course_a1"].id,
                "student": self.fx["users"]["instructor_a"].id,
            },
        )
        self.assertEqual(resp_non_stu.status_code, 400)
        self.assertEqual(Enrollment.objects.count(), before_count)

    def test_course_create_rejects_other_department_id(self):
        """Department head A cannot create a course inside department B by tampering the department field."""
        before_count = Course.objects.count()
        resp = self.head_client.post(
            reverse("kura:course_create"),
            data={
                "department": self.fx["departments"]["dept_b"].id,
                "code": "MATH999",
                "title": "Tampered Dept Course",
                "description": "Should be rejected",
                "semester": "1",
                "academic_year": "2026",
                "is_published": "true",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(Course.objects.count(), before_count)

    def test_grade_entry_ignores_tampered_owner_or_course_and_rejects_out_of_range_scores(self):
        """Grade entry must ignore tampered student/course/status fields and reject scores < 0 or > max_score."""
        # Mark the submitted attempt as REQUIRES_MANUAL_GRADING so grade_entry accepts grading.
        attempt = self.fx["objects"]["attempt_submitted"]
        attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
        attempt.save(update_fields=["status"])

        grade = self.fx["objects"]["grade_draft"]
        original_score = grade.score
        grade_url = reverse("kura:grade_entry", kwargs={"attempt_id": attempt.id})

        # 1. Negative score -> rejected (400), DB unchanged.
        resp_neg = self.instructor_client.post(
            grade_url, data={"score": "-5.00", "feedback": "Negative"}
        )
        self.assertEqual(resp_neg.status_code, 400)
        grade.refresh_from_db()
        self.assertEqual(grade.score, original_score)

        # 2. Score exceeding assessment.max_score (100.00) -> rejected (400), DB unchanged.
        resp_over = self.instructor_client.post(
            grade_url, data={"score": "150.00", "feedback": "Too high"}
        )
        self.assertEqual(resp_over.status_code, 400)
        grade.refresh_from_db()
        self.assertEqual(grade.score, original_score)

        # 3. Valid score with tampered student, course, grader, and status fields -> tampered fields ignored.
        resp_tamper = self.instructor_client.post(
            grade_url,
            data={
                "score": "85.00",
                "feedback": "Updated feedback",
                # Tampered extra fields:
                "student": str(self.fx["users"]["student_2"].id),
                "course": str(self.fx["courses"]["course_b1"].id),
                "grader": str(self.fx["users"]["admin"].id),
                "status": GradeStatus.RELEASED,
            },
        )
        self.assertEqual(resp_tamper.status_code, 302)
        grade.refresh_from_db()
        self.assertEqual(grade.score, Decimal("85.00"))
        self.assertEqual(grade.student_id, self.fx["users"]["student_1"].id)
        self.assertEqual(grade.assessment.course_id, self.fx["courses"]["course_a1"].id)
        self.assertEqual(grade.grader_id, self.fx["users"]["instructor_a"].id)
        self.assertEqual(grade.status, GradeStatus.DRAFT)


class ResourceExhaustionRegressionTests(TestCase):
    """Verify upload size cap, server-side pagination maximum, and login rate-limit (429)."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.instructor_client, _ = create_authenticated_client(self.fx["users"]["instructor_a"])
        self.admin_client, _ = create_authenticated_client(self.fx["users"]["admin"])

    def test_upload_size_limit_rejects_oversized_file(self):
        """Files exceeding MAX_UPLOAD_BYTES (25 MiB) must be rejected without saving to storage."""
        self.assertEqual(MAX_UPLOAD_BYTES, 25 * 1024 * 1024)
        before_count = StoredFile.objects.count()

        # 1. Direct upload validator check at exact 25 MiB + 1 byte boundary (without allocating 25 MiB).
        class _OversizedStubFile:
            name = "oversized.pdf"
            size = MAX_UPLOAD_BYTES + 1

            def read(self):
                raise AssertionError("Oversized upload must be rejected before reading body")

        with self.assertRaises(ValidationError):
            validate_and_save_upload(_OversizedStubFile(), self.fx["users"]["instructor_a"])
        self.assertEqual(StoredFile.objects.count(), before_count)

        # 2. End-to-end HTTP upload route check with a patched small cap so the test runs instantaneously.
        upload_url = reverse(
            "kura:course_file_upload", kwargs={"course_id": self.fx["courses"]["course_a1"].id}
        )
        with patch("kura.views.MAX_UPLOAD_BYTES", 32):
            big_pdf = SimpleUploadedFile(
                "too_big.pdf", MINIMAL_PDF_BYTES + b"A" * 64, content_type="application/pdf"
            )
            resp = self.instructor_client.post(
                upload_url, data={"title": "Oversized", "file": big_pdf}
            )
            self.assertEqual(resp.status_code, 302)
        self.assertEqual(StoredFile.objects.count(), before_count)

    def test_pagination_maximum_is_capped_server_side(self):
        """Client-supplied per_page/page_size/limit parameters cannot bypass server-side page caps."""
        # Create 30 additional users so total users > 25 (the admin_users page size).
        User.objects.bulk_create(
            [
                User(email=f"pagetest_{i}@kura.edu", first_name="Page", last_name=f"User{i}")
                for i in range(30)
            ]
        )
        resp = self.admin_client.get(
            reverse("kura:admin_users"),
            data={"per_page": "10000", "page_size": "10000", "limit": "10000", "page": "1"},
        )
        self.assertEqual(resp.status_code, 200)
        page_obj = resp.context["page_obj"]
        self.assertLessEqual(len(page_obj.object_list), 25)
        self.assertEqual(page_obj.paginator.per_page, 25)

        # Extreme page number must clamp gracefully rather than erroring or dumping all rows.
        resp_far = self.admin_client.get(reverse("kura:admin_users"), data={"page": "999999"})
        self.assertEqual(resp_far.status_code, 200)
        self.assertLessEqual(len(resp_far.context["page_obj"].object_list), 25)

    @override_settings(AXES_ENABLED=True, AXES_FAILURE_LIMIT=3)
    def test_login_rate_limit_returns_429_after_n_attempts(self):
        """Repeated failed logins must trigger HTTP 429 with Retry-After once AXES_FAILURE_LIMIT is reached."""
        AccessAttempt.objects.all().delete()
        anon = Client()
        login_url = reverse("kura:login")
        target_email = self.fx["users"]["student_1"].email

        statuses = []
        last_resp = None
        for _ in range(4):
            last_resp = anon.post(
                login_url,
                data={"email": target_email, "password": "WrongPassword!999"},
                REMOTE_ADDR="198.51.100.99",
            )
            statuses.append(last_resp.status_code)

        # Attempts 1..(N-1) return 400; reaching the Nth failure triggers HTTP 429 lockout.
        self.assertIn(429, statuses, f"Expected HTTP 429 lockout within 4 attempts, got {statuses}")
        self.assertEqual(last_resp.status_code, 429)
        self.assertIn("Retry-After", last_resp)


class ErrorHandlingLeakageRegressionTests(TestCase):
    """Verify DEBUG=False renders custom 403, 404, and 500 templates without leaking internals."""

    LEAK_MARKERS = (
        "Traceback (most recent call last)",
        "RuntimeError",
        "DB_LEAK_SENTINEL",
        "SELECT * FROM",
        "kura/views.py",
        "SECRET_KEY",
        "DATABASE_PASSWORD",
    )

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student_client, _ = create_authenticated_client(self.fx["users"]["student_1"])

    def _assert_no_leakage(self, body, label):
        for marker in self.LEAK_MARKERS:
            self.assertNotIn(marker, body, f"Sensitive marker {marker!r} leaked in {label}")
        self.assertNotIn(settings.SECRET_KEY, body, f"SECRET_KEY leaked in {label}")
        self.assertNotIn(str(settings.BASE_DIR), body, f"BASE_DIR path leaked in {label}")

    @override_settings(DEBUG=False, ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
    def test_404_uses_custom_template_without_leakage(self):
        """With DEBUG=False, an unknown URL must render custom 404.html with zero internal details."""
        resp = self.student_client.get("/this-route-does-not-exist-owasp-test/")
        self.assertEqual(resp.status_code, 404)
        body = resp.content.decode("utf-8")
        self.assertIn("404 - Page not found - Kura", body)
        self.assertIn("Page not found.", body)
        self._assert_no_leakage(body, "404")

    @override_settings(DEBUG=False, ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
    def test_403_uses_custom_template_without_leakage(self):
        """With DEBUG=False, a permission denial must render custom 403.html with zero internal details."""
        resp = self.student_client.get(reverse("kura:admin_users"))
        self.assertEqual(resp.status_code, 403)
        body = resp.content.decode("utf-8")
        self.assertIn("403 - Access denied - Kura", body)
        self.assertIn("You do not have access to this page.", body)
        self._assert_no_leakage(body, "403")

    @override_settings(DEBUG=False, ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
    def test_forced_500_uses_custom_template_without_leakage(self):
        """With DEBUG=False, an unhandled view exception must render custom 500.html with zero stack trace."""
        client = Client(raise_request_exception=False)
        client.force_login(self.fx["users"]["student_1"], backend="kura.backends.KuraAuthBackend")
        session = client.session
        session.save()
        from datetime import timedelta
        from django.utils import timezone
        from .views import hash_session_token

        us = UserSession.objects.create(
            user=self.fx["users"]["student_1"],
            session_token_hash=hash_session_token(session.session_key),
            ip_address="127.0.0.1",
            user_agent="ErrorLeakTest/1.0",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        session["user_session_id"] = str(us.id)
        session.save()

        with patch(
            "kura.views.build_dashboard_attention",
            side_effect=RuntimeError("DB_LEAK_SENTINEL SELECT * FROM users WHERE id=1"),
        ):
            resp = client.get(reverse("kura:home"))

        self.assertEqual(resp.status_code, 500)
        body = resp.content.decode("utf-8")
        self.assertIn("500 - Something went wrong - Kura", body)
        self.assertIn("Something went wrong.", body)
        self._assert_no_leakage(body, "500")


class XXEOutOfScopeRegressionTests(SimpleTestCase):
    """Document and enforce that Kura does not parse XML, keeping XXE out of scope.

    If XML parsing is ever introduced into Kura runtime code, this test fails so that
    defusedxml and dedicated XXE entity-expansion rejection tests must be added.
    """

    FORBIDDEN_XML_MODULES = (
        "xml.etree",
        "xml.dom",
        "xml.sax",
        "xml.parsers",
        "lxml",
        "xmlrpc",
    )

    def test_no_xml_parser_imported_in_runtime_code(self):
        """Kura runtime modules (kura/ and config/) must not import stdlib or lxml XML parsers."""
        base = Path(settings.BASE_DIR)
        runtime_files = []
        for root_dir in (base / "kura", base / "config"):
            for py_file in root_dir.rglob("*.py"):
                rel = py_file.relative_to(base).as_posix()
                if "/migrations/" in rel or os.path.basename(rel).startswith("tests"):
                    continue
                runtime_files.append((rel, py_file))

        self.assertTrue(runtime_files, "Expected runtime Python files to scan")
        for rel, py_file in runtime_files:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for forbidden in self.FORBIDDEN_XML_MODULES:
                            self.assertFalse(
                                alias.name == forbidden or alias.name.startswith(f"{forbidden}."),
                                f"XML parser import {alias.name!r} found in {rel}; add defusedxml & XXE tests.",
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for forbidden in self.FORBIDDEN_XML_MODULES:
                        self.assertFalse(
                            node.module == forbidden or node.module.startswith(f"{forbidden}."),
                            f"XML parser import {node.module!r} found in {rel}; add defusedxml & XXE tests.",
                        )

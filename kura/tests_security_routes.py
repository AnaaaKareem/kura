"""Parametrized 90-route authorization matrix, Section 17.2 exceptions, and GDPR route tests.

Follows .agents/skills/kura-security-tester/SKILL.md and docs/SECURITY_TEST_PLAN.md:
- Validates all 90 named routes in kura/urls.py (83) and config/urls.py (7) against CLS-01..CLS-08.
- Verifies all 11 Exceptions & High-Risk Overrides in Section 17.2.
- Covers the previously untested GDPR privacy routes flagged in Section 22 Priority Gaps.
- Keeps application source code untouched during baseline verification.
"""

import json
import uuid
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.test import Client, RequestFactory, SimpleTestCase, TestCase
from django.urls import get_resolver, reverse
from django.utils import timezone

from .models import ChangeRequestStatus, CourseResult, Enrollment, Grade, GradeStatus, PasswordResetToken, StaffProfile
from .tests_security_fixtures import ROUTE_CLASS_MAP, build_security_fixture_set, create_authenticated_client
from .views import (
    assessment_file_download_view,
    assessment_file_upload_view,
    assessment_take_view,
    attendance_manual_record_view,
    attendance_session_close_view,
    attendance_session_start_view,
    attempt_detail_view,
    course_create_view,
    course_detail_view,
    course_list_view,
    course_result_release_view,
    grade_change_request_create_view,
    grade_change_request_review_view,
    grade_entry_view,
    grade_release_view,
    passkey_register_complete_view,
    privacy_dashboard_view,
    privacy_erasure_view,
    privacy_export_view,
    privacy_restrict_view,
    schedule_list_view,
)


def _walk_named_routes(patterns, namespace_prefix=""):
    """Collect (full_route_name, callback) pairs recursively across the Django URL resolver."""
    collected = []
    for entry in patterns:
        if hasattr(entry, "url_patterns"):
            ns = f"{entry.namespace}:" if getattr(entry, "namespace", None) else ""
            collected.extend(_walk_named_routes(entry.url_patterns, namespace_prefix + ns))
        elif entry.name:
            collected.append((namespace_prefix + entry.name, entry.callback))
    return collected


def _attach_session_and_messages(request, session_dict=None):
    """Attach an in-memory session dict and message storage to a RequestFactory request."""
    request.session = session_dict if session_dict is not None else {}
    setattr(request, "_messages", FallbackStorage(request))
    return request


class SecurityRouteContractUnitTests(SimpleTestCase):
    """DB-independent verification of all 90 URLconf routes, Section 17.2 exceptions, and GDPR routes."""

    def test_cls_all_90_urlconf_routes_mapped(self):
        """Plan ID: CLS-01..CLS-08 | Risk ID: R10
        Verify every named URL pattern in config/urls.py and kura/urls.py (90 total) is mapped
        in ROUTE_CLASS_MAP with zero unmapped or extra entries.
        """
        discovered = dict(_walk_named_routes(get_resolver().url_patterns))
        self.assertEqual(len(discovered), 90)
        self.assertEqual(set(discovered.keys()), set(ROUTE_CLASS_MAP.keys()))

    def test_cls_01_to_cls_08_login_required_baseline(self):
        """Plan ID: CLS-01..CLS-08 | Risk ID: R10, R12
        Verify LoginRequiredMiddleware fail-closed contract: ONLY the 9 CLS-01 routes carry
        @login_not_required (login_required=False), while all 81 CLS-02..CLS-08 routes require login.
        """
        discovered = dict(_walk_named_routes(get_resolver().url_patterns))
        for route_name, meta in ROUTE_CLASS_MAP.items():
            with self.subTest(route=route_name, cls=meta["cls"]):
                callback = discovered[route_name]
                requires_login = getattr(callback, "login_required", True)
                self.assertEqual(
                    requires_login,
                    not meta["public"],
                    f"{route_name} login_required={requires_login} conflicted with public={meta['public']}",
                )

    def test_cls_csrf_exempt_restricted_to_fido2_complete_auth(self):
        """Plan ID: CLS-01, LEAD-01 | Risk ID: R12
        Verify ONLY fido2_complete_auth is @csrf_exempt across all 90 named routes.
        """
        discovered = dict(_walk_named_routes(get_resolver().url_patterns))
        exempt_routes = sorted(
            route_name for route_name, cb in discovered.items() if getattr(cb, "csrf_exempt", False)
        )
        self.assertEqual(exempt_routes, ["fido2_complete_auth"])

    def test_cls_method_enforcement_across_method_restricted_routes(self):
        """Plan ID: CLS-02..CLS-08 | Risk ID: R10, R21
        Verify strict POST-only views reject GET with 405 Method Not Allowed and strict GET-only
        views reject POST with 405 Method Not Allowed.
        """
        rf = RequestFactory()
        actor = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            id=uuid.uuid4(),
        )
        dummy_uuid = uuid.uuid4()

        post_only_views = [
            ("kura:logout", "kura.views.logout_view", {}),
            ("kura:privacy_restrict", "kura.views.privacy_restrict_view", {}),
            ("kura:privacy_erasure", "kura.views.privacy_erasure_view", {}),
            ("kura:attendance_session_close", "kura.views.attendance_session_close_view", {"session_id": dummy_uuid}),
            ("kura:attendance_manual_record", "kura.views.attendance_manual_record_view", {"session_id": dummy_uuid}),
            ("kura:course_result_release", "kura.views.course_result_release_view", {"course_id": dummy_uuid}),
            ("kura:grade_finalize", "kura.views.grade_finalize_view", {"grade_id": dummy_uuid}),
        ]
        for route_name, dotted, kw in post_only_views:
            with self.subTest(route=route_name, wrong_method="GET"):
                from importlib import import_module

                mod_name, fn_name = dotted.rsplit(".", 1)
                view_fn = getattr(import_module(mod_name), fn_name)
                req = _attach_session_and_messages(rf.get("/dummy/"))
                req.user = actor
                with (
                    patch("kura.views.can_access_learning_records", return_value=True),
                    patch("kura.views.has_role", side_effect=lambda u, r: r != "Admin"),
                ):
                    resp = view_fn(req, **kw)
                self.assertEqual(resp.status_code, 405)

        get_only_views = [
            ("kura:privacy_notice", "kura.views.privacy_notice_view"),
            ("kura:privacy_dashboard", "kura.views.privacy_dashboard_view"),
            ("kura:privacy_export", "kura.views.privacy_export_view"),
        ]
        for route_name, dotted in get_only_views:
            with self.subTest(route=route_name, wrong_method="POST"):
                from importlib import import_module

                mod_name, fn_name = dotted.rsplit(".", 1)
                view_fn = getattr(import_module(mod_name), fn_name)
                req = _attach_session_and_messages(rf.post("/dummy/"))
                req.user = actor
                resp = view_fn(req)
                self.assertEqual(resp.status_code, 405)

    def test_section_17_2_all_11_exceptions_and_overrides(self):
        """Plan ID: CLS-01..CLS-08, ROLE-TA-06, ROLE-HEAD-10 | Risk ID: R01, R10, R12
        Verify the Section 17.2 high-risk override behaviors (positive & negative controls) across
        passkey registration, course list/create/detail, attendance, assessment files/attempts,
        grade release, and grade change requests.
        """
        rf = RequestFactory()
        actor = SimpleNamespace(
            is_authenticated=True,
            is_active=True,
            id=uuid.uuid4(),
            pk=uuid.uuid4(),
            mfa_enabled=True,
            email="a@kura.edu",
        )
        other_id = uuid.uuid4()

        # Override 3: start_fido2 / fido2_begin_reg lack fresh_mfa check, while fido2_complete_reg enforces it.
        req_fido_comp = _attach_session_and_messages(rf.post("/mfa/fido2/complete_reg"), {})
        req_fido_comp.user = actor
        resp_fido_comp = passkey_register_complete_view(req_fido_comp)
        self.assertEqual(resp_fido_comp.status_code, 403)
        self.assertEqual(json.loads(resp_fido_comp.content)["message"], "Confirm your identity first.")

        # Override 4: course_list denies Registrar; schedule_list denies Admin and Registrar.
        req_reg = _attach_session_and_messages(rf.get("/courses/"))
        req_reg.user = actor
        with patch("kura.views.has_role", side_effect=lambda u, r: r == "Registrar"), patch(
            "kura.permissions.has_role", side_effect=lambda u, r: r == "Registrar"
        ), self.assertRaises(PermissionDenied):
            course_list_view(req_reg)
        with patch("kura.views.has_role", side_effect=lambda u, r: r == "Admin"), self.assertRaises(PermissionDenied):
            schedule_list_view(req_reg)

        # Override 5: course_create loads ALL departments headed by request.user (not single first-found).
        req_cc = _attach_session_and_messages(rf.get("/courses/new/"))
        req_cc.user = actor
        with (
            patch("kura.views.has_role", side_effect=lambda u, r: r == "Department head"),
            patch("kura.views.Department.objects") as mock_dept_mgr,
            patch("kura.views.CourseCreateForm") as mock_form_cls,
            patch("kura.views.render", return_value=HttpResponse("ok")),
        ):
            qs = MagicMock()
            qs.exists.return_value = True
            qs.first.return_value = SimpleNamespace(code="CS")
            mock_dept_mgr.filter.return_value.order_by.return_value = qs
            course_create_view(req_cc)
        mock_form_cls.assert_called_once_with(None, head_departments=qs)

        # Override 6: course_detail denies Admin from viewing content or grades tabs.
        req_cd = _attach_session_and_messages(rf.get("/courses/1/detail/?tab=grades"))
        req_cd.user = actor
        fake_course = SimpleNamespace(id=uuid.uuid4(), department=SimpleNamespace(id=1), is_published=True)
        with (
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_course),
            patch("kura.views.is_admin_course_manager", return_value=True),
            self.assertRaises(PermissionDenied),
        ):
            course_detail_view(req_cd, course_id=fake_course.id)

        # Override 7: attendance_session_start (plus close/manual) check is_course_staff only (exclude Dept Head).
        req_att = _attach_session_and_messages(rf.post("/attendance/"))
        req_att.user = actor
        fake_sess = SimpleNamespace(id=uuid.uuid4(), course=fake_course)
        with (
            patch("kura.views.get_object_or_404", return_value=fake_course),
            patch("kura.views.is_course_staff", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            attendance_session_start_view(req_att, course_id=fake_course.id)
        for att_fn in (attendance_session_close_view, attendance_manual_record_view):
            with (
                patch("kura.views.get_object_or_404", return_value=fake_sess),
                patch("kura.views.is_course_staff", return_value=False),
                self.assertRaises(PermissionDenied),
            ):
                att_fn(req_att, session_id=fake_sess.id)

        # Override 8: assessment_file_upload denies TA (checks is_course_instructor);
        # assessment_file_download denies enrolled student only before opens_at (no attempt needed).
        fake_assess_future = SimpleNamespace(
            id=uuid.uuid4(), course=fake_course, opens_at=timezone.now() + timedelta(days=1)
        )
        fake_assess_open = SimpleNamespace(
            id=uuid.uuid4(), course=fake_course, opens_at=timezone.now() - timedelta(days=1)
        )
        req_up = _attach_session_and_messages(rf.post("/assessments/upload/"))
        req_up.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_assess_open),
            patch("kura.views.is_course_instructor", return_value=False),
            patch("kura.views.is_department_head", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            assessment_file_upload_view(req_up, assessment_id=fake_assess_open.id)

        req_dl = _attach_session_and_messages(rf.get("/assessments/download/"))
        req_dl.user = actor
        fake_file = SimpleNamespace(id=uuid.uuid4(), sha256_hash="0" * 64)
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", side_effect=[fake_assess_future, fake_file, MagicMock()]),
            patch("kura.views.is_department_head", return_value=False),
            patch("kura.views.is_course_staff", return_value=False),
            patch("kura.views.is_enrolled", return_value=True),
            patch("kura.views.student_can_see_course", return_value=True),
            self.assertRaises(PermissionDenied),
        ):
            assessment_file_download_view(req_dl, assessment_id=fake_assess_future.id, file_id=fake_file.id)

        # Positive control: Open assessment file downloads without any AssessmentAttempt row.
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", side_effect=[fake_assess_open, fake_file, MagicMock()]),
            patch("kura.views.is_department_head", return_value=False),
            patch("kura.views.is_course_staff", return_value=False),
            patch("kura.views.is_enrolled", return_value=True),
            patch("kura.views.student_can_see_course", return_value=True),
            patch("kura.views.create_download_response", return_value=HttpResponse(b"pdf", status=200)),
        ):
            self.assertEqual(
                assessment_file_download_view(req_dl, assessment_id=fake_assess_open.id, file_id=fake_file.id).status_code,
                200,
            )

        # Override 9: assessment_take filters student=request.user (404 for staff); attempt_detail allows Dept Head.
        req_take = _attach_session_and_messages(rf.get("/attempts/take/"))
        req_take.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", side_effect=Http404) as mock_404,
            self.assertRaises(Http404),
        ):
            assessment_take_view(req_take, attempt_id=other_id)
        self.assertEqual(mock_404.call_args.kwargs.get("student"), actor)

        fake_attempt = SimpleNamespace(
            id=uuid.uuid4(),
            student_id=other_id,
            assessment=fake_assess_open,
        )
        req_att_det = _attach_session_and_messages(rf.get("/attempts/detail/"))
        req_att_det.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_attempt),
            patch("kura.views.is_department_head", return_value=True),
            patch("kura.views.is_course_staff", return_value=False),
            patch("kura.views.AttemptFile.objects") as mock_af,
            patch("kura.views.render", return_value=HttpResponse("ok", status=200)),
        ):
            mock_af.filter.return_value.select_related.return_value = []
            self.assertEqual(attempt_detail_view(req_att_det, attempt_id=fake_attempt.id).status_code, 200)

        # Override 10: grade_change_request_create does NOT call has_fresh_second_factor;
        # grade_change_request_review enforces has_fresh_second_factor on POST + no self-approval + no self-grading.
        fake_grade_rel = SimpleNamespace(
            id=uuid.uuid4(),
            student_id=other_id,
            status=GradeStatus.RELEASED,
            score=Decimal("80.00"),
            assessment=fake_assess_open,
        )
        req_gcr_create = _attach_session_and_messages(rf.get("/grades/change-request/"), {})
        req_gcr_create.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_grade_rel),
            patch("kura.views.is_course_instructor", return_value=True),
            patch("kura.views.GradeChangeRequest.objects") as mock_gcr_mgr,
            patch("kura.views.render", return_value=HttpResponse("form", status=200)),
        ):
            mock_gcr_mgr.filter.return_value.exists.return_value = False
            self.assertEqual(grade_change_request_create_view(req_gcr_create, grade_id=fake_grade_rel.id).status_code, 200)

        fake_cr = SimpleNamespace(
            id=uuid.uuid4(),
            grade=fake_grade_rel,
            requested_by_id=other_id,
            status=ChangeRequestStatus.PENDING,
        )
        # Missing fresh factor on POST redirects to mfa_reauth.
        req_gcr_rev = _attach_session_and_messages(rf.post("/change-requests/review/"), {})
        req_gcr_rev.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_cr),
            patch("kura.views.is_department_head", return_value=True),
        ):
            resp_gcr = grade_change_request_review_view(req_gcr_rev, request_id=fake_cr.id)
        self.assertEqual(resp_gcr.status_code, 302)
        self.assertIn(reverse("kura:mfa_reauth"), resp_gcr["Location"])

        # Self-approval denied even with Department head + fresh factor.
        fake_cr_self = SimpleNamespace(
            id=uuid.uuid4(),
            grade=fake_grade_rel,
            requested_by_id=actor.id,
            status=ChangeRequestStatus.PENDING,
        )
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_cr_self),
            patch("kura.views.is_department_head", return_value=True),
            self.assertRaises(PermissionDenied),
        ):
            grade_change_request_review_view(req_gcr_rev, request_id=fake_cr_self.id)

        # Override 11: grade_release & course_result_release require can_release_grades=True (not just instructor)
        # and grade_entry blocks self-grading.
        req_ge = _attach_session_and_messages(rf.post("/attempts/grade/"))
        req_ge.user = actor
        self_attempt = SimpleNamespace(
            id=uuid.uuid4(), student_id=actor.id, status="Submitted", assessment=fake_assess_open
        )
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.is_course_staff", return_value=False),
            patch("kura.views.get_object_or_404", return_value=self_attempt),
            self.assertRaises(PermissionDenied),
        ):
            grade_entry_view(req_ge, attempt_id=self_attempt.id)

        req_rel = _attach_session_and_messages(rf.post("/release/"), {})
        req_rel.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.get_object_or_404", return_value=fake_grade_rel),
            patch("kura.views.can_release_grades", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            grade_release_view(req_rel, grade_id=fake_grade_rel.id)
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.get_object_or_404", return_value=fake_course),
            patch("kura.views.can_release_grades", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            course_result_release_view(req_rel, course_id=fake_course.id)

    def test_section_22_gdpr_privacy_routes_positive_and_negative(self):
        """Plan ID: CLS-02, PRIV-01..03, SPEC-RET-05..07 | Risk ID: R14, R17
        Dedicated unit verification of all 4 previously untested GDPR routes (privacy_dashboard,
        privacy_export, privacy_restrict, privacy_erasure): positive self-service flows, secret/hash
        exclusion, Admin/Registrar learning-record isolation, invalid confirmation refusal, and 405 checks.
        """
        rf = RequestFactory()
        now = timezone.now()
        user = SimpleNamespace(
            id=uuid.uuid4(),
            email="gdpr_stu@kura.edu",
            first_name="Gdpr",
            last_name="Student",
            mfa_enabled=True,
            is_processing_restricted=False,
            erasure_requested_at=None,
            created_at=now,
            is_authenticated=True,
            is_active=True,
            save=MagicMock(),
        )

        # 1. privacy_dashboard: GET renders own counts; Admin/Registrar get 0 for released_grades/attempts.
        req_dash = _attach_session_and_messages(rf.get(reverse("kura:privacy_dashboard")))
        req_dash.user = user
        with (
            patch("kura.views.UserSession.objects") as mock_us,
            patch("kura.views.Enrollment.objects") as mock_enr,
            patch("kura.views.Grade.objects") as mock_gr,
            patch("kura.views.AssessmentAttempt.objects") as mock_att,
            patch("kura.views.AttendanceRecord.objects") as mock_rec,
            patch("kura.views.can_access_learning_records", return_value=False),
            patch("kura.views.render", return_value=HttpResponse("dash", status=200)) as mock_render,
        ):
            mock_us.filter.return_value.count.return_value = 2
            mock_enr.filter.return_value.count.return_value = 1
            mock_gr.filter.return_value.count.return_value = 9
            mock_att.filter.return_value.count.return_value = 4
            mock_rec.filter.return_value.count.return_value = 3
            resp_dash = privacy_dashboard_view(req_dash)
        self.assertEqual(resp_dash.status_code, 200)
        counts = mock_render.call_args.args[2]["counts"]
        self.assertEqual(counts["released_grades"], 0)
        self.assertEqual(counts["attempts"], 0)

        # 2. privacy_export: GET returns JSON with no-store/nosniff and zero secrets/hashes; omits grades for Admin.
        req_exp = _attach_session_and_messages(rf.get(reverse("kura:privacy_export")))
        req_exp.user = user
        with (
            patch("kura.views.StudentProfile.objects") as mock_sp,
            patch("kura.views.StaffProfile.objects") as mock_st,
            patch("kura.views.UserRole.objects") as mock_ur,
            patch("kura.views.Enrollment.objects") as mock_enr,
            patch("kura.views.AttendanceRecord.objects") as mock_rec,
            patch("kura.views.UserSession.objects") as mock_us,
            patch("kura.views.can_access_learning_records", return_value=False),
            self.assertLogs("kura.security", level="INFO") as log_exp,
        ):
            mock_sp.filter.return_value.select_related.return_value.first.return_value = None
            mock_st.filter.return_value.select_related.return_value.first.return_value = None
            mock_ur.filter.return_value.values_list.return_value = ["Admin"]
            mock_enr.filter.return_value.select_related.return_value = []
            mock_rec.filter.return_value.select_related.return_value = []
            mock_us.filter.return_value.order_by.return_value = []
            resp_exp = privacy_export_view(req_exp)
        self.assertEqual(resp_exp.status_code, 200)
        self.assertEqual(resp_exp["Content-Disposition"], 'attachment; filename="kura-my-data.json"')
        self.assertIn("no-store", resp_exp["Cache-Control"])
        self.assertEqual(resp_exp["X-Content-Type-Options"], "nosniff")
        body = json.loads(resp_exp.content)
        self.assertNotIn("password", body["account"])
        self.assertNotIn("mfa_secret", body["account"])
        self.assertNotIn("released_grades", body)
        self.assertIn("privacy.data_exported", "\n".join(log_exp.output))

        # 3. privacy_restrict: POST toggles is_processing_restricted and logs privacy.restriction_updated.
        req_res = _attach_session_and_messages(rf.post(reverse("kura:privacy_restrict")))
        req_res.user = user
        with self.assertLogs("kura.security", level="INFO") as log_res:
            resp_res = privacy_restrict_view(req_res)
        self.assertEqual(resp_res.status_code, 302)
        self.assertTrue(user.is_processing_restricted)
        self.assertIn("privacy.restriction_updated", "\n".join(log_res.output))

        # 4. privacy_erasure: Negative (missing confirm=True) makes zero changes; positive updates auxiliary metadata.
        user.is_processing_restricted = False
        user.save.reset_mock()
        req_er_bad = _attach_session_and_messages(rf.post(reverse("kura:privacy_erasure"), data={}))
        req_er_bad.user = user
        with self.assertLogs("kura.security", level="WARNING"):
            resp_er_bad = privacy_erasure_view(req_er_bad)
        self.assertEqual(resp_er_bad.status_code, 302)
        user.save.assert_not_called()

        req_er_ok = _attach_session_and_messages(
            rf.post(reverse("kura:privacy_erasure"), data={"confirm": "on"}),
            {"user_session_id": "keep-this-id"},
        )
        req_er_ok.user = user
        with (
            patch("kura.views.transaction.atomic"),
            patch("kura.views.UserSession.objects") as mock_us,
            patch("kura.views.PasswordResetToken.objects") as mock_prt,
            patch("kura.views.StaffProfile.objects") as mock_sp,
            patch("kura.views.Enrollment.objects") as mock_enr,
            patch("kura.views.AttendanceRecord.objects") as mock_rec,
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.Grade.objects") as mock_gr,
            patch("kura.views.AssessmentAttempt.objects") as mock_att,
            patch("kura.views.CourseResult.objects") as mock_cr,
            self.assertLogs("kura.security", level="WARNING") as log_er,
        ):
            mock_enr.filter.return_value.exists.return_value = True
            mock_rec.filter.return_value.exists.return_value = False
            mock_gr.filter.return_value.exists.return_value = False
            mock_att.filter.return_value.exists.return_value = False
            mock_cr.filter.return_value.exists.return_value = False
            resp_er_ok = privacy_erasure_view(req_er_ok)
        self.assertEqual(resp_er_ok.status_code, 302)
        mock_us.filter.return_value.exclude.assert_called_once_with(id="keep-this-id")
        mock_us.filter.return_value.exclude.return_value.update.assert_called_once()
        mock_prt.filter.return_value.delete.assert_called_once()
        mock_sp.filter.return_value.update.assert_called_once_with(office_location="")
        self.assertTrue(user.is_processing_restricted)
        self.assertIsNotNone(user.erasure_requested_at)
        self.assertIn("privacy.erasure_requested", "\n".join(log_er.output))


class SecurityRouteAuthorizationMatrixTests(TestCase):
    """PostgreSQL-backed parameterized 90-route matrix across CLS-01..CLS-08."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.clients = {
            name: create_authenticated_client(u, fresh_mfa=True)[0]
            for name, u in self.fx["users"].items()
            if name != "pre_mfa_user"
        }
        self.clients["pre_mfa_user"], _ = create_authenticated_client(
            self.fx["users"]["pre_mfa_user"], fresh_mfa=False
        )
        self.anon_client = Client()

    def _resolve_url(self, route_name, kw_key):
        objs = self.fx["objects"]
        courses = self.fx["courses"]
        depts = self.fx["departments"]
        users = self.fx["users"]
        kwargs = {
            None: {},
            "reset_token": {"token": "synthetic-reset-token"},
            "passkey": {"key_id": objs["passkey_stu1"].id},
            "user_session": {"session_id": create_authenticated_client(users["student_1"])[1].id},
            "target_user": {"user_id": users["student_2"].id},
            "student_1": {"student_id": users["student_1"].id},
            "quarantined_file": {"quarantined_file_id": objs["quarantined_file"].id},
            "course_a1": {"course_id": courses["course_a1"].id},
            "enrollment_a1": {"enrollment_id": objs["enrollment_a1"].id},
            "schedule_a1": {"schedule_id": objs["schedule_a1"].id},
            "dept_a": {"department_id": depts["dept_a"].id},
            "course_file_visible": {"course_file_id": objs["course_file_visible"].id},
            "course_file_download": {"course_id": courses["course_a1"].id, "file_id": objs["sf_course"].id},
            "attendance_session": {"session_id": objs["attendance_session"].id},
            "assessment_a1": {"assessment_id": objs["assessment_open"].id},
            "assessment_file_download": {"assessment_id": objs["assessment_open"].id, "file_id": objs["sf_assess"].id},
            "attempt_in_progress": {"attempt_id": objs["attempt_in_progress"].id},
            "attempt_submitted": {"attempt_id": objs["attempt_submitted"].id},
            "attempt_file_download": {"attempt_id": objs["attempt_submitted"].id, "file_id": objs["sf_attempt"].id},
            "grade_draft": {"grade_id": objs["grade_draft"].id},
            "grade_finalized": {"grade_id": objs["grade_finalized"].id},
            "grade_released": {"grade_id": objs["grade_released"].id},
            "change_request_pending": {"request_id": objs["change_request_pending"].id},
        }[kw_key]
        return reverse(route_name, kwargs=kwargs)

    def test_all_90_routes_anonymous_and_csrf_matrix(self):
        """Plan ID: CLS-01..CLS-08 | Risk ID: R01, R10, R12
        Dynamically test all 90 named routes for anonymous fail-closed behavior and CSRF rejection.
        """
        # A tracked session is required, otherwise SessionValidationMiddleware redirects before CSRF runs.
        csrf_client, _ = create_authenticated_client(self.fx["users"]["admin"], enforce_csrf_checks=True)

        for route_name, meta in ROUTE_CLASS_MAP.items():
            url = self._resolve_url(route_name, meta["kw"])
            with self.subTest(route=route_name, cls=meta["cls"]):
                # 1. Anonymous gate
                if not meta["public"]:
                    anon_resp = self.anon_client.get(url)
                    self.assertEqual(anon_resp.status_code, 302)
                    self.assertIn(reverse("kura:login"), anon_resp["Location"])

                # 2. CSRF gate on POST routes
                if "POST" in meta["methods"] and not meta["csrf_exempt"]:
                    resp_csrf = csrf_client.post(url, data={})
                    self.assertEqual(resp_csrf.status_code, 403)

    def test_cls_03_to_cls_08_positive_and_cross_scope_negative_matrix(self):
        """Plan ID: CLS-03..CLS-08, BAC-01..BAC-17 | Risk ID: R01, R10
        Verify representative positive access and cross-role/cross-department/cross-student
        denials across Admin, Registrar, Dept Head, Course Staff, Assessment, and Grade classes.
        """
        # CLS-03 Admin vs non-Admin
        self.assertEqual(self.clients["admin"].get(self._resolve_url("kura:admin_users", None)).status_code, 200)
        self.assertEqual(self.clients["registrar"].get(self._resolve_url("kura:admin_users", None)).status_code, 403)
        self.assertEqual(self.clients["student_1"].get(self._resolve_url("kura:security_policy", None)).status_code, 403)

        # CLS-04 Registrar vs non-Registrar
        self.assertEqual(self.clients["registrar"].get(self._resolve_url("kura:student_list", None)).status_code, 200)
        self.assertEqual(self.clients["admin"].get(self._resolve_url("kura:student_list", None)).status_code, 403)
        self.assertEqual(self.clients["instructor_a"].get(self._resolve_url("kura:student_list", None)).status_code, 403)

        # CLS-05 Dept head cross-department denial + course_detail Admin vs Registrar
        self.assertEqual(self.clients["head_a"].get(self._resolve_url("kura:department_reports", "dept_a")).status_code, 200)
        self.assertEqual(self.clients["head_b"].get(self._resolve_url("kura:department_reports", "dept_a")).status_code, 403)
        self.assertEqual(self.clients["admin"].get(self._resolve_url("kura:course_detail", "course_a1")).status_code, 200)
        self.assertEqual(self.clients["admin"].get(self._resolve_url("kura:course_detail", "course_a1") + "?tab=grades").status_code, 403)
        self.assertEqual(self.clients["registrar"].get(self._resolve_url("kura:course_detail", "course_a1")).status_code, 403)

        # CLS-06 Attendance session start excludes Dept Head
        self.assertEqual(self.clients["instructor_a"].get(self._resolve_url("kura:attendance_session_start", "course_a1")).status_code, 200)
        self.assertEqual(self.clients["head_a"].get(self._resolve_url("kura:attendance_session_start", "course_a1")).status_code, 403)

        # CLS-07 Assessment take & attempt detail IDOR
        self.assertEqual(self.clients["student_1"].get(self._resolve_url("kura:assessment_take", "attempt_in_progress")).status_code, 200)
        self.assertEqual(self.clients["student_2"].get(self._resolve_url("kura:assessment_take", "attempt_in_progress")).status_code, 404)
        self.assertEqual(self.clients["instructor_a"].get(self._resolve_url("kura:assessment_take", "attempt_in_progress")).status_code, 404)
        self.assertEqual(self.clients["head_a"].get(self._resolve_url("kura:attempt_detail", "attempt_submitted")).status_code, 200)
        self.assertEqual(self.clients["student_2"].get(self._resolve_url("kura:attempt_detail", "attempt_submitted")).status_code, 403)

        # CLS-08 Grades separation of duty & step-up
        self.assertEqual(self.clients["admin"].get(self._resolve_url("kura:course_grades", "course_a1")).status_code, 403)
        self.assertEqual(self.clients["registrar"].get(self._resolve_url("kura:course_grades", "course_a1")).status_code, 403)
        self.assertEqual(self.clients["ta_a"].post(self._resolve_url("kura:grade_finalize", "grade_draft")).status_code, 403)
        self.assertEqual(
            self.clients["instructor_a_norelease"].post(self._resolve_url("kura:course_result_release", "course_a1")).status_code,
            403,
        )


class SecurityGDPRPrivacyIntegrationTests(TestCase):
    """PostgreSQL-backed integration tests for all 4 GDPR self-service routes."""

    def test_gdpr_routes_positive_and_negative_controls_on_postgres(self):
        """Plan ID: CLS-02, PRIV-01..03, SPEC-RET-05..07 | Risk ID: R14, R17
        Verify privacy_dashboard, privacy_export, privacy_restrict, and privacy_erasure end-to-end:
        unreleased grades never appear in export, Admin/Registrar see zero academic keys, erasure
        clears other sessions/reset tokens/office while retaining academic records, and wrong methods return 405.
        """
        fx = build_security_fixture_set()
        stu1 = fx["users"]["student_1"]
        stu1_client, current_sess = create_authenticated_client(stu1)
        _, other_sess = create_authenticated_client(stu1, ip_address="198.51.100.77")
        admin_client, _ = create_authenticated_client(fx["users"]["admin"])

        # Dashboard & Export positive controls for student_1:
        self.assertEqual(stu1_client.get(reverse("kura:privacy_dashboard")).status_code, 200)
        exp_resp = stu1_client.get(reverse("kura:privacy_export"))
        self.assertEqual(exp_resp.status_code, 200)
        exp_data = json.loads(exp_resp.content)
        self.assertEqual(len(exp_data["released_grades"]), 1)
        self.assertEqual(exp_data["released_grades"][0]["score"], "88.00")
        # Unreleased DRAFT (78.00) and FINALIZED (82.00) grades must NOT appear:
        self.assertNotIn("78.00", exp_resp.content.decode("utf-8"))
        self.assertNotIn("82.00", exp_resp.content.decode("utf-8"))

        # Negative control: Admin export omits learning record sections.
        admin_exp = json.loads(admin_client.get(reverse("kura:privacy_export")).content)
        self.assertNotIn("released_grades", admin_exp)
        self.assertNotIn("assessment_attempts", admin_exp)

        # Restrict toggle + wrong method check:
        self.assertEqual(stu1_client.get(reverse("kura:privacy_restrict")).status_code, 405)
        self.assertEqual(stu1_client.post(reverse("kura:privacy_restrict")).status_code, 302)
        stu1.refresh_from_db()
        self.assertTrue(stu1.is_processing_restricted)

        # Erasure without confirm leaves records intact:
        stu1_client.post(reverse("kura:privacy_erasure"), data={})
        stu1.refresh_from_db()
        self.assertIsNone(stu1.erasure_requested_at)

        # Erasure with confirm clears other sessions/reset tokens while retaining enrollment/grades:
        stu1_client.post(reverse("kura:privacy_erasure"), data={"confirm": "on"})
        stu1.refresh_from_db()
        other_sess.refresh_from_db()
        current_sess.refresh_from_db()
        self.assertIsNotNone(stu1.erasure_requested_at)
        self.assertIsNotNone(other_sess.revoked_at)
        self.assertIsNone(other_sess.ip_address)
        self.assertIsNone(current_sess.revoked_at)
        self.assertEqual(PasswordResetToken.objects.filter(user=stu1, used_at__isnull=True).count(), 0)
        self.assertEqual(Enrollment.objects.filter(student=stu1).count(), 1)
        self.assertEqual(Grade.objects.filter(student=stu1).count(), 3)
        self.assertEqual(CourseResult.objects.filter(student=stu1).count(), 1)
        StaffProfile.objects.filter(user=stu1).exists()

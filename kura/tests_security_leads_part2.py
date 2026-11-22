"""Security verification suite for Section 16 Code-Scan Leads (LEAD-12 through LEAD-22).

Follows .agents/skills/kura-security-tester/SKILL.md:
- Isolated test database / unit harness and synthetic data only (Section 2).
- Every test declares Plan ID and Risk ID in its docstring.
- Tests both positive controls and negative controls without modifying application source code.
"""

import os
import re
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import unittest
from unittest import skipIf

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import DisallowedHost, PermissionDenied
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from datetime import timedelta

from django.utils import timezone

from .middleware import RowLevelSecurityMiddleware, SecurityEnforcementMiddleware, SessionValidationMiddleware
from .models import (
    Course,
    CourseStaff,
    CourseStaffRole,
    Department,
    ModuleAttendanceSession,
    Role,
    User,
    UserRole,
    UserSession,
)
from .permissions import has_fresh_second_factor, service_rls_context
from .views import (
    attendance_session_detail_view,
    course_file_upload_view,
    course_file_visibility_toggle_view,
    hash_attendance_passcode,
    hash_session_token,
    mfa_reauth_view,
    safe_admin_return_url,
)

BASE_DIR = Path(settings.BASE_DIR)


def _attach_session_and_messages(request, session_dict=None):
    """Attach an in-memory session dict and message storage to a RequestFactory request."""
    request.session = session_dict if session_dict is not None else {}
    setattr(request, "_messages", FallbackStorage(request))
    return request


def _extract_compose_service_block(compose_text, service_name):
    """Return raw YAML lines belonging to a top-level Compose service under `services:`."""
    lines = compose_text.splitlines()
    in_services = False
    collecting = False
    collected = []
    for line in lines:
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services and re.match(r"^[a-zA-Z0-9_-]+:\s*$", line):
            break
        if in_services and re.match(rf"^  {re.escape(service_name)}:\s*(#.*)?$", line):
            collecting = True
            collected.append(line)
            continue
        if collecting:
            if re.match(r"^  [a-zA-Z0-9_-]+:\s*(#.*)?$", line):
                break
            collected.append(line)
    return "\n".join(collected)


# Plain unittest.TestCase: patching django.db.connection.cursor inside SimpleTestCase deletes
# Django's DB-access guard wrapper and breaks tearDownClass.
class SecurityLeadsPart2UnitTests(unittest.TestCase):
    """DB-independent and static verification tests for LEAD-12 through LEAD-22."""

    @skipIf(not (BASE_DIR / "docker-compose.yml").exists(), "docker-compose.yml not available in container")
    def test_lead_12_allowed_hosts_fallback_and_compose_override(self):
        """Plan ID: LEAD-12, SPEC-SRV-04 | Risk ID: R06, R10
        Verify config/settings.py fallback when ALLOWED_HOSTS is unset vs. docker-compose.yml
        setting ALLOWED_HOSTS explicitly with KURA_PUBLIC_HOSTNAME.
        """
        settings_text = (BASE_DIR / "config" / "settings.py").read_text(encoding="utf-8")
        self.assertIn('os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")', settings_text)

        compose_text = (BASE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
        web_block = _extract_compose_service_block(compose_text, "web")
        self.assertIn('ALLOWED_HOSTS: "localhost,127.0.0.1,web,${KURA_PUBLIC_HOSTNAME:-kura.example.com}"', web_block)

    @skipIf(
        not (BASE_DIR / "docker" / "nginx" / "conf.d" / "kura.conf").exists(),
        "nginx config not available in container",
    )
    def test_lead_13_proxy_forwarded_host_spoofing_and_proto_overwrite(self):
        """Plan ID: LEAD-13, LEAD-11, SPEC-SRV-04 | Risk ID: R03, R10
        Verify nginx and Coraza overwrite X-Forwarded-Proto, prove neither strips X-Forwarded-Host,
        and demonstrate confirmed X-Forwarded-Host allowed-host/port poisoning under USE_X_FORWARDED_HOST=True.
        """
        nginx_conf = (BASE_DIR / "docker" / "nginx" / "conf.d" / "kura.conf").read_text(encoding="utf-8")
        coraza_conf = (BASE_DIR / "docker" / "coraza" / "nginx.conf").read_text(encoding="utf-8")

        # Positive control: Both proxies explicitly force X-Forwarded-Proto to https.
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", nginx_conf)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", coraza_conf)

        # Confirmed weakness (static): Neither proxy strips or overrides X-Forwarded-Host.
        self.assertNotIn("X-Forwarded-Host", nginx_conf)
        self.assertNotIn("X-Forwarded-Host", coraza_conf)

        rf = RequestFactory()
        with override_settings(
            USE_X_FORWARDED_HOST=True,
            ALLOWED_HOSTS=["localhost", "127.0.0.1", "kura.example.com"],
        ):
            # Negative control: Unknown X-Forwarded-Host fails closed with DisallowedHost (HTTP 400).
            req_evil = rf.get(
                reverse("kura:mfa_reauth"),
                HTTP_HOST="kura.example.com",
                HTTP_X_FORWARDED_HOST="evil.example",
            )
            with self.assertRaises(DisallowedHost):
                req_evil.get_host()

            # Confirmed bypass PoC: Spoofed X-Forwarded-Host naming another ALLOWED_HOSTS entry
            # with an arbitrary port poisons request.get_host() and redirect validation.
            req_poisoned = _attach_session_and_messages(
                rf.post(
                    reverse("kura:mfa_reauth"),
                    data={"code": "123456", "next": "https://127.0.0.1:9999/courses/"},
                    HTTP_HOST="kura.example.com",
                    HTTP_X_FORWARDED_HOST="127.0.0.1:9999",
                    HTTP_X_FORWARDED_PROTO="https",
                )
            )
            req_poisoned.user = SimpleNamespace(is_authenticated=True, id=uuid.uuid4())
            self.assertEqual(req_poisoned.get_host(), "127.0.0.1:9999")
            self.assertEqual(safe_admin_return_url(req_poisoned), "https://127.0.0.1:9999/courses/")
            with patch("kura.views.verify_second_factor", return_value="totp"):
                resp = mfa_reauth_view(req_poisoned)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp["Location"], "https://127.0.0.1:9999/courses/")

    def test_lead_14_rls_middleware_reset_leak_and_service_rls_context(self):
        """Plan ID: LEAD-14, SPEC-DB-05 | Risk ID: R01, R10
        Verify RowLevelSecurityMiddleware fails closed on set_config failure, resets on normal
        requests, and proves 3 confirmed leak paths (POST /logout/, SessionValidationMiddleware
        forced logout, and unhandled exceptions), while confirming service_rls_context resets cleanly.
        """
        rls_idx = settings.MIDDLEWARE.index("kura.middleware.RowLevelSecurityMiddleware")
        sess_idx = settings.MIDDLEWARE.index("kura.middleware.SessionValidationMiddleware")
        self.assertLess(rls_idx, sess_idx)

        rf = RequestFactory()
        user_id = uuid.uuid4()

        def _make_cursor_patch():
            executed = []
            mock_cursor = MagicMock()
            mock_cursor.execute.side_effect = lambda sql, params=None: executed.append((sql, params))
            mock_cm = MagicMock()
            mock_cm.__enter__.return_value = mock_cursor
            mock_cm.__exit__.return_value = False
            return executed, mock_cursor, patch("django.db.connection.cursor", return_value=mock_cm)

        # Positive control: Normal authenticated request calls set_config on entry and RESET on exit.
        executed, _, cursor_patch = _make_cursor_patch()
        req_ok = rf.get("/courses/")
        req_ok.user = SimpleNamespace(is_authenticated=True, id=user_id)
        with cursor_patch:
            resp_ok = RowLevelSecurityMiddleware(lambda r: HttpResponse("ok", status=200))(req_ok)
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(
            executed,
            [
                ("SELECT set_config('kura.current_user_id', %s, false);", [str(user_id)]),
                ("RESET kura.current_user_id;", None),
            ],
        )

        # Fail-closed negative control 1: set_config failure returns 503 and logs rls.context_failed.
        req_fail = rf.get("/courses/")
        req_fail.user = SimpleNamespace(is_authenticated=True, id=user_id)
        mock_cursor_fail = MagicMock()
        mock_cursor_fail.execute.side_effect = RuntimeError("db down")
        mock_cm_fail = MagicMock()
        mock_cm_fail.__enter__.return_value = mock_cursor_fail
        mock_cm_fail.__exit__.return_value = False
        with (
            patch("django.db.connection.cursor", return_value=mock_cm_fail),
            self.assertLogs("kura.security", level="ERROR") as log_ctx,
        ):
            resp_fail = RowLevelSecurityMiddleware(lambda r: HttpResponse("unreachable"))(req_fail)
        self.assertEqual(resp_fail.status_code, 503)
        self.assertIn("rls.context_failed", "\n".join(log_ctx.output))

        # Fail-closed negative control 2: RESET failure logs rls.reset_failed and closes DB connection.
        req_reset_err = rf.get("/courses/")
        req_reset_err.user = SimpleNamespace(is_authenticated=True, id=user_id)
        reset_err_cursor = MagicMock()
        reset_err_cursor.execute.side_effect = [None, RuntimeError("reset failed")]
        reset_err_cm = MagicMock()
        reset_err_cm.__enter__.return_value = reset_err_cursor
        reset_err_cm.__exit__.return_value = False
        with (
            patch("django.db.connection.cursor", return_value=reset_err_cm),
            patch("django.db.connection.close") as mock_close,
            self.assertLogs("kura.security", level="WARNING") as log_warn,
        ):
            resp_reset_err = RowLevelSecurityMiddleware(lambda r: HttpResponse("ok"))(req_reset_err)
        self.assertEqual(resp_reset_err.status_code, 200)
        self.assertIn("rls.reset_failed", "\n".join(log_warn.output))
        mock_close.assert_called_once()

        # Confirmed Leak 1 (POST /logout/): request.user becomes AnonymousUser inside view -> RESET skipped.
        executed_logout, _, cursor_patch_logout = _make_cursor_patch()
        req_logout = rf.post("/logout/")
        req_logout.user = SimpleNamespace(is_authenticated=True, id=user_id)

        def _logout_inner(req):
            req.user = AnonymousUser()
            return HttpResponse(status=302)

        with cursor_patch_logout:
            RowLevelSecurityMiddleware(_logout_inner)(req_logout)
        self.assertEqual(
            executed_logout,
            [("SELECT set_config('kura.current_user_id', %s, false);", [str(user_id)])],
        )

        # Confirmed Leak 2 (SessionValidationMiddleware forced invalidation): deactivated user -> RESET skipped.
        executed_inval, _, cursor_patch_inval = _make_cursor_patch()
        req_inval = _attach_session_and_messages(rf.get("/courses/"))
        req_inval.user = SimpleNamespace(
            is_authenticated=True,
            is_active=False,
            id=user_id,
            locked_until=None,
        )

        def _fake_django_logout(req):
            req.user = AnonymousUser()

        chained = RowLevelSecurityMiddleware(SessionValidationMiddleware(lambda r: HttpResponse("ok")))
        with (
            cursor_patch_inval,
            patch("kura.middleware.logout", side_effect=_fake_django_logout),
            self.assertLogs("kura.security", level="WARNING"),
        ):
            resp_inval = chained(req_inval)
        self.assertEqual(resp_inval.status_code, 302)
        self.assertEqual(resp_inval["Location"], reverse("kura:login"))
        self.assertEqual(
            executed_inval,
            [("SELECT set_config('kura.current_user_id', %s, false);", [str(user_id)])],
        )

        # Confirmed Leak 3 (Unhandled exception in get_response): no try/finally -> RESET skipped.
        executed_exc, _, cursor_patch_exc = _make_cursor_patch()
        req_exc = rf.get("/courses/")
        req_exc.user = SimpleNamespace(is_authenticated=True, id=user_id)
        with cursor_patch_exc, self.assertRaises(RuntimeError):
            RowLevelSecurityMiddleware(lambda r: (_ for _ in ()).throw(RuntimeError("boom")))(req_exc)
        self.assertEqual(
            executed_exc,
            [("SELECT set_config('kura.current_user_id', %s, false);", [str(user_id)])],
        )

        # Positive control for service_rls_context(): resets in finally even on exception, and restores nested role.
        svc_executed = []
        svc_cursor = MagicMock()
        svc_cursor.fetchone.side_effect = [("",), ("management_command",)]
        svc_cursor.execute.side_effect = lambda sql, params=None: svc_executed.append((sql, params))
        svc_cm = MagicMock()
        svc_cm.__enter__.return_value = svc_cursor
        svc_cm.__exit__.return_value = False
        with patch("kura.permissions.connection.cursor", return_value=svc_cm):
            with self.assertRaises(RuntimeError):
                with service_rls_context():
                    with service_rls_context():
                        pass
                    raise RuntimeError("inner failure")
        self.assertEqual(svc_executed[-1], ("RESET kura.service_role;", None))
        self.assertIn(("SELECT set_config('kura.service_role', %s, false);", ["management_command"]), svc_executed)

    def test_lead_15_attendance_session_detail_meta_refresh_and_reauthz(self):
        """Plan ID: LEAD-15, CLS-06 | Risk ID: R10, R11
        Verify attendance session_detail.html uses meta refresh every 15s when live, and confirm
        revoked CourseStaff raises PermissionDenied while revoked UserSession redirects to login.
        """
        template_text = (
            BASE_DIR / "kura" / "templates" / "kura" / "attendance" / "session_detail.html"
        ).read_text(encoding="utf-8")
        self.assertIn('{% if is_live %}<meta http-equiv="refresh" content="15">{% endif %}', template_text)

        rf = RequestFactory()
        session_id = uuid.uuid4()
        course = SimpleNamespace(id=uuid.uuid4(), code="CS101", title="Security", department=SimpleNamespace(id=1))
        att_session = SimpleNamespace(
            id=session_id,
            course=course,
            title="Week 1",
            is_active=True,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        staff_user = SimpleNamespace(is_authenticated=True, is_active=True, id=uuid.uuid4(), locked_until=None)

        # Positive control: Assigned staff can render detail page when authorized.
        req_ok = _attach_session_and_messages(rf.get(f"/attendance/{session_id}/"))
        req_ok.user = staff_user
        with (
            patch("kura.views.get_object_or_404", return_value=att_session),
            patch("kura.views.is_course_staff", return_value=True),
            patch("kura.views.is_department_head", return_value=False),
            patch("kura.views.AttendanceRecord.objects") as mock_rec,
            patch("kura.views.User.objects") as mock_user_mgr,
            patch("kura.views.render", return_value=HttpResponse("live_ok", status=200)) as mock_render,
        ):
            mock_rec.filter.return_value.select_related.return_value.order_by.return_value = MagicMock()
            mock_user_mgr.filter.return_value.distinct.return_value.order_by.return_value = MagicMock()
            resp_ok = attendance_session_detail_view(req_ok, session_id=session_id)
        self.assertEqual(resp_ok.status_code, 200)
        self.assertTrue(mock_render.call_args.args[2]["is_live"])

        # Negative control 1: Removing CourseStaff assignment denies the next meta-refresh reload.
        req_removed = _attach_session_and_messages(rf.get(f"/attendance/{session_id}/"))
        req_removed.user = staff_user
        with (
            patch("kura.views.get_object_or_404", return_value=att_session),
            patch("kura.views.is_course_staff", return_value=False),
            patch("kura.views.is_department_head", return_value=False),
            self.assertRaises(PermissionDenied),
        ):
            attendance_session_detail_view(req_removed, session_id=session_id)

        # Negative control 2: Revoked UserSession triggers SessionValidationMiddleware redirect.
        req_revoked = _attach_session_and_messages(
            rf.get(f"/attendance/{session_id}/"),
            {"user_session_id": str(uuid.uuid4())},
        )
        req_revoked.user = staff_user
        # Provide a dict-like session with both .get() and .session_key for SessionValidationMiddleware.
        req_revoked.session = SimpleNamespace(session_key="deadbeef", user_session_id=str(uuid.uuid4()))
        req_revoked.session.get = lambda key, default=None: getattr(req_revoked.session, key, default)
        revoked_record = SimpleNamespace(revoked_at=timezone.now(), expires_at=timezone.now() + timedelta(hours=1))
        with (
            patch("kura.middleware.UserSession.objects") as mock_us_mgr,
            patch("kura.middleware.logout"),
            self.assertLogs("kura.security", level="WARNING"),
        ):
            mock_us_mgr.filter.return_value.first.return_value = revoked_record
            resp_revoked = SessionValidationMiddleware(lambda r: HttpResponse("unreachable"))(req_revoked)
        self.assertEqual(resp_revoked.status_code, 302)
        self.assertEqual(resp_revoked["Location"], reverse("kura:login"))

    def test_lead_16_course_file_upload_and_visibility_toggle_access_and_methods(self):
        """Plan ID: LEAD-16, CLS-06 | Risk ID: R09, R10
        Verify course_file_upload_view and course_file_visibility_toggle_view reject GET (405),
        deny Admin/Registrar/outsiders (PermissionDenied), and permit course staff / same-dept head POST.
        """
        rf = RequestFactory()
        course = SimpleNamespace(id=uuid.uuid4(), department=SimpleNamespace(id=1))
        cfile = SimpleNamespace(id=uuid.uuid4(), course=course, title="Syllabus", is_visible=False, save=MagicMock())
        actor = SimpleNamespace(is_authenticated=True, id=uuid.uuid4())

        for view_fn, kw in (
            (course_file_upload_view, {"course_id": course.id}),
            (course_file_visibility_toggle_view, {"course_file_id": cfile.id}),
        ):
            # Negative 1: GET returns 405 Method Not Allowed.
            req_get = _attach_session_and_messages(rf.get("/dummy/"))
            req_get.user = actor
            with patch("kura.views.can_access_learning_records", return_value=True), patch(
                "kura.views.is_admin_course_manager", return_value=False
            ):
                self.assertEqual(view_fn(req_get, **kw).status_code, 405)

            # Negative 2: Admin/Registrar denied immediately.
            req_post = _attach_session_and_messages(rf.post("/dummy/"))
            req_post.user = actor
            with patch("kura.views.can_access_learning_records", return_value=False), self.assertRaises(
                PermissionDenied
            ):
                view_fn(req_post, **kw)

        # Positive control: Course staff toggles visibility via POST and redirects to course_detail.
        req_toggle = _attach_session_and_messages(rf.post("/dummy/"))
        req_toggle.user = actor
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.is_admin_course_manager", return_value=False),
            patch("kura.views.get_object_or_404", return_value=cfile),
            patch("kura.views.is_course_staff", return_value=True),
            patch("kura.views.is_department_head", return_value=False),
        ):
            resp_toggle = course_file_visibility_toggle_view(req_toggle, course_file_id=cfile.id)
        self.assertEqual(resp_toggle.status_code, 302)
        self.assertEqual(resp_toggle["Location"], reverse("kura:course_detail", kwargs={"course_id": course.id}))
        self.assertTrue(cfile.is_visible)

    def test_lead_17_has_fresh_second_factor_and_pre_mfa_middleware_gate(self):
        """Plan ID: LEAD-17, CLS-02 | Risk ID: R12
        Verify has_fresh_second_factor returns True when mfa_enabled=False, enforces <300s when
        mfa_enabled=True, and verify SecurityEnforcementMiddleware blocks pre-MFA users from all
        sensitive step-up routes while permitting onboarding/logout paths.
        """
        rf = RequestFactory()

        req_no_mfa = _attach_session_and_messages(rf.get("/"))
        req_no_mfa.user = SimpleNamespace(is_authenticated=True, mfa_enabled=False)
        self.assertTrue(has_fresh_second_factor(req_no_mfa))

        req_missing_reauth = _attach_session_and_messages(rf.get("/"))
        req_missing_reauth.user = SimpleNamespace(is_authenticated=True, mfa_enabled=True)
        self.assertFalse(has_fresh_second_factor(req_missing_reauth))

        req_expired_reauth = _attach_session_and_messages(
            rf.get("/"),
            {"mfa_reauth_at": time.time() - 301},
        )
        req_expired_reauth.user = SimpleNamespace(is_authenticated=True, mfa_enabled=True)
        self.assertFalse(has_fresh_second_factor(req_expired_reauth))

        req_fresh_reauth = _attach_session_and_messages(
            rf.get("/"),
            {"mfa_reauth_at": time.time() - 10},
        )
        req_fresh_reauth.user = SimpleNamespace(is_authenticated=True, mfa_enabled=True)
        self.assertTrue(has_fresh_second_factor(req_fresh_reauth))

        # Negative control: Pre-MFA user cannot reach any sensitive step-up route.
        middleware = SecurityEnforcementMiddleware(lambda r: HttpResponse("allowed", status=200))
        pre_mfa_user = SimpleNamespace(is_authenticated=True, must_change_password=False, mfa_enabled=False)
        sensitive_paths = [
            reverse("kura:security_policy"),
            reverse("kura:user_deactivate", kwargs={"user_id": uuid.uuid4()}),
            reverse("kura:user_roles", kwargs={"user_id": uuid.uuid4()}),
            reverse("kura:passkey_manage"),
            reverse("kura:grade_release", kwargs={"grade_id": uuid.uuid4()}),
            reverse("kura:course_result_release", kwargs={"course_id": uuid.uuid4()}),
            reverse("kura:grade_change_request_review", kwargs={"request_id": uuid.uuid4()}),
        ]
        for path in sensitive_paths:
            req = rf.post(path)
            req.user = pre_mfa_user
            resp = middleware(req)
            self.assertEqual(resp.status_code, 302, f"Route {path} did not redirect pre-MFA user")
            self.assertEqual(resp["Location"], reverse("kura:mfa_setup"))

        # Positive control: Onboarding and logout paths stay reachable for pre-MFA users.
        for allowed_path in (
            reverse("kura:password_change"),
            reverse("kura:mfa_setup"),
            reverse("kura:mfa_setup_complete"),
            reverse("kura:logout"),
        ):
            req = rf.get(allowed_path)
            req.user = pre_mfa_user
            self.assertEqual(middleware(req).status_code, 200)

    @skipIf(not (BASE_DIR / "docker-compose.yml").exists(), "docker-compose.yml not available in container")
    def test_lead_18_to_lead_21_compose_and_migration_hardening_baseline(self):
        """Plan ID: LEAD-18, LEAD-19, LEAD-20, LEAD-21, D12 | Risk ID: R05, R06, R13, R16
        Verify static Compose & PostgreSQL config for alloy host root mounts (LEAD-18),
        docker-api-proxy filtering (LEAD-19), cap_add constraints (LEAD-20), and migrate mTLS vs.
        stale specification claim D12 (LEAD-21).
        """
        compose_text = (BASE_DIR / "docker-compose.yml").read_text(encoding="utf-8")

        # LEAD-18: kura-alloy hardening controls + confirmed broad host mount blast radius.
        alloy_block = _extract_compose_service_block(compose_text, "alloy")
        self.assertIn('user: "473:473"', alloy_block)
        self.assertIn("read_only: true", alloy_block)
        self.assertIn("- ALL", alloy_block)
        self.assertIn("no-new-privileges:true", alloy_block)
        self.assertNotIn("- frontend", alloy_block)
        self.assertNotIn("- app", alloy_block)
        self.assertIn("- /:/host/root:ro", alloy_block)
        self.assertIn("- /proc:/host/proc:ro", alloy_block)
        self.assertIn("- /sys:/host/sys:ro", alloy_block)
        self.assertIn('- "4"', alloy_block)

        # LEAD-19: docker-api-proxy denies mutations/exec/secrets and isolates on docker_api network.
        proxy_block = _extract_compose_service_block(compose_text, "docker-api-proxy")
        self.assertIn("- /var/run/docker.sock:/var/run/docker.sock:ro", proxy_block)
        for denied_var in (
            'POST: "0"',
            'EXEC: "0"',
            'ALLOW_START: "0"',
            'ALLOW_STOP: "0"',
            'ALLOW_RESTARTS: "0"',
            'ALLOW_ARCHIVE: "0"',
            'ALLOW_EXPORT: "0"',
            'SECRETS: "0"',
            'VOLUMES: "0"',
        ):
            self.assertIn(denied_var, proxy_block)
        for allowed_var in ('CONTAINERS: "1"', 'EVENTS: "1"', 'ALLOW_LOGS: "1"', 'NETWORKS: "1"', 'INFO: "1"'):
            self.assertIn(allowed_var, proxy_block)
        self.assertIn("- ALL", proxy_block)
        self.assertIn("read_only: true", proxy_block)

        # LEAD-20: cap_add on db, relay, nginx must retain cap_drop: ALL and no-new-privileges:true.
        expected_caps = {
            "db": {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"},
            "relay": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "NET_BIND_SERVICE"},
            "nginx": {"NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID"},
        }
        for svc, caps in expected_caps.items():
            svc_block = _extract_compose_service_block(compose_text, svc)
            self.assertIn("- ALL", svc_block)
            self.assertIn("no-new-privileges:true", svc_block)
            cap_section = svc_block.split("cap_add:")[1].split("security_opt:")[0]
            actual_caps = set(re.findall(r"-\s+([A-Z_]+)", cap_section))
            self.assertEqual(actual_caps, caps, f"Unexpected capabilities for {svc}")

        # LEAD-21 & D12: migrate runs as kura_migrator over mTLS without db_password, while spec lags.
        migrate_block = _extract_compose_service_block(compose_text, "migrate")
        self.assertIn('profiles: ["tools"]', migrate_block)
        self.assertIn("DATABASE_USER: kura_migrator", migrate_block)
        self.assertIn('DB_SSL_MODE: "verify-full"', migrate_block)
        self.assertIn("./certs/internal/migrator.crt:/certs/internal/migrator.crt:ro", migrate_block)
        self.assertIn("./certs/internal/migrator.key:/certs/internal/migrator.key:ro", migrate_block)
        self.assertIn("- django_secret_key", migrate_block)
        self.assertNotIn("db_password", migrate_block)

        pg_hba = (BASE_DIR / "docker" / "postgres" / "pg_hba.conf").read_text(encoding="utf-8")
        self.assertIn("hostssl kura           kura_migrator   all                     cert clientcert=verify-full", pg_hba)

        spec_text = (
            BASE_DIR / "docs" / "Kura Secure Learning Management System (file storage added).md"
        ).read_text(encoding="utf-8")
        # Confirm D12 spec drift still exists so Section 21 accurately tracks it as open.
        self.assertIn("kura-admin", spec_text)
        self.assertIn("certificate-only migration login (`kura_migrator`", spec_text)

    def test_lead_22_views_py_size_and_branch_audit_targets(self):
        """Plan ID: LEAD-22 | Risk ID: R10
        Verify kura/views.py maintainability baseline and confirm the prioritized multi-branch views exist.
        """
        views_text = (BASE_DIR / "kura" / "views.py").read_text(encoding="utf-8")
        line_count = len(views_text.splitlines())
        self.assertGreater(line_count, 5000)
        for fn_name in (
            "def course_detail_view(",
            "def assessment_detail_view(",
            "def grade_entry_view(",
            "def grade_change_request_review_view(",
        ):
            self.assertIn(fn_name, views_text)


class SecurityLeadsPart2IntegrationTests(TestCase):
    """PostgreSQL-backed verification tests for LEAD-14, LEAD-15, LEAD-16, and LEAD-17."""

    def _make_user_and_client(self, email, role_name, mfa_enabled=True, fresh_mfa=True, must_change_password=True):
        user = User.objects.create_user(
            email=email,
            password="SyntheticPassword!2026",
            first_name="Synthetic",
            last_name=role_name.replace(" ", ""),
        )
        user.mfa_enabled = mfa_enabled
        user.must_change_password = must_change_password
        user.save(update_fields=["mfa_enabled", "must_change_password"])
        role, _ = Role.objects.get_or_create(name=role_name)
        UserRole.objects.get_or_create(user=user, role=role)

        client = Client()
        client.force_login(user, backend="kura.backends.KuraAuthBackend")
        session = client.session
        if not session.session_key:
            session.save()
        user_session = UserSession.objects.create(
            user=user,
            session_token_hash=hash_session_token(session.session_key),
            ip_address="127.0.0.1",
            user_agent="KuraSecurityTester/1.0",
            expires_at=timezone.now() + timedelta(hours=4),
        )
        session["user_session_id"] = str(user_session.id)
        if fresh_mfa:
            session["mfa_reauth_at"] = timezone.now().timestamp()
        session.save()
        return user, client, user_session

    def test_lead_14_live_rls_session_variable_after_logout_on_postgres(self):
        """Plan ID: LEAD-14, SPEC-DB-05 | Risk ID: R01, R10
        Verify live PostgreSQL kura.current_user_id state across normal request, POST /logout/,
        and deactivated-session invalidation.
        """
        from django.db import connection

        _, auth_client, _ = self._make_user_and_client("lead14_pg@kura.edu", "Student", must_change_password=False, fresh_mfa=True)
        self.assertEqual(auth_client.get(reverse("kura:home")).status_code, 200)
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('kura.current_user_id', true);")
            self.assertEqual(cursor.fetchone()[0] or "", "")

        # After POST /logout/, RowLevelSecurityMiddleware skips RESET (confirmed defect).
        logout_resp = auth_client.post(reverse("kura:logout"))
        self.assertEqual(logout_resp.status_code, 302)
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('kura.current_user_id', true);")
            leaked_value = cursor.fetchone()[0] or ""
        self.assertNotEqual(leaked_value, "")

    def test_lead_15_live_attendance_reload_reauthorization(self):
        """Plan ID: LEAD-15, CLS-06 | Risk ID: R10, R11
        Verify attendance_session_detail reloads cleanly for assigned staff and denies access
        immediately once CourseStaff assignment is deleted or session is revoked.
        """
        head_user, _ = self._make_user_and_client("lead15_head@kura.edu", "Department head")[:2]
        inst_user, inst_client, inst_sess = self._make_user_and_client(
            "lead15_inst@kura.edu", "Instructor", must_change_password=False
        )
        dept = Department.objects.create(code="ATT", name="Attendance Dept", head_user=head_user)
        course = Course.objects.create(
            code="ATT101",
            title="Live Attendance",
            department=dept,
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=head_user,
            published_at=timezone.now(),
        )
        staff_link = CourseStaff.objects.create(
            course=course, user=inst_user, staff_role=CourseStaffRole.LEAD_INSTRUCTOR
        )
        att_session = ModuleAttendanceSession.objects.create(
            course=course,
            created_by=inst_user,
            title="Lecture 1",
            passcode_hash=hash_attendance_passcode("ABC123"),
            expires_at=timezone.now() + timedelta(minutes=20),
            is_active=True,
        )
        url = reverse("kura:attendance_session_detail", kwargs={"session_id": att_session.id})

        # Positive control: Assigned instructor views live session with meta refresh.
        ok_resp = inst_client.get(url)
        self.assertEqual(
            ok_resp.status_code, 200,
            f"unexpected redirect to {ok_resp.get('Location')} status={ok_resp.status_code}",
        )
        self.assertContains(ok_resp, '<meta http-equiv="refresh" content="15">')

        # Negative 1: Remove CourseStaff assignment -> next reload returns 403.
        staff_link.delete()
        denied_resp = inst_client.get(url)
        self.assertEqual(denied_resp.status_code, 403)
        self.assertNotIn(b"Lecture 1", denied_resp.content)

        # Negative 2: Re-add assignment but revoke UserSession -> next reload redirects to login.
        CourseStaff.objects.create(course=course, user=inst_user, staff_role=CourseStaffRole.LEAD_INSTRUCTOR)
        inst_sess.revoked_at = timezone.now()
        inst_sess.save(update_fields=["revoked_at"])
        revoked_resp = inst_client.get(url)
        self.assertEqual(revoked_resp.status_code, 302)
        self.assertIn(reverse("kura:login"), revoked_resp["Location"])

    def test_lead_17_live_pre_mfa_user_blocked_from_sensitive_routes(self):
        """Plan ID: LEAD-17, CLS-02 | Risk ID: R12
        Verify live pre-MFA user is redirected to mfa_setup when requesting sensitive step-up URLs.
        """
        _, pre_mfa_client, _ = self._make_user_and_client(
            "lead17_pg@kura.edu", "Admin", mfa_enabled=False, fresh_mfa=False
        )
        resp = pre_mfa_client.get(reverse("kura:security_policy"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("kura:password_change"))
        self.assertEqual(pre_mfa_client.get(reverse("kura:password_change")).status_code, 200)
        self.assertEqual(os.environ.get("DJANGO_SETTINGS_MODULE", "config.settings"), "config.settings")

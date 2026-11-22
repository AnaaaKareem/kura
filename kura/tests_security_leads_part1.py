"""Security verification suite for Section 16 Code-Scan Leads (LEAD-01 through LEAD-11).

Follows .agents/skills/kura-security-tester/SKILL.md:
- Isolated test database and synthetic fixtures only (Section 2).
- Every test declares Plan ID and Risk ID in its docstring.
- Tests both positive controls (authorized/expected behavior) and negative controls
  (unauthorized/malformed/cross-tenant denial with zero data leakage).
- Keeps application source code untouched during baseline verification.
"""

import hashlib
import io
import json
import socket
import urllib.error
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.cache import caches
from django.core.exceptions import DisallowedRedirect, PermissionDenied, ValidationError
from django.http import HttpResponse, JsonResponse
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from .logging_utils import get_client_ip
from .middleware import RateLimitMiddleware, SecurityEnforcementMiddleware
from .models import (
    Course,
    Department,
    Role,
    User,
    UserRole,
    UserSession,
)
from .views import (
    check_breached_password,
    department_reports_view,
    hash_session_token,
    mfa_login_callback,
    mfa_reauth_view,
    passkey_auth_complete_view,
    safe_admin_return_url,
    safe_csv_cell,
    scan_file_for_malware,
)


def _attach_session_and_messages(request, session_dict=None):
    """Attach an in-memory session dict and message storage to a RequestFactory request."""
    request.session = session_dict if session_dict is not None else {}
    setattr(request, "_messages", FallbackStorage(request))
    return request


class SecurityLeadsPart1UnitTests(SimpleTestCase):
    """DB-independent verification tests for LEAD-01 through LEAD-11 (runs without PostgreSQL)."""

    def test_lead_01_passkey_auth_complete_csrf_exempt_and_pre_mfa_binding(self):
        """Plan ID: LEAD-01, CLS-01, AUTH-09 | Risk ID: R12
        Verify passkey_auth_complete_view and mfa_login_callback reject cross-site POSTs without
        challenge, missing pre-MFA sessions, and cross-user pre-MFA sessions with generic errors,
        while allowing a valid pending user login.
        """
        rf = RequestFactory()
        user_a = SimpleNamespace(
            id=uuid.uuid4(),
            email="lead01_a@kura.edu",
            is_active=True,
            locked_until=None,
            must_change_password=False,
            save=MagicMock(),
        )
        user_b = SimpleNamespace(
            id=uuid.uuid4(),
            email="lead01_b@kura.edu",
            is_active=True,
            locked_until=None,
            must_change_password=False,
            save=MagicMock(),
        )

        # Negative 1: Cross-site POST with no session fido2_state returns generic normalized JSON error.
        req_no_state = _attach_session_and_messages(
            rf.post(
                reverse("fido2_complete_auth"),
                data=json.dumps({"id": "forged"}),
                content_type="application/json",
                HTTP_ORIGIN="https://evil.example",
            )
        )
        req_no_state.user = AnonymousUser()
        with patch("mfa.FIDO2.User_Keys.objects") as mock_keys:
            mock_qs = MagicMock()
            mock_qs.exists.return_value = False
            mock_qs.__iter__.return_value = iter([])
            mock_keys.filter.return_value = mock_qs
            resp_no_state = passkey_auth_complete_view(req_no_state)
        self.assertEqual(resp_no_state.status_code, 500)
        self.assertEqual(
            json.loads(resp_no_state.content),
            {"status": "ERR", "message": "Sign-in failed. Please start again."},
        )

        # Negative 2: mfa_login_callback with no pre_mfa_user_id in session fails closed.
        req_no_pre = _attach_session_and_messages(rf.post(reverse("fido2_complete_auth")))
        req_no_pre.user = AnonymousUser()
        with patch("kura.views.get_object_or_404", return_value=user_a), patch("kura.views.login") as mock_login:
            resp_no_pre = mfa_login_callback(req_no_pre, username=user_a.email)
        self.assertEqual(resp_no_pre.status_code, 302)
        self.assertEqual(resp_no_pre["Location"], reverse("kura:login"))
        mock_login.assert_not_called()

        # Negative 3: Pre-MFA session belongs to user_a, but passkey assertion resolves to user_b.
        req_mismatch = _attach_session_and_messages(
            rf.post(reverse("fido2_complete_auth")),
            {
                "pre_mfa_user_id": str(user_a.id),
                "pre_mfa_started_at": timezone.now().timestamp(),
                "base_username": user_a.email,
            },
        )
        req_mismatch.user = AnonymousUser()
        with patch("kura.views.get_object_or_404", return_value=user_b), patch("kura.views.login") as mock_login:
            resp_mismatch = mfa_login_callback(req_mismatch, username=user_b.email)
        self.assertEqual(resp_mismatch.status_code, 302)
        self.assertEqual(resp_mismatch["Location"], reverse("kura:login"))
        self.assertNotIn("pre_mfa_user_id", req_mismatch.session)
        mock_login.assert_not_called()

        # Positive control: Matching pre_mfa_user_id within 300s window completes login.
        req_ok = _attach_session_and_messages(
            rf.post(reverse("fido2_complete_auth")),
            {
                "pre_mfa_user_id": str(user_a.id),
                "pre_mfa_started_at": timezone.now().timestamp(),
                "base_username": user_a.email,
            },
        )
        req_ok.user = AnonymousUser()
        with (
            patch("kura.views.get_object_or_404", return_value=user_a),
            patch("kura.views.login") as mock_login,
            patch("kura.views.create_user_session") as mock_create_session,
        ):
            resp_ok = mfa_login_callback(req_ok, username=user_a.email)
        self.assertEqual(resp_ok.status_code, 302)
        self.assertEqual(resp_ok["Location"], reverse("kura:home"))
        mock_login.assert_called_once()
        mock_create_session.assert_called_once_with(req_ok, user_a, method="passkey")
        self.assertNotIn("pre_mfa_user_id", req_ok.session)

    def test_lead_02_mfa_reset_cookie_does_not_mutate_server_state_or_logout_user(self):
        """Plan ID: LEAD-02, CLS-01, SESS-06 | Risk ID: R11, R12
        Verify GET /mfa/reset raises DisallowedRedirect (unhandled crash because settings.LOGIN_URL
        is 'kura:login'), leaves server-side session state untouched, and does not log out a user.
        """
        from mfa import views as mfa_views

        rf = RequestFactory()
        session_state = {"_auth_user_id": "user-123", "user_session_id": "sess-456"}
        req = _attach_session_and_messages(rf.get(reverse("mfa_reset_cookie")), dict(session_state))
        req.COOKIES["base_username"] = "lead02@kura.edu"

        # Confirmed weakness: mfa.views.reset_cookie passes settings.LOGIN_URL ("kura:login")
        # directly to HttpResponseRedirect without reverse/resolve_url, crashing with DisallowedRedirect.
        with self.assertRaisesRegex(DisallowedRedirect, "Unsafe redirect to URL with protocol 'kura'"):
            mfa_views.reset_cookie(req)

        # Negative control: Server-side session dictionary is untouched.
        self.assertEqual(req.session, session_state)

    def test_lead_03_public_passkey_begin_auth_without_pre_mfa_session(self):
        """Plan ID: LEAD-03, CLS-01, AUTH-09 | Risk ID: R12
        Verify GET /mfa/fido2/auth and GET /mfa/fido2/begin_auth without a pre-MFA session
        leak zero credential IDs and zero account-existence signals, while confirming that
        FIDO2.authenticate_begin still issues an empty-allowCredentials challenge.
        """
        from mfa import FIDO2

        rf = RequestFactory()
        req_auth = _attach_session_and_messages(rf.get(reverse("fido2_auth")))
        req_auth.user = AnonymousUser()
        resp_auth = FIDO2.auth(req_auth)
        self.assertEqual(resp_auth.status_code, 200)

        req_begin = _attach_session_and_messages(rf.get(reverse("fido2_begin_auth")))
        req_begin.user = AnonymousUser()
        with patch("mfa.FIDO2.getUserCredentials") as mock_get_creds:
            resp_begin = FIDO2.authenticate_begin(req_begin)

        self.assertEqual(resp_begin.status_code, 200)
        mock_get_creds.assert_not_called()
        data = json.loads(resp_begin.content)
        public_key_opts = data.get("publicKey", {})

        # Negative control: Zero credential IDs or account signals returned.
        self.assertEqual(public_key_opts.get("allowCredentials", []), [])
        # Confirmed LEAD-03 finding: challenge and fido2_state are still generated without pre-MFA session.
        self.assertIn("challenge", public_key_opts)
        self.assertIn("fido2_state", req_begin.session)

    def test_lead_04_media_url_bypass_serves_no_content_and_redirects_other_routes(self):
        """Plan ID: LEAD-04, CLS-02 | Risk ID: R10, R12
        Verify SecurityEnforcementMiddleware redirects pre-MFA users away from application routes,
        while /media/* resolves to no route in URLconf (Resolver404) and sets Cache-Control: no-store.
        """
        from django.urls import Resolver404, resolve

        rf = RequestFactory()
        pre_mfa_user = SimpleNamespace(is_authenticated=True, must_change_password=False, mfa_enabled=False)

        # Negative control: Protected route redirects pre-MFA user to mfa_setup.
        middleware = SecurityEnforcementMiddleware(lambda req: HttpResponse("NotFound", status=404))
        req_home = rf.get(reverse("kura:home"))
        req_home.user = pre_mfa_user
        resp_home = middleware(req_home)
        self.assertEqual(resp_home.status_code, 302)
        self.assertEqual(resp_home["Location"], reverse("kura:mfa_setup"))
        self.assertIn("no-store", resp_home["Cache-Control"])

        # Positive verification for LEAD-04: No URL pattern exists under /media/ and response carries no-store.
        with self.assertRaises(Resolver404):
            resolve("/media/secret.pdf")
        req_media = rf.get("/media/secret.pdf")
        req_media.user = pre_mfa_user
        resp_media = middleware(req_media)
        self.assertEqual(resp_media.status_code, 404)
        self.assertIn("no-store", resp_media["Cache-Control"])

    @override_settings(
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
            "ratelimit": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "rl-test"},
        }
    )
    def test_lead_05_and_lead_06_ratelimit_non_atomic_race_and_ttl_extension(self):
        """Plan ID: LEAD-05, LEAD-06, SPEC-SRV-07 | Risk ID: R04
        Verify RateLimitMiddleware enforces the 20/min upload limit sequentially, resets the 60s TTL
        on every allowed hit 1..20 (LEAD-06), and permits burst overshoot when concurrent requests
        read the same non-atomic counter value (LEAD-05).
        """
        ratelimit_cache = caches["ratelimit"]
        ratelimit_cache.clear()

        user_id = uuid.uuid4()
        user = SimpleNamespace(is_authenticated=True, id=user_id)
        upload_path = reverse("kura:course_file_upload", kwargs={"course_id": uuid.uuid4()})
        rf = RequestFactory()
        middleware = RateLimitMiddleware(lambda req: HttpResponse("OK", status=200))

        def _make_upload_request():
            req = rf.post(upload_path)
            req.user = user
            req.META["REMOTE_ADDR"] = "198.51.100.55"
            return req

        # 1. Sequential positive & negative control: 20 pass (200), 21st returns 429.
        for i in range(20):
            self.assertEqual(middleware(_make_upload_request()).status_code, 200, f"Hit {i + 1} failed")
        blocked = middleware(_make_upload_request())
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked["Retry-After"], "60")

        # 2. LEAD-06 verification: each allowed hit calls cache.set(..., timeout=60);
        # rejected 429 hits do not call cache.set().
        ratelimit_cache.clear()
        with patch.object(type(ratelimit_cache), "set", wraps=ratelimit_cache.set) as mock_set:
            for _ in range(20):
                self.assertEqual(middleware(_make_upload_request()).status_code, 200)
            self.assertEqual(mock_set.call_count, 40)
            for call_args in mock_set.call_args_list:
                self.assertEqual(call_args.kwargs.get("timeout"), 60)

            self.assertEqual(middleware(_make_upload_request()).status_code, 429)
            self.assertEqual(mock_set.call_count, 40)

        # 3. LEAD-05 confirmed race proof: 10 parallel requests reading counter=19 all pass (29 > 20).
        ratelimit_cache.clear()
        user_key = f"rate_limit_upload_{user_id}"
        ip_key = "rate_limit_upload_ip_198.51.100.55"
        stale_snapshot = {user_key: 19, ip_key: 19}
        accepted_in_burst = 0
        with patch.object(type(ratelimit_cache), "get", side_effect=lambda k, default=0: stale_snapshot.get(k, default)):
            for _ in range(10):
                if middleware(_make_upload_request()).status_code == 200:
                    accepted_in_burst += 1

        self.assertEqual(accepted_in_burst, 10)
        self.assertEqual(ratelimit_cache.get(user_key), 20)

    def test_lead_07_get_client_ip_trust_proxy_header_and_fallback(self):
        """Plan ID: LEAD-07, SPEC-SRV-06 | Risk ID: R02, R04
        Verify get_client_ip ignores X-Real-IP when TRUST_PROXY_IP_HEADER=False, uses valid
        X-Real-IP when TRUST_PROXY_IP_HEADER=True, and falls back to REMOTE_ADDR on malformed input.
        """
        rf = RequestFactory()
        with override_settings(TRUST_PROXY_IP_HEADER=False):
            req = rf.get("/login/", REMOTE_ADDR="10.0.0.5", HTTP_X_REAL_IP="203.0.113.99")
            self.assertEqual(get_client_ip(req), "10.0.0.5")

        with override_settings(TRUST_PROXY_IP_HEADER=True):
            req_valid = rf.get("/login/", REMOTE_ADDR="10.0.0.5", HTTP_X_REAL_IP=" 203.0.113.99 ")
            self.assertEqual(get_client_ip(req_valid), "203.0.113.99")
            for bad_header in ("not-an-ip", "203.0.113.1, 198.51.100.2", "127.0.0.1\nmalicious=1", ""):
                req_bad = rf.get("/login/", REMOTE_ADDR="10.0.0.5", HTTP_X_REAL_IP=bad_header)
                self.assertEqual(get_client_ip(req_bad), "10.0.0.5")

    def test_lead_08_safe_csv_cell_and_department_reports_content_disposition(self):
        """Plan ID: LEAD-08, CLS-05, ROLE-HEAD-06 | Risk ID: R03, R10, R14
        Verify safe_csv_cell escapes standard formula prefixes (=, +, -, @, \\t, \\r), enforce
        cross-department denial (PermissionDenied), and prove the two confirmed edge cases:
        leading LF ('\\n=1+1') in safe_csv_cell and unescaped quotes in Department.code Content-Disposition.
        """
        # Positive control: Standard 6 prefixes are neutralized with a leading single quote.
        for payload in ("=CMD|' /C calc'!A0", "+1+1", "-1+1", "@SUM(1,1)", "\t=1+1", "\r=1+1"):
            self.assertEqual(safe_csv_cell(payload), "'" + payload)
        self.assertEqual(safe_csv_cell("Normal Course Title"), "Normal Course Title")

        # Confirmed Edge Case A: Leading LF ('\n=1+1') is NOT escaped by safe_csv_cell.
        self.assertEqual(safe_csv_cell("\n=1+1"), "\n=1+1")

        # Negative control: Cross-department head is denied with PermissionDenied.
        rf = RequestFactory()
        req_denied = rf.get("/departments/1/reports/?format=csv")
        req_denied.user = SimpleNamespace(is_authenticated=True, id=uuid.uuid4())
        fake_dept = SimpleNamespace(id=1, code='cs";x="', name="Injected Dept")
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_dept),
            patch("kura.views.is_department_head", return_value=False),
        ):
            with self.assertRaises(PermissionDenied):
                department_reports_view(req_denied, department_id=1)

        # Confirmed Edge Case B: Department.code with quotes/semicolons injects into Content-Disposition.
        req_ok = rf.get("/departments/1/reports/?format=csv")
        req_ok.user = SimpleNamespace(is_authenticated=True, id=uuid.uuid4())
        fake_course = SimpleNamespace(
            id=uuid.uuid4(),
            code="=CS101",
            title="@Malicious",
            semester="1",
            academic_year=2026,
            is_published=True,
        )
        with (
            patch("kura.views.can_access_learning_records", return_value=True),
            patch("kura.views.has_role", return_value=False),
            patch("kura.views.get_object_or_404", return_value=fake_dept),
            patch("kura.views.is_department_head", return_value=True),
            patch("kura.views.Course.objects") as mock_course_mgr,
            patch("kura.views.Enrollment.objects") as mock_enroll_mgr,
            patch("kura.views.CourseResult.objects") as mock_res_mgr,
        ):
            mock_course_mgr.filter.return_value.order_by.return_value = [fake_course]
            mock_enroll_mgr.filter.return_value.values_list.return_value.annotate.return_value = []
            mock_res_mgr.filter.return_value.values_list.return_value.annotate.return_value = []
            mock_res_mgr.filter.return_value.exists.return_value = False
            resp_csv = department_reports_view(req_ok, department_id=1)

        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("'=CS101,'@Malicious", resp_csv.content.decode("utf-8"))
        self.assertEqual(resp_csv["Content-Disposition"], 'attachment; filename="cs";x="_report.csv"')

    def test_lead_09_check_breached_password_fixed_host_prefix_and_fail_open(self):
        """Plan ID: LEAD-09, SPEC-AUTH-03, SPEC-AUTH-04 | Risk ID: R02, R08, R23
        Verify check_breached_password sends only the 5-character SHA-1 prefix to
        https://api.pwnedpasswords.com/range/<5-hex>, rejects matching suffixes, and fails open
        with auth.breach_check.unavailable on network error without logging secrets.
        """
        captured_requests = []

        class _FakeResponse(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        sha1_hex = hashlib.sha1(b"Password123!@#", usedforsecurity=False).hexdigest().upper()
        prefix, suffix = sha1_hex[:5], sha1_hex[5:]

        class _FakeOpener:
            def open(self, req, timeout=None):
                captured_requests.append((req.full_url, timeout))
                return _FakeResponse(f"{suffix}:42\r\n".encode("utf-8"))

        with patch("urllib.request.build_opener", return_value=_FakeOpener()):
            with self.assertRaises(ValidationError) as ctx:
                check_breached_password("Password123!@#")
            self.assertEqual(ctx.exception.code, "password_breached")

        self.assertEqual(captured_requests, [(f"https://api.pwnedpasswords.com/range/{prefix}", 2.5)])

        class _FailingOpener:
            def open(self, req, timeout=None):
                raise urllib.error.URLError("proxy unreachable")

        with (
            patch("urllib.request.build_opener", return_value=_FailingOpener()),
            self.assertLogs("kura.security", level="WARNING") as log_ctx,
        ):
            check_breached_password("Password123!@#")

        log_output = "\n".join(log_ctx.output)
        self.assertIn("auth.breach_check.unavailable", log_output)
        self.assertNotIn("Password123!@#", log_output)
        self.assertNotIn(suffix, log_output)

    @override_settings(CLAMAV_REQUIRED=True)
    def test_lead_10_clamav_instream_fails_closed_on_timeout_error_or_malformed_reply(self):
        """Plan ID: LEAD-10, SPEC-FILE-06, SPEC-FILE-07 | Risk ID: R09, R18
        Verify scan_file_for_malware with CLAMAV_REQUIRED=True rejects timeouts, closed connections,
        ERROR replies, malformed replies, and FOUND detections, and accepts only a terminated 'stream: OK'.
        """
        sample_bytes = b"%PDF-1.4 synthetic test payload"

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("timed out")
            mock_sock_cls.return_value = mock_sock
            with self.assertRaisesMessage(ValidationError, "Antivirus service is unavailable"):
                scan_file_for_malware(sample_bytes)

        for bad_reply in (b"", b"stream: INSTREAM size limit exceeded. ERROR\x00", b"stream: OK"):
            with patch("socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                # The reply is followed by a closed connection (b""), as a real socket would do.
                # A reply that never ends would make the read loop spin forever.
                mock_sock.recv.side_effect = [bad_reply, b""]
                mock_sock_cls.return_value = mock_sock
                with self.assertRaisesMessage(ValidationError, "Security scanner encountered an error"):
                    scan_file_for_malware(sample_bytes)

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"stream: Eicar-Test-Signature FOUND\x00"
            mock_sock_cls.return_value = mock_sock
            with self.assertRaises(ValidationError) as ctx:
                scan_file_for_malware(sample_bytes)
            self.assertEqual(ctx.exception.code, "malware")

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"stream: OK\x00"
            mock_sock_cls.return_value = mock_sock
            scan_file_for_malware(sample_bytes)

    def test_lead_11_open_redirect_and_disallowed_host_rejection(self):
        """Plan ID: LEAD-11, CLS-01, CLS-02 | Risk ID: R03, R12
        Verify mfa_reauth_view and safe_admin_return_url reject external and scheme-relative
        'next' payloads, accept valid relative in-site paths, and reject disallowed Host headers.
        """
        from django.core.exceptions import DisallowedHost

        rf = RequestFactory()
        user = SimpleNamespace(is_authenticated=True, id=uuid.uuid4())
        malicious_next_urls = [
            "//evil.example/phish",
            "/\\evil.example/phish",
            "https:evil.example",
            "https://evil.example/login",
            "javascript:alert(1)",
            "http://evil.example/%2F..",
        ]

        for bad_next in malicious_next_urls:
            req = _attach_session_and_messages(rf.post("/admin/users/", data={"next": bad_next}))
            req.user = user
            self.assertEqual(safe_admin_return_url(req), reverse("kura:staff_list"))

            req_reauth = _attach_session_and_messages(
                rf.post(reverse("kura:mfa_reauth"), data={"code": "123456", "next": bad_next})
            )
            req_reauth.user = user
            with patch("kura.views.verify_second_factor", return_value="totp"):
                resp = mfa_reauth_view(req_reauth)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp["Location"], reverse("kura:home"))

        # Disallowed Host header raises DisallowedHost (which Django maps to HTTP 400).
        req_bad_host = rf.get(reverse("kura:mfa_reauth"), HTTP_HOST="evil.example")
        with self.assertRaises(DisallowedHost):
            req_bad_host.get_host()

        # Positive control: Valid internal relative path is preserved.
        req_ok = _attach_session_and_messages(
            rf.post(reverse("kura:mfa_reauth"), data={"code": "123456", "next": "/courses/"})
        )
        req_ok.user = user
        with patch("kura.views.verify_second_factor", return_value="totp"):
            resp_ok = mfa_reauth_view(req_ok)
        self.assertEqual(resp_ok.status_code, 302)
        self.assertEqual(resp_ok["Location"], "/courses/")


def _create_authenticated_client(email, role_name, mfa_enabled=True, must_change_password=False, fresh_mfa=True):
    """Create a synthetic user with the given role and an active tracked UserSession."""
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

    totp_key = random_hex(20)
    TOTPDevice.objects.create(user=user, name="default", confirmed=True, key=totp_key)
    user.mfa_secret = totp_key
    user.save(update_fields=["mfa_secret"])

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
    return user, client, totp_key


class SecurityLeadsPart1Tests(TestCase):
    """PostgreSQL-backed integration tests for Section 16 LEAD-01 through LEAD-11."""

    def test_lead_01_passkey_auth_complete_csrf_exempt_and_pre_mfa_binding(self):
        """Plan ID: LEAD-01, CLS-01, AUTH-09 | Risk ID: R12
        Verify passkey_auth_complete_view (/mfa/fido2/complete_auth) and mfa_login_callback
        reject cross-site POSTs without challenge, missing pre-MFA sessions, and cross-user
        pre-MFA sessions with generic errors, while allowing a valid pending user login.
        """
        user_a = User.objects.create_user(
            email="lead01_a@kura.edu",
            password="SyntheticPassword!2026",
            first_name="Lead",
            last_name="OneA",
        )
        user_a.mfa_enabled = True
        user_a.save(update_fields=["mfa_enabled"])

        user_b = User.objects.create_user(
            email="lead01_b@kura.edu",
            password="SyntheticPassword!2026",
            first_name="Lead",
            last_name="OneB",
        )
        user_b.mfa_enabled = True
        user_b.save(update_fields=["mfa_enabled"])

        anon_client = Client(enforce_csrf_checks=True)
        resp_no_state = anon_client.post(
            reverse("fido2_complete_auth"),
            data=json.dumps({"id": "forged"}),
            content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertIn(resp_no_state.status_code, (400, 500))
        self.assertEqual(resp_no_state.json(), {"status": "ERR", "message": "Sign-in failed. Please start again."})
        self.assertNotIn("_auth_user_id", anon_client.session)

        resp_no_pre_mfa = mfa_login_callback(anon_client.get("/login/").wsgi_request, username=user_a.email)
        self.assertEqual(resp_no_pre_mfa.status_code, 302)
        self.assertEqual(resp_no_pre_mfa["Location"], reverse("kura:login"))
        self.assertEqual(UserSession.objects.filter(user=user_a).count(), 0)

        mismatch_client = Client()
        s = mismatch_client.session
        s["pre_mfa_user_id"] = str(user_a.id)
        s["pre_mfa_started_at"] = timezone.now().timestamp()
        s["base_username"] = user_a.email
        s.save()
        with patch(
            "mfa.FIDO2.authenticate_complete",
            side_effect=lambda req: mfa_login_callback(req, username=user_b.email),
        ):
            resp_mismatch = mismatch_client.post(
                reverse("fido2_complete_auth"),
                data=json.dumps({"id": "cred_b"}),
                content_type="application/json",
            )
        self.assertEqual(resp_mismatch.status_code, 302)
        self.assertEqual(resp_mismatch["Location"], reverse("kura:login"))
        self.assertNotIn("_auth_user_id", mismatch_client.session)
        self.assertEqual(UserSession.objects.filter(user=user_b).count(), 0)

        valid_client = Client()
        s = valid_client.session
        s["pre_mfa_user_id"] = str(user_a.id)
        s["pre_mfa_started_at"] = timezone.now().timestamp()
        s["base_username"] = user_a.email
        s.save()
        with patch(
            "mfa.FIDO2.authenticate_complete",
            side_effect=lambda req: JsonResponse(
                {"status": "OK", "redirect": mfa_login_callback(req, username=user_a.email)["Location"]}
            ),
        ):
            resp_ok = valid_client.post(
                reverse("fido2_complete_auth"),
                data=json.dumps({"id": "cred_a"}),
                content_type="application/json",
            )
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(resp_ok.json(), {"status": "OK", "redirect": reverse("kura:password_change")})
        self.assertEqual(valid_client.session.get("_auth_user_id"), str(user_a.id))
        self.assertEqual(UserSession.objects.filter(user=user_a, revoked_at__isnull=True).count(), 1)

    def test_lead_02_mfa_reset_cookie_does_not_mutate_server_state_or_logout_user(self):
        """Plan ID: LEAD-02, CLS-01, SESS-06 | Risk ID: R11, R12
        Verify GET /mfa/reset raises DisallowedRedirect (unhandled crash because settings.LOGIN_URL
        is 'kura:login'), leaves server-side UserSession state untouched, and does not log out a user.
        """
        user, auth_client, _ = _create_authenticated_client("lead02@kura.edu", "Student")
        self.assertEqual(UserSession.objects.filter(user=user, revoked_at__isnull=True).count(), 1)

        # Call the view directly so DisallowedRedirect propagates instead of being caught by the client.
        from mfa import views as mfa_views
        req = auth_client.get(reverse("mfa_reset_cookie")).wsgi_request
        with self.assertRaisesRegex(DisallowedRedirect, "Unsafe redirect to URL with protocol 'kura'"):
            mfa_views.reset_cookie(req)

        self.assertEqual(auth_client.session.get("_auth_user_id"), str(user.id))
        self.assertEqual(UserSession.objects.filter(user=user, revoked_at__isnull=True).count(), 1)
        self.assertEqual(auth_client.get(reverse("kura:home")).status_code, 200)

    def test_lead_03_public_passkey_begin_auth_without_pre_mfa_session(self):
        """Plan ID: LEAD-03, CLS-01, AUTH-09 | Risk ID: R12
        Verify GET /mfa/fido2/auth and GET /mfa/fido2/begin_auth without a pre-MFA session
        leak zero credential IDs and zero account-existence signals, while documenting that
        django-mfa2 still issues an empty-allowCredentials challenge.
        """
        from mfa.models import User_Keys

        user = User.objects.create_user(
            email="lead03@kura.edu",
            password="SyntheticPassword!2026",
            first_name="Lead",
            last_name="Three",
        )
        User_Keys.objects.create(
            username=user.email,
            key_type="FIDO2",
            enabled=True,
            properties={"device": "AAAA", "type": "packed"},
        )

        anon_client = Client()
        auth_page_resp = anon_client.get(reverse("fido2_auth"))
        self.assertEqual(auth_page_resp.status_code, 200)
        self.assertNotIn(user.email.encode(), auth_page_resp.content)

        begin_resp = anon_client.get(reverse("fido2_begin_auth"))
        self.assertEqual(begin_resp.status_code, 200)
        data = begin_resp.json()
        public_key_opts = data.get("publicKey", {})
        self.assertEqual(public_key_opts.get("allowCredentials", []), [])
        self.assertNotIn(user.email, json.dumps(data))
        self.assertIn("challenge", public_key_opts)
        self.assertIn("fido2_state", anon_client.session)

    def test_lead_04_media_url_bypass_serves_no_content_and_returns_404(self):
        """Plan ID: LEAD-04, CLS-02 | Risk ID: R10, R12
        Verify that an authenticated user who has not completed MFA setup or forced password
        change receives HTTP 404 (with Cache-Control: no-store) on /media/* and is redirected
        away from protected application routes.
        """
        _, pre_onboard_client, _ = _create_authenticated_client(
            "lead04@kura.edu",
            "Student",
            mfa_enabled=False,
            must_change_password=False,
            fresh_mfa=False,
        )

        home_resp = pre_onboard_client.get(reverse("kura:home"))
        self.assertEqual(home_resp.status_code, 302)
        self.assertEqual(home_resp["Location"], reverse("kura:mfa_setup"))

        media_resp = pre_onboard_client.get("/media/secret.pdf")
        self.assertEqual(media_resp.status_code, 404)
        self.assertIn("no-store", media_resp.get("Cache-Control", ""))

    def test_lead_05_and_lead_06_ratelimit_non_atomic_race_and_ttl_extension(self):
        """Plan ID: LEAD-05, LEAD-06, SPEC-SRV-07 | Risk ID: R04
        Verify RateLimitMiddleware enforces the 20/min upload limit sequentially, shifts TTL
        to last_allowed_hit + 60s on each allowed hit (LEAD-06), and permits overshoot when
        concurrent requests read the same non-atomic counter value (LEAD-05).
        """
        ratelimit_cache = caches["ratelimit"]
        ratelimit_cache.clear()

        user, _, _ = _create_authenticated_client("lead05@kura.edu", "Instructor")
        dept = Department.objects.create(code="RL", name="Rate Limit Dept")
        course = Course.objects.create(
            code="RL101",
            title="Rate Limit Course",
            department=dept,
            semester="1",
            academic_year=2026,
            is_published=True,
            published_by=user,
            published_at=timezone.now(),
        )
        upload_path = reverse("kura:course_file_upload", kwargs={"course_id": course.id})

        rf = RequestFactory()
        middleware = RateLimitMiddleware(lambda req: HttpResponse("OK", status=200))

        def _make_upload_request():
            req = rf.post(upload_path)
            req.user = user
            req.META["REMOTE_ADDR"] = "198.51.100.55"
            return req

        for i in range(20):
            resp = middleware(_make_upload_request())
            self.assertEqual(resp.status_code, 200, f"Request {i + 1} should succeed")

        blocked_resp = middleware(_make_upload_request())
        self.assertEqual(blocked_resp.status_code, 429)
        self.assertEqual(blocked_resp["Retry-After"], "60")

        ratelimit_cache.clear()
        with patch.object(type(ratelimit_cache), "set", wraps=ratelimit_cache.set) as mock_set:
            for _ in range(20):
                self.assertEqual(middleware(_make_upload_request()).status_code, 200)
            self.assertEqual(mock_set.call_count, 40)
            for call_args in mock_set.call_args_list:
                self.assertEqual(call_args.kwargs.get("timeout"), 60)

            self.assertEqual(middleware(_make_upload_request()).status_code, 429)
            self.assertEqual(mock_set.call_count, 40)

        ratelimit_cache.clear()
        user_key = f"rate_limit_upload_{user.id}"
        ip_key = "rate_limit_upload_ip_198.51.100.55"
        ratelimit_cache.set(user_key, 19, timeout=60)
        ratelimit_cache.set(ip_key, 19, timeout=60)

        stale_snapshot = {user_key: 19, ip_key: 19}
        accepted_in_burst = 0
        with patch.object(type(ratelimit_cache), "get", side_effect=lambda k, default=0: stale_snapshot.get(k, default)):
            for _ in range(10):
                resp = middleware(_make_upload_request())
                if resp.status_code == 200:
                    accepted_in_burst += 1

        self.assertEqual(accepted_in_burst, 10)
        self.assertEqual(ratelimit_cache.get(user_key), 20)

    def test_lead_08_department_reports_csv_injection_and_content_disposition(self):
        """Plan ID: LEAD-08, CLS-05, ROLE-HEAD-06 | Risk ID: R03, R10, R14
        Verify safe_csv_cell escapes standard formula prefixes (=, +, -, @, \\t, \\r), enforce
        cross-department denial (403), and demonstrate the two confirmed edge cases: leading LF
        ('\\n=1+1') in safe_csv_cell and unescaped quotes in Department.code Content-Disposition.
        """
        head_user, head_client, _ = _create_authenticated_client("lead08_head@kura.edu", "Department head")
        _, other_client, _ = _create_authenticated_client("lead08_other@kura.edu", "Department head")

        dept = Department.objects.create(code="CS", name="Computer Science", head_user=head_user)
        for idx, prefix in enumerate(("=CMD|' /C calc'!A0", "+1+1", "-1+1", "@SUM(1,1)", "\t=1+1", "\r=1+1"), start=1):
            Course.objects.create(
                code=f"CS10{idx}",
                title=f"{prefix}_Title",
                department=dept,
                semester="1",
                academic_year=2026,
                is_published=True,
                published_by=head_user,
                published_at=timezone.now(),
            )

        url = reverse("kura:department_reports", kwargs={"department_id": dept.id}) + "?format=csv"
        denied_resp = other_client.get(url)
        self.assertEqual(denied_resp.status_code, 403)
        self.assertNotIn(b"Course Code", denied_resp.content)

        ok_resp = head_client.get(url)
        self.assertEqual(ok_resp.status_code, 200)
        csv_text = ok_resp.content.decode("utf-8")
        for prefix in ("'=CMD|' /C calc'!A0_Title", "'+1+1_Title", "'-1+1_Title", "'@SUM(1,1)_Title", "'\t=1+1_Title", "'\r=1+1_Title"):
            self.assertIn(prefix, csv_text)

        self.assertEqual(safe_csv_cell("\n=1+1"), "\n=1+1")

        injected_dept = Department.objects.create(code='cs";x="', name="Injected Dept", head_user=head_user)
        inj_url = reverse("kura:department_reports", kwargs={"department_id": injected_dept.id}) + "?format=csv"
        inj_resp = head_client.get(inj_url)
        self.assertEqual(inj_resp.status_code, 200)
        self.assertEqual(inj_resp["Content-Disposition"], 'attachment; filename="cs";x="_report.csv"')

    def test_lead_11_open_redirect_and_disallowed_host_rejection(self):
        """Plan ID: LEAD-11, CLS-01, CLS-02 | Risk ID: R03, R12
        Verify mfa_reauth_view and safe_admin_return_url reject external and scheme-relative
        'next' payloads, accept valid relative in-site paths, and return HTTP 400 on disallowed Host headers.
        """
        user, auth_client, totp_key = _create_authenticated_client("lead11@kura.edu", "Admin")
        rf = RequestFactory()

        malicious_next_urls = [
            "//evil.example/phish",
            "/\\evil.example/phish",
            "https:evil.example",
            "https://evil.example/login",
            "javascript:alert(1)",
            "http://evil.example/%2F..",
        ]

        for bad_next in malicious_next_urls:
            req = rf.post("/admin/users/", data={"next": bad_next})
            req.user = user
            self.assertEqual(safe_admin_return_url(req), reverse("kura:staff_list"))

            code = f"{TOTP(bytes.fromhex(totp_key)).token():06d}"
            with patch("kura.views.verify_second_factor", return_value="totp"):
                resp = auth_client.post(reverse("kura:mfa_reauth"), data={"code": code, "next": bad_next})
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp["Location"], reverse("kura:home"))

        bad_host_resp = auth_client.get(reverse("kura:mfa_reauth") + "?next=/courses/", HTTP_HOST="evil.example")
        self.assertEqual(bad_host_resp.status_code, 400)

        with patch("kura.views.verify_second_factor", return_value="totp"):
            ok_resp = auth_client.post(
                reverse("kura:mfa_reauth"),
                data={"code": "123456", "next": "/courses/"},
            )
        self.assertEqual(ok_resp.status_code, 302)
        self.assertEqual(ok_resp["Location"], "/courses/")

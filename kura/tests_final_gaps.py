"""Final security gap regression tests for Kura LMS (session, TOTP, reset, enumeration, redirects, SSRF, banners).

Covers the seven defensive verification controls in Part A:
1. Session invalidation after logout (__Host-kura_session replay rejected) — OWASP A07 / ASVS V3.3.1
2. Stale & future TOTP codes outside drift window rejected and throttled — OWASP A07 / ASVS V2.8.2, V2.8.4
3. Password reset cross-user token/uidb64 abuse & 1-char token mutation rejected — OWASP A07 / ASVS V2.5.2, V2.5.6
4. Account enumeration parity on login and password reset (CSRF/nonces stripped) — OWASP A07 / ASVS V2.2.2, V2.5.1
5. Open-redirect variants blocked on login, MFA verify, and MFA re-auth — OWASP A01 / ASVS V5.1.5
6. Static AST verification that outbound HTTP calls use only api.pwnedpasswords.com — OWASP A10 / ASVS V12.6.1
7. Framework/runtime/server banner hiding and no X-Powered-By on 404, 403, and 500 — OWASP A02 / ASVS V14.3.3, V7.4.1
"""

import ast
import os
import re
import sys
import time
import urllib.parse
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import django
import gunicorn
from django.conf import settings
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice

from . import tests_owasp_regression
from .models import PasswordResetToken, UserSession
from .tests_security_fixtures import build_security_fixture_set, create_authenticated_client
from .views import create_reset_token, hash_session_token

SYNTHETIC_PASSWORD = "SyntheticPassword!2026"

PRODUCTION_HOST_COOKIE_SETTINGS = {
    "SESSION_COOKIE_NAME": "__Host-kura_session",
    "CSRF_COOKIE_NAME": "__Host-kura_csrftoken",
    "SESSION_COOKIE_SECURE": True,
    "CSRF_COOKIE_SECURE": True,
    "SESSION_COOKIE_HTTPONLY": True,
    "CSRF_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "CSRF_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_PATH": "/",
    "CSRF_COOKIE_PATH": "/",
    "SESSION_COOKIE_DOMAIN": None,
    "CSRF_COOKIE_DOMAIN": None,
}


def _generate_totp_for_timestamp(user, device, timestamp_seconds):
    """Compute a 6-digit TOTP string for `user` and `device` at `timestamp_seconds`.

    Who can use it: Defensive MFA test suites in `kura/tests_final_gaps.py`.
    Security: Uses only synthetic in-memory hex TOTP seeds generated per test case.
    """
    totp = TOTP(bytes.fromhex(user.mfa_secret), device.step, device.t0, device.digits, device.drift)
    totp.time = timestamp_seconds
    return str(totp.token()).zfill(device.digits)


class SessionAfterLogoutRegressionTests(TestCase):
    """Verify server-side session invalidation prevents __Host-kura_session replay after logout."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student = self.fx["users"]["student_1"]
        self.device = TOTPDevice.objects.get(user=self.student, confirmed=True)

    @override_settings(**PRODUCTION_HOST_COOKIE_SETTINGS)
    def test_replayed_host_session_cookie_rejected_after_logout(self):
        """OWASP Top 10 2025 A07 (Authentication Failures) | ASVS v4.0.3 V3.3.1:
        Logging out must invalidate the session server-side so replaying a captured
        `__Host-kura_session` cookie on protected pages redirects to login or returns 403, never 200.
        """
        client = Client()

        # Step 1: password sign-in over HTTPS.
        resp_pw = client.post(
            reverse("kura:login"),
            data={"email": self.student.email, "password": SYNTHETIC_PASSWORD},
            secure=True,
        )
        self.assertEqual(resp_pw.status_code, 302)
        self.assertEqual(resp_pw["Location"], reverse("kura:mfa_verify"))

        # Step 2: valid TOTP verification issues the authenticated __Host-kura_session cookie.
        valid_code = _generate_totp_for_timestamp(self.student, self.device, time.time())
        resp_mfa = client.post(
            reverse("kura:mfa_verify"),
            data={"code": valid_code},
            secure=True,
        )
        self.assertEqual(resp_mfa.status_code, 302)
        self.assertEqual(resp_mfa["Location"], reverse("kura:home"))
        self.assertIn("__Host-kura_session", client.cookies)

        captured_cookie_value = client.cookies["__Host-kura_session"].value
        self.assertTrue(captured_cookie_value)

        # Positive control before logout: protected page returns 200 OK.
        resp_active = client.get(reverse("kura:home"), secure=True)
        self.assertEqual(resp_active.status_code, 200)
        tracked_session = UserSession.objects.filter(user=self.student, revoked_at__isnull=True).latest("created_at")

        # POST to logout to flush Django session storage and mark UserSession.revoked_at.
        resp_logout = client.post(reverse("kura:logout"), secure=True)
        self.assertEqual(resp_logout.status_code, 302)
        self.assertIn(reverse("kura:login"), resp_logout["Location"])
        tracked_session.refresh_from_db()
        self.assertIsNotNone(tracked_session.revoked_at)

        # Replay the captured pre-logout __Host-kura_session cookie in a separate client.
        replay_client = Client()
        replay_client.cookies["__Host-kura_session"] = captured_cookie_value
        login_path = reverse("kura:login")

        for route_name in ("kura:home", "kura:course_list", "kura:student_grades"):
            with self.subTest(route=route_name):
                resp_replay = replay_client.get(reverse(route_name), secure=True)
                self.assertNotEqual(resp_replay.status_code, 200)
                if resp_replay.status_code == 302:
                    self.assertIn(login_path, resp_replay["Location"])
                else:
                    self.assertEqual(resp_replay.status_code, 403)


class StaleTOTPCodeRegressionTests(TestCase):
    """Verify TOTP codes just outside the allowed clock-drift window are rejected and throttled."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student = self.fx["users"]["student_1"]
        self.device = TOTPDevice.objects.get(user=self.student, confirmed=True)

    def test_totp_codes_just_outside_drift_window_rejected_and_throttled(self):
        """OWASP Top 10 2025 A07 (Authentication Failures) | ASVS v4.0.3 V2.8.2 & V2.8.4:
        TOTP codes generated one step earlier and one step later than `device.tolerance`
        must be rejected with HTTP 400 and increment `device.throttling_failure_count`.
        """
        # Pin verification to the midpoint (+15s) of the current 30-second step to prevent clock-edge flakiness.
        step = self.device.step
        mid_step_now = float((int(time.time()) // step) * step + (step // 2))
        outside_delta_seconds = (self.device.tolerance + 1) * step

        earlier_code = _generate_totp_for_timestamp(self.student, self.device, mid_step_now - outside_delta_seconds)
        later_code = _generate_totp_for_timestamp(self.student, self.device, mid_step_now + outside_delta_seconds)

        for direction, stale_or_future_code in (
            ("earlier_outside_drift", earlier_code),
            ("later_outside_drift", later_code),
        ):
            with self.subTest(direction=direction):
                # Reset throttling before each check so both directions start from a clean unthrottled baseline.
                self.device.refresh_from_db()
                self.device.throttle_reset(commit=True)
                self.assertEqual(self.device.throttling_failure_count, 0)
                self.assertTrue(self.device.verify_is_allowed()[0])

                sessions_before = UserSession.objects.filter(user=self.student).count()
                client = Client()
                resp_pw = client.post(
                    reverse("kura:login"),
                    data={"email": self.student.email, "password": SYNTHETIC_PASSWORD},
                )
                self.assertEqual(resp_pw.status_code, 302)
                self.assertEqual(resp_pw["Location"], reverse("kura:mfa_verify"))

                with patch("kura.views.time.time", return_value=mid_step_now):
                    resp_mfa = client.post(reverse("kura:mfa_verify"), data={"code": stale_or_future_code})

                self.assertEqual(resp_mfa.status_code, 400)
                self.assertIn("Invalid security code.", resp_mfa.content.decode("utf-8"))
                self.assertEqual(UserSession.objects.filter(user=self.student).count(), sessions_before)

                # Verify the out-of-window code incremented django-otp's failure throttle counter.
                self.device.refresh_from_db()
                self.assertEqual(self.device.throttling_failure_count, 1)
                self.assertIsNotNone(self.device.throttling_failure_timestamp)
                self.assertFalse(self.device.verify_is_allowed()[0])


class PasswordResetAbuseRegressionTests(TestCase):
    """Verify cross-account password reset token/uidb64 abuse and token bit-flipping are rejected."""

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.user_a = self.fx["users"]["student_1"]
        self.user_b = self.fx["users"]["student_2"]
        self.pre_mfa_user = self.fx["users"]["pre_mfa_user"]

    @patch("kura.views.check_breached_password", return_value=None)
    def test_cross_user_token_with_other_uidb64_rejected_and_victim_unchanged(self, _mock_hibp):
        """OWASP Top 10 2025 A07 (Authentication Failures) & A01 (Broken Access Control) | ASVS v4.0.3 V2.5.2 & V2.5.6:
        Combining user A's valid reset token with user B's `uidb64` (via URL path or tampered parameters
        and second-factor code) must fail to alter user B's password.
        """
        user_b_hash_before = self.user_b.password
        user_a_hash_before = self.user_a.password
        uidb64_b = urlsafe_base64_encode(force_bytes(self.user_b.pk))
        attacker_password = "AttackerChosenPass!2026"

        raw_token_a, token_record_a = create_reset_token(self.user_a)
        device_b = TOTPDevice.objects.get(user=self.user_b, confirmed=True)
        code_b = _generate_totp_for_timestamp(self.user_b, device_b, time.time())

        client = Client()

        # 1. Django-default style URL `/password/reset/<uidb64_b>/<raw_token_a>/` does not exist and is rejected (404).
        resp_uid_path = client.post(
            f"/password/reset/{uidb64_b}/{raw_token_a}/",
            data={
                "uidb64": uidb64_b,
                "code": code_b,
                "new_password": attacker_password,
                "confirm_password": attacker_password,
            },
        )
        self.assertEqual(resp_uid_path.status_code, 404)

        # 2. Combined `<uidb64_b>-<raw_token_a>` token segment fails SHA-256 lookup and redirects as invalid.
        resp_combined = client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": f"{uidb64_b}-{raw_token_a}"}),
            data={
                "uidb64": uidb64_b,
                "code": code_b,
                "new_password": attacker_password,
                "confirm_password": attacker_password,
            },
        )
        self.assertEqual(resp_combined.status_code, 302)
        self.assertEqual(resp_combined["Location"], reverse("kura:password_reset_request"))

        # 3. Submitting user B's uidb64/user_id/email and user B's TOTP code against user A's valid token URL
        # is rejected because the token is server-side bound to user A (burning user A's single-use link).
        confirm_url_a = reverse("kura:password_reset_confirm", kwargs={"token": raw_token_a})
        resp_cross = client.post(
            f"{confirm_url_a}?uidb64={uidb64_b}&user_id={self.user_b.pk}",
            data={
                "uidb64": uidb64_b,
                "uid": str(self.user_b.pk),
                "user_id": str(self.user_b.pk),
                "email": self.user_b.email,
                "code": code_b,
                "new_password": attacker_password,
                "confirm_password": attacker_password,
            },
        )
        self.assertEqual(resp_cross.status_code, 302)
        self.assertEqual(resp_cross["Location"], reverse("kura:password_reset_request"))

        self.user_b.refresh_from_db()
        self.user_a.refresh_from_db()
        token_record_a.refresh_from_db()
        self.assertEqual(self.user_b.password, user_b_hash_before)
        self.assertFalse(self.user_b.check_password(attacker_password))
        self.assertEqual(self.user_a.password, user_a_hash_before)
        self.assertIsNotNone(token_record_a.used_at)

        # 4. Even when an un-enrolled user's token is submitted with tampered uidb64/user_id/email for user B,
        # user B's password remains untouched because PasswordResetToken resolves strictly from token_hash.
        raw_token_pre, _ = create_reset_token(self.pre_mfa_user)
        client.post(
            reverse("kura:password_reset_confirm", kwargs={"token": raw_token_pre}) + f"?uidb64={uidb64_b}",
            data={
                "uidb64": uidb64_b,
                "user_id": str(self.user_b.pk),
                "email": self.user_b.email,
                "new_password": attacker_password,
                "confirm_password": attacker_password,
            },
        )
        self.user_b.refresh_from_db()
        self.assertEqual(self.user_b.password, user_b_hash_before)
        self.assertFalse(self.user_b.check_password(attacker_password))

    @patch("kura.views.check_breached_password", return_value=None)
    def test_single_character_flipped_reset_token_rejected(self, _mock_hibp):
        """OWASP Top 10 2025 A07 (Authentication Failures) | ASVS v4.0.3 V2.5.6:
        Flipping a single character of a valid password reset token must fail SHA-256 verification,
        leave the token unconsumed, and keep the user's password unchanged.
        """
        original_hash = self.user_a.password
        raw_token, token_record = create_reset_token(self.user_a)
        device_a = TOTPDevice.objects.get(user=self.user_a, confirmed=True)
        valid_code_a = _generate_totp_for_timestamp(self.user_a, device_a, time.time())

        flipped_last = raw_token[:-1] + ("A" if raw_token[-1] != "A" else "B")
        mid = len(raw_token) // 2
        flipped_mid = raw_token[:mid] + ("x" if raw_token[mid] != "x" else "y") + raw_token[mid + 1 :]

        client = Client()
        for label, bad_token in (("last_char_flipped", flipped_last), ("mid_char_flipped", flipped_mid)):
            with self.subTest(mutation=label):
                url = reverse("kura:password_reset_confirm", kwargs={"token": bad_token})

                resp_get = client.get(url, follow=True)
                self.assertEqual(resp_get.redirect_chain, [(reverse("kura:password_reset_request"), 302)])
                self.assertIn(
                    "This password reset link is invalid or has expired.",
                    resp_get.content.decode("utf-8"),
                )

                resp_post = client.post(
                    url,
                    data={
                        "code": valid_code_a,
                        "new_password": "BrandNewValidPass!2026",
                        "confirm_password": "BrandNewValidPass!2026",
                    },
                    follow=True,
                )
                self.assertEqual(resp_post.redirect_chain, [(reverse("kura:password_reset_request"), 302)])
                self.assertIn(
                    "This password reset link is invalid or has expired.",
                    resp_post.content.decode("utf-8"),
                )

        self.user_a.refresh_from_db()
        token_record.refresh_from_db()
        self.assertEqual(self.user_a.password, original_hash)
        self.assertIsNone(token_record.used_at)
        self.assertTrue(PasswordResetToken.objects.filter(id=token_record.id, used_at__isnull=True).exists())


class AccountEnumerationRegressionTests(TestCase):
    """Verify login and password-reset endpoints emit identical status codes and visible messages."""

    CSRF_RE = re.compile(r'(<input[^>]*name="csrfmiddlewaretoken"[^>]*value=")[^"]*(")', re.IGNORECASE)
    NONCE_RE = re.compile(r'(\bnonce=")[^"]*(")', re.IGNORECASE)

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.known_email = self.fx["users"]["student_1"].email
        self.unknown_email = "definitely.nonexistent.account@kura.edu"

    @classmethod
    def _strip_csrf_and_nonces(cls, html_text, echoed_email=None):
        """Remove per-request CSRF tokens, CSP nonces, and echoed form input values before comparison.

        Who can use it: Account-enumeration parity tests in `AccountEnumerationRegressionTests`.
        Security: Ensures dynamic anti-CSRF/CSP tokens do not mask or falsely trigger body diffs.
        """
        cleaned = cls.CSRF_RE.sub(r"\1<CSRF_STRIPPED>\2", html_text)
        cleaned = cls.NONCE_RE.sub(r"\1<NONCE_STRIPPED>\2", cleaned)
        if echoed_email:
            cleaned = cleaned.replace(f'value="{echoed_email}"', 'value="<EMAIL_INPUT>"')
        return cleaned

    def test_login_and_password_reset_prevent_account_enumeration(self):
        """OWASP Top 10 2025 A07 (Authentication Failures) | ASVS v4.0.3 V2.2.2 & V2.5.1:
        Submitting a known email versus an unknown email on `/login/` and `/password/reset/`
        must return identical HTTP status codes, identical user-visible messages, and identical HTML
        after stripping CSRF tokens and nonces.
        """
        # 1. Login endpoint: known email (wrong password) vs unknown email (wrong password).
        login_url = reverse("kura:login")
        resp_login_known = Client().post(
            login_url,
            data={"email": self.known_email, "password": "IncorrectPassword!999"},
            REMOTE_ADDR="198.51.100.11",
        )
        resp_login_unknown = Client().post(
            login_url,
            data={"email": self.unknown_email, "password": "IncorrectPassword!999"},
            REMOTE_ADDR="198.51.100.12",
        )

        self.assertEqual(resp_login_known.status_code, 400)
        self.assertEqual(resp_login_known.status_code, resp_login_unknown.status_code)

        known_login_msgs = [str(m) for m in resp_login_known.context["messages"]]
        unknown_login_msgs = [str(m) for m in resp_login_unknown.context["messages"]]
        self.assertEqual(known_login_msgs, ["Invalid email or password."])
        self.assertEqual(known_login_msgs, unknown_login_msgs)

        self.assertEqual(
            self._strip_csrf_and_nonces(resp_login_known.content.decode("utf-8"), echoed_email=self.known_email),
            self._strip_csrf_and_nonces(resp_login_unknown.content.decode("utf-8"), echoed_email=self.unknown_email),
        )

        # 2. Password reset endpoint: known email vs unknown email (both immediate 302 and followed 200).
        reset_url = reverse("kura:password_reset_request")
        client_known = Client()
        client_unknown = Client()

        resp_reset_known_302 = client_known.post(reset_url, data={"email": self.known_email})
        resp_reset_unknown_302 = client_unknown.post(reset_url, data={"email": self.unknown_email})

        self.assertEqual(resp_reset_known_302.status_code, 302)
        self.assertEqual(resp_reset_known_302.status_code, resp_reset_unknown_302.status_code)
        self.assertEqual(resp_reset_known_302["Location"], resp_reset_unknown_302["Location"])

        resp_reset_known_page = client_known.get(resp_reset_known_302["Location"])
        resp_reset_unknown_page = client_unknown.get(resp_reset_unknown_302["Location"])
        self.assertEqual(resp_reset_known_page.status_code, 200)
        self.assertEqual(resp_reset_known_page.status_code, resp_reset_unknown_page.status_code)

        known_reset_msgs = [str(m) for m in resp_reset_known_page.context["messages"]]
        unknown_reset_msgs = [str(m) for m in resp_reset_unknown_page.context["messages"]]
        self.assertEqual(
            known_reset_msgs,
            ["If an account exists with that email address, password reset instructions have been sent."],
        )
        self.assertEqual(known_reset_msgs, unknown_reset_msgs)

        self.assertEqual(
            self._strip_csrf_and_nonces(resp_reset_known_page.content.decode("utf-8")),
            self._strip_csrf_and_nonces(resp_reset_unknown_page.content.decode("utf-8")),
        )


class OpenRedirectVariantsRegressionTests(TestCase):
    """Verify open-redirect bypass payloads in `next` stay strictly on the Kura host."""

    MALICIOUS_NEXT_VALUES = (
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "%2F%2Fevil.com",
        "javascript:alert(1)",
    )

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student = self.fx["users"]["student_1"]
        self.pre_mfa_user = self.fx["users"]["pre_mfa_user"]
        self.device = TOTPDevice.objects.get(user=self.student, confirmed=True)

    def _assert_redirect_stays_on_kura_host(self, response, source_path, label):
        """Assert a redirect response's `Location` resolves strictly to `testserver` over HTTP(S).

        Who can use it: Open-redirect regression tests in `OpenRedirectVariantsRegressionTests`.
        Security: Rejects protocol-relative, backslash, scheme-less, encoded, and script-scheme redirects.
        """
        self.assertEqual(response.status_code, 302, f"Expected 302 redirect for {label}, got {response.status_code}")
        location = response["Location"]
        self.assertFalse(location.startswith("//"), f"Protocol-relative redirect leaked in {label}: {location!r}")
        self.assertFalse(location.startswith("/\\"), f"Backslash redirect leaked in {label}: {location!r}")
        self.assertFalse(location.lower().startswith("javascript:"), f"Script-scheme redirect in {label}: {location!r}")

        resolved = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://testserver{source_path}", location))
        self.assertIn(resolved.scheme, ("http", "https"), f"Disallowed redirect scheme in {label}: {location!r}")
        self.assertEqual(resolved.netloc, "testserver", f"External redirect host in {label}: {location!r}")
        self.assertNotIn("evil.com", resolved.netloc.lower())

    def test_login_mfa_verify_and_mfa_reauth_reject_open_redirect_variants(self):
        """OWASP Top 10 2025 A01 (Broken Access Control) | ASVS v4.0.3 V5.1.5:
        Supplying `//evil.com`, `/\\evil.com`, `https:evil.com`, `%2F%2Fevil.com`, or `javascript:`
        in `next` on login, MFA verify, and MFA re-auth must keep the final redirect on Kura's host.
        """
        login_url = reverse("kura:login")
        mfa_verify_url = reverse("kura:mfa_verify")
        mfa_reauth_url = reverse("kura:mfa_reauth")

        for payload in self.MALICIOUS_NEXT_VALUES:
            encoded_qs = urllib.parse.urlencode({"next": payload})

            # 1a. Login view (POST with query string + POST body `next`) for MFA-enrolled user.
            with self.subTest(view="login_post_mfa_user", next_val=payload):
                client = Client()
                resp_login = client.post(
                    f"{login_url}?{encoded_qs}",
                    data={"email": self.student.email, "password": SYNTHETIC_PASSWORD, "next": payload},
                )
                self._assert_redirect_stays_on_kura_host(resp_login, login_url, f"login_post({payload!r})")

                # 1b. Continue straight into MFA verify (POST with query string + POST body `next`).
                self.device.refresh_from_db()
                self.device.last_t = -1
                self.device.throttle_reset(commit=True)
                valid_code = _generate_totp_for_timestamp(self.student, self.device, time.time())
                resp_verify = client.post(
                    f"{mfa_verify_url}?{encoded_qs}",
                    data={"code": valid_code, "next": payload},
                )
                self._assert_redirect_stays_on_kura_host(resp_verify, mfa_verify_url, f"mfa_verify({payload!r})")

            # 1c. Login view for non-MFA user (completes login directly in login_view).
            with self.subTest(view="login_post_pre_mfa_user", next_val=payload):
                resp_premfa = Client().post(
                    f"{login_url}?{encoded_qs}",
                    data={"email": self.pre_mfa_user.email, "password": SYNTHETIC_PASSWORD, "next": payload},
                )
                self._assert_redirect_stays_on_kura_host(resp_premfa, login_url, f"login_premfa({payload!r})")

            # 2a. MFA re-auth view: POST with `next` in both query string and form data.
            with self.subTest(view="mfa_reauth_post", next_val=payload):
                auth_client, _ = create_authenticated_client(self.student, fresh_mfa=False)
                self.device.refresh_from_db()
                self.device.last_t = -1
                self.device.throttle_reset(commit=True)
                reauth_code = _generate_totp_for_timestamp(self.student, self.device, time.time())
                resp_reauth = auth_client.post(
                    f"{mfa_reauth_url}?{encoded_qs}",
                    data={"code": reauth_code, "next": payload},
                )
                self._assert_redirect_stays_on_kura_host(resp_reauth, mfa_reauth_url, f"mfa_reauth({payload!r})")

            # 2b. Raw unencoded query string (specifically tests raw `?next=%2F%2Fevil.com` -> decoded `//evil.com`).
            if "%" in payload:
                with self.subTest(view="mfa_reauth_raw_query", next_val=payload):
                    auth_client, _ = create_authenticated_client(self.student, fresh_mfa=False)
                    self.device.refresh_from_db()
                    self.device.last_t = -1
                    self.device.throttle_reset(commit=True)
                    reauth_code = _generate_totp_for_timestamp(self.student, self.device, time.time())
                    resp_raw = auth_client.post(
                        f"{mfa_reauth_url}?next={payload}",
                        data={"code": reauth_code},
                    )
                    self._assert_redirect_stays_on_kura_host(
                        resp_raw, mfa_reauth_url, f"mfa_reauth_raw({payload!r})"
                    )


class SSRFStaticEvidenceRegressionTests(SimpleTestCase):
    """Static AST guard confirming Kura makes no user-controlled outbound HTTP requests."""

    ALLOWLISTED_HOSTS = frozenset({"api.pwnedpasswords.com"})
    HTTP_CLIENT_MODULES = ("requests", "httpx")
    HTTP_REQUEST_CALLS = frozenset(
        {
            "urlopen",
            "urllib.request.urlopen",
            "request.urlopen",
            "urllib.request.Request",
            "request.Request",
            "opener.open",
        }
    )

    @staticmethod
    def _static_url_prefix(expr):
        """Extract the constant leading URL string from an AST Constant or JoinedStr node.

        Who can use it: `SSRFStaticEvidenceRegressionTests` AST inspector.
        Security: Returns None if the scheme or host portion depends on a dynamic expression.
        """
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.JoinedStr) and expr.values:
            first = expr.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    def test_every_outbound_http_call_in_kura_targets_allowlisted_host(self):
        """OWASP Top 10 2025 A10 / OWASP 2021 A10 (Server-Side Request Forgery) | ASVS v4.0.3 V12.6.1:
        Walk `kura/*.py` (and non-test runtime submodules) with `ast` and assert that every
        `requests`, `httpx`, `urlopen`, `urllib.request.Request`, or `opener.open` call uses a
        constant HTTPS URL whose host is strictly in `ALLOWLISTED_HOSTS` (`api.pwnedpasswords.com`).
        """
        base_dir = Path(settings.BASE_DIR)
        kura_dir = base_dir / "kura"
        runtime_files = [
            py_file
            for py_file in sorted(kura_dir.rglob("*.py"))
            if "/migrations/" not in py_file.as_posix() and not os.path.basename(py_file).startswith("tests")
        ]
        self.assertTrue(runtime_files, "Expected runtime Python files in kura/")

        verified_targets = []

        for py_file in runtime_files:
            rel = py_file.relative_to(base_dir).as_posix()
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=rel)

            # Collect local variable assignments (`request = urllib.request.Request(...)`) per function/module scope,
            # binding each node to its innermost enclosing scope.
            local_assigns = {}
            parent_scope = {}

            def _bind_scope(scope_node):
                for child in ast.iter_child_nodes(scope_node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _bind_scope(child)
                        continue
                    parent_scope[id(child)] = scope_node
                    if isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                        local_assigns[(id(scope_node), child.targets[0].id)] = child.value
                    for desc in ast.walk(child):
                        if isinstance(desc, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        parent_scope[id(desc)] = scope_node
                        if isinstance(desc, ast.Assign) and len(desc.targets) == 1 and isinstance(desc.targets[0], ast.Name):
                            local_assigns[(id(scope_node), desc.targets[0].id)] = desc.value
                for nested in ast.walk(scope_node):
                    if nested is not scope_node and isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        _bind_scope(nested)

            _bind_scope(tree)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for mod in self.HTTP_CLIENT_MODULES:
                            self.assertFalse(
                                alias.name == mod or alias.name.startswith(f"{mod}."),
                                f"Unapproved HTTP library import {alias.name!r} in {rel}",
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for mod in self.HTTP_CLIENT_MODULES:
                        self.assertFalse(
                            node.module == mod or node.module.startswith(f"{mod}."),
                            f"Unapproved HTTP library import {node.module!r} in {rel}",
                        )
                elif isinstance(node, ast.Call):
                    func_name = ast.unparse(node.func)
                    is_http_lib_call = any(
                        func_name == mod or func_name.startswith(f"{mod}.") for mod in self.HTTP_CLIENT_MODULES
                    )
                    if not is_http_lib_call and func_name not in self.HTTP_REQUEST_CALLS:
                        continue

                    self.assertTrue(node.args, f"Outbound HTTP call {func_name} at {rel}:{node.lineno} has no URL arg")
                    url_arg = node.args[0]

                    # Resolve `opener.open(request, ...)` back to `request = urllib.request.Request(...)`.
                    if isinstance(url_arg, ast.Name):
                        enclosing = parent_scope.get(id(node))
                        assigned = local_assigns.get((id(enclosing), url_arg.id)) if enclosing else None
                        self.assertIsNotNone(
                            assigned,
                            f"Dynamic/unresolvable URL variable {url_arg.id!r} in {func_name} at {rel}:{node.lineno}",
                        )
                        if isinstance(assigned, ast.Call) and assigned.args:
                            url_arg = assigned.args[0]
                        else:
                            url_arg = assigned

                    prefix = self._static_url_prefix(url_arg)
                    self.assertIsNotNone(
                        prefix,
                        f"Non-constant URL expression in {func_name} at {rel}:{node.lineno}: {ast.unparse(url_arg)}",
                    )
                    parsed = urllib.parse.urlsplit(prefix)
                    self.assertEqual(
                        parsed.scheme,
                        "https",
                        f"Outbound HTTP call at {rel}:{node.lineno} must use https://, got {prefix!r}",
                    )
                    self.assertIn(
                        parsed.hostname,
                        self.ALLOWLISTED_HOSTS,
                        f"Outbound HTTP host {parsed.hostname!r} at {rel}:{node.lineno} not in allowlist",
                    )
                    # Ensure path delimiter already follows the constant hostname so f-string suffixes cannot alter the host.
                    self.assertTrue(
                        parsed.path.startswith("/"),
                        f"Constant URL prefix at {rel}:{node.lineno} must terminate hostname with '/': {prefix!r}",
                    )
                    verified_targets.append((rel, func_name, parsed.hostname))

        # Sanity check: ensure check_breached_password in kura/views.py was inspected.
        self.assertTrue(
            any(rel == "kura/views.py" and host == "api.pwnedpasswords.com" for rel, _, host in verified_targets),
            f"Expected kura/views.py HIBP call to be verified, got {verified_targets}",
        )


class BannerHidingRegressionTests(TestCase):
    """Verify 404, 403, and 500 responses disclose no version banners, tracebacks, or X-Powered-By."""

    VERSION_BANNER_PATTERNS = (
        re.compile(r"\bdjango[\s/]+\d+\.\d+", re.IGNORECASE),
        re.compile(r"\bpython[\s/]+\d+\.\d+", re.IGNORECASE),
        re.compile(r"\bgunicorn[\s/]+\d+\.\d+", re.IGNORECASE),
        re.compile(r"\bwsgiserver[\s/]+\d+\.\d+", re.IGNORECASE),
    )

    def setUp(self):
        self.fx = build_security_fixture_set()
        self.student = self.fx["users"]["student_1"]
        self.student_client, _ = create_authenticated_client(self.student)

    def _assert_no_banners_or_traceback(self, response, label):
        """Assert headers and body expose no framework/runtime/server versions or stack traces.

        Who can use it: Error-response banner checks in `BannerHidingRegressionTests`.
        Security: Verifies suppression of `X-Powered-By`, version strings, and tracebacks.
        """
        self.assertNotIn("X-Powered-By", response, f"X-Powered-By header present on {label}")
        server_hdr = response.get("Server", "")
        for token in ("django", "python", "gunicorn", "wsgiserver"):
            self.assertNotIn(token, server_hdr.lower(), f"Server header leaked {token!r} on {label}: {server_hdr!r}")

        body = response.content.decode("utf-8")
        for marker in tests_owasp_regression.ErrorHandlingLeakageRegressionTests.LEAK_MARKERS:
            self.assertNotIn(marker, body, f"Traceback/internal marker {marker!r} leaked on {label}")

        exact_versions = (
            django.get_version(),
            sys.version.split()[0],
            gunicorn.__version__,
        )
        for ver in exact_versions:
            self.assertNotIn(f"Django/{ver}", body)
            self.assertNotIn(f"Python/{ver}", body)
            self.assertNotIn(f"gunicorn/{ver}", body)

        for pattern in self.VERSION_BANNER_PATTERNS:
            self.assertIsNone(pattern.search(body), f"Version banner matched {pattern.pattern!r} on {label}")

    @override_settings(DEBUG=False, ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
    def test_404_403_and_500_hide_versions_tracebacks_and_x_powered_by(self):
        """OWASP Top 10 2025 A02 (Security Misconfiguration) | ASVS v4.0.3 V14.3.3 & V7.4.1:
        404, 403, and unhandled 500 responses with `DEBUG=False` must omit Django, Python, and
        Gunicorn version strings, omit tracebacks, and never emit an `X-Powered-By` header
        (while Nginx `server_tokens off` suppresses version strings at the reverse-proxy edge).
        """
        # 1. 404 Not Found
        resp_404 = self.student_client.get("/nonexistent-banner-hiding-probe/")
        self.assertEqual(resp_404.status_code, 404)
        self._assert_no_banners_or_traceback(resp_404, "404")

        # 2. 403 Forbidden
        resp_403 = self.student_client.get(reverse("kura:admin_users"))
        self.assertEqual(resp_403.status_code, 403)
        self._assert_no_banners_or_traceback(resp_403, "403")

        # 3. Forced 500 Internal Server Error
        err_client = Client(raise_request_exception=False)
        err_client.force_login(self.student, backend="kura.backends.KuraAuthBackend")
        session = err_client.session
        session.save()
        us = UserSession.objects.create(
            user=self.student,
            session_token_hash=hash_session_token(session.session_key),
            ip_address="127.0.0.1",
            user_agent="BannerHideTest/1.0",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        session["user_session_id"] = str(us.id)
        session.save()

        with patch(
            "kura.views.build_dashboard_attention",
            side_effect=RuntimeError("DB_LEAK_SENTINEL SELECT * FROM users WHERE id=1"),
        ):
            resp_500 = err_client.get(reverse("kura:home"))
        self.assertEqual(resp_500.status_code, 500)
        self._assert_no_banners_or_traceback(resp_500, "500")

        # Confirm Nginx edge config keeps `server_tokens off;` enabled.
        for nginx_rel in ("docker/nginx/nginx.conf", "docker/nginx/conf.d/kura.conf"):
            nginx_cfg = (Path(settings.BASE_DIR) / nginx_rel).read_text(encoding="utf-8")
            self.assertIn("server_tokens off;", nginx_cfg, f"Missing server_tokens off in {nginx_rel}")

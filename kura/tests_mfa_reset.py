"""Tests for emailed account activation, MFA reset, and the egress firewall config.

Covers: Admins and Registrars never see a password for the accounts they create; the
set-password link works once and expires; Admin plus Registrar is refused; Admins cannot
enrol MFA for anyone; a user can reset their own MFA after step-up; an Admin can reset
another user's MFA only with step-up, the Admin's password and a reason, and never for
themselves; every reset is logged, revokes sessions and is rate-limited.
"""

import re
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.core.cache import caches
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from mfa.models import User_Keys

from .models import (
    AcademicLevel,
    Department,
    OutgoingEmail,
    PasswordResetToken,
    Role,
    User,
    UserRole,
    UserSession,
)
from .tests_security_fixtures import _create_synthetic_user, create_authenticated_client
from .views import hash_recovery_code

PASSWORD = "SyntheticPassword!2026"
RECOVERY_CODE = "ABCD1234"
NEW_PASSWORD = "Correct-Horse-Battery-9!"
LINK_PATTERN = re.compile(r"/password/reset/([^/\s]+)/")


def add_recovery_code(user, code=RECOVERY_CODE):
    """Give a test user one unused recovery code (stored as the keyed hash, like production)."""
    device, _ = StaticDevice.objects.get_or_create(user=user, name="recovery", defaults={"confirmed": True})
    StaticToken.objects.create(device=device, token=hash_recovery_code(code))


def emailed_token(to_email):
    """Return the raw token from the single queued activation email for an address."""
    email = OutgoingEmail.objects.get(to_email=to_email, event_key__startswith="account-activation:")
    return LINK_PATTERN.search(email.body).group(1)


@override_settings(SITE_URL="https://kura.example.com")
class AccountActivationTests(TestCase):
    def setUp(self):
        caches["ratelimit"].clear()
        self.admin = _create_synthetic_user("act_admin@kura.edu", ["Admin"])
        self.registrar = _create_synthetic_user("act_registrar@kura.edu", ["Registrar"])
        self.department = Department.objects.create(name="Activation Dept", code="ACT")
        self.admin_client, _ = create_authenticated_client(self.admin)
        self.registrar_client, _ = create_authenticated_client(self.registrar)

    def _create_staff(self, email="new.staff@kura.edu", title="Department head"):
        return self.admin_client.post(
            reverse("kura:staff_create"),
            {
                "email": email,
                "first_name": "New",
                "last_name": "Staff",
                "department": self.department.id,
                "staff_title": title,
            },
        )

    def test_admin_gets_no_password_and_user_gets_link(self):
        with self.assertLogs("kura.security", level="INFO") as logs:
            response = self._create_staff()
        self.assertRedirects(response, reverse("kura:staff_list"))
        token = emailed_token("new.staff@kura.edu")
        listing = self.admin_client.get(reverse("kura:staff_list"))
        self.assertNotIn(b"Temporary password", listing.content)
        self.assertNotIn("new_account_temp_password", self.admin_client.session)
        # Neither the page nor the security log may contain the link token.
        self.assertNotIn(token.encode(), listing.content)
        self.assertNotIn(token, "\n".join(logs.output))
        email = OutgoingEmail.objects.get(to_email="new.staff@kura.edu")
        self.assertIn("https://kura.example.com/password/reset/", email.body)
        self.assertTrue(User.objects.get(email="new.staff@kura.edu").must_change_password)

    def test_registrar_gets_no_password_for_new_student(self):
        response = self.registrar_client.post(
            reverse("kura:student_create"),
            {
                "email": "new.student@kura.edu",
                "first_name": "New",
                "last_name": "Student",
                "department": self.department.id,
                "current_level": AcademicLevel.YEAR_1,
                "matriculation_year": "2026",
            },
        )
        self.assertEqual(response.status_code, 302)
        listing = self.registrar_client.get(reverse("kura:enrollment_list"))
        self.assertNotIn(b"Temporary password", listing.content)
        self.assertNotIn("new_account_temp_password", self.registrar_client.session)
        self.assertTrue(OutgoingEmail.objects.filter(to_email="new.student@kura.edu").exists())

    @patch("kura.views.check_breached_password")
    def test_link_works_once_then_is_invalid(self, _breach):
        self._create_staff()
        token = emailed_token("new.staff@kura.edu")
        url = reverse("kura:password_reset_confirm", kwargs={"token": token})
        anonymous = Client()
        self.assertEqual(anonymous.get(url).status_code, 200)
        done = anonymous.post(url, {"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        self.assertRedirects(done, reverse("kura:login"))
        user = User.objects.get(email="new.staff@kura.edu")
        self.assertTrue(user.check_password(NEW_PASSWORD))
        # Used once: the same link is refused afterwards.
        self.assertRedirects(anonymous.get(url), reverse("kura:password_reset_request"))

    def test_link_expires(self):
        self._create_staff()
        token = emailed_token("new.staff@kura.edu")
        record = PasswordResetToken.objects.get(user__email="new.staff@kura.edu")
        # The activation window is two days, not the 30 minutes of a normal reset.
        self.assertGreater(record.expires_at - timezone.now(), timezone.timedelta(hours=40))
        record.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        record.save(update_fields=["expires_at"])
        url = reverse("kura:password_reset_confirm", kwargs={"token": token})
        self.assertRedirects(Client().get(url), reverse("kura:password_reset_request"))

    def test_admin_and_registrar_cannot_be_combined(self):
        registrar_role = Role.objects.get(name="Registrar")
        admin_role = Role.objects.get(name="Admin")
        other_admin = _create_synthetic_user("act_admin2@kura.edu", ["Admin"])
        other_registrar = _create_synthetic_user("act_registrar2@kura.edu", ["Registrar"])
        self.admin_client.post(
            reverse("kura:user_roles", kwargs={"user_id": other_admin.id}),
            {"action": "assign", "role_id": registrar_role.id},
        )
        self.admin_client.post(
            reverse("kura:user_roles", kwargs={"user_id": other_registrar.id}),
            {"action": "assign", "role_id": admin_role.id},
        )
        self.assertFalse(UserRole.objects.filter(user=other_admin, role=registrar_role).exists())
        self.assertFalse(UserRole.objects.filter(user=other_registrar, role=admin_role).exists())


@override_settings(SITE_URL="https://kura.example.com")
class MFAResetTests(TestCase):
    def setUp(self):
        caches["ratelimit"].clear()
        self.admin = _create_synthetic_user("rst_admin@kura.edu", ["Admin"])
        self.other_admin = _create_synthetic_user("rst_admin2@kura.edu", ["Admin"])
        self.instructor = _create_synthetic_user("rst_instructor@kura.edu", ["Instructor"])
        self.student = _create_synthetic_user("rst_student@kura.edu", ["Student"])
        for user in (self.admin, self.other_admin, self.instructor, self.student):
            add_recovery_code(user)
            User_Keys.objects.create(username=user.email, key_type="FIDO2", properties={})
        self.admin_client, _ = create_authenticated_client(self.admin)

    def reset_url(self, target):
        return reverse("kura:admin_user_mfa_reset", kwargs={"user_id": target.id})

    def admin_post(self, target, **overrides):
        data = {"reason": "User lost their phone and recovery codes", "password": PASSWORD}
        data.update(overrides)
        return self.admin_client.post(self.reset_url(target), data)

    def assert_factors_intact(self, user):
        user.refresh_from_db()
        self.assertTrue(user.mfa_enabled)
        self.assertTrue(TOTPDevice.objects.filter(user=user).exists())
        self.assertTrue(User_Keys.objects.filter(username=user.email).exists())

    # ---- self-service ----
    def test_self_reset_needs_password_and_code(self):
        client, _ = create_authenticated_client(self.student, fresh_mfa=False)
        url = reverse("kura:mfa_reset")
        wrong_password = client.post(url, {"password": "not-my-password", "code": RECOVERY_CODE})
        self.assertEqual(wrong_password.status_code, 400)
        wrong_code = client.post(url, {"password": PASSWORD, "code": "00000000"})
        self.assertEqual(wrong_code.status_code, 400)
        self.assert_factors_intact(self.student)
        # A wrong password must not spend the recovery code.
        self.assertEqual(StaticToken.objects.filter(device__user=self.student).count(), 1)

    def test_self_reset_removes_factors_keeps_current_session_and_logs(self):
        client, current_session = create_authenticated_client(self.student, fresh_mfa=False)
        _, other_session = create_authenticated_client(self.student)
        with self.assertLogs("kura.security", level="INFO") as logs:
            response = client.post(reverse("kura:mfa_reset"), {"password": PASSWORD, "code": RECOVERY_CODE})
        self.assertRedirects(response, reverse("kura:mfa_setup"), fetch_redirect_response=False)
        self.student.refresh_from_db()
        self.assertFalse(self.student.mfa_enabled)
        self.assertIsNone(self.student.mfa_secret)
        self.assertFalse(TOTPDevice.objects.filter(user=self.student).exists())
        self.assertFalse(StaticDevice.objects.filter(user=self.student).exists())
        self.assertFalse(User_Keys.objects.filter(username=self.student.email).exists())
        other_session.refresh_from_db()
        current_session.refresh_from_db()
        self.assertIsNotNone(other_session.revoked_at)
        self.assertIsNone(current_session.revoked_at)
        joined = "\n".join(logs.output)
        self.assertIn('event="auth.mfa.reset"', joined)
        self.assertIn("target_user_id", joined)
        self.assertIn("ip=", joined)
        self.assertTrue(OutgoingEmail.objects.filter(to_email=self.student.email, subject__contains="reset").exists())

    # ---- admin-assisted ----
    def test_non_admins_get_403(self):
        client, _ = create_authenticated_client(self.instructor)
        self.assertEqual(client.get(self.reset_url(self.student)).status_code, 403)
        self.assertEqual(
            client.post(self.reset_url(self.student), {"reason": "x" * 20, "password": PASSWORD}).status_code, 403
        )
        self.assert_factors_intact(self.student)

    def test_admin_needs_fresh_second_factor(self):
        client, _ = create_authenticated_client(self.admin, fresh_mfa=False)
        response = client.post(
            self.reset_url(self.student), {"reason": "User lost their phone", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("kura:mfa_reauth"), response["Location"])
        self.assert_factors_intact(self.student)

    def test_admin_needs_reason_and_own_password(self):
        self.assertEqual(self.admin_post(self.student, reason="").status_code, 400)
        self.assertEqual(self.admin_post(self.student, reason="too short").status_code, 400)
        self.assertEqual(self.admin_post(self.student, password="wrong-password").status_code, 400)
        self.assert_factors_intact(self.student)

    def test_admin_reset_removes_factors_revokes_sessions_and_logs(self):
        _, student_session = create_authenticated_client(self.student)
        with self.assertLogs("kura.security", level="INFO") as logs:
            response = self.admin_post(self.student)
        self.assertRedirects(response, reverse("kura:admin_users"), fetch_redirect_response=False)
        self.student.refresh_from_db()
        self.assertFalse(self.student.mfa_enabled)
        self.assertIsNone(self.student.mfa_secret)
        self.assertFalse(TOTPDevice.objects.filter(user=self.student).exists())
        self.assertFalse(StaticDevice.objects.filter(user=self.student).exists())
        self.assertFalse(User_Keys.objects.filter(username=self.student.email).exists())
        student_session.refresh_from_db()
        self.assertIsNotNone(student_session.revoked_at)
        self.assertFalse(UserSession.objects.filter(user=self.student, revoked_at__isnull=True).exists())
        # The old password stops working; the user must use the emailed link.
        self.assertFalse(self.student.check_password(PASSWORD))
        self.assertTrue(self.student.must_change_password)
        token = emailed_token(self.student.email)
        # The Admin never sees the link: not in the page, the session or the log.
        followed = self.admin_client.get(reverse("kura:admin_users"))
        self.assertNotIn(token.encode(), followed.content)
        self.assertNotIn(token, "\n".join(logs.output))
        self.assertNotIn(token, str(dict(self.admin_client.session)))
        joined = "\n".join(logs.output)
        self.assertIn('event="admin.mfa.reset"', joined)
        self.assertIn("lost their phone", joined)
        self.assertIn(f"actor_user_id=\"{self.admin.id}\"", joined)
        self.assertIn(f"target_user_id={self.student.id}", joined.replace('"', ""))
        self.assertIn("ip=", joined)

    def test_admin_cannot_reset_self_but_another_admin_can(self):
        response = self.admin_post(self.admin)
        self.assertRedirects(response, reverse("kura:admin_users"), fetch_redirect_response=False)
        self.assert_factors_intact(self.admin)
        second_client, _ = create_authenticated_client(self.other_admin)
        second = second_client.post(
            self.reset_url(self.admin), {"reason": "Admin lost their device", "password": PASSWORD}
        )
        self.assertEqual(second.status_code, 302)
        self.admin.refresh_from_db()
        self.assertFalse(self.admin.mfa_enabled)

    def test_admin_cannot_enrol_mfa_for_another_user(self):
        # The reset removes factors only. No view takes a user id and creates a device for that user.
        self.admin_post(self.student)
        self.assertFalse(TOTPDevice.objects.filter(user=self.student).exists())
        self.assertIsNone(User.objects.get(id=self.student.id).mfa_secret)
        # The MFA setup page always acts on the signed-in Admin only.
        before = TOTPDevice.objects.filter(user=self.instructor).count()
        self.admin_client.get(reverse("kura:mfa_setup"))
        self.assertEqual(TOTPDevice.objects.filter(user=self.instructor).count(), before)

    def test_mfa_resets_are_rate_limited(self):
        statuses = [self.admin_post(self.student, reason="short").status_code for _ in range(6)]
        self.assertEqual(statuses[:5], [400] * 5)
        self.assertEqual(statuses[5], 429)


class EgressFirewallConfigTests(SimpleTestCase):
    """The nftables rule, the compose bridge name and the allowlist sets must agree."""

    def read(self, name):
        return (Path(settings.BASE_DIR) / name).read_text()

    def test_nft_interface_matches_compose_bridge_name(self):
        compose = self.read("docker-compose.yml")
        bridge = re.search(r"com\.docker\.network\.bridge\.name:\s*(\S+)", compose).group(1)
        nft = self.read("docker/nftables/kura.nft")
        self.assertIn(f'iifname "{bridge}" ip saddr 172.28.60.10 jump web_egress', nft)
        self.assertLessEqual(len(bridge), 15)
        self.assertNotIn("eth1", nft)

    def test_egress_sets_allow_timed_elements(self):
        nft = self.read("docker/nftables/kura.nft")
        for name in ("egress_smtp", "egress_hibp", "egress_dns"):
            declaration = re.search(r"set %s \{[^}]*\}" % name, nft).group(0)
            self.assertIn("flags timeout", declaration, name)

    def test_egress_refresh_does_not_hide_nft_errors(self):
        script = self.read("kura.sh")
        add_lines = [line for line in script.splitlines() if "nft add element" in line]
        self.assertTrue(add_lines)
        for line in add_lines:
            self.assertNotIn("2>/dev/null", line)
            self.assertNotIn("|| true", line)

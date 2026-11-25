"""Regression and verification tests for Kura Security Gap Plan items (G01-G17).

Follows .gemini/skills/kura-security-tester/SKILL.md conventions:
- Isolated test database and synthetic data only.
- Every test declares Plan ID and Risk ID in its docstring.
"""

import os
import re
import unittest
from pathlib import Path
from unittest import skipIf

from unittest.mock import patch

from django.conf import settings
from django.db import OperationalError
from django.http import JsonResponse
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

BASE_DIR = Path(settings.BASE_DIR)


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


class SecurityGapStaticTests(unittest.TestCase):
    """Static configuration checks for G01, G02, and related compose/host rules."""

    @skipIf(not (BASE_DIR / "docker-compose.yml").exists(), "docker-compose.yml not available in container")
    def test_g01_no_inline_vault_credentials_in_compose(self):
        """Plan ID: G01 | Risk ID: R02, R16
        Verify docker-compose.yml passes Vault AppRole credentials via Docker secrets
        rather than literal environment variables in any service block.
        """
        compose_text = (BASE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertNotRegex(compose_text, r"VAULT_ROLE_ID\s*:")
        self.assertNotRegex(compose_text, r"VAULT_SECRET_ID\s*:")

        web_block = _extract_compose_service_block(compose_text, "web")
        self.assertIn("- vault_role_id", web_block)
        self.assertIn("- vault_secret_id", web_block)

    @skipIf(
        not (BASE_DIR / "docker-compose.yml").exists()
        or not (BASE_DIR / "docker" / "postgres" / "pg_hba.conf").exists(),
        "compose or pg_hba.conf not available in container",
    )
    def test_g02_postgres_port_not_published_and_superuser_tcp_blocked(self):
        """Plan ID: G02 | Risk ID: R01, R06
        Verify PostgreSQL publishes no host ports in docker-compose.yml and pg_hba.conf
        never allows password-only TCP logins for the kura-admin superuser.
        """
        compose_text = (BASE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
        db_block = _extract_compose_service_block(compose_text, "db")
        uncommented_db = "\n".join(
            line for line in db_block.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotRegex(uncommented_db, r"(?m)^\s*ports\s*:")
        self.assertNotIn('"5432:5432"', uncommented_db)

        pg_hba_lines = [
            line.strip()
            for line in (BASE_DIR / "docker" / "postgres" / "pg_hba.conf").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        admin_tcp_lines = [
            line for line in pg_hba_lines if line.startswith("host") and "kura-admin" in line.split()
        ]
        for line in admin_tcp_lines:
            self.assertFalse(
                line.endswith("scram-sha-256"),
                f"kura-admin TCP rule must require clientcert=verify-full or reject: {line}",
            )
            self.assertTrue(
                line.endswith("reject") or "clientcert=verify-full" in line,
                f"kura-admin TCP rule is too permissive: {line}",
            )
        self.assertEqual(os.environ.get("DJANGO_SETTINGS_MODULE", "config.settings"), "config.settings")

    @skipIf(
        not (BASE_DIR / "docker" / "alloy" / "config.alloy").exists()
        or not (BASE_DIR / "docker" / "prometheus" / "alerts.yml").exists()
        or not (BASE_DIR / "docker" / "loki" / "rules" / "fake" / "kura-alerts.yml").exists(),
        "observability configs not available in container",
    )
    def test_g03_loki_scrape_and_missing_logs_alerts_configured(self):
        """Plan ID: G03 | Risk ID: R08, R14
        Verify Alloy scrapes Loki metrics and both Prometheus and Loki rules alert when
        Loki goes down or web security logs stop arriving.
        """
        alloy_cfg = (BASE_DIR / "docker" / "alloy" / "config.alloy").read_text(encoding="utf-8")
        self.assertIn('prometheus.scrape "loki"', alloy_cfg)
        self.assertIn('"loki:3100"', alloy_cfg)

        prom_alerts = (BASE_DIR / "docker" / "prometheus" / "alerts.yml").read_text(encoding="utf-8")
        self.assertIn("alert: LokiDown", prom_alerts)
        self.assertIn("alert: SecurityLogsStopped", prom_alerts)

        loki_alerts = (BASE_DIR / "docker" / "loki" / "rules" / "fake" / "kura-alerts.yml").read_text(encoding="utf-8")
        self.assertIn("alert: WebLogsAbsent", loki_alerts)
        self.assertIn('absent_over_time({service="web"}[15m])', loki_alerts)

    @skipIf(not (BASE_DIR / ".dockerignore").exists(), ".dockerignore not available in container")
    def test_g06_dockerignore_and_pinned_workflows(self):
        """Plan ID: G06 | Risk ID: R15, R16
        Verify .dockerignore excludes secrets, certs, keys, and local artifacts, and verify
        GitHub workflows pin every third-party action to a 40-hex commit SHA.
        """
        dockerignore = (BASE_DIR / ".dockerignore").read_text(encoding="utf-8")
        for required in (".git", ".env", "secrets/", "certs/", ".venv", "docs/", "*.key", "*.pem", "staticfiles/"):
            self.assertIn(required, dockerignore)

        workflows_dir = BASE_DIR / ".github" / "workflows"
        if workflows_dir.exists():
            for wf in workflows_dir.glob("*.yml"):
                text = wf.read_text(encoding="utf-8")
                for match in re.findall(r"uses:\s*([^\s#]+)", text):
                    self.assertRegex(
                        match,
                        r"^[^@]+@[0-9a-f]{40}$",
                        f"Workflow {wf.name} uses mutable action reference: {match}",
                    )


class SecurityGapG04ErrorHandlingTests(TestCase):
    """Regression tests for G04 malformed POST payloads and DB/Vault dependency outages."""

    def _assert_no_sensitive_leak(self, response):
        body = response.content.decode("utf-8", errors="replace")
        for forbidden in ("Traceback", 'File "/', "SECRET_KEY", "DATABASES"):
            self.assertNotIn(forbidden, body)

    def test_g04_malformed_and_fuzz_payloads_never_return_500(self):
        """Plan ID: G04 | Risk ID: R16, R20
        Verify login and password-reset endpoints return 4xx (never 500) on missing CSRF,
        invalid emails, oversized inputs, non-UTF-8 bytes, JSON/multipart bodies, and bad Host/IP headers.
        """
        csrf_client = Client(enforce_csrf_checks=True)
        for url in (reverse("kura:login"), reverse("kura:password_reset_request")):
            resp = csrf_client.post(url, {"email": "a@b.c", "password": "x"})
            self.assertEqual(resp.status_code, 403)
            self._assert_no_sensitive_leak(resp)

        client = Client()
        payloads = [
            {"email": "ZAP", "password": "x"},
            {"email": "<script>alert(1)</script>", "password": ""},
            {"email": ("a" * 5000) + "@kura.edu", "password": "x"},
            {"email": ["a@kura.edu", "b@kura.edu"], "password": ["1", "2"]},
        ]
        for data in payloads:
            for url in (reverse("kura:login"), reverse("kura:password_reset_request")):
                resp = client.post(url, data, HTTP_X_REAL_IP="not-an-ip-garbage")
                expected = (302, 400, 403, 429) if (url == reverse("kura:password_reset_request") and isinstance(data["email"], list)) else (400, 403, 429)
                self.assertIn(resp.status_code, expected)
                self._assert_no_sensitive_leak(resp)

        for url in (reverse("kura:login"), reverse("kura:password_reset_request")):
            resp_bin = client.post(url, data=b"email=\xff\xfe&password=x", content_type="application/x-www-form-urlencoded")
            self.assertIn(resp_bin.status_code, (400, 403, 429))
            self._assert_no_sensitive_leak(resp_bin)

            resp_json = client.post(url, data='{"email":"a@b.c"}', content_type="application/json")
            self.assertIn(resp_json.status_code, (400, 403, 429))
            self._assert_no_sensitive_leak(resp_json)

            resp_host = client.get(url, HTTP_HOST="unknown-attacker-host.example")
            self.assertEqual(resp_host.status_code, 400)
            self._assert_no_sensitive_leak(resp_host)

    def test_g04_dependency_outage_returns_503_and_logs_event(self):
        """Plan ID: G04 | Risk ID: R16, R20
        Verify OperationalError during login or password reset returns HTTP 503 with 503.html
        and logs server.dependency_unavailable instead of returning an unhandled 500.
        """
        client = Client()
        with (
            patch("kura.views.authenticate", side_effect=OperationalError("Could not get a database login from Vault.")),
            self.assertLogs("kura.security", level="ERROR") as captured,
        ):
            resp = client.post(reverse("kura:login"), {"email": "user@kura.edu", "password": "ValidPassword123!"})
        self.assertEqual(resp.status_code, 503)
        self._assert_no_sensitive_leak(resp)
        self.assertIn(b"503", resp.content)
        self.assertTrue(any('event="server.dependency_unavailable"' in rec.getMessage() for rec in captured.records))

        with (
            patch("kura.views.OutgoingEmail.objects.create", side_effect=OperationalError("db down")),
            self.assertLogs("kura.security", level="ERROR") as captured_reset,
        ):
            resp_reset = client.post(reverse("kura:password_reset_request"), {"email": "user@kura.edu"})
        self.assertEqual(resp_reset.status_code, 503)
        self._assert_no_sensitive_leak(resp_reset)
        self.assertTrue(any('event="server.dependency_unavailable"' in rec.getMessage() for rec in captured_reset.records))


class SecurityGapG12PasskeyOriginTests(TestCase):
    """Verification tests for G12 Origin/Referer and pre-MFA checks on passkey_auth_complete_view."""

    def test_g12_passkey_complete_enforces_post_origin_and_pre_mfa_window(self):
        """Plan ID: G12 | Risk ID: R12
        Verify passkey_auth_complete_view rejects GET (405), missing/foreign Origin (403),
        and missing pre-MFA session (403) before delegating to FIDO2.authenticate_complete.
        """
        client = Client()
        url = reverse("fido2_complete_auth")

        self.assertEqual(client.get(url).status_code, 405)

        with self.assertLogs("kura.security", level="WARNING") as cap_missing:
            resp_missing = client.post(url, data="{}", content_type="application/json")
        self.assertEqual(resp_missing.status_code, 403)
        self.assertTrue(any('event="access.csrf_failed"' in r.getMessage() for r in cap_missing.records))

        with self.assertLogs("kura.security", level="WARNING"):
            resp_bad_origin = client.post(
                url,
                data="{}",
                content_type="application/json",
                HTTP_ORIGIN="https://attacker.example",
            )
        self.assertEqual(resp_bad_origin.status_code, 403)

        # Valid Origin without pre_mfa window must still be rejected.
        with override_settings(DEBUG=False, SITE_URL="https://kura.example.com"):
            resp_no_premfa = client.post(
                url,
                data="{}",
                content_type="application/json",
                HTTP_ORIGIN="https://kura.example.com",
            )
            self.assertEqual(resp_no_premfa.status_code, 403)

            session = client.session
            session["pre_mfa_user_id"] = "00000000-0000-0000-0000-000000000001"
            session["pre_mfa_started_at"] = timezone.now().timestamp()
            session.save()

            # Referer fallback works when Origin is omitted and pre-MFA window is active.
            with patch("mfa.FIDO2.authenticate_complete", return_value=JsonResponse({"status": "OK"})) as mock_fido:
                resp_ok = client.post(
                    url,
                    data="{}",
                    content_type="application/json",
                    HTTP_REFERER="https://kura.example.com/login/mfa/",
                )
            self.assertEqual(resp_ok.status_code, 200)
            mock_fido.assert_called_once()


class SecurityGapG08UnicodeTests(TestCase):
    """Verification tests for G08 Unicode normalization, bidi/control blocking, and filename sanitization."""

    def test_g08_fullwidth_email_normalizes_and_cyrillic_homoglyph_rejected(self):
        """Plan ID: G08 | Risk ID: R16
        Verify full-width ASCII email normalizes via NFKC before LoginForm validation, while
        Cyrillic homoglyph emails are rejected before lookup or account creation.
        """
        from kura.forms import LoginForm, StaffCreateForm
        from kura.models import Department
        from kura.tests import make_user

        make_user("Student", email="admin@kura.edu", password="ValidPassword123!")
        login_form = LoginForm({"email": "\uff21dmin@kura.edu", "password": "ValidPassword123!\U0001f680"})
        self.assertTrue(login_form.is_valid(), login_form.errors)
        self.assertEqual(login_form.cleaned_data["email"], "admin@kura.edu")
        self.assertEqual(login_form.cleaned_data["password"], "ValidPassword123!\U0001f680")

        dept = Department.objects.create(code="UNI", name="Unicode Dept")
        homoglyph_form = StaffCreateForm(
            {
                "email": "\u0430dmin@kura.edu",
                "first_name": "Alice",
                "last_name": "Smith",
                "department": str(dept.id),
                "staff_title": "Instructor",
            }
        )
        self.assertFalse(homoglyph_form.is_valid())
        self.assertIn("email", homoglyph_form.errors)

    def test_g08_bidi_control_chars_rejected_in_forms_and_multiline_preserved(self):
        """Plan ID: G08 | Risk ID: R16
        Verify zero-width/bidi characters are rejected in text forms, newlines pass in Textarea
        fields, and mixed-script tokens emit input.mixed_script telemetry.
        """
        from decimal import Decimal
        from kura.forms import CourseCreateForm, GradeEntryForm
        from kura.models import Department, SemesterType
        from kura.tests import make_user

        head = make_user("Department head")
        dept = Department.objects.create(code="U2", name="Unicode Security", head_user=head)

        bad_course = CourseCreateForm(
            {
                "department": str(dept.id),
                "code": "SEC101",
                "title": "Intro\u200bSec",
                "description": "Syllabus",
                "semester": SemesterType.SEMESTER_1,
                "academic_year": "2026",
            },
            head_departments=Department.objects.filter(id=dept.id),
        )
        self.assertFalse(bad_course.is_valid())
        self.assertIn("title", bad_course.errors)

        grade_form = GradeEntryForm({"score": Decimal("85.00"), "feedback": "Line 1\nLine 2\tOK"})
        self.assertTrue(grade_form.is_valid(), grade_form.errors)
        self.assertIn("\n", grade_form.cleaned_data["feedback"])

        with self.assertLogs("kura.security", level="INFO") as captured:
            mixed_form = GradeEntryForm({"score": Decimal("90.00"), "feedback": "Good work Al\u0435x"})
            self.assertTrue(mixed_form.is_valid(), mixed_form.errors)
        self.assertTrue(any('event="input.mixed_script"' in r.getMessage() for r in captured.records))

    def test_g08_sanitize_filename_removes_bidi_override_and_logs(self):
        """Plan ID: G08 | Risk ID: R16
        Verify sanitize_filename strips U+202E right-to-left override and emits file.name_sanitized.
        """
        from kura.views import sanitize_filename

        with self.assertLogs("kura.security", level="INFO") as captured:
            cleaned = sanitize_filename("../../report\u202efdp.exe")
        self.assertEqual(cleaned, "reportfdp.exe")
        self.assertTrue(any('event="file.name_sanitized"' in r.getMessage() for r in captured.records))


class SecurityGapG09DeceptionTests(TestCase):
    """Verification tests for G09 honeypot decoy routes and honeytoken login detection."""

    def test_g09_honeypot_paths_return_404_and_log_without_normal_404_false_positive(self):
        """Plan ID: G09 | Risk ID: R14
        Every HONEYPOT_PATHS route returns 404 on GET and POST and emits security.honeypot.hit
        without duplicate logfmt keys, whereas normal unknown URLs emit access.not_found only.
        """
        from kura.views import HONEYPOT_PATHS

        client = Client()
        for hp in HONEYPOT_PATHS:
            url = "/" + hp.lstrip("/")
            with self.subTest(path=url):
                with self.assertLogs("kura.security", level="WARNING") as cap_get:
                    resp_get = client.get(url)
                self.assertEqual(resp_get.status_code, 404)
                get_lines = [r.getMessage() for r in cap_get.records if 'event="security.honeypot.hit"' in r.getMessage()]
                self.assertEqual(len(get_lines), 1)
                self.assertEqual(get_lines[0].count("path="), 1)

                with self.assertLogs("kura.security", level="WARNING") as cap_post:
                    resp_post = client.post(url, {"probe": "1"})
                self.assertEqual(resp_post.status_code, 404)
                self.assertTrue(any('event="security.honeypot.hit"' in r.getMessage() for r in cap_post.records))

        with self.assertLogs("kura.security", level="INFO") as cap_normal:
            resp_normal = client.get("/not-a-honeypot-page-12345/")
        self.assertEqual(resp_normal.status_code, 404)
        self.assertTrue(any('event="access.not_found"' in r.getMessage() for r in cap_normal.records))
        self.assertFalse(any('event="security.honeypot.hit"' in r.getMessage() for r in cap_normal.records))

    def test_g09_honeytoken_login_returns_generic_failure_and_logs_error(self):
        """Plan ID: G09 | Risk ID: R14
        Submitting the honeytoken account returns the same status and generic message as any unknown
        email while logging security.honeytoken.used at ERROR level.
        """
        client = Client()
        resp_unknown = client.post(
            reverse("kura:login"),
            {"email": "nonexistent@kura.edu", "password": "WrongPassword123!"},
        )
        with (
            override_settings(KURA_HONEYTOKEN_EMAIL="it-support@kura.edu"),
            self.assertLogs("kura.security", level="ERROR") as captured,
        ):
            resp_honey = client.post(
                reverse("kura:login"),
                {"email": "it-support@kura.edu", "password": "WrongPassword123!"},
            )
        self.assertEqual(resp_honey.status_code, 400)
        self.assertEqual(resp_honey.status_code, resp_unknown.status_code)
        self.assertContains(resp_honey, "Invalid email or password.", status_code=400)
        self.assertContains(resp_unknown, "Invalid email or password.", status_code=400)
        self.assertTrue(any('event="security.honeytoken.used"' in r.getMessage() for r in captured.records))


class SecurityGapG13TimingTests(TestCase):
    """Verification tests for G13 constant-work password reset request handling."""

    def test_g13_known_and_unknown_emails_execute_identical_query_count(self):
        """Plan ID: G13 | Risk ID: R03
        Verify POST /password/reset/ performs the exact same number of SQL queries for an
        existing user and an unknown email, while send_queued_emails resolves only valid users
        and deletes unknown lookup rows without marking FAILED.
        """
        from django.core.management import call_command
        from io import StringIO
        from kura.models import OutgoingEmail, OutgoingEmailStatus, PasswordResetToken
        from kura.tests import make_user

        known_user = make_user("Student", email="known-student@kura.edu")
        client = Client()

        # Warm the cache/security policy or middleware state so first-request lazy queries don't skew.
        client.get(reverse("kura:password_reset_request"))

        with self.assertNumQueries(1) as ctx_unknown:
            resp_unknown = client.post(
                reverse("kura:password_reset_request"),
                {"email": "missing-person@kura.edu"},
            )
        self.assertEqual(resp_unknown.status_code, 302)

        with self.assertNumQueries(len(ctx_unknown.captured_queries)):
            resp_known = client.post(
                reverse("kura:password_reset_request"),
                {"email": known_user.email},
            )
        self.assertEqual(resp_known.status_code, 302)

        self.assertEqual(PasswordResetToken.objects.filter(user=known_user).count(), 0)
        call_command("send_queued_emails", stdout=StringIO())

        self.assertEqual(PasswordResetToken.objects.filter(user=known_user).count(), 1)
        self.assertFalse(OutgoingEmail.objects.filter(to_email="missing-person@kura.edu").exists())
        self.assertFalse(OutgoingEmail.objects.filter(status=OutgoingEmailStatus.FAILED).exists())


class SecurityGapG14HostCookieTests(TestCase):
    """Verification tests for G14 __Host- session and CSRF cookie prefixes when DEBUG=False."""

    @override_settings(
        DEBUG=False,
        SESSION_COOKIE_NAME="__Host-kura_session",
        CSRF_COOKIE_NAME="__Host-kura_csrftoken",
        SESSION_COOKIE_SECURE=True,
        CSRF_COOKIE_SECURE=True,
        SESSION_COOKIE_PATH="/",
        CSRF_COOKIE_PATH="/",
        SESSION_COOKIE_DOMAIN=None,
        CSRF_COOKIE_DOMAIN=None,
    )
    def test_g14_host_prefix_cookies_set_secure_root_path_and_no_domain(self):
        """Plan ID: G14 | Risk ID: R04
        Verify GET/POST on login with production cookie settings sets __Host-kura_csrftoken
        with Secure, Path=/, and empty Domain.
        """
        client = Client(enforce_csrf_checks=False)
        resp = client.get(reverse("kura:login"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("__Host-kura_csrftoken", resp.cookies)
        csrf_cookie = resp.cookies["__Host-kura_csrftoken"]
        self.assertTrue(csrf_cookie["secure"])
        self.assertEqual(csrf_cookie["path"], "/")
        self.assertEqual(csrf_cookie["domain"], "")


class SecurityGapG11LogChainTests(unittest.TestCase):
    """Verification tests for G11 tamper-evident HMAC-SHA256 log chains."""

    def test_g11_log_chain_verifies_and_detects_edit_and_deletion(self):
        """Plan ID: G11 | Risk ID: R08, R14
        Verify generated log chains pass verify_log_lines, a 1-character edit fails at that seq,
        and a deleted middle line triggers a sequence gap failure.
        """
        from kura.logging_utils import log_security_event, reset_log_chain_for_tests
        from kura.management.commands.verify_log_chain import verify_log_lines

        reset_log_chain_for_tests()
        with self.assertLogs("kura.security", level="INFO") as captured:
            log_security_event(None, "chain.step_one", {"index": "1"})
            log_security_event(None, "chain.step_two", {"index": "2"})
            log_security_event(None, "chain.step_three", {"index": "3"})

        lines = [rec.getMessage() for rec in captured.records]
        self.assertEqual(verify_log_lines(lines), len(lines))

        # 1-char edit inside step_two (seq=2) must fail HMAC check at seq=2.
        edited = list(lines)
        edited[2] = edited[2].replace('index="2"', 'index="9"')
        with self.assertRaisesRegex(ValueError, "seq=2: tampered"):
            verify_log_lines(edited)

        # Deleting a middle line (seq=2) must fail with a sequence gap at seq=3.
        deleted = [lines[0], lines[1], lines[3]]
        with self.assertRaisesRegex(ValueError, "sequence gap detected.*expected seq=2, got seq=3"):
            verify_log_lines(deleted)


class SecurityGapG17FimTests(unittest.TestCase):
    """Verification tests for G17 host file-integrity baseline and drift detection."""

    @skipIf(not (BASE_DIR / "kura.sh").exists(), "kura.sh not available in container")
    def test_g17_fim_baseline_and_drift_detection(self):
        """Plan ID: G17 | Risk ID: R09
        Verify ./kura.sh fim-baseline records deterministic hashes and ./kura.sh fim-check
        exits 0 on clean files and non-zero with event="fim.changed" when modified.
        """
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "repo"
            (root / "config").mkdir(parents=True)
            (root / "docker" / "nginx").mkdir(parents=True)
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.14-slim\n", encoding="utf-8")
            (root / "gunicorn.conf.py").write_text("workers = 5\n", encoding="utf-8")
            (root / "config" / "settings.py").write_text("DEBUG = False\n", encoding="utf-8")
            (root / "docker" / "nginx" / "kura.conf").write_text("server {}\n", encoding="utf-8")
            baseline_file = Path(tmpdir) / "fim-baseline.json"

            env = {
                **os.environ,
                "KURA_FIM_ROOT": str(root),
                "KURA_FIM_BASELINE": str(baseline_file),
            }
            res_base = subprocess.run(
                [str(BASE_DIR / "kura.sh"), "fim-baseline"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_base.returncode, 0, res_base.stderr)
            self.assertTrue(baseline_file.exists())

            res_ok = subprocess.run(
                [str(BASE_DIR / "kura.sh"), "fim-check"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
            self.assertIn('event="fim.ok"', res_ok.stdout)

            # Mutate a monitored file and verify fim-check detects drift cleanly.
            (root / "docker" / "nginx" / "kura.conf").write_text("server { listen 80; }\n", encoding="utf-8")
            res_drift = subprocess.run(
                [str(BASE_DIR / "kura.sh"), "fim-check"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res_drift.returncode, 0)
            self.assertIn('event="fim.changed"', res_drift.stdout)





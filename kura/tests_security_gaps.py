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
from django.test import Client, TestCase
from django.urls import reverse

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
            patch("kura.views.User.objects.filter", side_effect=OperationalError("db down")),
            self.assertLogs("kura.security", level="ERROR") as captured_reset,
        ):
            resp_reset = client.post(reverse("kura:password_reset_request"), {"email": "user@kura.edu"})
        self.assertEqual(resp_reset.status_code, 503)
        self._assert_no_sensitive_leak(resp_reset)
        self.assertTrue(any('event="server.dependency_unavailable"' in rec.getMessage() for rec in captured_reset.records))


"""Verify tamper-evident HMAC-SHA256 log chains emitted by kura.logging_utils."""

import hashlib
import hmac
import json
import re
import sys

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

_EVENT_START_RE = re.compile(r'event="')
_PAIR_RE = re.compile(r'([A-Za-z0-9_]+)=("(?:\\.|[^"])*"|\S+)')


def _log_hmac_key_bytes():
    raw_key = getattr(settings, "LOG_HMAC_KEY", "") or ""
    if not raw_key:
        raw_key = hmac.new(settings.SECRET_KEY.encode("utf-8"), b"kura-log-hmac-v1", hashlib.sha256).hexdigest()
    return raw_key.encode("utf-8")


def _decode_value(token):
    if token.startswith('"') and token.endswith('"'):
        try:
            return json.loads(token)
        except ValueError:
            return token.strip('"')
    return token


def verify_log_lines(lines, key_bytes=None):
    """Verify sequence continuity and HMAC-SHA256 links across security log lines.

    Who can use it: verify_log_chain management command and G11 unit tests.
    Security: Splits each line per worker PID, validates monotonic seq increments (catch deletions),
    and recomputes chained HMAC-SHA256 tags (catch edits); raises ValueError on first violation.
    """
    if key_bytes is None:
        key_bytes = _log_hmac_key_bytes()

    workers = {}
    verified = 0

    for line_no, raw_line in enumerate(lines, start=1):
        match = _EVENT_START_RE.search(raw_line)
        if not match or " mac=" not in raw_line:
            continue
        segment = raw_line[match.start() :].rstrip("\r\n")
        mac_idx = segment.rfind(" mac=")
        if mac_idx < 0:
            raise ValueError(f"Line {line_no}: missing mac field.")

        line_without_mac = segment[:mac_idx]
        fields = {m.group(1): _decode_value(m.group(2)) for m in _PAIR_RE.finditer(segment)}
        if "worker" not in fields or "seq" not in fields or "mac" not in fields:
            raise ValueError(f"Line {line_no}: incomplete chain metadata.")

        worker = str(fields["worker"])
        seq = int(fields["seq"])
        mac = str(fields["mac"])
        event_name = str(fields.get("event", ""))

        if event_name == "log.chain.start":
            if seq != 0:
                raise ValueError(f"Line {line_no} worker={worker}: log.chain.start expected seq=0, got {seq}.")
            boot_ts = str(fields.get("boot", ""))
            seed_mac = hmac.new(key_bytes, f"start:{worker}:{boot_ts}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
            expected_mac = hmac.new(key_bytes, f"{seed_mac}|{line_without_mac}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
            if not hmac.compare_digest(expected_mac, mac):
                raise ValueError(f"Line {line_no} worker={worker} seq={seq}: broken HMAC at chain start.")
            workers[worker] = {"seq": seq, "mac": mac}
            verified += 1
            continue

        state = workers.get(worker)
        if state is None:
            raise ValueError(f"Line {line_no} worker={worker} seq={seq}: missing log.chain.start before event.")

        expected_seq = state["seq"] + 1
        if seq != expected_seq:
            raise ValueError(
                f"Line {line_no} worker={worker}: sequence gap detected (expected seq={expected_seq}, got seq={seq})."
            )
        expected_mac = hmac.new(key_bytes, f"{state['mac']}|{line_without_mac}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(expected_mac, mac):
            raise ValueError(f"Line {line_no} worker={worker} seq={seq}: tampered or forged HMAC signature.")

        workers[worker] = {"seq": seq, "mac": mac}
        verified += 1

    if verified == 0:
        raise ValueError("No chained security log entries found in input.")
    return verified


class Command(BaseCommand):
    """Verify HMAC-SHA256 tamper-evident security log chains exported from Loki or Docker logs."""

    help = "Verify worker/seq/mac log chains emitted by log_security_event (G11)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--from",
            dest="source",
            required=True,
            help="Input file path, or '-' to read from stdin (e.g., from logcli query --output=raw).",
        )

    def handle(self, *args, **options):
        source = options["source"]
        if source == "-":
            lines = sys.stdin.readlines()
        else:
            with open(source, encoding="utf-8") as fh:
                lines = fh.readlines()

        try:
            verified = verify_log_lines(lines)
        except ValueError as error:
            raise CommandError(str(error)) from error

        self.stdout.write(self.style.SUCCESS(f"PASS: verified {verified} chained security log line(s)."))

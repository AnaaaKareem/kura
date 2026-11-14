import ipaddress
import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.logging_utils import log_security_event
from kura.models import AssessmentAttempt, AttendanceRecord, UserSession
from kura.permissions import service_rls_context


def anonymize_ip_address(ip_address: str) -> str:
    """
    Anonymizes an IP address by zeroing out host bits while keeping a valid format.
    IPv4 addresses are masked to /24 (e.g. 198.51.100.42 becomes 198.51.100.0).
    IPv6 addresses are masked to /48 (e.g. 2001:db8:abcd:12::1 becomes 2001:db8:abcd::).
    """
    if not ip_address:
        return ip_address
    try:
        ip = ipaddress.ip_address(ip_address.strip())
        if ip.version == 4:
            # Mask to /24 subnet (replaces the final octet with 0)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network.network_address)
        elif ip.version == 6:
            # Mask to /48 subnet (zeroes out the last 80 bits)
            network = ipaddress.IPv6Network(f"{ip}/48", strict=False)
            return str(network.network_address)
    except ValueError:
        return ip_address
    return ip_address


class Command(BaseCommand):
    help = "Anonymizes IP addresses in historic records older than the retention threshold (Law 151/2020 & GDPR compliance)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=180,
            help="Age threshold in days. IP addresses in records older than this will be anonymized (default: 180).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate anonymization without writing changes to the database.",
        )

    def handle(self, *args, **options):
        """
        Masks IP addresses in old session, login, attendance, and attempt records.
        """
        days = options["days"]
        dry_run = options["dry_run"]
        cutoff = timezone.now() - timezone.timedelta(days=days)

        self.stdout.write(
            f"[+] Starting IP anonymization for records older than {days} days (cutoff: {cutoff.isoformat()})..."
        )
        if dry_run:
            self.stdout.write(self.style.WARNING("[!] DRY-RUN MODE: No database changes will be saved."))

        total_anonymized = 0
        try:
            with service_rls_context():
                # 1. Anonymize historic UserSessions (pseudonymised to /24 IPv4 or /48 IPv6 subnet).
                sessions = UserSession.objects.filter(created_at__lt=cutoff).exclude(ip_address__isnull=True)
                session_count = 0
                for user_session in sessions:
                    anonymized_ip = anonymize_ip_address(user_session.ip_address)
                    if anonymized_ip != user_session.ip_address:
                        session_count += 1
                        if not dry_run:
                            user_session.ip_address = anonymized_ip
                            user_session.save(update_fields=["ip_address"])
                self.stdout.write(f"  - User sessions anonymized: {session_count}")
                total_anonymized += session_count

                # 2. Anonymize historic AttendanceRecords
                attendance_records = AttendanceRecord.objects.filter(verified_at__lt=cutoff).exclude(ip_address__isnull=True)
                attendance_count = 0
                for attendance_record in attendance_records:
                    anonymized_ip = anonymize_ip_address(attendance_record.ip_address)
                    if anonymized_ip != attendance_record.ip_address:
                        attendance_count += 1
                        if not dry_run:
                            attendance_record.ip_address = anonymized_ip
                            attendance_record.save(update_fields=["ip_address"])
                self.stdout.write(f"  - Attendance records anonymized: {attendance_count}")
                total_anonymized += attendance_count

                # 3. Anonymize historic AssessmentAttempts
                exam_attempts = AssessmentAttempt.objects.filter(started_at__lt=cutoff)
                exam_count = 0
                for assessment_attempt in exam_attempts:
                    anonymized_ip = anonymize_ip_address(assessment_attempt.ip_address)
                    if anonymized_ip != assessment_attempt.ip_address:
                        exam_count += 1
                        if not dry_run:
                            assessment_attempt.ip_address = anonymized_ip
                            assessment_attempt.save(update_fields=["ip_address"])
                self.stdout.write(f"  - Assessment attempts anonymized: {exam_count}")
                total_anonymized += exam_count

                # 4. Anonymize Axes AccessAttempt and AccessLog if django-axes is installed (O7, P3, P4).
                try:
                    from axes.models import AccessAttempt, AccessLog
                except ImportError:
                    self.stdout.write("  - django-axes not installed; skipping axes anonymization.")
                else:
                    axes_attempts = AccessAttempt.objects.filter(attempt_time__lt=cutoff).exclude(ip_address__isnull=True)
                    axes_attempt_count = 0
                    for access_attempt in axes_attempts:
                        anonymized_ip = anonymize_ip_address(access_attempt.ip_address)
                        if anonymized_ip != access_attempt.ip_address:
                            axes_attempt_count += 1
                            if not dry_run:
                                access_attempt.ip_address = anonymized_ip
                                access_attempt.save(update_fields=["ip_address"])
                    self.stdout.write(f"  - Axes access attempts anonymized: {axes_attempt_count}")
                    total_anonymized += axes_attempt_count

                    axes_logs = AccessLog.objects.filter(attempt_time__lt=cutoff).exclude(ip_address__isnull=True)
                    axes_count = 0
                    for access_log in axes_logs:
                        anonymized_ip = anonymize_ip_address(access_log.ip_address)
                        if anonymized_ip != access_log.ip_address:
                            axes_count += 1
                            if not dry_run:
                                access_log.ip_address = anonymized_ip
                                access_log.save(update_fields=["ip_address"])
                    self.stdout.write(f"  - Axes access logs anonymized: {axes_count}")
                    total_anonymized += axes_count
        except Exception as error:
            log_security_event(
                None,
                "retention.job_failed",
                {"command": "anonymize_ips", "error_type": type(error).__name__},
                level=logging.ERROR,
            )
            raise

        msg = f"[✓] IP Anonymization complete. Total records updated: {total_anonymized}."
        self.stdout.write(self.style.SUCCESS(msg))

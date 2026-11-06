import ipaddress
from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.models import AssessmentAttempt, AttendanceRecord, LoginAttempt, UserSession


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

        # 1. Anonymize historic UserSessions
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

        # 2. Anonymize historic LoginAttempts
        attempts = LoginAttempt.objects.filter(created_at__lt=cutoff)
        attempt_count = 0
        for login_attempt in attempts:
            anonymized_ip = anonymize_ip_address(login_attempt.ip_address)
            if anonymized_ip != login_attempt.ip_address:
                attempt_count += 1
                if not dry_run:
                    login_attempt.ip_address = anonymized_ip
                    login_attempt.save(update_fields=["ip_address"])
        self.stdout.write(f"  - Login attempts anonymized: {attempt_count}")
        total_anonymized += attempt_count

        # 3. Anonymize historic AttendanceRecords
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

        # 4. Anonymize historic AssessmentAttempts
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

        # 5. Anonymize Axes AccessLog if django-axes is installed
        try:
            from axes.models import AccessLog

            axes_logs = AccessLog.objects.filter(attempt_time__lt=cutoff)
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
        except ImportError, Exception:
            pass

        msg = f"[✓] IP Anonymization complete. Total records updated: {total_anonymized}."
        self.stdout.write(self.style.SUCCESS(msg))

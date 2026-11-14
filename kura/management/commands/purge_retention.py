from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.logging_utils import log_security_event
from kura.models import LoginAttempt, OutgoingEmail, OutgoingEmailStatus, UserSession
from kura.permissions import service_rls_context


class Command(BaseCommand):
    help = "Purges expired sessions, obsolete login logs, and old sent emails exceeding retention thresholds (Law 175/2018 & Law 151/2020)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=180,
            help="Retention threshold in days for sessions and login logs (default: 180).",
        )
        parser.add_argument(
            "--email-days",
            type=int,
            default=30,
            help="Retention threshold in days for sent outgoing emails (default: 30).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate purge without deleting records from the database.",
        )

    def handle(self, *args, **options):
        """
        Deletes expired sessions, old login records, and sent emails older than the retention thresholds while preserving active lockouts.
        """
        days = options["days"]
        email_days = options["email_days"]
        dry_run = options["dry_run"]
        now = timezone.now()
        cutoff = now - timezone.timedelta(days=days)
        email_cutoff = now - timezone.timedelta(days=email_days)

        self.stdout.write(
            f"[+] Starting retention purge for expired records older than {days} days (cutoff: {cutoff.isoformat()})..."
        )
        if dry_run:
            self.stdout.write(self.style.WARNING("[!] DRY-RUN MODE: No records will be deleted."))

        total_purged = 0
        with service_rls_context():
            # 1. Purge expired or revoked UserSessions
            expired_sessions = UserSession.objects.filter(expires_at__lt=cutoff)
            session_count = expired_sessions.count()
            if not dry_run and session_count > 0:
                deleted_sessions, _ = expired_sessions.delete()
            self.stdout.write(f"  - Expired user sessions purged: {session_count}")
            total_purged += session_count

            # 2. Purge resolved historical LoginAttempts
            # Keep currently locked attempts to prevent bypassing active lockouts
            attempts_without_active_lock = LoginAttempt.objects.filter(
                created_at__lt=cutoff,
                locked_until__isnull=True,
            )
            attempts_with_expired_lock = LoginAttempt.objects.filter(created_at__lt=cutoff, locked_until__lt=timezone.now())
            old_attempts = attempts_without_active_lock | attempts_with_expired_lock
            attempt_count = old_attempts.count()
            if not dry_run and attempt_count > 0:
                deleted_attempts, _ = old_attempts.delete()
            self.stdout.write(f"  - Obsolete login attempts purged: {attempt_count}")
            total_purged += attempt_count

            # 3. Purge historic Axes AccessLog
            try:
                from axes.models import AccessLog

                old_axes = AccessLog.objects.filter(attempt_time__lt=cutoff)
                axes_count = old_axes.count()
                if not dry_run and axes_count > 0:
                    old_axes.delete()
                self.stdout.write(f"  - Axes access logs purged: {axes_count}")
                total_purged += axes_count
            except ImportError, Exception:
                pass

            # 4. Purge sent OutgoingEmail rows older than 30 days (Q10)
            old_sent_emails = OutgoingEmail.objects.filter(
                status=OutgoingEmailStatus.SENT,
                sent_at__lt=email_cutoff,
            )
            email_count = old_sent_emails.count()
            if not dry_run:
                deleted_emails = 0
                if email_count > 0:
                    deleted_emails, _ = old_sent_emails.delete()
                log_security_event(None, "email.purged", {"count": deleted_emails})
            self.stdout.write(f"  - Sent emails purged (>{email_days}d): {email_count}")
            total_purged += email_count

        msg = f"[✓] Retention purge complete. Total expired records deleted: {total_purged}."
        self.stdout.write(self.style.SUCCESS(msg))

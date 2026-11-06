from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.models import LoginAttempt, UserSession


class Command(BaseCommand):
    help = "Purges expired sessions and obsolete login logs exceeding the retention threshold (Law 175/2018 & Law 151/2020)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=180,
            help="Retention threshold in days. Expired records older than this will be permanently purged (default: 180).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate purge without deleting records from the database.",
        )

    def handle(self, *args, **options):
        """
        Deletes expired sessions and old login records while preserving active lockouts.
        """
        days = options["days"]
        dry_run = options["dry_run"]
        cutoff = timezone.now() - timezone.timedelta(days=days)

        self.stdout.write(
            f"[+] Starting retention purge for expired records older than {days} days (cutoff: {cutoff.isoformat()})..."
        )
        if dry_run:
            self.stdout.write(self.style.WARNING("[!] DRY-RUN MODE: No records will be deleted."))

        total_purged = 0

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

        msg = f"[✓] Retention purge complete. Total expired records deleted: {total_purged}."
        self.stdout.write(self.style.SUCCESS(msg))

"""
Prints Kura's application numbers in Prometheus text format.

The host cron job saves the output into the metrics folder that Alloy reads
(the "textfile" collector), so Prometheus can graph and alert on them:

    docker compose exec -T web python manage.py write_app_metrics > var/metrics/kura_app.prom.tmp
    mv var/metrics/kura_app.prom.tmp var/metrics/kura_app.prom

(writing to .tmp first and then renaming means Alloy never reads half a file).
Only COUNTS are printed: no names, emails, IDs or any other personal data.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.models import (
    AppealStatus,
    GradeAppeal,
    OutgoingEmail,
    OutgoingEmailStatus,
    QuarantinedFile,
    UserSession,
)


class Command(BaseCommand):
    help = "Prints application metrics (counts only) in Prometheus text format."

    def handle(self, *args, **options):
        now = timezone.now()

        # Emails still waiting to be sent, and how long the oldest has waited.
        pending_emails = OutgoingEmail.objects.filter(status=OutgoingEmailStatus.PENDING)
        pending_count = pending_emails.count()
        oldest_pending = pending_emails.order_by("created_at").first()
        oldest_pending_seconds = 0
        if oldest_pending:
            oldest_pending_seconds = int((now - oldest_pending.created_at).total_seconds())

        # Emails given up on (it only ever grows, so alerts can use increase()).
        failed_count = OutgoingEmail.objects.filter(status=OutgoingEmailStatus.FAILED).count()

        # Rejected uploads kept for investigation.
        quarantined_count = QuarantinedFile.objects.count()

        # Sessions that are still valid (not ended and not expired).
        active_sessions = UserSession.objects.filter(revoked_at__isnull=True, expires_at__gt=now).count()

        # Grade appeals waiting for a decision.
        pending_appeals = GradeAppeal.objects.filter(status=AppealStatus.PENDING).count()

        # One block per metric: a description, its type, and its value.
        metrics = [
            ("kura_outbox_pending", "gauge", "Emails waiting in the outbox.", pending_count),
            ("kura_outbox_oldest_pending_seconds", "gauge", "Age of the oldest waiting email.", oldest_pending_seconds),
            ("kura_outbox_failed_total", "counter", "Emails given up on after all attempts.", failed_count),
            ("kura_quarantined_files", "gauge", "Uploads rejected by ClamAV and kept in quarantine.", quarantined_count),
            ("kura_active_sessions", "gauge", "Sessions that are still valid.", active_sessions),
            ("kura_pending_appeals", "gauge", "Grade appeals waiting for a decision.", pending_appeals),
        ]
        for name, metric_type, description, value in metrics:
            self.stdout.write(f"# HELP {name} {description}")
            self.stdout.write(f"# TYPE {name} {metric_type}")
            self.stdout.write(f"{name} {value}")

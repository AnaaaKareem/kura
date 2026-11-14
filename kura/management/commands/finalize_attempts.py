from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from kura.models import AssessmentAttempt, AttemptStatus
from kura.permissions import service_rls_context
from kura.views import compute_submission_hash, evaluate_attempt


class Command(BaseCommand):
    help = "Auto-finalizes assessment attempts that passed their deadline without manual submission."

    def handle(self, *args, **options):
        """
        Submits and grades assessment attempts whose allowed duration has expired.
        """
        with service_rls_context():
            # Query active in-progress attempts whose timer has expired.
            now = timezone.now()
            overdue_attempts = AssessmentAttempt.objects.filter(
                status=AttemptStatus.IN_PROGRESS,
                expires_at__lt=now,
            )

            finalized_count = 0
            for overdue_attempt in overdue_attempts:
                # Share the upload/submission lock and recheck in case another request finished first.
                with transaction.atomic():
                    attempt = AssessmentAttempt.objects.select_for_update().get(id=overdue_attempt.id)
                    if attempt.status != AttemptStatus.IN_PROGRESS or attempt.expires_at >= timezone.now():
                        continue
                    attempt.submitted_at = attempt.expires_at
                    attempt.submission_hash = compute_submission_hash(attempt)
                    evaluate_attempt(attempt)
                    finalized_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"Successfully finalized {finalized_count} overdue assessment attempt(s).")
        )

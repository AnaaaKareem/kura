from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from kura.models import AssessmentAttempt, AttemptStatus
from kura.permissions import service_rls_context
from kura.signing import build_submission_payload, sign_payload
from kura.views import compute_submission_hash


class Command(BaseCommand):
    help = "Auto-finalizes assessment attempts that passed their deadline without manual submission."

    def handle(self, *args, **options):
        """Submit assessment attempts that are still open after their assessment's due date."""
        with service_rls_context():
            # Query in-progress attempts whose assessment is past its due date.
            now = timezone.now()
            overdue_attempts = AssessmentAttempt.objects.filter(
                status=AttemptStatus.IN_PROGRESS,
                assessment__due_date__lt=now,
            )

            finalized_count = 0
            for overdue_attempt in overdue_attempts:
                # Share the upload/submission lock and recheck in case another request finished first.
                with transaction.atomic():
                    attempt = AssessmentAttempt.objects.select_for_update().select_related("assessment").get(
                        id=overdue_attempt.id
                    )
                    if attempt.status != AttemptStatus.IN_PROGRESS or attempt.assessment.due_date >= timezone.now():
                        continue
                    # An empty attempt is still sealed, with a hash and signature over no files, so it goes to the marker as a signed non-submission record.
                    attempt.submitted_at = attempt.assessment.due_date
                    attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
                    attempt.submission_hash = compute_submission_hash(attempt)
                    attempt.submission_signature = sign_payload(build_submission_payload(attempt))
                    attempt.save()
                    finalized_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"Successfully finalized {finalized_count} overdue assessment attempt(s).")
        )

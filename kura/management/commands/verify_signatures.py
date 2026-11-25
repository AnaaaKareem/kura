"""Verify cryptographic signatures on submitted attempts and finalized/released grades."""

import datetime
import logging

from django.core.management.base import BaseCommand, CommandError

from kura.logging_utils import log_security_event
from kura.models import AssessmentAttempt, AttemptStatus, Grade, GradeHistory, GradeStatus
from kura.permissions import service_rls_context
from kura.signing import build_grade_payload, build_submission_payload, verify_payload
from kura.views import compute_submission_hash


class Command(BaseCommand):
    """Management command that checks receipt hashes and ECDSA/Ed25519 signatures."""

    help = "Verify cryptographic signatures on submitted attempts and finalized/released grades."

    def add_arguments(self, parser):
        parser.add_argument(
            "--since",
            help="Optional ISO date (YYYY-MM-DD); check records stamped on or after this date.",
        )

    def handle(self, *args, **options):
        """Verify stored submission receipts and grade decision signatures inside service RLS context.

        Who can use it: Host operators, nightly cron, and automated test suites.
        Security: Emits integrity.signature_failed on mismatch or missing signature and exits non-zero.
        """
        since_date = None
        if options.get("since"):
            try:
                since_date = datetime.date.fromisoformat(options["since"])
            except ValueError as error:
                raise CommandError(f"Invalid --since date {options['since']!r}; expected YYYY-MM-DD.") from error

        checked_rows = []
        failed_count = 0

        with service_rls_context():
            attempts = AssessmentAttempt.objects.exclude(status=AttemptStatus.IN_PROGRESS).filter(
                submitted_at__isnull=False
            )
            if since_date is not None:
                attempts = attempts.filter(submitted_at__date__gte=since_date)

            for attempt in attempts.order_by("submitted_at", "id"):
                recomputed_hash = compute_submission_hash(attempt)
                hash_ok = bool(attempt.submission_hash) and recomputed_hash == attempt.submission_hash
                sig_ok = bool(attempt.submission_signature) and verify_payload(
                    build_submission_payload(attempt), attempt.submission_signature
                )
                ok = hash_ok and sig_ok
                status_label = "OK" if ok else "FAIL"
                checked_rows.append(f"ATTEMPT  {attempt.id}  {status_label}")
                if not ok:
                    failed_count += 1
                    log_security_event(
                        None,
                        "integrity.signature_failed",
                        {"record_type": "assessment_attempt", "record_id": attempt.id},
                        level=logging.ERROR,
                    )

            grades = Grade.objects.filter(status__in=[GradeStatus.FINALIZED, GradeStatus.RELEASED]).order_by(
                "graded_at", "id"
            )
            if since_date is not None:
                grades = grades.filter(finalized_at__date__gte=since_date)

            for grade in grades:
                # If a post-release grade change updated grade.score, finalization_signature covers the original finalized score.
                finalized_hist = (
                    GradeHistory.objects.filter(grade=grade, new_status=GradeStatus.FINALIZED)
                    .order_by("-changed_at", "-id")
                    .first()
                )
                finalized_score = finalized_hist.new_score if finalized_hist is not None else grade.score
                fin_ok = bool(grade.finalization_signature) and verify_payload(
                    build_grade_payload(
                        grade,
                        status=GradeStatus.FINALIZED,
                        actor_id=grade.finalized_by_id,
                        at=grade.finalized_at,
                        score=finalized_score,
                    ),
                    grade.finalization_signature,
                )
                rel_ok = True
                if grade.status == GradeStatus.RELEASED:
                    rel_ok = bool(grade.release_signature) and verify_payload(
                        build_grade_payload(
                            grade,
                            status=GradeStatus.RELEASED,
                            actor_id=grade.released_by_id,
                            at=grade.released_at,
                            score=grade.score,
                        ),
                        grade.release_signature,
                    )
                ok = fin_ok and rel_ok
                status_label = "OK" if ok else "FAIL"
                checked_rows.append(f"GRADE    {grade.id}  {status_label}")
                if not ok:
                    failed_count += 1
                    log_security_event(
                        None,
                        "integrity.signature_failed",
                        {"record_type": "grade", "record_id": grade.id},
                        level=logging.ERROR,
                    )

        for row in checked_rows:
            self.stdout.write(row)
        self.stdout.write(f"Checked {len(checked_rows)} signed record(s); failures={failed_count}.")

        if failed_count > 0:
            raise CommandError(f"Signature verification failed for {failed_count} record(s).")

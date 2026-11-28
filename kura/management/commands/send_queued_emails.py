"""
Sends the emails waiting in the outbox (OutgoingEmail).

Run it every minute (host crontab):
    * * * * *  cd /path/to/kura && docker compose exec -T web python manage.py send_queued_emails

For each run:
  1. Emails that waited too long are given up on: password-reset emails after
     30 minutes (their link has expired), everything else after 3 days.
  2. Each pending email is sent through Gmail SMTP. A failed email is
     retried with growing gaps: after N failures it waits until 2**N minutes
     after it was queued (2, 4, 8 ... minutes), up to 12 attempts in total.
     So a Gmail outage of a few hours does not lose the queue.
  3. The body is wiped as soon as an email is sent or given up on, because it
     may contain a password-reset link.
Running two copies at once is safe: each email is locked while it is sent
(select_for_update with skip_locked), so it is never sent twice.
"""

import logging

from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.core.management.base import BaseCommand
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from kura.logging_utils import log_security_event
from kura.models import OutgoingEmail, OutgoingEmailStatus, PasswordResetToken, User
from kura.permissions import service_rls_context
from kura.views import create_reset_token

# How many times to try one email before giving up. The retry gaps double
# (2**attempts minutes after creation), so the last try is about 34 hours
# after queueing, inside the 3-day expiry.
MAX_ATTEMPTS = 12


class Command(BaseCommand):
    help = "Sends pending emails from the outbox through Gmail SMTP."

    def _resolve_password_reset_lookups(self, now):
        """Resolve deferred password-reset lookups outside the HTTP request path (G13).

        Who can use it: send_queued_emails cron worker running under service_rls_context().
        Security: Moves User lookups, 2-per-5-minute rate limits, and token creation out of
        password_reset_request_view so response timing does not disclose valid accounts; deletes
        unknown or throttled lookups instead of marking FAILED to avoid false EmailFailures alerts.
        """
        lookup_ids = list(
            OutgoingEmail.objects.filter(status=OutgoingEmailStatus.PENDING_LOOKUP)
            .order_by("created_at")
            .values_list("id", flat=True)[:200]
        )
        for lookup_id in lookup_ids:
            with transaction.atomic():
                row = (
                    OutgoingEmail.objects.select_for_update(skip_locked=True)
                    .filter(id=lookup_id, status=OutgoingEmailStatus.PENDING_LOOKUP)
                    .first()
                )
                if row is None:
                    continue
                if row.created_at < now - timezone.timedelta(minutes=30):
                    row.delete()
                    continue
                user = User.objects.filter(email__iexact=row.to_email, is_active=True).first()
                if user is None:
                    row.delete()
                    continue
                recent_requests = PasswordResetToken.objects.filter(
                    user=user, created_at__gte=now - timezone.timedelta(minutes=5)
                ).count()
                if recent_requests >= 2:
                    log_security_event(
                        None,
                        "auth.password.reset_throttled",
                        {"user_id": user.id},
                        level=logging.WARNING,
                    )
                    row.delete()
                    continue
                raw_token, reset_token = create_reset_token(user)
                reset_url = settings.SITE_URL.rstrip("/") + reverse(
                    "kura:password_reset_confirm", kwargs={"token": raw_token}
                )
                row.event_key = f"password-reset:{reset_token.id}"
                row.to_email = user.email
                row.subject = "Kura Password Reset Request"
                row.body = (
                    f"Hello,\n\nPlease reset your password using this link:\n{reset_url}\n\n"
                    "This link expires in 30 minutes. If you did not ask for this, ignore this email."
                )
                row.status = OutgoingEmailStatus.PENDING
                row.save(update_fields=["event_key", "to_email", "subject", "body", "status"])

    def handle(self, *args, **options):
        now = timezone.now()
        with service_rls_context():
            self._resolve_password_reset_lookups(now)

        # Give up on emails that are too old to be useful.
        expired_reset_ids = list(
            OutgoingEmail.objects.filter(
                status=OutgoingEmailStatus.PENDING,
                event_key__startswith="password-reset:",
                created_at__lt=now - timezone.timedelta(minutes=30),
            ).values_list("id", flat=True)
        )
        expired_other_ids = list(
            OutgoingEmail.objects.filter(
                status=OutgoingEmailStatus.PENDING,
                created_at__lt=now - timezone.timedelta(days=3),
            )
            .exclude(id__in=expired_reset_ids)
            .values_list("id", flat=True)
        )
        expired_ids = expired_reset_ids + expired_other_ids
        # Only touch still-pending rows so a concurrent run cannot overwrite a SENT email.
        OutgoingEmail.objects.filter(id__in=expired_ids, status=OutgoingEmailStatus.PENDING).update(
            status=OutgoingEmailStatus.FAILED, body="", last_error="Expired before it could be sent."
        )

        # Report expired messages by ID only; never log their addresses or reset links.
        for expired_email_id in expired_ids:
            log_security_event(None, "email.expired", {"email_id": expired_email_id, "error_type": "Expired"}, level=logging.WARNING)

        # Send the pending emails, oldest first (at most 200 per run).
        # shortcut: takes the 200 oldest pending emails before skipping ones whose backoff is not due, so newer emails
        # can wait behind them; revisit when enrollment or burst email volume exceeds 200 emails per outage window.
        pending_ids = list(
            OutgoingEmail.objects.filter(status=OutgoingEmailStatus.PENDING)
            .order_by("created_at")
            .values_list("id", flat=True)[:200]
        )
        sent_count = 0
        failed_count = 0

        # One SMTP connection to the relay for the whole batch.
        connection = get_connection()
        for email_id in pending_ids:
            with transaction.atomic():
                # Lock this email; skip it if another run is already sending it.
                email = (
                    OutgoingEmail.objects.select_for_update(skip_locked=True)
                    .filter(id=email_id, status=OutgoingEmailStatus.PENDING)
                    .first()
                )
                if email is None:
                    continue
                # Back off: a previously failed email waits until 2**attempts minutes after it was queued.
                retry_at = email.created_at + timezone.timedelta(minutes=2**email.attempts)
                if email.attempts > 0 and now < retry_at:
                    continue

                email.attempts += 1
                try:
                    message = EmailMessage(
                        subject=email.subject,
                        body=email.body,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[email.to_email],
                        connection=connection,
                    )
                    message.send()
                except Exception as error:
                    # Record only the kind of error (no addresses or message text).
                    email.last_error = type(error).__name__[:255]
                    failed_count += 1
                    if email.attempts >= MAX_ATTEMPTS:
                        email.status = OutgoingEmailStatus.FAILED
                        email.body = ""
                    log_security_event(
                        None,
                        "email.failed",
                        {"email_id": email.id, "error_type": type(error).__name__},
                        level=logging.WARNING,
                    )
                else:
                    # Sent: wipe the body and remember when.
                    email.status = OutgoingEmailStatus.SENT
                    email.sent_at = timezone.now()
                    email.body = ""
                    email.last_error = ""
                    sent_count += 1
                    log_security_event(None, "email.sent", {"email_id": email.id})
                email.save()
        connection.close()

        # Print only counts, never addresses or contents.
        self.stdout.write(
            f"Sent {sent_count}, failed {failed_count}, expired {len(expired_ids)}."
        )

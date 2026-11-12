"""
Sends the emails waiting in the outbox (OutgoingEmail).

Run it every minute (host crontab):
    * * * * *  cd /path/to/kura && docker compose exec -T web python manage.py send_queued_emails

For each run:
  1. Emails that waited too long are given up on: password-reset emails after
     30 minutes (their link has expired), everything else after 3 days.
  2. Each pending email is sent through the Postfix relay. A failure is
     retried on the next run, up to 5 attempts in total.
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
from django.utils import timezone

from kura.logging_utils import log_security_event
from kura.models import OutgoingEmail, OutgoingEmailStatus

# How many times to try one email before giving up.
MAX_ATTEMPTS = 5


class Command(BaseCommand):
    help = "Sends pending emails from the outbox through the mail relay."

    def handle(self, *args, **options):
        now = timezone.now()

        # 1. Give up on emails that are too old to be useful.
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
        expired_resets = OutgoingEmail.objects.filter(
            status=OutgoingEmailStatus.PENDING,
            event_key__startswith="password-reset:",
            created_at__lt=now - timezone.timedelta(minutes=30),
        ).update(status=OutgoingEmailStatus.FAILED, body="", last_error="Expired before it could be sent.")
        expired_others = OutgoingEmail.objects.filter(
            status=OutgoingEmailStatus.PENDING,
            created_at__lt=now - timezone.timedelta(days=3),
        ).update(status=OutgoingEmailStatus.FAILED, body="", last_error="Expired before it could be sent.")

        # Report expired messages by ID only; never log their addresses or reset links.
        expired_ids = expired_reset_ids + expired_other_ids
        for expired_email_id in expired_ids:
            log_security_event(None, "email.expired", {"email_id": expired_email_id, "error_type": "Expired"}, level=logging.WARNING)

        # 2. Send the pending emails, oldest first (at most 200 per run).
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
            f"Sent {sent_count}, failed {failed_count}, expired {expired_resets + expired_others}."
        )

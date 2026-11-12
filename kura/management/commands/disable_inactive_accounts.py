"""
Disables user accounts that have not signed in for --days (default 90).

Accounts that have never signed in are disabled once created_at is older than
the cutoff. Admin accounts follow the same rule so no privileged account stays
dormant; the summary reports how many Admin accounts were affected (ACL-08).
"""

import logging

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from kura.logging_utils import log_security_event
from kura.models import User, UserRole, UserSession


class Command(BaseCommand):
    help = "Disables active user accounts with no sign-in for --days (default 90)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=90,
            help="Disable accounts inactive for more than this many days (default: 90).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many accounts would be disabled without changing anything.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        if days < 1:
            raise CommandError("--days must be at least 1.")

        now = timezone.now()
        cutoff = now - timezone.timedelta(days=days)

        # Select active accounts whose last login is older than the cutoff, or
        # that were created before the cutoff and have never signed in (ACL-08).
        inactive_users = User.objects.filter(is_active=True).filter(
            Q(last_login__lt=cutoff) | Q(last_login__isnull=True, created_at__lt=cutoff)
        )

        # Uniform rule: Admin accounts are not exempted, only counted separately.
        admin_user_ids = set(
            UserRole.objects.filter(user__in=inactive_users, role__name="Admin").values_list("user_id", flat=True)
        )

        if options["dry_run"]:
            total_count = inactive_users.count()
            self.stdout.write(
                f"Dry run: would disable {total_count} inactive account(s) ({len(admin_user_ids)} Admin)."
            )
            return

        disabled_count = 0
        admin_disabled_count = 0
        for target_user in inactive_users.iterator():
            with transaction.atomic():
                locked_user = User.objects.select_for_update().filter(id=target_user.id, is_active=True).first()
                if locked_user is None:
                    continue
                locked_user.is_active = False
                locked_user.deactivated_at = now
                locked_user.save(update_fields=["is_active", "deactivated_at"])
                UserSession.objects.filter(user=locked_user, revoked_at__isnull=True).update(revoked_at=now)
                log_security_event(
                    None,
                    "account.deactivated.inactive",
                    {"user_id": str(locked_user.id), "days": days},
                    level=logging.WARNING,
                )
            disabled_count += 1
            if locked_user.id in admin_user_ids:
                admin_disabled_count += 1

        # Print only counts, never email addresses or personal details.
        self.stdout.write(
            self.style.SUCCESS(
                f"Disabled {disabled_count} inactive account(s) ({admin_disabled_count} Admin)."
            )
        )

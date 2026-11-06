"""
Deletes quarantined uploads (files ClamAV rejected) older than 7 days.

The security log entry written when each file was rejected stays: only the
stored bytes and the quarantine record are removed. Run it once a day, e.g.:
    docker compose exec web python manage.py purge_quarantine
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from kura.models import QuarantinedFile


class Command(BaseCommand):
    help = "Deletes quarantined uploads older than --days (default 7)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Keep quarantined uploads for this many days (default: 7).",
        )

    def handle(self, *args, **options):
        # Anything created before this moment is old enough to delete.
        cutoff = timezone.now() - timezone.timedelta(days=options["days"])

        # Delete the old records (and their bytes) in one query.
        deleted_count, _ = QuarantinedFile.objects.filter(created_at__lt=cutoff).delete()

        # Print only a count, never file names or contents.
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} quarantined upload(s)."))

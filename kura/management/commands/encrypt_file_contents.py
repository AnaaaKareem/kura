"""
Encrypts uploaded file contents saved before hybrid file encryption was enabled.

Run it once after deploying with Vault running and the kura-files key created:
    docker compose exec web python manage.py encrypt_file_contents

Rows already at encryption_version=1 are skipped, so running it again is safe.
Only counts are printed, never keys, nonces, or file contents.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from kura.models import FileContent
from kura.vault import encrypt_file_content


class Command(BaseCommand):
    help = "Encrypts legacy plaintext FileContent rows with AES-256-GCM + Vault RSA-4096 key wrapping."

    def handle(self, *args, **options):
        if not getattr(settings, "VAULT_ENABLED", False):
            raise CommandError("Vault is disabled (VAULT_ENABLED is False), so nothing was encrypted.")

        encrypted_count = 0
        skipped_count = FileContent.objects.exclude(encryption_version=0).count()

        batch_ids = list(
            FileContent.objects.filter(encryption_version=0).order_by("file_id").values_list("file_id", flat=True)
        )
        batch_size = 100
        for start in range(0, len(batch_ids), batch_size):
            chunk_ids = batch_ids[start : start + batch_size]
            for file_content in FileContent.objects.filter(file_id__in=chunk_ids, encryption_version=0).order_by(
                "file_id"
            ):
                with transaction.atomic():
                    locked = FileContent.objects.select_for_update().get(file_id=file_content.file_id)
                    if locked.encryption_version != 0:
                        continue
                    encrypted = encrypt_file_content(bytes(locked.content), locked.file_id)
                    locked.content = encrypted["content"]
                    locked.wrapped_key = encrypted["wrapped_key"]
                    locked.nonce = encrypted["nonce"]
                    locked.encryption_version = encrypted["encryption_version"]
                    locked.save(update_fields=["content", "wrapped_key", "nonce", "encryption_version"])
                    encrypted_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"Encrypted {encrypted_count} file(s); {skipped_count} were already encrypted.")
        )

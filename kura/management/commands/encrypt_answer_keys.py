"""
Encrypts exam answer keys that were saved before answer-key encryption existed.

Run it once after deploying, with Vault running:
    docker compose exec web python manage.py encrypt_answer_keys

Keys that are already encrypted are skipped, so running it again does no harm.
It prints only counts, never an answer key.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from kura.models import ExamAnswerKey
from kura.vault import encrypt_answer_key


class Command(BaseCommand):
    help = "Encrypts plain answer keys with Vault (already encrypted keys are skipped)."

    def handle(self, *args, **options):
        # With Vault off nothing can be encrypted, so stop instead of pretending.
        if not getattr(settings, "VAULT_ENABLED", False):
            raise CommandError("Vault is disabled (VAULT_ENABLED is False), so nothing was encrypted.")

        encrypted_count = 0
        skipped_count = 0
        for answer_key in ExamAnswerKey.objects.all():
            # An encrypted key looks like {"ciphertext": "vault:v1:..."}: leave it alone.
            ciphertext = answer_key.answer_key_json.get("ciphertext", "")
            if isinstance(ciphertext, str) and ciphertext.startswith("vault:"):
                skipped_count += 1
                continue

            # Encrypt the plain key and save only that one field. If Vault is
            # down, encrypt_answer_key raises an error and the command stops;
            # keys saved before the error stay encrypted.
            answer_key.answer_key_json = encrypt_answer_key(answer_key.answer_key_json)
            answer_key.save(update_fields=["answer_key_json"])
            encrypted_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"Encrypted {encrypted_count} answer key(s); {skipped_count} were already encrypted.")
        )

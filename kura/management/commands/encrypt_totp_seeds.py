"""
Moves existing authenticator (TOTP) seeds into Vault.

Before stage 2, each seed was stored in plain text in TOTPDevice.key. Now the
seed must only exist as Vault ciphertext in User.mfa_secret. This command, for
every confirmed authenticator whose user has no mfa_secret yet:
  1. asks Vault to encrypt the old seed and saves the ciphertext in User.mfa_secret,
  2. replaces TOTPDevice.key with a random placeholder.
The user's authenticator app keeps working, because the seed itself is unchanged.

Run it once after Vault is set up and unsealed:
    docker compose exec web python manage.py encrypt_totp_seeds
Running it again is safe: users who already have mfa_secret are skipped.
"""

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from kura.vault import encrypt_mfa_secret


class Command(BaseCommand):
    help = "Encrypts existing authenticator seeds with Vault and removes them from TOTPDevice.key."

    def handle(self, *args, **options):
        moved_count = 0

        # Only confirmed authenticators matter: unconfirmed ones get a fresh
        # seed the next time the user opens the MFA setup page.
        devices = TOTPDevice.objects.filter(confirmed=True).select_related("user")
        for device in devices:
            user = device.user

            # Skip users whose seed is already in Vault (safe to run twice).
            if user.mfa_secret:
                continue

            # Encrypt the old seed and swap in a placeholder in one transaction,
            # so a user can never end up with neither (or both) copies saved.
            try:
                with transaction.atomic():
                    user.mfa_secret = encrypt_mfa_secret(device.key)
                    user.save(update_fields=["mfa_secret"])
                    device.key = random_hex(20)
                    device.save(update_fields=["key"])
            except ValidationError as error:
                # Vault is down or sealed. Stop: nothing for this user was changed.
                raise CommandError(
                    f"Vault could not encrypt the seeds. {moved_count} moved before the error."
                ) from error

            moved_count += 1

        # Print only a count: never print seeds or e-mail addresses.
        self.stdout.write(self.style.SUCCESS(f"Moved {moved_count} authenticator seed(s) into Vault."))

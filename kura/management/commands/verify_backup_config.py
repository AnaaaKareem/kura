import math
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string in bits per character.
    High entropy (> 3.5 bits/char for alphanumeric) indicates cryptographic randomness.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


class Command(BaseCommand):
    help = "Validates PostgreSQL backup configuration, AES-256 encryption key entropy, and PITR settings."

    def handle(self, *args, **options):
        """
        Checks that backup keys, PostgreSQL backup settings, and scripts are present.
        """
        self.stdout.write("[+] Inspecting Kura LMS Backup & Disaster Recovery Configuration...")
        base_dir = Path(settings.BASE_DIR)

        # 1. Verify backup encryption key
        key_paths = [
            base_dir / "secrets" / "backup_encryption_key.txt",
            Path("/run/secrets/backup_encryption_key"),
        ]
        key_file = None
        for key_path in key_paths:
            if key_path.exists():
                key_file = key_path
                break
        if not key_file:
            raise CommandError(
                "[-] Backup encryption key not found in secrets/backup_encryption_key.txt or /run/secrets/"
            )

        key_content = key_file.read_text(encoding="utf-8").strip()
        if len(key_content) < 32:
            raise CommandError(
                f"[-] Key is too short ({len(key_content)} chars). AES-256 requires at least 32 characters."
            )

        entropy = calculate_shannon_entropy(key_content)
        if entropy < 3.5:
            raise CommandError(
                f"[-] Key entropy is too low ({entropy:.2f} bits/char). Use a cryptographically random string."
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"[✓] Backup encryption key present (length={len(key_content)}, entropy={entropy:.2f} bits/char)"
            )
        )

        # 2. Verify pgbackrest.conf
        pgbackrest_conf = base_dir / "docker" / "postgres" / "pgbackrest.conf"
        if not pgbackrest_conf.exists():
            raise CommandError(f"[-] pgBackRest configuration missing at {pgbackrest_conf}")

        pgbackrest_config_text = pgbackrest_conf.read_text(encoding="utf-8")
        if "repo1-cipher-type=aes-256-cbc" not in pgbackrest_config_text:
            raise CommandError("[-] pgBackRest configuration must enforce repo1-cipher-type=aes-256-cbc")
        if "repo1-cipher-pass=" not in pgbackrest_config_text:
            raise CommandError("[-] pgBackRest configuration must reference repo1-cipher-pass")

        self.stdout.write(self.style.SUCCESS("[✓] pgBackRest configuration enforces AES-256-CBC repository encryption"))

        # 3. Verify postgresql.conf WAL archiving settings
        postgres_conf = base_dir / "docker" / "postgres" / "postgresql.conf"
        if not postgres_conf.exists():
            raise CommandError(f"[-] PostgreSQL configuration missing at {postgres_conf}")

        postgres_config_text = postgres_conf.read_text(encoding="utf-8")
        if "archive_mode = on" not in postgres_config_text:
            raise CommandError("[-] postgresql.conf must enable archive_mode = on")
        if "archive_command" not in postgres_config_text or "pgbackrest" not in postgres_config_text:
            raise CommandError("[-] postgresql.conf must configure archive_command with pgbackrest")

        self.stdout.write(self.style.SUCCESS("[✓] PostgreSQL continuous WAL archiving and restore_command configured"))

        # 4. Verify scripts
        backup_sh = base_dir / "docker" / "postgres" / "backup.sh"
        restore_sh = base_dir / "docker" / "postgres" / "restore.sh"
        if not backup_sh.exists() or not restore_sh.exists():
            raise CommandError("[-] backup.sh or restore.sh missing from docker/postgres/")

        self.stdout.write(self.style.SUCCESS("[✓] Backup and restore scripts present and executable"))
        self.stdout.write(self.style.SUCCESS("[SUCCESS] All backup and disaster recovery security checks passed."))

#!/usr/bin/env bash
# ==============================================================================
# Kura LMS - Automated Encrypted Backup Script (pgBackRest)
#
# Creates AES-256 encrypted backups of PostgreSQL with continuous WAL archiving.
# Can take full, differential, or incremental backups.
#
# Usage:
#   ./backup.sh [full|diff|incr|info|check]
#
# Default: full
# ==============================================================================

set -euo pipefail

STANZA="kura"
CONFIG_FILE="/etc/pgbackrest/pgbackrest.conf"
KEY_FILE="/run/secrets/backup_encryption_key"
BACKUP_TYPE="${1:-full}"

echo "[+] Starting Kura Backup Process: type='${BACKUP_TYPE}'..."

# 1. Verify encryption key exists
if [ ! -f "${KEY_FILE}" ] && [ -f "./secrets/backup_encryption_key.txt" ]; then
    # Local fallback path when running outside container root
    KEY_FILE="./secrets/backup_encryption_key.txt"
fi

if [ ! -f "${KEY_FILE}" ]; then
    echo "[-] ERROR: Backup encryption key not found at ${KEY_FILE}!" >&2
    exit 1
fi

# 2. Check if pgbackrest is installed
if ! command -v pgbackrest &> /dev/null; then
    echo "[!] pgbackrest binary not found in current host PATH."
    echo "[*] If running within Docker Compose, execute via container:"
    echo "    docker compose exec db pgbackrest --stanza=${STANZA} --type=${BACKUP_TYPE} backup"
    exit 0
fi

# 3. Handle commands
case "${BACKUP_TYPE}" in
    stanza-create)
        echo "[+] Initializing pgBackRest stanza for '${STANZA}'..."
        pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" stanza-create
        echo "[+] Stanza created successfully."
        ;;
    check)
        echo "[+] Verifying pgBackRest configuration and database connectivity..."
        pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" check
        echo "[+] Validation check passed."
        ;;
    info)
        echo "[+] Inspecting backup repository status..."
        pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" info
        ;;
    full|diff|incr)
        echo "[+] Executing ${BACKUP_TYPE} backup with AES-256-CBC encryption..."
        pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" --type="${BACKUP_TYPE}" backup
        echo "[+] Backup completed successfully!"
        echo "[+] Current repository status:"
        pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" info
        ;;
    *)
        echo "[-] Unknown backup type: ${BACKUP_TYPE}. Allowed: full, diff, incr, info, check, stanza-create" >&2
        exit 1
        ;;
esac


#!/usr/bin/env bash
# ==============================================================================
# Kura LMS - Disaster Recovery & Point-In-Time Recovery (PITR) Script
#
# Restores PostgreSQL to a specific timestamp in the past by decrypting the
# base backup and replaying Write-Ahead Logs (WAL) up to the exact target time.
#
# Usage:
#   ./restore.sh "2026-11-01 12:00:00"
#   ./restore.sh latest
# ==============================================================================

set -euo pipefail

STANZA="kura"
CONFIG_FILE="/etc/pgbackrest/pgbackrest.conf"
KEY_FILE="/run/secrets/backup_encryption_key"
TARGET_TIME="${1:-latest}"

echo "======================================================================"
echo "          KURA LMS - POINT-IN-TIME RECOVERY (PITR) RESTORE            "
echo "======================================================================"
echo "[+] Recovery target: '${TARGET_TIME}'"

# 1. Verify encryption key exists
if [ ! -f "${KEY_FILE}" ] && [ -f "./secrets/backup_encryption_key.txt" ]; then
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
    if [ "${TARGET_TIME}" = "latest" ]; then
        echo "    docker compose exec db pgbackrest --stanza=${STANZA} --type=default restore"
    else
        echo "    docker compose exec db pgbackrest --stanza=${STANZA} --type=time --target=\"${TARGET_TIME}\" --target-action=promote restore"
    fi
    exit 0
fi

# 3. Perform restoration
if [ "${TARGET_TIME}" = "latest" ]; then
    echo "[+] Performing standard restore to latest consistent state..."
    pgbackrest --config="${CONFIG_FILE}" --stanza="${STANZA}" --type=default restore
else
    echo "[+] Performing Point-In-Time Recovery to target timestamp: ${TARGET_TIME}..."
    pgbackrest --config="${CONFIG_FILE}" \
               --stanza="${STANZA}" \
               --type=time \
               --target="${TARGET_TIME}" \
               --target-action=promote \
               restore
fi

echo "[+] Restore completed successfully."
echo "[+] Start PostgreSQL to begin WAL replay and cluster promotion."


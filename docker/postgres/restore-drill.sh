#!/bin/sh
# ==============================================================================
# SAFE restore drill: restores the backups into a THROWAWAY database and
# compares it with the live one. The live database is never touched.
#
#     sh docker/postgres/restore-drill.sh                    # latest backup
#     sh docker/postgres/restore-drill.sh "2026-11-06 15:30:00+00"   # point in time
#
# Safety:
#   - the restore runs in a separate container with NO network (--network none)
#   - into its own new, empty volume (kura_restore_drill_<time>)
#   - with WAL archiving OFF, so the drill can never write into the backup repo
#   - the backup repository volume is mounted READ-ONLY
# At the end it prints row counts from the live and the restored database and
# how long the restore took (the "RTO"). Remove the drill volume afterwards
# with the command it prints.
# ==============================================================================
set -e
cd "$(dirname "$0")/../.."

TARGET_TIME=${1:-latest}
IMAGE=$(docker compose config --images db | head -1)
DRILL_VOLUME="kura_restore_drill_$(date +%Y%m%d%H%M%S)"
DRILL_CONTAINER="kura-restore-drill"
START_SECONDS=$(date +%s)

# The tables compared between live and restored databases (counts only).
TABLES="users courses enrollments assessments grades outgoing_emails"

# 1. A new empty volume for the restored data, owned by the image's postgres user (UID 26).
docker volume create "$DRILL_VOLUME" > /dev/null
docker run --rm -v "$DRILL_VOLUME":/restore --entrypoint sh "$IMAGE" -c 'chown 26:26 /restore && chmod 700 /restore' > /dev/null 2>&1 || \
    docker run --rm --user 0 -v "$DRILL_VOLUME":/restore --entrypoint sh "$IMAGE" -c 'chown 26:26 /restore && chmod 700 /restore'

# 2. Restore with pgBackRest into that volume. "--type=time" stops replaying
#    WAL at TARGET_TIME (point-in-time recovery); "latest" replays everything.
#    The options are kept as separate, quoted arguments ("set --"), because the
#    target time contains a space and must stay one argument.
if [ "$TARGET_TIME" = "latest" ]; then
    set -- --type=default
else
    set -- --type=time "--target=$TARGET_TIME" --target-action=promote
fi
echo "[1/3] Restoring backup ($TARGET_TIME) into $DRILL_VOLUME (no network)..."
docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /var/run/postgresql --tmpfs /var/log/pgbackrest \
    -v "$DRILL_VOLUME":/restore \
    -v kura_postgres_backups:/var/lib/pgbackrest:ro \
    -v "$PWD/docker/postgres/pgbackrest.conf":/etc/pgbackrest/pgbackrest.conf:ro \
    -v "$PWD/secrets/backup_encryption_key.txt":/run/secrets/backup_encryption_key:ro \
    --entrypoint pgbackrest "$IMAGE" \
    --stanza=kura --pg1-path=/restore --lock-path=/tmp "$@" restore > /dev/null

# 3. Start PostgreSQL on the restored copy: no network, no archiving, and the
#    default settings from the restored folder (so it never touches the repo).
echo "[2/3] Starting the restored copy and replaying WAL..."
docker run -d --name "$DRILL_CONTAINER" --network none --tmpfs /tmp --tmpfs /var/run/postgresql:mode=1777 --tmpfs /var/log/pgbackrest:mode=1777 \
    -v "$DRILL_VOLUME":/restore \
    -v kura_postgres_backups:/var/lib/pgbackrest:ro \
    -v "$PWD/docker/postgres/pgbackrest.conf":/etc/pgbackrest/pgbackrest.conf:ro \
    -v "$PWD/secrets/backup_encryption_key.txt":/run/secrets/backup_encryption_key:ro \
    --entrypoint postgres "$IMAGE" \
    -D /restore -c listen_addresses='' -c archive_mode=off -c shared_preload_libraries='' \
    -c unix_socket_directories=/var/run/postgresql > /dev/null

# Wait until recovery is finished and the copy accepts queries (at most 2 minutes).
for attempt in $(seq 1 60); do
    if docker exec "$DRILL_CONTAINER" psql -h /var/run/postgresql -U kura-admin -d kura -X -q -t -A -c "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q '^f$'; then
        break
    fi
    sleep 2
done
END_SECONDS=$(date +%s)

# 4. Compare row counts, live vs restored.
echo "[3/3] Comparing row counts (live -> restored):"
for TABLE in $TABLES; do
    LIVE=$(docker compose exec -T db psql -U kura-admin -d kura -X -q -t -A -c "SELECT count(*) FROM $TABLE;" 2>/dev/null || echo "?")
    RESTORED=$(docker exec "$DRILL_CONTAINER" psql -h /var/run/postgresql -U kura-admin -d kura -X -q -t -A -c "SELECT count(*) FROM $TABLE;" 2>/dev/null || echo "?")
    printf '  %-16s %6s -> %s\n' "$TABLE" "$LIVE" "$RESTORED"
done
echo "Restore + recovery took $((END_SECONDS - START_SECONDS)) seconds (RTO for this database size)."
echo ""
echo "The restored copy is still running for inspection:"
echo "  docker exec -it $DRILL_CONTAINER psql -h /var/run/postgresql -U kura-admin -d kura"
echo "Remove it when done:"
echo "  docker rm -f $DRILL_CONTAINER && docker volume rm $DRILL_VOLUME"

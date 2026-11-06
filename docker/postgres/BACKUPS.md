# PostgreSQL Encrypted Backups & Point-In-Time Recovery (PITR)

This document describes the backup and disaster recovery architecture for the Kura Learning Management System (LMS), implemented with **pgBackRest** and hardware-accelerated **AES-256-CBC encryption**.

---

## 1. Security Architecture & RPO/RTO Objectives

In an LMS holding student grades, transcripts, and assessment submissions, database resilience and confidentiality are paramount.

- **Recovery Point Objective (RPO)**: **< 5 minutes is a target, not a guarantee**. PostgreSQL is configured with `archive_timeout = 300` seconds and pgBackRest WAL archiving, but the target depends on the database and archive pipeline remaining healthy and should be verified by monitoring archive completion.
- **Recovery Time Objective (RTO)**: **< 15 minutes** is a target, not a measured guarantee. Actual recovery time depends on backup size, storage, and operator steps; test it with the isolated drill procedure before adopting it as an operational commitment.
- **Confidentiality & At-Rest Encryption**: All database backups and archived WAL segments are encrypted using **AES-256-CBC** before writing to disk (`repo1-cipher-type=aes-256-cbc`). Even if an attacker steals the backup volume or snapshots, they cannot read student data without the encryption key.
- **Key Isolation**: The encryption passphrase is never stored in source control or Git. It is injected into the container via Docker secrets at `/run/secrets/backup_encryption_key`.

---

## 2. How Point-In-Time Recovery (PITR) Works

Examiners often ask: *"How does PostgreSQL restore to an exact second in the past?"*

1. **Continuous WAL Archiving**:
   - When any transaction commits (such as grade finalization or an assessment attempt), PostgreSQL writes the change to the Write-Ahead Log (WAL).
   - As each 16 MB WAL segment completes, PostgreSQL runs `archive_command = 'pgbackrest --stanza=kura archive-push %p'`.
   - pgBackRest compresses (`lz4`) and encrypts (`AES-256`) the WAL segment, writing it to `/var/lib/pgbackrest/archive/kura/`.
2. **Physical Base Backups**:
   - Running `backup.sh full` takes a live, consistent snapshot of all table data files while PostgreSQL is active.
3. **Restoration & Replay**:
   - When restoring to a specific target (e.g. `2026-11-01 14:00:00`), pgBackRest extracts the most recent base backup taken before that timestamp into the data directory.
   - It sets `recovery_target_time = '2026-11-01 14:00:00'` and `recovery_target_action = 'promote'`.
   - When PostgreSQL starts, it decrypts and replays every archived WAL log up to that exact second, stops replay, and promotes the database to read-write mode.

---

## 3. Operational Commands & Drills

### A. Initializing the Repository Stanza (One-time setup)
Inside the database container:
```bash
docker compose exec db backup.sh stanza-create
```
Or directly via the host wrapper:
```bash
docker compose exec db pgbackrest --stanza=kura stanza-create
```

### B. Validating Connectivity & Encryption
```bash
docker compose exec db pgbackrest --stanza=kura check
```
This tests database connectivity, WAL archiving pipeline, and AES-256 cipher validation.

### C. Taking Backups
- **Full Backup**:
  ```bash
  docker compose exec db pgbackrest --stanza=kura --type=full backup
  ```
- **Differential Backup** (changes since last full):
  ```bash
  docker compose exec db pgbackrest --stanza=kura --type=diff backup
  ```
- **View Backup History and Encryption Status**:
  ```bash
  docker compose exec db pgbackrest --stanza=kura info
  ```

---

## 4. Disaster Recovery Drill (Restoring to a Point in Time)

Suppose a catastrophic event (e.g. accidental deletion or malicious grade alteration) occurred at **2026-11-01 14:15:00**:

1. **Stop the Application**:
   ```bash
   docker compose stop web
   ```
2. **Do not run a restore against the running Compose database.** pgBackRest restore replaces the cluster data directory and requires PostgreSQL to be stopped. The current `restore.sh` helper does not stop the database, and `docker compose exec` cannot run inside the service after it is stopped; the repository does not yet provide a safe, tested Compose restore workflow. Prepare a separate stopped-database restore procedure and verify it against isolated volumes before using it on any data that matters.
3. **After a separately validated restore procedure**, start PostgreSQL first, verify recovery and data integrity, and only then start the web service:
   ```bash
   docker compose restart db
   docker compose start web
   ```
4. **Verify Consistency**:
   Check student grades and assessment logs to verify that the corrupted data has been reverted and the system is back in a clean state.

---

## 5. Verification Log (2026-11-03, isolated full-stack drill)

All items below were verified on this project's pgEdge database image
(`ghcr.io/pgedge/pgedge-postgres:17-spock5-standard`, PostgreSQL 17.11,
pgBackRest 2.59.3) inside an isolated Compose project with fresh volumes;
the production volumes and data were never touched:

- `stanza-create`, two `full` backups, and `pgbackrest info` all succeeded;
  the repository reports `cipher: aes-256-cbc` (the passphrase is loaded from
  the Docker secret via `repo1-cipher-pass=file:/run/secrets/backup_encryption_key`,
  confirmed working empirically with pgBackRest 2.59.3).
- Continuous WAL archiving pushed segments 1–8 (`pg_switch_wal` used to force
  segment completion).
- A table inserted between the two backup sets restored correctly with the
  `--type=default` restore into a separate path (`/tmp/drill-restore`),
  confirming decryption and row recovery; row counts matched the source
  database exactly (users, courses, stored files, and probe rows).
- pgAudit produced audit records for DDL (`CREATE TABLE`, `CREATE EXTENSION`,
  `REVOKE`) and DML (`INSERT`) in the Docker log stream.
- Migration rollback was rehearsed with disposable volumes: a live-data dump
  was restored into a fresh pgEdge volume, a post-cutover probe write was
  dumped back into a fresh PostgreSQL 17 Alpine volume, and the probe plus
  application row counts matched. The rollback copy accepted `kura_app` reads
  and denied its attempt to create a table. Neither production volume was
  attached or changed. After a real cutover, writes must be frozen and copied
  back before routing to the previous database; restarting an old snapshot
  alone would lose post-cutover writes (see `README.md`).

## 6. Safe restore drill (checked 6 November 2026)

`docker/postgres/restore-drill.sh` restores into a **throwaway** database and
never touches the live one:
- a separate container with no network
- its own new volume
- WAL archiving switched off
- the backup volume mounted read-only

Use it for every drill. **Never** run `restore.sh` against the live data
folder.

```bash
# Point-in-time drill (time in UTC); prints live vs restored row counts and the RTO.
sh docker/postgres/restore-drill.sh "2026-11-06 15:26:03+00"
```

Result of the first drill:
- Before it, the stanza was created (it had never existed, so WAL archiving had
  been failing), then `check` and a full backup passed.
- Marker row A was written, then the target time noted, then row B written.
- The PITR restore to the target time contained **only row A**.
- Restore and recovery took 3 seconds for a 33 MB database.

The off-site repo2 drill is still to do (it needs the S3 details).

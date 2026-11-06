from django.db import migrations


TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION check_attempt_files_lock()
RETURNS TRIGGER AS $$
DECLARE
    target_status VARCHAR(50);
    target_expires_at TIMESTAMPTZ;
BEGIN
    IF (TG_OP = 'INSERT') THEN
        SELECT status, expires_at INTO target_status, target_expires_at
        FROM assessment_attempts WHERE id = NEW.attempt_id;
    ELSE
        SELECT status, expires_at INTO target_status, target_expires_at
        FROM assessment_attempts WHERE id = OLD.attempt_id;
    END IF;

    IF (target_status IS NULL) THEN
        RAISE EXCEPTION 'Associated assessment attempt not found.';
    END IF;

    IF (target_status <> 'In_Progress') THEN
        RAISE EXCEPTION 'Cannot modify attempt files: attempt is no longer in progress.';
    END IF;

    IF (target_expires_at <= CURRENT_TIMESTAMP) THEN
        RAISE EXCEPTION 'Cannot modify attempt files: attempt deadline has expired.';
    END IF;

    IF (TG_OP = 'INSERT') THEN
        RETURN NEW;
    ELSE
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS attempt_files_lock ON attempt_files;
CREATE TRIGGER attempt_files_lock
BEFORE INSERT OR DELETE ON attempt_files
FOR EACH ROW
EXECUTE FUNCTION check_attempt_files_lock();
"""

REVERSE_TRIGGER_SQL = """
DROP TRIGGER IF EXISTS attempt_files_lock ON attempt_files;
DROP FUNCTION IF EXISTS check_attempt_files_lock();
"""


class Migration(migrations.Migration):

    dependencies = [
        ('kura', '0002_seed_roles_permissions'),
    ]

    operations = [
        migrations.RunSQL(
            sql=TRIGGER_SQL,
            reverse_sql=REVERSE_TRIGGER_SQL,
        ),
    ]


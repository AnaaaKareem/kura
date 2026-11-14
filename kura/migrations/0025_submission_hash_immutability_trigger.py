from django.db import migrations


TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION protect_submission_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.submission_hash IS NOT NULL AND NEW.submission_hash IS DISTINCT FROM OLD.submission_hash) THEN
        RAISE EXCEPTION 'Cannot modify submission_hash once set.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS submission_hash_immutable ON assessment_attempts;
CREATE TRIGGER submission_hash_immutable
BEFORE UPDATE ON assessment_attempts
FOR EACH ROW
EXECUTE FUNCTION protect_submission_hash();
"""

REVERSE_TRIGGER_SQL = """
DROP TRIGGER IF EXISTS submission_hash_immutable ON assessment_attempts;
DROP FUNCTION IF EXISTS protect_submission_hash();
"""


class Migration(migrations.Migration):

    dependencies = [
        ("kura", "0024_non_empty_reason_constraints"),
    ]

    operations = [
        migrations.RunSQL(TRIGGER_SQL, REVERSE_TRIGGER_SQL),
    ]

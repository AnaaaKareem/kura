from django.db import migrations, models


TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION protect_submission_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.submission_hash IS NOT NULL AND NEW.submission_hash IS DISTINCT FROM OLD.submission_hash) THEN
        RAISE EXCEPTION 'Cannot modify submission_hash once set.';
    END IF;
    IF (
        OLD.submission_signature IS NOT NULL
        AND OLD.submission_signature <> ''
        AND NEW.submission_signature IS DISTINCT FROM OLD.submission_signature
    ) THEN
        RAISE EXCEPTION 'Cannot modify submission_signature once set.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

REVERSE_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION protect_submission_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.submission_hash IS NOT NULL AND NEW.submission_hash IS DISTINCT FROM OLD.submission_hash) THEN
        RAISE EXCEPTION 'Cannot modify submission_hash once set.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("kura", "0030_fix_attempt_files_lock_trigger"),
    ]

    operations = [
        migrations.AddField(
            model_name="assessmentattempt",
            name="submission_signature",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="grade",
            name="finalization_signature",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="grade",
            name="release_signature",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.RunSQL(TRIGGER_SQL, REVERSE_TRIGGER_SQL),
    ]

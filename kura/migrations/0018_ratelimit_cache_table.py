"""Create Django's shared cache table for RateLimitMiddleware (AUTH-08)."""

from django.core.management import call_command
from django.db import migrations


def create_ratelimit_cache(apps, schema_editor):
    # Create the shared PostgreSQL cache table so all Gunicorn workers share limits.
    call_command("createcachetable", "kura_ratelimit_cache", database=schema_editor.connection.alias, verbosity=0)


class Migration(migrations.Migration):
    dependencies = [("kura", "0017_building_room")]

    # Cache entries are temporary; keeping the table on rollback avoids dropping data.
    operations = [migrations.RunPython(create_ratelimit_cache, migrations.RunPython.noop)]

"""Create Django's shared cache table for Registrar search limits."""

from django.core.management import call_command
from django.db import migrations


def create_search_cache(apps, schema_editor):
    # Django's built-in command creates its cache table on the selected database.
    call_command("createcachetable", "kura_search_cache", database=schema_editor.connection.alias, verbosity=0)


class Migration(migrations.Migration):
    dependencies = [("kura", "0010_convert_section_items_to_markdown")]

    # Cache entries are temporary; keeping the table on rollback avoids deleting data.
    operations = [migrations.RunPython(create_search_cache, migrations.RunPython.noop)]

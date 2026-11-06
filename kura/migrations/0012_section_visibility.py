"""Allow staff to hide a section while keeping its assessment attempts."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("kura", "0011_search_cache_table")]

    operations = [
        # Existing sections stay visible after the migration.
        migrations.AddField(
            model_name="modulesection",
            name="is_visible",
            field=models.BooleanField(default=True),
        ),
    ]

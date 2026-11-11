from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("kura", "0016_grade_history_insert_only")]

    operations = [
        migrations.CreateModel(
            name="Building",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=80, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name="Room",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=80)),
                ("building", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="rooms", to="kura.building")),
            ],
            options={"constraints": [models.UniqueConstraint(fields=("building", "name"), name="unique_building_room")]},
        ),
    ]

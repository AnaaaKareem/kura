from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("kura", "0031_receipt_signatures"),
    ]

    operations = [
        migrations.AlterField(
            model_name="outgoingemail",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("pending_lookup", "Pending lookup"),
                    ("sent", "Sent"),
                    ("failed", "Failed"),
                ],
                default="pending",
                max_length=20,
            ),
        ),
    ]

# Makes the grade history (the grade audit log) insert-only for the web app.
#
# Django logs in to PostgreSQL as short-lived users that Vault creates as
# members of the kura_app role, so they have exactly kura_app's permissions.
# Kura's code only ever adds rows to grade_history; it never changes or removes
# them. This migration takes UPDATE, DELETE and TRUNCATE away from kura_app on
# that table, so even a bug or an SQL injection in the web app cannot rewrite
# or erase the record of who changed a grade.
#
# Migrations run as the table owner (kura_migrator), which keeps full rights,
# so future schema changes still work. Note: a later "GRANT ... ON ALL TABLES"
# to kura_app would give these rights back, so never add one without
# repeating this REVOKE.
#
# This uses raw SQL because Django has no ORM feature for database
# permissions (approved by the project owner, like the RLS migrations 0004
# and 0013).

from django.db import migrations

REVOKE_SQL = """
REVOKE UPDATE, DELETE, TRUNCATE ON grade_history FROM kura_app;
"""

# Undoing the migration gives back the rights the app had before.
GRANT_BACK_SQL = """
GRANT UPDATE, DELETE ON grade_history TO kura_app;
"""


class Migration(migrations.Migration):
    dependencies = [
        ("kura", "0015_outgoing_emails"),
    ]

    operations = [
        migrations.RunSQL(sql=REVOKE_SQL, reverse_sql=GRANT_BACK_SQL),
    ]

from django.db import migrations


def update_admin_permissions(apps, schema_editor):
    """Give Admin course and all-session permissions, and remove personal-session grants."""
    Role = apps.get_model("kura", "Role")
    SystemPermission = apps.get_model("kura", "SystemPermission")
    RolePermission = apps.get_model("kura", "RolePermission")
    database_alias = schema_editor.connection.alias

    # Find the existing Admin role created by the earlier role-seeding migration.
    admin_role = Role.objects.using(database_alias).get(name="Admin")

    # Add only the approved institution-wide course and session permissions to Admin.
    admin_permissions = [
        ("read", "courses", "institution"),
        ("write", "courses", "institution"),
        ("view", "sessions", "institution"),
        ("revoke", "sessions", "institution"),
    ]
    for action, resource, scope in admin_permissions:
        permission, _ = SystemPermission.objects.using(database_alias).get_or_create(
            action=action,
            resource=resource,
            scope=scope,
        )
        RolePermission.objects.using(database_alias).get_or_create(
            role_id=admin_role.pk,
            permission_id=permission.pk,
        )

    # Remove personal-session permissions from every role except Admin.
    non_admin_role_ids = Role.objects.using(database_alias).exclude(pk=admin_role.pk).values_list("pk", flat=True)
    personal_session_permissions = SystemPermission.objects.using(database_alias).filter(
        action__in=["view", "revoke"],
        resource="sessions",
        scope="self",
    )
    RolePermission.objects.using(database_alias).filter(
        role_id__in=non_admin_role_ids,
        permission_id__in=personal_session_permissions.values_list("pk", flat=True),
    ).delete()


def restore_previous_permissions(apps, schema_editor):
    """Restore personal-session grants and remove the permissions this migration added."""
    Role = apps.get_model("kura", "Role")
    SystemPermission = apps.get_model("kura", "SystemPermission")
    RolePermission = apps.get_model("kura", "RolePermission")
    database_alias = schema_editor.connection.alias

    # Find the existing Admin role so only this migration's Admin grants are removed.
    admin_role = Role.objects.using(database_alias).get(name="Admin")
    admin_permissions = [
        ("read", "courses", "institution"),
        ("write", "courses", "institution"),
        ("view", "sessions", "institution"),
        ("revoke", "sessions", "institution"),
    ]
    for action, resource, scope in admin_permissions:
        RolePermission.objects.using(database_alias).filter(
            role_id=admin_role.pk,
            permission__action=action,
            permission__resource=resource,
            permission__scope=scope,
        ).delete()

    # Restore the personal-session access that applied before this migration.
    non_admin_roles = Role.objects.using(database_alias).exclude(pk=admin_role.pk)
    for action in ["view", "revoke"]:
        permission, _ = SystemPermission.objects.using(database_alias).get_or_create(
            action=action,
            resource="sessions",
            scope="self",
        )
        for role in non_admin_roles:
            RolePermission.objects.using(database_alias).get_or_create(
                role_id=role.pk,
                permission_id=permission.pk,
            )


class Migration(migrations.Migration):
    dependencies = [
        ("kura", "0008_expand_upload_mime_allowlist"),
    ]

    operations = [
        migrations.RunPython(update_admin_permissions, restore_previous_permissions),
    ]

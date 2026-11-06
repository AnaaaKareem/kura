from django.db import migrations


def seed_roles_and_permissions(apps, schema_editor):
    Role = apps.get_model('kura', 'Role')
    SystemPermission = apps.get_model('kura', 'SystemPermission')
    RolePermission = apps.get_model('kura', 'RolePermission')

    # Six core roles from specification
    roles_data = {
        'Admin': 'System administrator (creates staff, assigns roles, sets policy; no grade access)',
        'Registrar': 'Academic registrar (creates students, enrolls and drops students; no grade access)',
        'Department head': 'Department head (manages department courses, instructors, approves grade changes)',
        'Instructor': 'Course instructor (schedules classes, manages content/assessments, finalizes/releases grades)',
        'Teaching assistant': 'Teaching assistant (conducts attendance rolls, enters draft scores)',
        'Student': 'Enrolled student (views content, takes assessments, views released grades)',
    }

    role_objs = {}
    for name, desc in roles_data.items():
        role, _ = Role.objects.get_or_create(name=name, defaults={'description': desc})
        role_objs[name] = role

    # Permissions per role as specified in "Roles" section
    role_perms = {
        'Admin': [
            ('create', 'staff_accounts', 'institution'),
            ('deactivate', 'staff_accounts', 'institution'),
            ('assign', 'system_roles', 'institution'),
            ('update', 'system_roles', 'institution'),
            ('lock', 'user_accounts', 'institution'),
            ('unlock', 'user_accounts', 'institution'),
            ('configure', 'security_policies', 'institution'),
            ('monitor', 'audit_logs', 'institution'),
            ('execute', 'backup_recovery', 'institution'),
            ('execute', 'data_retention', 'institution'),
            ('execute', 'incident_response', 'institution'),
        ],
        'Registrar': [
            ('create', 'student_accounts', 'institution'),
            ('enroll', 'course_students', 'institution'),
            ('drop', 'course_students', 'institution'),
            ('view', 'enrollment_records', 'institution'),
            ('view', 'student_profiles', 'institution'),
        ],
        'Department head': [
            ('create', 'courses', 'department'),
            ('publish', 'courses', 'department'),
            ('assign', 'course_instructors', 'department'),
            ('supervise', 'course_modules', 'department'),
            ('monitor', 'course_enrollment', 'department'),
            ('monitor', 'student_performance', 'department'),
            ('generate', 'performance_reports', 'department'),
            ('approve', 'grade_modifications', 'department'),
        ],
        'Instructor': [
            ('schedule', 'class_sessions', 'course'),
            ('manage', 'modules_and_sections', 'course'),
            ('manage', 'assessments', 'course'),
            ('assign', 'teaching_assistants', 'course'),
            ('conduct', 'attendance_sessions', 'course'),
            ('review', 'draft_grades', 'course'),
            ('finalize', 'course_grades', 'course'),
            ('release', 'course_grades', 'course'),
        ],
        'Teaching assistant': [
            ('author', 'course_materials', 'course'),
            ('conduct', 'attendance_rolls', 'course'),
            ('log', 'manual_attendance', 'course'),
            ('score', 'draft_grades', 'course'),
        ],
        'Student': [
            ('view', 'course_materials', 'enrolled_course'),
            ('view', 'class_schedules', 'enrolled_course'),
            ('checkin', 'attendance_sessions', 'enrolled_course'),
            ('view', 'attendance_history', 'self'),
            ('view', 'released_grades', 'self'),
            ('take', 'assessments', 'enrolled_course'),
            ('file', 'grade_appeals', 'self'),
            ('view', 'transcripts', 'self'),
        ],
    }

    for role_name, perms in role_perms.items():
        role = role_objs[role_name]
        for action, resource, scope in perms:
            perm, _ = SystemPermission.objects.get_or_create(
                action=action,
                resource=resource,
                scope=scope,
            )
            RolePermission.objects.get_or_create(role=role, permission=perm)


def remove_roles_and_permissions(apps, schema_editor):
    Role = apps.get_model('kura', 'Role')
    SystemPermission = apps.get_model('kura', 'SystemPermission')
    RolePermission = apps.get_model('kura', 'RolePermission')

    RolePermission.objects.all().delete()
    SystemPermission.objects.all().delete()
    Role.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('kura', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_roles_and_permissions, remove_roles_and_permissions),
    ]


"""Role and course checks used by views before they show or change records.

Every helper treats anonymous or inactive users as having no access. Roles come
from the UserRole table, and course access also needs a matching CourseStaff or
Enrollment row, so holding a role alone is never enough to open a course.
"""
from contextlib import contextmanager

from django.db import connection
from django.utils import timezone

from .models import CourseStaff, Enrollment, EnrollmentStatus, RolePermission, UserRole


@contextmanager
def service_rls_context():
    """Set the PostgreSQL service RLS context for authorized background commands (nest-safe)."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('kura.service_role', true);")
        previous_role = cursor.fetchone()[0]
        cursor.execute("SET kura.service_role = 'management_command';")
    try:
        yield
    finally:
        with connection.cursor() as cursor:
            if previous_role:
                # set_config is SET for the session, but accepts a bound parameter.
                cursor.execute("SELECT set_config('kura.service_role', %s, false);", [previous_role])
            else:
                cursor.execute("RESET kura.service_role;")


def has_role(user, role_name):
    """Check whether an active user has been assigned a specific system role.
    Returns False for anonymous or inactive accounts.
    """
    # Anonymous or inactive users cannot hold active roles.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check if the user has a UserRole record with this role name.
    return UserRole.objects.filter(user=user, role__name=role_name).exists()


def is_admin_course_manager(user):
    """Check whether the user has institution-wide course management authority (Admin role)."""
    # The system role, not Django's unrelated is_staff flag, grants this authority.
    return has_role(user, "Admin")


def can_manage_quarantine(user):
    """Check whether the user may see and delete quarantined uploads (files ClamAV rejected).
    Rule: system security and maintenance belong to the Admin role only.
    """
    # Only the Admin system role may review infected uploads.
    return has_role(user, "Admin")


def can_access_learning_records(user):
    """Check whether the user is allowed to access learning records and grades.
    Denies access when the user holds either the Admin or Registrar role.
    """
    # A restricted role still applies when the same user also has another role.
    if has_role(user, "Admin"):
        return False

    if has_role(user, "Registrar"):
        return False

    return True


def has_permission(user, action, resource, scope):
    """Check whether any of the user's assigned roles grant a system permission.
    Admins and Registrars are blocked from instructional content and grades.
    """
    # Anonymous or inactive users have no permissions.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # An additional role must not bypass restricted access to teaching or assessment content.
    restricted_resources = (
        "grades",
        "course_grades",
        "draft_grades",
        "grade_modifications",
        "assessments",
        "assessment_attempts",
        "attempts",
        "scores",
        "course_materials",
    )
    if resource in restricted_resources and not can_access_learning_records(user):
        return False

    # Look up if any of the user's roles has been granted this permission.
    user_roles = UserRole.objects.filter(user=user).values_list("role_id", flat=True)
    return RolePermission.objects.filter(
        role_id__in=user_roles,
        permission__action=action,
        permission__resource=resource,
        permission__scope=scope,
    ).exists()


def is_department_head(user, department):
    """Check whether the user is the appointed Department Head for the given department."""
    # Anonymous or inactive users cannot be department heads.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check if the user is the assigned head of this department and holds the Department head role.
    if not department or department.head_user_id != user.id:
        return False

    return has_role(user, "Department head")


def is_course_staff(user, course):
    """Check whether the user is assigned as staff (instructor or TA) on the course."""
    # Anonymous or inactive users cannot be course staff.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # The current system role must match the course assignment, even after a role change.
    if (
        has_role(user, "Instructor")
        and CourseStaff.objects.filter(
            course=course, user=user, staff_role__in=["lead_instructor", "co_instructor"]
        ).exists()
    ):
        return True
    if (
        has_role(user, "Teaching assistant")
        and CourseStaff.objects.filter(course=course, user=user, staff_role="teaching_assistant").exists()
    ):
        return True
    return False


def is_course_instructor(user, course):
    """Check whether the user is assigned as a lead or co-instructor on the course.
    Rule: teaching assistants may enter grades but cannot finalize them.
    """
    # Anonymous or inactive users cannot be course instructors.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Both the Instructor role and a lead/co-instructor assignment on this course are required.
    return (
        has_role(user, "Instructor")
        and CourseStaff.objects.filter(
            course=course,
            user=user,
            staff_role__in=["lead_instructor", "co_instructor"],
        ).exists()
    )


def is_lead_instructor(user, course):
    """Check whether the user is assigned as the Lead Instructor for the course."""
    # Anonymous or inactive users cannot be lead instructors.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # A former instructor must not retain lead-instructor authority.
    return (
        has_role(user, "Instructor")
        and CourseStaff.objects.filter(
            course=course,
            user=user,
            staff_role="lead_instructor",
        ).exists()
    )


def can_release_grades(user, course):
    """Check whether the user is allowed to release finalized grades for this course.
    Requires the Instructor role and the can_release_grades flag on the course assignment.
    """
    # Anonymous or inactive users cannot release grades.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Only instructors can release grades; restricted roles cannot bypass this rule.
    if not can_access_learning_records(user) or not has_role(user, "Instructor"):
        return False

    # Instructors must have can_release_grades=True on their staff assignment.
    return CourseStaff.objects.filter(
        course=course,
        user=user,
        staff_role__in=["lead_instructor", "co_instructor"],
        can_release_grades=True,
    ).exists()


def is_enrolled(user, course):
    """Check whether the user has an active student enrollment in the course."""
    # Anonymous or inactive users cannot be enrolled.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check for an active enrollment record.
    return Enrollment.objects.filter(
        course=course,
        student=user,
        status=EnrollmentStatus.ACTIVE,
    ).exists()


def student_can_see_course(user, course):
    """Check whether a student can open a course's materials and assessments.
    Enforces the coursework specification rule: students see only published courses.
    """
    # Anonymous or inactive users cannot access course content.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Draft courses stay hidden until an instructor publishes them.
    return course.is_published


# How long a fresh second-factor check counts for (seconds).
FRESH_SECOND_FACTOR_SECONDS = 300


def has_fresh_second_factor(request):
    """Check for a second-factor code accepted in the last five minutes (AUTH-02, ACL-05).

    Passkey changes, role changes, account deactivation and result releases use
    this check so a stolen session cookie alone cannot authorize them.
    Users without MFA pass because they have no second factor to check.
    """
    if not request.user.mfa_enabled:
        return True

    # The time of the last successful check is kept in the session.
    confirmed_at = request.session.get("mfa_reauth_at")
    if not confirmed_at:
        return False
    try:
        age = timezone.now().timestamp() - float(confirmed_at)
    except (ValueError, TypeError):
        return False
    return age < FRESH_SECOND_FACTOR_SECONDS

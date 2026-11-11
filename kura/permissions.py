from .models import CourseStaff, Enrollment, EnrollmentStatus, RolePermission, StudentProfile, UserRole


def has_role(user, role_name):
    """
    Checks whether an active user has been assigned a specific system role.
    Returns False for anonymous or inactive accounts.
    """
    # Anonymous or inactive users cannot hold active roles.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check if the user has a UserRole record with this role name.
    return UserRole.objects.filter(user=user, role__name=role_name).exists()


def is_admin_course_manager(user):
    """
    Checks whether the user has institution-wide course management authority (Admin role).
    """
    # The system role, not Django's unrelated is_staff flag, grants this authority.
    return has_role(user, "Admin")


def can_manage_quarantine(user):
    """
    Checks whether the user may see and delete quarantined uploads (files ClamAV rejected).
    Rule: system security and maintenance belong to the Admin role only.
    """
    # Only the Admin system role may review infected uploads.
    return has_role(user, "Admin")


def can_access_learning_records(user):
    """
    Checks whether the user is allowed to access learning records and grades.
    Denies access when the user holds either the Admin or Registrar role.
    """
    # A restricted role still applies when the same user also has another role.
    if has_role(user, "Admin"):
        return False

    if has_role(user, "Registrar"):
        return False

    return True


def has_permission(user, action, resource, scope):
    """
    Checks whether any of the user's assigned roles grant a system permission.
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
        "answer_keys",
        "exam_answer_keys",
        "course_materials",
        "modules_and_sections",
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
    """
    Checks whether the user is the appointed Department Head for the given department.
    """
    # Anonymous or inactive users cannot be department heads.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check if the user is the assigned head of this department and holds the Department head role.
    if not department or department.head_user_id != user.id:
        return False

    return has_role(user, "Department head")


def is_course_staff(user, course):
    """
    Checks whether the user is assigned as staff (instructor or TA) on the course.
    """
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


def is_lead_instructor(user, course):
    """
    Checks whether the user is assigned as the Lead Instructor for the course.
    """
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
    """
    Checks whether the user is allowed to release finalized grades for this course.
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
    """
    Checks whether the user has an active student enrollment in the course.
    """
    # Anonymous or inactive users cannot be enrolled.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check for an active enrollment record.
    return Enrollment.objects.filter(
        course=course,
        student=user,
        status=EnrollmentStatus.ACTIVE,
    ).exists()


def student_can_see_module(user, course, module):
    """
    Checks whether a student can access a module within a course.
    Enforces the coursework specification rule: students see only published courses,
    visible modules, and modules matching their own academic level.
    """
    # Anonymous or inactive users cannot access course modules.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # The course must be published and the module visible.
    if not course.is_published or not module.is_visible:
        return False

    # If the module restricts access to specific target levels, verify the student's level.
    target_levels = list(module.target_levels.values_list("target_level", flat=True))
    if target_levels:
        student_profile = StudentProfile.objects.filter(user=user).first()
        student_level = student_profile.current_level if student_profile else None
        if not student_level or student_level not in target_levels:
            return False

    return True

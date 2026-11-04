from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from .models import Department, User, UserRole, Schedule, Course, UserSession, StudentProfile, Enrollment, GradeChangeRequest, CourseResult, GradeStatus, ChangeRequestStatus, CourseStaff, CourseStaffRole, Assessment, Grade, ModuleAttendanceSession, AttendanceRecord, AttendanceStatus, AssessmentAttempt

DASHBOARD_CARDS_BY_ROLE = {
    "Admin": [
        {"title": "Staff", "description": "Create and manage staff accounts.", "url": "/admin/staff/"},
        {"title": "Courses", "description": "Browse and manage university courses.", "url": "/courses/"},
        {
            "title": "Active sessions",
            "description": "Review and manage active user sessions.",
            "url": "/admin/sessions/",
        },
        {
            "title": "Security log",
            "description": "Open the private Grafana security and audit dashboards.",
            "url": "http://kura-server.netbird.cloud:3000",
            "external": True,
        },
    ],
    "Registrar": [
        {"title": "Students", "description": "Find and manage student accounts.", "url": "/registrar/students/"},
        {
            "title": "Enrollments",
            "description": "View and manage course enrollments.",
            "url": "/registrar/enrollments/",
        },
    ],
    "Department head": [
        {"title": "Courses", "description": "Manage courses in your department.", "url": "/courses/"},
        {"title": "Schedule", "description": "Review class schedules.", "url": "/schedules/"},
    ],
    "Instructor": [
        {"title": "Courses", "description": "Open your assigned courses.", "url": "/courses/"},
        {"title": "Schedule", "description": "Review class schedules.", "url": "/schedules/"},
        {
            "title": "Attendance",
            "description": "Review attendance records for your courses.",
            "url": "/attendance/history/",
        },
    ],
    "Teaching assistant": [
        {"title": "Courses", "description": "Open your assigned courses.", "url": "/courses/"},
        {
            "title": "Attendance",
            "description": "Review attendance records for your courses.",
            "url": "/attendance/history/",
        },
    ],
    "Student": [
        {"title": "Courses", "description": "Open your enrolled courses.", "url": "/courses/"},
        {"title": "Class schedule", "description": "Review your class timetable.", "url": "/schedules/"},
        {"title": "Attendance", "description": "Review your attendance history.", "url": "/attendance/history/"},
        {"title": "Grades", "description": "View grades released to you.", "url": "/grades/my/"},
        {"title": "Transcript", "description": "View your released course results.", "url": "/transcript/"},
    ],
}


def home_view(request):
    """
    Main dashboard displaying the work areas available to the user's roles.
    Who can use it: All authenticated users.
    Security: Requires login and active MFA.
"""
    # Fetch roles assigned to this user to customize the dashboard.
    user_roles = UserRole.objects.filter(user=request.user).select_related("role")
    role_names = [ur.role.name for ur in user_roles]
    # Find the department or departments this user leads for the dashboard card.
    head_departments = Department.objects.filter(head_user=request.user)

    # Collect one dashboard card for each work area available to the user's roles.
    dashboard_cards = []
    for role_name in role_names:
        for card in DASHBOARD_CARDS_BY_ROLE.get(role_name, []):
            if card not in dashboard_cards:
                dashboard_cards.append(card)

    # Give each department head a direct link to reports for their own department.
    for department in head_departments:
        dashboard_cards.append(
            {
                "title": f"Reports: {department.name}",
                "description": f"View enrollment and performance reports for {department.name}.",
                "url": reverse("kura:department_reports", args=[department.id]),
            }
        )

    # Load simple counts and recent records only from data the signed-in roles may access.
    dashboard_summaries, recent_activity = dashboard_home_data(request.user, role_names, head_departments)

    # Render the role-scoped work cards, counts, and activity records on the dashboard.
    return render(
        request,
        "kura/accounts/home.html",
        {
            "user": request.user,
            "roles": role_names,
            "head_departments": head_departments,
            "dashboard_cards": dashboard_cards,
            "dashboard_summaries": dashboard_summaries,
            "recent_activity": recent_activity,
        },
    )


def dashboard_home_data(user, role_names, head_departments):
    """
    Builds dashboard summaries and recent activity allowed for the user's roles.
    """
    now = timezone.now()
    activity = []
    summaries = []

    # Admin summaries contain account and course counts, never learning or grade data.
    if "Admin" in role_names:
        staff_roles = ["Admin", "Registrar", "Department head", "Instructor", "Teaching assistant"]
        staff_user_ids = UserRole.objects.filter(role__name__in=staff_roles).values_list("user_id", flat=True)
        staff_users = User.objects.filter(id__in=staff_user_ids)
        courses = Course.objects.all()
        active_sessions = UserSession.objects.filter(revoked_at__isnull=True, expires_at__gt=now).count()
        summaries.append(
            {
                "role": "Admin",
                "items": [
                    {
                        "label": "Active staff",
                        "value": staff_users.filter(is_active=True).exclude(locked_until__gt=now).count(),
                        "url": reverse("kura:staff_list"),
                    },
                    {
                        "label": "Locked staff",
                        "value": staff_users.filter(is_active=True, locked_until__gt=now).count(),
                        "url": reverse("kura:staff_list"),
                    },
                    {
                        "label": "Inactive staff",
                        "value": staff_users.filter(is_active=False).count(),
                        "url": reverse("kura:staff_list"),
                    },
                    {
                        "label": "Published courses",
                        "value": courses.filter(is_published=True).count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Draft courses",
                        "value": courses.filter(is_published=False).count(),
                        "url": reverse("kura:course_list"),
                    },
                    {"label": "Active sessions", "value": active_sessions, "url": reverse("kura:admin_sessions")},
                ],
            }
        )
        for account in User.objects.order_by("-created_at")[:5]:
            add_dashboard_activity(activity, "New account created", account.created_at)
        for assignment in UserRole.objects.select_related("role").order_by("-assigned_at")[:5]:
            add_dashboard_activity(activity, f"Role assigned: {assignment.role.name}", assignment.assigned_at)
        for session in UserSession.objects.order_by("-created_at")[:5]:
            add_dashboard_activity(activity, "User session started", session.created_at)

    # Registrar summaries use student profiles and course enrollment records only.
    if "Registrar" in role_names:
        students = StudentProfile.objects.select_related("user")
        enrollments = Enrollment.objects.all()
        summaries.append(
            {
                "role": "Registrar",
                "items": [
                    {
                        "label": "Active student accounts",
                        "value": students.filter(user__is_active=True).exclude(user__locked_until__gt=now).count(),
                        "url": reverse("kura:student_list"),
                    },
                    {
                        "label": "Locked student accounts",
                        "value": students.filter(user__is_active=True, user__locked_until__gt=now).count(),
                        "url": reverse("kura:student_list"),
                    },
                    {
                        "label": "Inactive student accounts",
                        "value": students.filter(user__is_active=False).count(),
                        "url": reverse("kura:student_list"),
                    },
                    {
                        "label": "Active enrollments",
                        "value": enrollments.filter(status=EnrollmentStatus.ACTIVE).count(),
                        "url": reverse("kura:enrollment_list"),
                    },
                    {
                        "label": "Other enrollment statuses",
                        "value": enrollments.exclude(status=EnrollmentStatus.ACTIVE).count(),
                        "url": reverse("kura:enrollment_list"),
                    },
                ],
            }
        )
        for profile in students.order_by("-user__created_at")[:5]:
            add_dashboard_activity(activity, "Student account created", profile.user.created_at)
        for enrollment in enrollments.select_related("course").order_by("-enrolled_at")[:5]:
            add_dashboard_activity(activity, f"Enrollment added to {enrollment.course.code}", enrollment.enrolled_at)

    # Department heads see only courses, enrollments, and aggregate results in their departments.
    if "Department head" in role_names:
        department_courses = Course.objects.filter(department__in=head_departments)
        course_ids = department_courses.values_list("id", flat=True)
        department_enrollments = Enrollment.objects.filter(course_id__in=course_ids)
        pending_requests = GradeChangeRequest.objects.filter(
            grade__assessment__section__module__course_id__in=course_ids,
            status=ChangeRequestStatus.PENDING,
        )
        result_average = CourseResult.objects.filter(
            course_id__in=course_ids,
            status=GradeStatus.RELEASED,
        ).aggregate(average=Avg("final_score"))["average"]
        if result_average is not None:
            formatted_result_average = f"{result_average:.1f}%"
        else:
            formatted_result_average = "—"
        summaries.append(
            {
                "role": "Department head",
                "items": [
                    {
                        "label": "Department courses",
                        "value": department_courses.count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Upcoming class meetings",
                        "value": count_upcoming_classes(course_ids, now),
                        "url": reverse("kura:schedule_list"),
                    },
                    {
                        "label": "Active enrollments",
                        "value": department_enrollments.filter(status=EnrollmentStatus.ACTIVE).count(),
                        "url": None,
                    },
                    {"label": "Pending grade-change requests", "value": pending_requests.count(), "url": None},
                    {"label": "Average released result", "value": formatted_result_average, "url": None},
                ],
            }
        )
        for course in department_courses.order_by("-created_at")[:5]:
            add_dashboard_activity(activity, f"Course created: {course.code}", course.created_at)
        staff_assignments = CourseStaff.objects.filter(course__department__in=head_departments)
        for assignment in staff_assignments.order_by("-assigned_at")[:5]:
            add_dashboard_activity(activity, "Staff assigned to a department course", assignment.assigned_at)
        for request_record in pending_requests.select_related("grade__assessment").order_by("-created_at")[:5]:
            add_dashboard_activity(activity, "Grade-change request submitted", request_record.created_at)
        for approved_request in GradeChangeRequest.objects.filter(
            grade__assessment__section__module__course_id__in=course_ids,
            reviewed_at__isnull=False,
        ).order_by("-reviewed_at")[:5]:
            add_dashboard_activity(activity, "Grade-change request reviewed", approved_request.reviewed_at)

    # Teaching staff summaries use only their own assigned courses and never show grade details.
    if "Instructor" in role_names or "Teaching assistant" in role_names:
        staff_roles = []
        if "Instructor" in role_names:
            staff_roles.extend([CourseStaffRole.LEAD_INSTRUCTOR, CourseStaffRole.CO_INSTRUCTOR])
        if "Teaching assistant" in role_names:
            staff_roles.append(CourseStaffRole.TEACHING_ASSISTANT)
        assignments = CourseStaff.objects.filter(user=user, staff_role__in=staff_roles)
        assigned_course_ids = assignments.values_list("course_id", flat=True)
        upcoming_assessments = Assessment.objects.filter(
            section__module__course_id__in=assigned_course_ids,
            due_date__gte=now,
        )
        draft_grades = Grade.objects.filter(
            assessment__section__module__course_id__in=assigned_course_ids,
            status=GradeStatus.DRAFT,
        )
        attendance_sessions = ModuleAttendanceSession.objects.filter(
            module__course_id__in=assigned_course_ids,
            is_active=True,
            expires_at__gt=now,
        )
        summaries.append(
            {
                "role": "Teaching staff",
                "items": [
                    {
                        "label": "Assigned courses",
                        "value": assignments.values("course_id").distinct().count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Upcoming class meetings",
                        "value": count_upcoming_classes(assigned_course_ids, now),
                        "url": reverse("kura:schedule_list"),
                    },
                    {
                        "label": "Upcoming assessments",
                        "value": upcoming_assessments.count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Draft grades to review",
                        "value": draft_grades.count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Open attendance sessions",
                        "value": attendance_sessions.count(),
                        "url": reverse("kura:attendance_history"),
                    },
                ],
            }
        )
        for assessment in upcoming_assessments.order_by("-updated_at")[:5]:
            add_dashboard_activity(activity, "Assessment updated", assessment.updated_at)
        for session in attendance_sessions.order_by("-created_at")[:5]:
            add_dashboard_activity(activity, "Attendance session opened", session.created_at)
        for grade in draft_grades.order_by("-graded_at")[:5]:
            add_dashboard_activity(activity, "Draft grading activity", grade.graded_at)

    # Students see only their own enrolled courses, attendance, attempts, and released-grade count.
    if "Student" in role_names:
        active_enrollments = Enrollment.objects.filter(student=user, status=EnrollmentStatus.ACTIVE)
        enrolled_course_ids = active_enrollments.values_list("course_id", flat=True)
        upcoming_assessments = Assessment.objects.filter(
            section__module__course_id__in=enrolled_course_ids,
            due_date__gte=now,
        )
        student_attendance = AttendanceRecord.objects.filter(student=user)
        new_released_grades = Grade.objects.filter(
            student=user,
            status=GradeStatus.RELEASED,
            released_at__gte=now - timezone.timedelta(days=7),
        ).count()
        summaries.append(
            {
                "role": "Student",
                "items": [
                    {
                        "label": "Active courses",
                        "value": active_enrollments.count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Upcoming class meetings",
                        "value": count_upcoming_classes(enrolled_course_ids, now),
                        "url": reverse("kura:schedule_list"),
                    },
                    {
                        "label": "Upcoming assessments",
                        "value": upcoming_assessments.count(),
                        "url": reverse("kura:course_list"),
                    },
                    {
                        "label": "Present or late classes",
                        "value": student_attendance.filter(
                            status__in=[AttendanceStatus.PRESENT, AttendanceStatus.LATE]
                        ).count(),
                        "url": reverse("kura:attendance_history"),
                    },
                    {
                        "label": "Absent classes",
                        "value": student_attendance.filter(status=AttendanceStatus.ABSENT).count(),
                        "url": reverse("kura:attendance_history"),
                    },
                    {
                        "label": "New released grades",
                        "value": new_released_grades,
                        "url": reverse("kura:student_grades"),
                    },
                ],
            }
        )
        for attempt in (
            AssessmentAttempt.objects.filter(student=user).select_related("assessment").order_by("-started_at")[:5]
        ):
            add_dashboard_activity(activity, "Assessment attempt activity", attempt.started_at)
        for record in student_attendance.order_by("-verified_at")[:5]:
            add_dashboard_activity(activity, "Attendance recorded", record.verified_at)

    # One activity list shows the five newest records regardless of the user's assigned roles.
    activity.sort(key=lambda item: item["date"], reverse=True)
    return summaries, activity[:5]


def add_dashboard_activity(activity, label, happened_at):
    """
    Adds a short activity label without including sensitive record details.
    """
    activity.append({"label": label, "date": happened_at})


def count_upcoming_classes(course_ids, now):
    """
    Counts course meetings scheduled to occur in the next seven days.
    """
    today = timezone.localdate(now)
    last_day = today + timezone.timedelta(days=7)
    weekday_names = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedules = Schedule.objects.filter(
        course_id__in=course_ids,
        recurrence_start__lte=last_day,
        recurrence_end__gte=today,
    )
    upcoming_count = 0

    # Find the next matching weekday and skip schedules that begin after that first occurrence.
    for schedule in schedules:
        if schedule.day not in weekday_names:
            continue
        weekday_index = weekday_names.index(schedule.day)
        days_ahead = (weekday_index - today.weekday()) % 7
        next_meeting = today + timezone.timedelta(days=days_ahead)
        if next_meeting < schedule.recurrence_start:
            next_meeting += timezone.timedelta(days=7)
        if next_meeting <= schedule.recurrence_end and next_meeting <= last_day:
            upcoming_count += 1

    return upcoming_count



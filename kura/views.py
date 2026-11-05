import hashlib
import logging
import secrets
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from axes.handlers.proxy import AxesProxyHandler
from .forms import LoginForm, PasswordChangeForm, PasswordResetRequestForm, PasswordResetConfirmForm
from .models import Department, Role, User, UserRole, UserSession, PasswordResetToken, Schedule, Course, StudentProfile, Enrollment, GradeChangeRequest, CourseResult, GradeStatus, ChangeRequestStatus, CourseStaff, CourseStaffRole, Assessment, Grade, ModuleAttendanceSession, AttendanceRecord, AttendanceStatus, AssessmentAttempt

security_logger = logging.getLogger("kura.security")

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


def axes_lockout_callable(request, credentials=None):
    """
    Called by django-axes when an IP or account exceeds failure limits.
    Security: Returns a 403 response with generic messaging to prevent enumeration.
    """
    return HttpResponseForbidden("Account temporarily locked due to repeated failures. Please try again later.")


def create_user_session(request, user):
    """
    Creates a new tracked UserSession record for an authenticated user.
    Records client IP address, browser user-agent, and a 14-day expiry.
    """
    # Generate random bytes for the session bearer token hash.
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Read client IP address from the request header.
    ip_address = request.META.get("REMOTE_ADDR")

    # Read the client browser user agent string.
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

    # Set expiry to 14 days from now.
    expires_at = timezone.now() + timezone.timedelta(days=14)

    # Save session record to the database.
    user_session = UserSession.objects.create(
        user=user,
        session_token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )

    # Store session id in the Django request session.
    request.session["user_session_id"] = str(user_session.id)
    return user_session


def login_view(request):
    """
    Authenticates users using email and password.
    Who can use it: Public unauthenticated users.
    Security: Generic error messages, brute-force tracking via axes,
    lockout checks on locked_until and is_active, and redirect to MFA.
"""
    # Redirect already-logged-in users straight to the dashboard.
    if request.user.is_authenticated:
        return redirect("kura:home")

    form = LoginForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            email = form.cleaned_data["email"].strip().lower()
            password = form.cleaned_data["password"]

            # Authenticate credentials against configured backends and axes.
            user = authenticate(request, email=email, password=password)

            # Reveal account status only after the submitted password is correct.
            if user is None:
                password_matched_user = User.objects.filter(email__iexact=email).first()
                if password_matched_user and password_matched_user.check_password(password):
                    # Explain deactivation only to someone who proved they know the password.
                    if not password_matched_user.is_active:
                        security_logger.warning(f"Login denied: deactivated user {email}")
                        messages.error(request, "This account has been deactivated. Contact the administrator.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                    # Include the lock expiry so a locked user knows when to try again.
                    if password_matched_user.locked_until and password_matched_user.locked_until > timezone.now():
                        lock_time = timezone.localtime(password_matched_user.locked_until).strftime("%d %b, %H:%M")
                        messages.error(request, f"This account is currently locked until {lock_time}.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                    # Keep automatic Axes lockouts understandable without exposing account details to wrong passwords.
                    is_locked_by_axes = AxesProxyHandler.is_locked(request, {"username": email})
                    if is_locked_by_axes:
                        request.axes_locked_out = False
                        security_logger.warning(f"Login denied: locked user {email}")
                        messages.error(request, "This account is currently locked. Contact the administrator.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                # Keep the same response for unknown emails and incorrect passwords.
                security_logger.warning(f"Failed authentication attempt for {email}")
                messages.error(request, "Invalid email or password.")
                return render(request, "kura/accounts/login.html", {"form": form})

            # Catch an account status change that happened just after authentication.
            if not user.is_active:
                security_logger.warning(f"Login denied: inactive user {email}")
                messages.error(request, "This account has been deactivated. Contact the administrator.")
                return render(request, "kura/accounts/login.html", {"form": form})

            # Show the lock expiry if an administrator locked the account during authentication.
            if user.locked_until and user.locked_until > timezone.now():
                security_logger.warning(f"Login denied: locked user {email}")
                lock_time = timezone.localtime(user.locked_until).strftime("%d %b, %H:%M")
                messages.error(request, f"This account is currently locked until {lock_time}.")
                return render(request, "kura/accounts/login.html", {"form": form})

            security_logger.info(f"Primary credentials authenticated for {user.email}")

            # If user has MFA enabled, require second factor verification.
            if user.mfa_enabled:
                request.session["pre_mfa_user_id"] = str(user.id)
                return redirect("kura:mfa_verify")

            # Complete login for users without MFA configured yet.
            login(request, user)
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            create_user_session(request, user)

            # Force first-login password change if required.
            if user.must_change_password:
                return redirect("kura:password_change")

            # Direct new users to set up mandatory MFA.
            return redirect("kura:mfa_setup")

    return render(request, "kura/accounts/login.html", {"form": form})


def logout_view(request):
    """
    Logs out the user and revokes their active session record.
    Who can use it: Authenticated users.
    Security: POST only with CSRF token to prevent forced logout attacks.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Revoke current UserSession in database.
    user_email = "anonymous"
    if request.user.is_authenticated:
        user_email = request.user.email
    security_logger.info(f"User logged out: {user_email}")
    session_id = request.session.get("user_session_id")
    if session_id:
        UserSession.objects.filter(id=session_id, user=request.user).update(revoked_at=timezone.now())

    # Clear Django authentication session.
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("kura:login")


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



def password_change_view(request):
    """
    Allows a user to rotate their password.
    Who can use it: All authenticated users (mandatory on first login).
    Security: Validates current password, checks minimum 12 chars and breaches.
"""
    form = PasswordChangeForm(request.user, request.POST or None)

    if request.method == "POST" and form.is_valid():
        new_password = form.cleaned_data["new_password"]

        # Save new password and update audit timestamps.
        request.user.set_password(new_password)
        request.user.must_change_password = False
        request.user.password_changed_at = timezone.now()
        request.user.save()

        # Keep current session logged in after password hash changes.
        update_session_auth_hash(request, request.user)

        # Mark the success message so the next page can show a clear confirmation card.
        messages.success(request, "Password updated successfully.", extra_tags="password_changed")

        # If MFA is not yet enabled, send user to set it up.
        if not request.user.mfa_enabled:
            return redirect("kura:mfa_setup")

        return redirect("kura:home")

    return render(request, "kura/accounts/password_change.html", {"form": form})


def password_reset_request_view(request):
    """
    Initiates a password reset by emailing a time-limited token link.
    Who can use it: Public unauthenticated users.
    Security: Returns the same confirmation message regardless of whether the email exists.
"""
    form = PasswordResetRequestForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"].strip().lower()
        user = User.objects.filter(email=email, is_active=True).first()

        # If user exists, generate single-use token valid for 30 minutes.
        if user:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            expires_at = timezone.now() + timezone.timedelta(minutes=30)

            PasswordResetToken.objects.create(
                user=user,
                token_hash=token_hash,
                expires_at=expires_at,
            )

            # Build reset link and send notification email.
            reset_url = request.build_absolute_uri(reverse("kura:password_reset_confirm", kwargs={"token": raw_token}))
            message_body = f"Hello,\n\nPlease reset your password using this link:\n{reset_url}\n\nThis link expires in 30 minutes."
            from_email = "webmaster@localhost"
            if hasattr(settings, "DEFAULT_FROM_EMAIL"):
                from_email = settings.DEFAULT_FROM_EMAIL
            send_mail(
                subject="Kura Password Reset Request",
                message=message_body,
                from_email=from_email,
                recipient_list=[user.email],
                fail_silently=True,
            )

        messages.success(
            request, "If an account exists with that email address, password reset instructions have been sent."
        )
        return redirect("kura:login")

    return render(request, "kura/accounts/password_reset_request.html", {"form": form})


def password_reset_confirm_view(request, token):
    """
    Completes password reset using a token from the email.
    Who can use it: Public users with a valid token.
    Security: Validates SHA-256 hash, 30-min window, single-use, and revokes all user sessions.
"""
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Look up unused, unexpired reset token.
    reset_record = PasswordResetToken.objects.filter(
        token_hash=token_hash,
        used_at__isnull=True,
        expires_at__gt=timezone.now(),
    ).first()

    # Reject invalid or expired tokens.
    if not reset_record:
        messages.error(request, "This password reset link is invalid or has expired.")
        return redirect("kura:password_reset_request")

    form = PasswordResetConfirmForm(reset_record.user, request.POST or None)

    if request.method == "POST" and form.is_valid():
        new_password = form.cleaned_data["new_password"]

        # Update password on user account.
        user = reset_record.user
        user.set_password(new_password)
        user.must_change_password = False
        user.password_changed_at = timezone.now()
        user.save()

        # Mark token as consumed.
        reset_record.used_at = timezone.now()
        reset_record.save()

        # Revoke all existing sessions for this user.
        UserSession.objects.filter(user=user, revoked_at__isnull=True).update(revoked_at=timezone.now())

        messages.success(request, "Your password has been reset. Please log in with your new password.")
        return redirect("kura:login")

    return render(request, "kura/accounts/password_reset_confirm.html", {"form": form})



from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
import qrcode.image.svg
import urllib.parse
from .forms import MFAVerifyForm

def mfa_verify_view(request):
    """
    Verifies the TOTP code or recovery code during two-factor login.
    Who can use it: Users who successfully passed password authentication.
    Security: Validates a one-time code against the user’s enrolled devices.
"""
    # Retrieve user ID stored during step 1 authentication.
    user_id = request.session.get("pre_mfa_user_id")
    if not user_id:
        return redirect("kura:login")

    user = get_object_or_404(User, id=user_id)
    form = MFAVerifyForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"].strip()

        # Check TOTP devices first.
        verified = False
        for device in TOTPDevice.objects.filter(user=user, confirmed=True):
            if device.verify_token(code):
                verified = True
                break

        # Check static recovery backup codes if TOTP did not match.
        if not verified:
            for static_device in StaticDevice.objects.filter(user=user):
                if static_device.verify_token(code):
                    verified = True
                    break

        # Reject invalid codes with generic error.
        if not verified:
            messages.error(request, "Invalid security code.")
            return render(request, "kura/accounts/mfa_verify.html", {"form": form})

        # Complete login and clean up pre-mfa session marker.
        request.session.pop("pre_mfa_user_id", None)
        login(request, user, backend="kura.backends.KuraAuthBackend")
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])
        create_user_session(request, user)

        # Handle first-login password rotation if needed.
        if user.must_change_password:
            return redirect("kura:password_change")

        return redirect("kura:home")

    return render(request, "kura/accounts/mfa_verify.html", {"form": form})


def mfa_setup_view(request):
    """
    Configures TOTP authenticator app and generates backup recovery codes.
    Who can use it: Authenticated users.
    Security: Uses local qrcode library (no external calls) and shows recovery codes once.
"""
    # Fetch or create an unconfirmed TOTP device for this user.
    device, _ = TOTPDevice.objects.get_or_create(
        user=request.user,
        name="default",
        defaults={"confirmed": False},
    )

    # Generate QR code in memory as an SVG data URI.
    qr_img = qrcode.make(device.config_url, image_factory=qrcode.image.svg.SvgPathImage)
    svg_data = qr_img.to_string().decode("utf-8")
    qr_code_data_uri = f"data:image/svg+xml;utf8,{urllib.parse.quote(svg_data)}"

    form = MFAVerifyForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"].strip()

        # Verify the user correctly entered the code from their authenticator app.
        if device.verify_token(code):
            device.confirmed = True
            device.save()

            # Set mfa_enabled on the user model.
            request.user.mfa_secret = device.key
            request.user.mfa_enabled = True
            request.user.save(update_fields=["mfa_secret", "mfa_enabled"])

            # Create or get static device for 10 single-use recovery codes.
            static_device, _ = StaticDevice.objects.get_or_create(
                user=request.user,
                name="recovery",
                defaults={"confirmed": True},
            )
            # Remove any previous recovery tokens.
            StaticToken.objects.filter(device=static_device).delete()

            # Generate 10 new random 8-character recovery codes.
            recovery_codes = []
            for _ in range(10):
                token_val = secrets.token_hex(4).upper()
                StaticToken.objects.create(device=static_device, token=token_val)
                recovery_codes.append(token_val)

            # Store recovery codes in session to display once on completion page.
            request.session["recovery_codes"] = recovery_codes
            return redirect("kura:mfa_setup_complete")
        else:
            messages.error(request, "Invalid security code. Please try again.")

    return render(
        request,
        "kura/accounts/mfa_setup.html",
        {
            "form": form,
            "qr_code_url": qr_code_data_uri,
        },
    )


def mfa_setup_complete_view(request):
    """
    Displays the 10 static recovery codes once after MFA setup.
    Who can use it: Authenticated users who just completed MFA setup.
    Security: Clears codes from session immediately after display.
"""
    recovery_codes = request.session.pop("recovery_codes", None)
    if not recovery_codes:
        return redirect("kura:home")

    return render(
        request,
        "kura/accounts/mfa_setup_complete.html",
        {"recovery_codes": recovery_codes},
    )


from .forms import AdminSessionFilterForm, AdminSessionRevokeForm
from .permissions import has_role
def user_sessions_view(request):
    """
    Redirects the old sessions page to the administrator's session list.
    Who can use it: Administrators only.
    Security: Non-admin users cannot view or revoke sessions through the old URL.
"""
    # Do not leave the former personal-session endpoint available to other roles.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])
    return redirect("kura:admin_sessions")


def admin_sessions_view(request):
    """
    Lists and filters session records across the university.
    Who can use it: Administrators only.
    Security: Validates filters with a Django form and never displays session tokens.
"""
    # Check the role before loading any other user's session records.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    # Reject invalid filters rather than accidentally showing an unfiltered list.
    form = AdminSessionFilterForm(request.GET or None)
    sessions = UserSession.objects.select_related("user").order_by("-created_at")
    selected_user = None
    if form.is_bound and not form.is_valid():
        sessions = sessions.none()
    else:
        filters = {}
        if form.is_bound:
            filters = form.cleaned_data
        search = filters.get("q", "")
        if search:
            sessions = sessions.annotate(
                full_name=Concat("user__first_name", Value(" "), "user__last_name"),
            ).filter(Q(user__email__icontains=search) | Q(full_name__icontains=search))
            selected_user = User.objects.filter(email__iexact=search).first()
        if filters.get("role"):
            sessions = sessions.filter(user__user_roles__role__name=filters["role"]).distinct()
        if filters.get("ip"):
            sessions = sessions.filter(ip_address__istartswith=filters["ip"])
        state = filters.get("state") or "active"
        if state == "active":
            sessions = sessions.filter(revoked_at__isnull=True, expires_at__gt=timezone.now())
        elif state == "revoked":
            sessions = sessions.filter(revoked_at__isnull=False)
        else:
            sessions = sessions.filter(revoked_at__isnull=True, expires_at__lte=timezone.now())

    # The page marks the current device and offers bulk revoke only for an exact email search.
    return render(
        request,
        "kura/accounts/admin_sessions.html",
        {
            "form": form,
            "sessions": sessions,
            "selected_user": selected_user,
            "current_session_id": request.session.get("user_session_id"),
        },
    )


def admin_sessions_revoke_view(request):
    """
    Ends one session or all active sessions belonging to a selected user.
    Who can use it: Administrators only.
    Security: Requires POST, CSRF, validated identifiers, and logs every revoked session.
"""
    # Only administrators may end sessions, and only POST can change them.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Require a valid action and the corresponding session or user identifier.
    form = AdminSessionRevokeForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Could not end the selected session.")
        return redirect("kura:admin_sessions")
    action = form.cleaned_data["action"]
    if action == "one" and form.cleaned_data["session_id"]:
        target = get_object_or_404(UserSession, id=form.cleaned_data["session_id"])
        sessions = UserSession.objects.filter(id=target.id)
    elif action == "all" and form.cleaned_data["user_id"]:
        target_user = get_object_or_404(User, id=form.cleaned_data["user_id"])
        sessions = UserSession.objects.filter(user=target_user)
    else:
        messages.error(request, "Could not end the selected session.")
        return redirect("kura:admin_sessions")

    # Mark each active session revoked and record who performed the action.
    for session in sessions.filter(revoked_at__isnull=True, expires_at__gt=timezone.now()):
        changed = UserSession.objects.filter(
            id=session.id,
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
        ).update(revoked_at=timezone.now())
        if changed:
            security_logger.info("Session %s ended by administrator %s", session.id, request.user.id)
    messages.success(request, "Selected sessions ended.")
    return redirect("kura:admin_sessions")



from .forms import AdminCourseFilterForm, AdminStaffFilterForm, StaffCreateForm, AdminCourseForm
from .permissions import is_admin_course_manager
def staff_list_view(request):
    """
    Displays the list of staff accounts for administrative management.
    Who can use it: System administrators.
    Security: Strictly restricted to users holding the Admin role.
"""
    # Verify the current user is an administrator.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    # Load staff accounts and profiles.
    staff_members = StaffProfile.objects.select_related("user", "department").order_by("-created_at")
    # Apply only validated filters to the administrator's staff list.
    filter_form = AdminStaffFilterForm(request.GET or None)
    if filter_form.is_valid():
        search = filter_form.cleaned_data["q"]
        if search:
            staff_members = staff_members.filter(
                Q(user__first_name__icontains=search)
                | Q(user__last_name__icontains=search)
                | Q(user__email__icontains=search)
            )
        if filter_form.cleaned_data["role"]:
            staff_members = staff_members.filter(user__user_roles__role__name=filter_form.cleaned_data["role"])
        if filter_form.cleaned_data["department"]:
            staff_members = staff_members.filter(department=filter_form.cleaned_data["department"])
        status = filter_form.cleaned_data["status"]
        now = timezone.now()
        if status == "deactivated":
            staff_members = staff_members.filter(user__is_active=False)
        elif status == "locked":
            staff_members = staff_members.filter(user__is_active=True, user__locked_until__gt=now)
        elif status == "active":
            staff_members = staff_members.filter(user__is_active=True).filter(
                Q(user__locked_until__isnull=True) | Q(user__locked_until__lte=now)
            )
        staff_members = staff_members.distinct()

    # Build a simple lookup so each staff row can show departments this user heads.
    head_department_names = {}
    for department in Department.objects.filter(head_user__isnull=False).order_by("name"):
        if department.head_user_id not in head_department_names:
            head_department_names[department.head_user_id] = []
        head_department_names[department.head_user_id].append(department.name)

    # Attach each user's managed department names to their staff profile for display.
    for staff_member in staff_members:
        staff_member.head_department_names = head_department_names.get(staff_member.user_id, [])

    return render(
        request,
        "kura/accounts/staff_list.html",
        {"staff_members": staff_members, "now": timezone.now(), "filter_form": filter_form},
    )


def staff_create_view(request):
    """
    Creates a new staff account and profile with an auto-generated temporary password.
    Who can use it: System administrators.
    Security: Restricted to Admin role; enforces must_change_password=True on first login.
"""
    # Check administrator permission.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    form = StaffCreateForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"].strip().lower()
        first_name = form.cleaned_data["first_name"].strip()
        last_name = form.cleaned_data["last_name"].strip()
        department = form.cleaned_data["department"]
        staff_title = form.cleaned_data["staff_title"].strip()
        office_location = form.cleaned_data["office_location"].strip()

        # Generate a secure 16-character temporary password.
        temporary_password = secrets.token_urlsafe(12)

        with transaction.atomic():
            # Create user account requiring password rotation on first login.
            new_user = User.objects.create_user(
                email=email,
                password=temporary_password,
                first_name=first_name,
                last_name=last_name,
                must_change_password=True,
                mfa_enabled=False,
            )

            # Create staff employment profile.
            StaffProfile.objects.create(
                user=new_user,
                department=department,
                staff_title=staff_title,
                office_location=office_location,
            )

        messages.success(request, f"Staff account created for {email}. Temporary password: {temporary_password}")
        return redirect("kura:staff_list")

    return render(request, "kura/accounts/staff_create.html", {"form": form})


def user_deactivate_view(request, user_id):
    """
    Deactivates a user account and immediately revokes all active sessions.
    Who can use it: System administrators.
    Security: Admin only; POST only; administrators cannot deactivate themselves.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Check administrator permission.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    # Prevent administrators from deactivating their own account.
    if str(request.user.id) == str(user_id):
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("kura:staff_list")

    target_user = get_object_or_404(User, id=user_id)

    # Deactivate the account and revoke its sessions together so they cannot get out of sync.
    with transaction.atomic():
        target_user.is_active = False
        target_user.deactivated_at = timezone.now()
        target_user.save(update_fields=["is_active", "deactivated_at"])
        ended_session_count = UserSession.objects.filter(
            user=target_user,
            revoked_at__isnull=True,
        ).update(revoked_at=timezone.now())

    # Tell the administrator how many sessions were ended by the deactivation.
    if ended_session_count == 1:
        session_label = "session"
    else:
        session_label = "sessions"
    messages.success(request, f"Account deactivated, {ended_session_count} {session_label} ended.")
    return redirect("kura:staff_list")


def user_lock_toggle_view(request, user_id):
    """
    Toggles administrative lockout for a user account.
    Who can use it: System administrators.
    Security: Admin only; POST only; administrators cannot lock themselves.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Check administrator permission.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    # Prevent administrators from locking their own account.
    if str(request.user.id) == str(user_id):
        messages.error(request, "You cannot lock your own account.")
        return redirect("kura:staff_list")

    target_user = get_object_or_404(User, id=user_id)

    # If currently locked, unlock it; otherwise set a 24-hour lockout.
    if target_user.locked_until and target_user.locked_until > timezone.now():
        target_user.locked_until = None
        messages.success(request, "Account unlocked.")
    else:
        target_user.locked_until = timezone.now() + timezone.timedelta(days=1)
        lock_time = timezone.localtime(target_user.locked_until).strftime("%d %b, %H:%M")
        messages.success(request, f"Account locked until {lock_time}.")

    target_user.save()
    return redirect("kura:staff_list")


def admin_course_create_view(request):
    """
    Creates a draft course in any department.
    Who can use it: Administrators.
    Security: Checks the Admin role and validates all fields with a Django form.
"""
    # Do not let other roles use this institution-wide course form.
    if not is_admin_course_manager(request.user):
        raise PermissionDenied

    # A validated POST creates a draft, never a published course.
    form = AdminCourseForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        course = form.save(commit=False)
        course.created_by = request.user
        course.is_published = False
        course.save()
        messages.success(request, "Course draft created.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/admin_course_form.html", {"form": form, "editing": False})


def admin_course_edit_view(request, course_id):
    """
    Edits course details in any department.
    Who can use it: Administrators.
    Security: Checks the Admin role and limits changes to the form's allowed fields.
"""
    # The Admin role is required before looking up the course.
    if not is_admin_course_manager(request.user):
        raise PermissionDenied

    # Load the requested course and validate only its editable metadata.
    course = get_object_or_404(Course, id=course_id)
    form = AdminCourseForm(request.POST or None, instance=course)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Course updated.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/admin_course_form.html", {"form": form, "editing": True, "course": course})



def user_roles_view(request, user_id):
    """
    Manages assigned system roles for a user.
    Who can use it: System administrators.
    Security: Admin only; enforces strict separation of duty between Admin and grading roles.
"""
    # Check administrator permission.
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    target_user = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        action = request.POST.get("action")
        role_id = request.POST.get("role_id")
        target_role = get_object_or_404(Role, id=role_id)

        # Get existing assigned role names for target user.
        existing_roles = list(UserRole.objects.filter(user=target_user).values_list("role__name", flat=True))

        if action == "assign":
            # Rule: Block assigning Admin to an Instructor or Teaching Assistant.
            if target_role.name == "Admin" and any(r in ("Instructor", "Teaching assistant") for r in existing_roles):
                messages.error(request, "Separation of duty: Administrators cannot hold grading roles.")
                return redirect("kura:user_roles", user_id=target_user.id)

            # Rule: Block assigning Instructor or TA to an Administrator.
            if target_role.name in ("Instructor", "Teaching assistant") and "Admin" in existing_roles:
                messages.error(request, "Separation of duty: Administrators cannot hold grading roles.")
                return redirect("kura:user_roles", user_id=target_user.id)

            UserRole.objects.get_or_create(
                user=target_user,
                role=target_role,
                defaults={"assigned_by": request.user},
            )
            messages.success(request, f"Assigned role {target_role.name} to {target_user.email}.")

        elif action == "remove":
            UserRole.objects.filter(user=target_user, role=target_role).delete()
            messages.success(request, f"Removed role {target_role.name} from {target_user.email}.")

        return redirect("kura:user_roles", user_id=target_user.id)

    # Load currently assigned roles and unassigned roles.
    assigned_roles = UserRole.objects.filter(user=target_user).select_related("role", "assigned_by")
    assigned_ids = [ur.role_id for ur in assigned_roles]
    available_roles = Role.objects.exclude(id__in=assigned_ids)

    return render(
        request,
        "kura/accounts/user_roles.html",
        {
            "target_user": target_user,
            "assigned_roles": assigned_roles,
            "available_roles": available_roles,
        },
    )

from .forms import StudentCreateForm, StudentFilterForm, EnrollmentFilterForm, EnrollmentSearchForm, EnrollmentForm
def student_create_view(request):
    """
    Creates a new student account and profile with an auto-generated temporary password.
    Who can use it: Academic registrar.
    Security: Restricted to Registrar role; assigns Student role automatically.
"""
    # Check registrar permission.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied

    form = StudentCreateForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"].strip().lower()
        first_name = form.cleaned_data["first_name"].strip()
        last_name = form.cleaned_data["last_name"].strip()
        department = form.cleaned_data["department"]
        current_level = form.cleaned_data["current_level"]
        matriculation_year = form.cleaned_data["matriculation_year"]

        # Generate a secure 16-character temporary password.
        temporary_password = secrets.token_urlsafe(12)

        with transaction.atomic():
            # Create student user account.
            new_user = User.objects.create_user(
                email=email,
                password=temporary_password,
                first_name=first_name,
                last_name=last_name,
                must_change_password=True,
                mfa_enabled=False,
            )

            # Create student academic profile.
            StudentProfile.objects.create(
                user=new_user,
                department=department,
                current_level=current_level,
                matriculation_year=matriculation_year,
            )

            # Assign Student system role.
            student_role, _ = Role.objects.get_or_create(name="Student")
            UserRole.objects.get_or_create(
                user=new_user,
                role=student_role,
                defaults={"assigned_by": request.user},
            )

        messages.success(request, f"Student account created for {email}. Temporary password: {temporary_password}")
        return redirect("kura:enrollment_list")

    return render(request, "kura/accounts/student_create.html", {"form": form})


def student_list_view(request):
    """
    Lists student accounts and their status for the registrar.
    Who can use it: Registrars.
    Security: Checks the Registrar role and validates all search filters.
"""
    # Other roles must not browse institutional student records.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied
    students = StudentProfile.objects.select_related("user", "department").order_by("user__email")
    form = StudentFilterForm(request.GET or None)
    now = timezone.now()
    if form.is_valid():
        search = form.cleaned_data["q"]
        if search:
            matches = (
                Q(user__first_name__icontains=search)
                | Q(user__last_name__icontains=search)
                | Q(user__email__icontains=search)
            )
            try:
                matches |= Q(user_id=uuid.UUID(search))
            except ValueError:
                pass
            students = students.filter(matches)
        if form.cleaned_data["department"]:
            students = students.filter(department=form.cleaned_data["department"])
        if form.cleaned_data["level"]:
            students = students.filter(current_level=form.cleaned_data["level"])
        status = form.cleaned_data["status"]
        if status == "deactivated":
            students = students.filter(user__is_active=False)
        elif status == "locked":
            students = students.filter(user__is_active=True, user__locked_until__gt=now)
        elif status == "active":
            students = students.filter(user__is_active=True).filter(
                Q(user__locked_until__isnull=True) | Q(user__locked_until__lte=now)
            )
    return render(request, "kura/accounts/student_list.html", {"students": students, "filter_form": form, "now": now})


def student_profile_view(request, student_id):
    """
    Shows a student's account details and enrollments without grades.
    Who can use it: Registrars.
    Security: Checks the role before looking up the requested student.
"""
    # A guessed student ID must not expose a profile to other roles.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied
    student = get_object_or_404(StudentProfile.objects.select_related("user", "department"), user_id=student_id)
    enrollments = Enrollment.objects.filter(student=student.user).select_related("course").order_by("-enrolled_at")
    return render(
        request,
        "kura/accounts/student_profile.html",
        {"student": student, "enrollments": enrollments, "now": timezone.now()},
    )


def enrollment_search_view(request):
    """
    Finds eligible students or published courses for enrollment.
    Who can use it: Registrars.
    Security: Checks the role, validates input, limits results, and rate-limits user and IP.
"""
    # Only registrars may search, and the search must not change data.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])
    form = EnrollmentSearchForm(request.GET)
    if not form.is_valid():
        return HttpResponse("Unable to search.", status=400)
    # Separate shared limits stop both one account and one IP from excessive searches.
    cache = caches["search_limits"]
    window = int(timezone.now().timestamp() // 60)
    for value in (f"user:{request.user.id}", f"ip:{request.META.get('REMOTE_ADDR', '')}"):
        key = "enrollment-search:" + hashlib.sha256(value.encode()).hexdigest() + f":{window}"
        # A short-lived lock makes the database cache's non-atomic increment safe.
        lock = key + ":lock"
        if not cache.add(lock, 1, timeout=120):
            return HttpResponse("Too many searches. Please try again later.", status=429)
        try:
            count = cache.get(key, 0) + 1
            cache.set(key, count, timeout=120)
            # Do not allow a search if the shared counter could not be saved.
            if cache.get(key) != count:
                return HttpResponse("Search is temporarily unavailable.", status=503)
        finally:
            cache.delete(lock)
        if count > 60:
            return HttpResponse("Too many searches. Please try again later.", status=429)
    query = form.cleaned_data["q"]
    kind = form.cleaned_data["kind"]
    results = []
    if query and kind == "course":
        results = (
            Course.objects.filter(is_published=True)
            .filter(Q(code__icontains=query) | Q(title__icontains=query))
            .order_by("code")[:10]
        )
    elif query:
        matches = Q(first_name__icontains=query) | Q(last_name__icontains=query) | Q(email__icontains=query)
        try:
            matches |= Q(id=uuid.UUID(query))
        except ValueError:
            pass
        results = (
            User.objects.filter(student_profile__isnull=False, is_active=True).filter(matches).order_by("email")[:10]
        )
    return render(request, "kura/accounts/_enrollment_search.html", {"results": results, "kind": kind})


def enrollment_list_view(request):
    """
    Lists course enrollments across the institution.
    Who can use it: Academic registrar.
    Security: Registrar only; no grade content or course material is exposed.
"""
    # Check registrar permission.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied

    enrollments = Enrollment.objects.select_related(
        "course",
        "student",
        "enrolled_by",
        "dropped_by",
    ).order_by("-enrolled_at")

    # Apply only values accepted by the filter form.
    form = EnrollmentFilterForm(request.GET or None)
    if form.is_valid():
        if form.cleaned_data["course"]:
            enrollments = enrollments.filter(course=form.cleaned_data["course"])
        if form.cleaned_data["student"]:
            enrollments = enrollments.filter(student=form.cleaned_data["student"])
        if form.cleaned_data["status"]:
            enrollments = enrollments.filter(status=form.cleaned_data["status"])
        if form.cleaned_data["semester"]:
            enrollments = enrollments.filter(course__semester=form.cleaned_data["semester"])
        if form.cleaned_data["year"]:
            enrollments = enrollments.filter(course__academic_year=form.cleaned_data["year"])
    return render(request, "kura/accounts/enrollment_list.html", {"enrollments": enrollments, "filter_form": form})


def enrollment_create_view(request):
    """
    Enrolls an active student into a published course.
    Who can use it: Academic registrar.
    Security: Registrar only; sets enrolled_by to preserve registration audit trail.
"""
    # Check registrar permission.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied

    form = EnrollmentForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        course = form.cleaned_data["course"]
        student = form.cleaned_data["student"]

        # Check if enrollment already exists.
        existing = Enrollment.objects.filter(course=course, student=student).first()
        if existing and existing.status == EnrollmentStatus.ACTIVE:
            messages.error(request, "This student is already actively enrolled in this course.")
            return render(request, "kura/accounts/enrollment_create.html", {"form": form})

        if existing:
            # Re-activate previously dropped enrollment.
            existing.status = EnrollmentStatus.ACTIVE
            existing.enrolled_by = request.user
            existing.dropped_by = None
            existing.dropped_at = None
            existing.save()
            messages.success(request, f"Re-enrolled {student.email} in {course.code}.")
            return redirect("kura:enrollment_list")

        # Create new active enrollment record.
        Enrollment.objects.create(
            course=course,
            student=student,
            status=EnrollmentStatus.ACTIVE,
            enrolled_by=request.user,
        )
        messages.success(request, f"Enrolled {student.email} in {course.code}.")
        return redirect("kura:enrollment_list")

    return render(request, "kura/accounts/enrollment_create.html", {"form": form})


def enrollment_drop_view(request, enrollment_id):
    """
    Drops a student from a course, recording who dropped them and preserving history.
    Who can use it: Academic registrar.
    Security: Registrar only; POST only; records dropped_by and dropped_at.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Check registrar permission.
    if not has_role(request.user, "Registrar"):
        raise PermissionDenied

    enrollment = get_object_or_404(Enrollment, id=enrollment_id)

    # Set status to dropped and record dropping registrar.
    enrollment.status = EnrollmentStatus.DROPPED
    enrollment.dropped_by = request.user
    enrollment.dropped_at = timezone.now()
    enrollment.save()

    messages.success(request, f"Dropped {enrollment.student.email} from {enrollment.course.code}.")
    return redirect("kura:enrollment_list")



from .forms import CourseCreateForm, CourseStaffAssignForm
from .permissions import is_department_head
def course_list_view(request):
    """
    Displays the course catalog according to the user's role.
    Who can use it: Students (enrolled published), Staff (assigned), Department heads (departmental).
    Security: Filtered by user permissions; students only see published courses they are enrolled in.
"""
    # Administrators manage course metadata across all departments, including drafts.
    is_admin = is_admin_course_manager(request.user)
    if is_admin:
        courses = Course.objects.select_related("department")

    # Department heads see all courses in their headed departments.
    elif has_role(request.user, "Department head"):
        headed_dept_ids = Department.objects.filter(head_user=request.user).values_list("id", flat=True)
        courses = Course.objects.filter(department_id__in=headed_dept_ids).select_related("department")

    # Instructors and TAs see courses where they are assigned staff.
    elif has_role(request.user, "Instructor") or has_role(request.user, "Teaching assistant"):
        # A retained assignment counts only while its corresponding role is active.
        staff_roles = []
        if has_role(request.user, "Instructor"):
            staff_roles.extend(["lead_instructor", "co_instructor"])
        if has_role(request.user, "Teaching assistant"):
            staff_roles.append("teaching_assistant")
        assigned_course_ids = CourseStaff.objects.filter(user=request.user, staff_role__in=staff_roles).values_list(
            "course_id", flat=True
        )
        courses = Course.objects.filter(id__in=assigned_course_ids).select_related("department")

    # Students see only published courses in which they are actively enrolled.
    elif has_role(request.user, "Student"):
        enrolled_ids = Enrollment.objects.filter(
            student=request.user,
            status=EnrollmentStatus.ACTIVE,
        ).values_list("course_id", flat=True)
        courses = Course.objects.filter(id__in=enrolled_ids, is_published=True).select_related("department")

    # Registrars and Admins see published courses catalog.
    else:
        courses = Course.objects.filter(is_published=True).select_related("department")

    # Admin filters narrow the already authorized catalog; invalid values are not used.
    filter_form = AdminCourseFilterForm(request.GET or None)
    if is_admin and filter_form.is_valid():
        if filter_form.cleaned_data["department"]:
            courses = courses.filter(department=filter_form.cleaned_data["department"])
        if filter_form.cleaned_data["semester"]:
            courses = courses.filter(semester=filter_form.cleaned_data["semester"])
        if filter_form.cleaned_data["year"]:
            courses = courses.filter(academic_year=filter_form.cleaned_data["year"])
        if filter_form.cleaned_data["published"]:
            courses = courses.filter(is_published=filter_form.cleaned_data["published"] == "yes")

    # Check if the user is a department head to display the "Create Course" action button.
    is_head = has_role(request.user, "Department head") and Department.objects.filter(head_user=request.user).exists()

    return render(
        request,
        "kura/courses/course_list.html",
        {"courses": courses, "is_head": is_head, "is_admin": is_admin, "filter_form": filter_form},
    )


def course_create_view(request):
    """
    Allows a Department Head to draft a new course in their department.
    Who can use it: Department Heads.
    Security: Checks Department Head role and restricts course to their department.
"""
    if not has_role(request.user, "Department head"):
        raise PermissionDenied

    department = Department.objects.filter(head_user=request.user).first()
    if not department:
        messages.error(request, "You are not assigned as head of any department.")
        return redirect("kura:course_list")

    form = CourseCreateForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        Course.objects.create(
            department=department,
            code=form.cleaned_data["code"],
            title=form.cleaned_data["title"],
            description=form.cleaned_data["description"],
            semester=form.cleaned_data["semester"],
            academic_year=form.cleaned_data["academic_year"],
            created_by=request.user,
            is_published=False,
        )
        messages.success(request, f"Course {form.cleaned_data['code']} created as draft.")
        return redirect("kura:course_list")

    return render(request, "kura/courses/course_create.html", {"form": form, "department": department})


def course_detail_view(request, course_id):
    """
    Displays course curriculum modules, sections, and learning materials.
    Who can use it: Enrolled students (published only, matching target level), assigned staff, department heads.
    Security: checks course access and filters students to visible modules and released items at their level.
"""
    # Registrars cannot open instructional content, even with another role.
    if has_role(request.user, "Registrar"):
        raise PermissionDenied

    course = get_object_or_404(Course.objects.select_related("department"), id=course_id)

    # Administrators see course metadata and staff, never curriculum content.
    if is_admin_course_manager(request.user):
        staff_assignments = CourseStaff.objects.filter(course=course).select_related("user")
        return render(
            request,
            "kura/courses/course_detail.html",
            {
                "course": course,
                "staff_assignments": staff_assignments,
                "is_admin": True,
            },
        )

    # Permission check: verify user is allowed to access this course.
    is_head = is_department_head(request.user, course.department)
    is_staff = is_course_staff(request.user, course)
    enrolled = is_enrolled(request.user, course)

    if not (is_head or is_staff or (enrolled and course.is_published)):
        raise PermissionDenied

    # Load modules and target levels, then fetch only released items for students.
    modules_qs = Module.objects.filter(course=course).prefetch_related("target_levels")

    # If user is a student, enforce visibility and academic level restrictions.
    if not (is_head or is_staff):
        modules_qs = modules_qs.filter(is_visible=True)
        released_item_times = Q(released_at__isnull=True) | Q(released_at__lte=timezone.now())
        student_items = (
            SectionItem.objects.filter(
                is_visible=True,
            )
            .filter(released_item_times)
            .prefetch_related("item_files__file")
        )
        student_sections = ModuleSection.objects.filter(is_visible=True).prefetch_related(
            Prefetch("items", queryset=student_items),
            "assessments",
        )
        modules_qs = modules_qs.prefetch_related(Prefetch("sections", queryset=student_sections))

        # Find the student's current academic level for the existing module restrictions.
        student_profile = StudentProfile.objects.filter(user=request.user).first()
        if student_profile:
            student_level = student_profile.current_level
        else:
            student_level = None

        # Filter out modules restricted to levels that do not match the student's level.
        allowed_modules = []
        for mod in modules_qs:
            target_levels = list(mod.target_levels.values_list("target_level", flat=True))
            if not target_levels or (student_level and student_level in target_levels):
                allowed_modules.append(mod)
        modules_list = allowed_modules
    else:
        # Staff must see hidden and scheduled items so they can manage the release state.
        modules_qs = modules_qs.prefetch_related("sections__items__item_files__file", "sections__assessments")
        modules_list = list(modules_qs)

    # Load course staff assignments.
    staff_assignments = CourseStaff.objects.filter(course=course).select_related("user")

    # Check lead instructor authority to assign TAs.
    is_lead = is_lead_instructor(request.user, course)

    context = {
        "course": course,
        "modules": modules_list,
        "staff_assignments": staff_assignments,
        "is_head": is_head,
        "is_staff": is_staff,
        "is_lead": is_lead,
    }
    return render(request, "kura/courses/course_detail.html", context)


def course_publish_toggle_view(request, course_id):
    """
    Publishes or unpublishes a course in the department catalog.
    Who can use it: Department Heads.
    Security: Restricts action to Department Head of the course's department; POST only.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    course = get_object_or_404(Course, id=course_id)

    # Verify user is head of this course's department.
    if not (is_admin_course_manager(request.user) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    if not course.is_published:
        course.is_published = True
        course.published_by = request.user
        course.published_at = timezone.now()
        messages.success(request, f"Course {course.code} is now published.")
    else:
        course.is_published = False
        course.published_by = None
        course.published_at = None
        messages.success(request, f"Course {course.code} is now unpublished (draft).")

    course.save()
    return redirect("kura:course_detail", course_id=course.id)


def course_staff_assign_view(request, course_id):
    """
    Assigns a lead instructor or co-instructor to a departmental course.
    Who can use it: Department Heads.
    Security: Department Head of the course's department only; auto-grants grade release for lead.
"""
    course = get_object_or_404(Course, id=course_id)

    if not is_department_head(request.user, course.department):
        raise PermissionDenied

    form = CourseStaffAssignForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        user = form.cleaned_data["user"]
        staff_role = form.cleaned_data["staff_role"]
        can_release = form.cleaned_data["can_release_grades"]

        # Lead instructors automatically hold grade release authority.
        if staff_role == "lead_instructor":
            can_release = True

        CourseStaff.objects.update_or_create(
            course=course,
            user=user,
            defaults={
                "staff_role": staff_role,
                "can_release_grades": can_release,
                "assigned_by": request.user,
            },
        )
        messages.success(request, f"Assigned {user.email} as {staff_role} in {course.code}.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/staff_assign.html", {"form": form, "course": course})


import nh3
import html
from django.db import transaction
from .forms import TAAssignForm, ModuleForm, DeleteConfirmationForm, ModuleSectionForm, SectionItemForm, MarkdownPreviewForm
from .templatetags.markdown import render_markdown
from .permissions import can_access_learning_records, is_course_staff
def course_ta_assign_view(request, course_id):
    """
    Assigns a teaching assistant to an instructor's course.
    Who can use it: Instructors assigned to the course and Department Heads.
    Security: TAs never receive can_release_grades authority.
"""
    course = get_object_or_404(Course, id=course_id)

    # Only an assigned instructor or the department head may assign teaching assistants.
    instructor = has_role(request.user, "Instructor") and is_course_staff(request.user, course)
    if is_admin_course_manager(request.user) or not (instructor or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = TAAssignForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        user = form.cleaned_data["user"]

        # Teaching assistants strictly receive can_release_grades=False.
        CourseStaff.objects.update_or_create(
            course=course,
            user=user,
            defaults={
                "staff_role": "teaching_assistant",
                "can_release_grades": False,
                "assigned_by": request.user,
            },
        )
        messages.success(request, f"Assigned {user.email} as Teaching Assistant.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/ta_assign.html", {"form": form, "course": course})


def module_create_view(request, course_id):
    """
    Creates a curriculum module with optional academic target levels.
    Who can use it: Course instructors and Department Heads.
    Security: Restricted to authorized course staff and department head.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins manage course metadata only, not instructional content.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    course = get_object_or_404(Course, id=course_id)

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = ModuleForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        title = form.cleaned_data["title"]
        description = form.cleaned_data["description"]
        is_visible = form.cleaned_data["is_visible"]
        target_levels = form.cleaned_data.get("target_levels", [])

        with transaction.atomic():
            module = Module.objects.create(
                course=course,
                title=title,
                description=description,
                is_visible=is_visible,
                created_by=request.user,
            )

            # Save target academic levels for access control.
            for level in target_levels:
                ModuleTargetLevel.objects.create(module=module, target_level=level)

        messages.success(request, f"Module '{title}' created successfully.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/module_create.html", {"form": form, "course": course})


def module_delete_view(request, module_id):
    """
    Deletes a module only when it has no student attempts or attendance records.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: POST, confirmation, course permission, row locks, and deletion logging.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Check the exact course and require an explicit POST confirmation.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    module = get_object_or_404(Module.objects.select_related("course__department"), id=module_id)
    course = module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if not DeleteConfirmationForm(request.POST).is_valid():
        messages.error(request, "Confirm module deletion first.")
        return redirect("kura:course_detail", course_id=course.id)
    # Lock child rows before checking so new attempts or attendance cannot race deletion.
    with transaction.atomic():
        module = Module.objects.select_for_update().get(id=module.id)
        sections = list(ModuleSection.objects.filter(module=module).order_by("id").select_for_update())
        assessments = list(Assessment.objects.filter(section__in=sections).order_by("id").select_for_update())
        sessions = list(ModuleAttendanceSession.objects.filter(module=module).order_by("id").select_for_update())
        if (
            AssessmentAttempt.objects.filter(assessment__in=assessments).exists()
            or AttendanceRecord.objects.filter(session__in=sessions).exists()
        ):
            messages.error(request, "This module contains student records and cannot be deleted. Hide it instead.")
            return redirect("kura:course_detail", course_id=course.id)
        module.delete()
        security_logger.info("Module %s deleted by %s", module_id, request.user.id)
    messages.success(request, "Module deleted.")
    return redirect("kura:course_detail", course_id=course.id)


def module_edit_view(request, module_id):
    """
    Edits a module and its target levels.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: Checks the exact course and validates changes before saving atomically.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Reject unrelated users before processing the form.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    module = get_object_or_404(Module.objects.select_related("course__department"), id=module_id)
    course = module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    initial = {
        "title": module.title,
        "description": module.description,
        "is_visible": module.is_visible,
        "target_levels": list(module.target_levels.values_list("target_level", flat=True)),
    }
    form = ModuleForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        # Keep module details and target-level rows consistent.
        with transaction.atomic():
            module.title = form.cleaned_data["title"]
            module.description = form.cleaned_data["description"]
            module.is_visible = form.cleaned_data["is_visible"]
            module.save(update_fields=["title", "description", "is_visible"])
            ModuleTargetLevel.objects.filter(module=module).delete()
            for level in form.cleaned_data["target_levels"]:
                ModuleTargetLevel.objects.create(module=module, target_level=level)
        messages.success(request, "Module updated.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/module_create.html", {"form": form, "course": course, "editing": True})


def section_edit_view(request, section_id):
    """
    Edits a section's title and type.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: Checks the exact course and accepts changes only from a validated POST.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Check the section's actual course rather than trusting the URL alone.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    section = get_object_or_404(ModuleSection.objects.select_related("module__course__department"), id=section_id)
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    form = ModuleSectionForm(
        request.POST or None, initial={"title": section.title, "section_type": section.section_type}
    )
    if request.method == "POST" and form.is_valid():
        section.title = form.cleaned_data["title"]
        section.section_type = form.cleaned_data["section_type"]
        section.save(update_fields=["title", "section_type"])
        messages.success(request, "Section updated.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(
        request, "kura/courses/section_create.html", {"form": form, "module": section.module, "editing": True}
    )


def section_create_view(request, module_id):
    """
    Creates a section grouping within a curriculum module.
    Who can use it: Course instructors and Department Heads.
    Security: Checks course staff assignment on the module's course.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins must not access instructional content through another assignment.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    module = get_object_or_404(Module.objects.select_related("course"), id=module_id)
    course = module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = ModuleSectionForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        ModuleSection.objects.create(
            module=module,
            title=form.cleaned_data["title"],
            section_type=form.cleaned_data["section_type"],
        )
        messages.success(request, f"Section '{form.cleaned_data['title']}' created.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/section_create.html", {"form": form, "module": module})


def section_delete_view(request, section_id):
    """
    Deletes an empty section or hides one containing assessment attempts.
    Who can use it: Assigned course staff and the department head, except Admins.
    Security: POST, confirmation, course permission, row locks, and an audit log.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Verify the request method and the user's permission for this section's course.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    section = get_object_or_404(ModuleSection.objects.select_related("module__course__department"), id=section_id)
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if not DeleteConfirmationForm(request.POST).is_valid():
        messages.error(request, "Confirm section deletion first.")
        return redirect("kura:course_detail", course_id=course.id)

    # Lock the section and its assessments so an attempt cannot race with deletion.
    with transaction.atomic():
        section = ModuleSection.objects.select_for_update().get(id=section.id)
        assessments = list(Assessment.objects.filter(section=section).order_by("id").select_for_update())
        if AssessmentAttempt.objects.filter(assessment__in=assessments).exists():
            section.is_visible = False
            section.save(update_fields=["is_visible"])
            messages.warning(request, "Section hidden because it contains student attempts.")
            security_logger.info("Section %s hidden instead of deletion by %s", section.id, request.user.id)
        else:
            section_id = section.id
            section.delete()
            security_logger.info("Section %s deleted by %s", section_id, request.user.id)
            messages.success(request, "Section deleted.")
    return redirect("kura:course_detail", course_id=course.id)


def section_visibility_toggle_view(request, section_id):
    """
    Hides or releases a section without deleting its contents.
    Who can use it: Assigned course staff and the department head, except Admins.
    Security: POST only, checks the exact course and preserves assessment attempts.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Reject administrators and non-POST requests before changing anything.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    section = get_object_or_404(ModuleSection.objects.select_related("module__course__department"), id=section_id)
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    # Keep the section and its attempts while changing only its visibility.
    section.is_visible = not section.is_visible
    section.save(update_fields=["is_visible"])
    security_logger.info("Section visibility changed: section %s, actor %s", section.id, request.user.id)
    messages.success(request, "Section visibility updated.")
    return redirect("kura:course_detail", course_id=course.id)


def item_edit_view(request, item_id):
    """
    Edits a learning item while preserving existing attachments.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: Checks the course, cleans Markdown, and validates optional uploads atomically.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Load the item only for an authorized course author.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    item = get_object_or_404(SectionItem.objects.select_related("section__module__course__department"), id=item_id)
    section = item.section
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    initial = {"title": item.title, "content_body": html.unescape(item.content_body), "released_at": item.released_at}
    form = SectionItemForm(
        request.POST or None, request.FILES or None, initial=initial, existing_file=item.item_files.exists()
    )
    if request.method == "POST" and form.is_valid():
        try:
            # Roll back the item update if the new attachment is rejected.
            with transaction.atomic():
                item.title = form.cleaned_data["title"]
                item.content_body = nh3.clean(html.escape(form.cleaned_data["content_body"]), tags=set(), attributes={})
                item.released_at = form.cleaned_data["released_at"]
                item.save(update_fields=["title", "content_body", "released_at"])
                if form.cleaned_data["file"]:
                    stored = validate_and_save_upload(form.cleaned_data["file"], request.user)
                    SectionItemFile.objects.create(section_item=item, file=stored)
        except ValidationError as error:
            if hasattr(error, "message"):
                error_message = str(error.message)
            else:
                error_message = str(error)
            messages.error(request, error_message)
        else:
            messages.success(request, "Item updated.")
            return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/item_create.html", {"form": form, "section": section, "editing": True})


def item_delete_view(request, item_id):
    """
    Deletes a learning item after confirmation.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: POST only, checks course permission and confirmation, and logs deletion.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Require the exact course permission and an explicit confirmation.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    item = get_object_or_404(SectionItem.objects.select_related("section__module__course__department"), id=item_id)
    course = item.section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if not DeleteConfirmationForm(request.POST).is_valid():
        messages.error(request, "Confirm item deletion first.")
        return redirect("kura:course_detail", course_id=course.id)
    # Delete only the requested item and record who made the change.
    item.delete()
    security_logger.info("Item %s deleted by %s", item_id, request.user.id)
    messages.success(request, "Item deleted.")
    return redirect("kura:course_detail", course_id=course.id)


def item_create_view(request, section_id):
    """
    Authors a section item, sanitizes rich text via nh3, and attaches an optional file.
    Who can use it: Assigned Instructors and Teaching Assistants, and the course's Department Head.
    Security: checks course access, sanitizes rich text against XSS, and validates uploaded files.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins manage course metadata, not teaching materials.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    section = get_object_or_404(ModuleSection.objects.select_related("module__course"), id=section_id)
    course = section.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = SectionItemForm(request.POST or None, request.FILES or None)

    if request.method == "POST" and form.is_valid():
        # Read the validated item details and optional release time from the form.
        title = form.cleaned_data["title"]
        raw_body = form.cleaned_data["content_body"]
        released_at = form.cleaned_data["released_at"]
        uploaded_file = form.cleaned_data.get("file")

        # Encode HTML as text and clean the Markdown source before storing it.
        clean_body = nh3.clean(html.escape(raw_body), tags=set(), attributes={})

        # Roll back the item if its attachment cannot be saved.
        upload_error = None
        with transaction.atomic():
            item = SectionItem.objects.create(
                section=section,
                title=title,
                content_body=clean_body,
                released_at=released_at,
            )

            # If a file was attached, validate and save it.
            if uploaded_file:
                try:
                    stored_file = validate_and_save_upload(uploaded_file, request.user)
                    SectionItemFile.objects.create(section_item=item, file=stored_file)
                except ValidationError as e:
                    if hasattr(e, "message"):
                        upload_error = str(e.message)
                    else:
                        upload_error = str(e)
                    transaction.set_rollback(True)

        # Show the error after leaving the rolled-back transaction.
        if upload_error:
            messages.error(request, upload_error)
            return render(request, "kura/courses/item_create.html", {"form": form, "section": section})

        messages.success(request, f"Item '{title}' created hidden. Release it when ready.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/item_create.html", {"form": form, "section": section})


def item_preview_view(request, section_id):
    """
    Previews Markdown for an item in a course section.
    Who can use it: Assigned instructors and TAs, and the department head.
    Security: Requires POST and CSRF, validates text, checks course access, and cleans HTML.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins cannot inspect teaching materials, even if they have another assignment.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Check access to the exact section before rendering submitted text.
    section = get_object_or_404(ModuleSection.objects.select_related("module__course__department"), id=section_id)
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    # Preview with the same sanitized renderer used for saved items.
    form = MarkdownPreviewForm(request.POST)
    if not form.is_valid():
        return HttpResponse("Unable to preview this content.", status=400)
    # Use the same source encoding as saving, so literal entities preview accurately.
    clean_body = nh3.clean(html.escape(form.cleaned_data["content_body"]), tags=set(), attributes={})
    return HttpResponse(render_markdown(clean_body))


def item_visibility_toggle_view(request, item_id):
    """
    Hides a section item or releases it for students.
    Who can use it: Instructors and Teaching Assistants assigned to the course, and its Department Head.
    Security: POST only; checks staff assignment or department ownership for this exact item.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins cannot change teaching materials, even with another course assignment.
    if is_admin_course_manager(request.user):
        raise PermissionDenied

    # Only POST requests may change an item's visibility.
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Load the item's course so access is checked against the resource being changed.
    item = get_object_or_404(
        SectionItem.objects.select_related("section__module__course"),
        id=item_id,
    )
    course = item.section.module.course

    # Only assigned course staff or this course's department head may change visibility.
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    # Flip the saved state and tell the staff member what happened.
    item.is_visible = not item.is_visible
    item.save(update_fields=["is_visible"])
    if item.is_visible:
        status_message = "released"
    else:
        status_message = "hidden"
    messages.success(request, f"Item '{item.title}' is now {status_message}.")
    return redirect("kura:course_detail", course_id=course.id)


from .models import (
    AppealStatus,
    Assessment,
    AssessmentAttempt,
    AssessmentDeliveryMode,
    AssessmentFile,
    AttemptFile,
    AttemptStatus,
    AttendanceMethod,
    AttendanceRecord,
    AttendanceStatus,
    ChangeRequestStatus,
    Course,
    CourseGradeScheme,
    CourseResult,
    CourseStaff,
    CourseStaffRole,
    Department,
    Enrollment,
    EnrollmentStatus,
    ExamAnswerKey,
    Grade,
    GradeAppeal,
    GradeChangeRequest,
    GradeHistory,
    GradeStatus,
    Module,
    ModuleAttendanceSession,
    ModuleSection,
    ModuleTargetLevel,
    PasswordResetToken,
    Role,
    Schedule,
    SectionItem,
    SectionItemFile,
    StaffProfile,
    StoredFile,
    StudentProfile,
    User,
    UserRole,
    UserSession,
)

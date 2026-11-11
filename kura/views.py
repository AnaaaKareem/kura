import hashlib
import html
import ipaddress
import json
import logging
import re
import secrets
import time
import urllib.parse
import uuid
from base64 import b32encode
from decimal import Decimal
import nh3
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.cache import caches
from django.db import transaction
from django.db.models import Avg, Prefetch, Q, Value
from django.db.models.functions import Concat
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from axes.handlers.proxy import AxesProxyHandler

from .files import create_download_response, validate_and_save_upload
from .forms import (
    AdminCourseForm,
    AdminCourseFilterForm,
    AdminStaffFilterForm,
    AdminSessionFilterForm,
    AdminSessionRevokeForm,
    AssessmentAttemptStartForm,
    AssessmentAnswerForm,
    AssessmentAutosaveForm,
    AssessmentCreateForm,
    AssessmentFileUploadForm,
    AssessmentQuestionAddForm,
    AssessmentQuestionFormSet,
    AttendanceSessionStartForm,
    CourseCreateForm,
    CourseStaffAssignForm,
    DeleteConfirmationForm,
    EnrollmentForm,
    EnrollmentFilterForm,
    EnrollmentSearchForm,
    GradeAppealForm,
    GradeAppealReviewForm,
    GradeChangeRequestForm,
    GradeChangeRequestReviewForm,
    GradeEntryForm,
    GradeReleaseForm,
    LoginForm,
    MFAVerifyForm,
    ManualAttendanceForm,
    MarkdownPreviewForm,
    ModuleForm,
    ModuleSectionForm,
    PasswordChangeForm,
    PasswordResetConfirmForm,
    PasswordResetRequestForm,
    ScheduleForm,
    ScannedPaperStaffUploadForm,
    SectionItemForm,
    StaffCreateForm,
    DepartmentForm,
    BuildingForm,
    RoomForm,
    StudentCheckinForm,
    StudentCreateForm,
    StudentFilterForm,
    TAAssignForm,
)
from .models import (
    OutgoingEmail,
    QuarantinedFile,
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
    Building,
    Room,
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
from .permissions import (
    can_access_learning_records,
    can_manage_quarantine,
    can_release_grades,
    has_role,
    is_course_staff,
    is_admin_course_manager,
    is_department_head,
    is_enrolled,
    is_lead_instructor,
)
from .templatetags.markdown import render_markdown
from .vault import decrypt_answer_key, decrypt_mfa_secret, encrypt_answer_key, encrypt_mfa_secret

security_logger = logging.getLogger("kura.security")

# Keep work-area links on the dashboard and only show areas for assigned roles.
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
    # Axes returns this 403 directly, so log it here instead of relying on handler403.
    log_security_event(request, "access.denied", {"reason": "axes_lockout"}, logging.WARNING)
    return HttpResponseForbidden("Account temporarily locked due to repeated failures. Please try again later.")


def get_client_ip(request):
    """
    Returns the IP address of the real visitor.
    Used by: session records, rate limits, attendance, assessment lab checks,
    the rate-limit middleware, and django-axes (AXES_CLIENT_IP_CALLABLE).
    Security: the X-Real-IP header is only trusted when TRUST_PROXY_IP_HEADER is
    on (only the WAF can reach Gunicorn then). The value must be a valid IP
    address, otherwise we fall back to REMOTE_ADDR, so a forged or garbage
    header can never be stored or used.
    """
    # The address of whatever connected to Django (the WAF in production).
    remote_addr = request.META.get("REMOTE_ADDR") or "127.0.0.1"

    # Without a trusted proxy in front, the header could be faked: ignore it.
    if not settings.TRUST_PROXY_IP_HEADER:
        return remote_addr

    # Use the visitor's address sent by the WAF, if it is a real IP address.
    header_value = request.META.get("HTTP_X_REAL_IP", "").strip()
    try:
        return str(ipaddress.ip_address(header_value))
    except ValueError:
        return remote_addr


def log_security_event(request, event, details, level=logging.INFO):
    """Write one escaped, searchable security event without logging secrets.

    The actor is named actor_user_id so event details can separately identify
    the affected user without creating duplicate logfmt keys.
    """
    # The proxy creates lowercase hexadecimal IDs; reject anything else before logging it.
    request_id = "-"
    if request is not None:
        received_request_id = request.META.get("HTTP_X_REQUEST_ID", "")
        if re.fullmatch(r"[0-9a-f]{32}", received_request_id):
            request_id = received_request_id

    # Password-reset URLs contain bearer tokens, so replace the token before writing the path.
    path = "-"
    if request is not None:
        path = re.sub(r"^/password/reset/[^/]+/", "/password/reset/<redacted>/", request.path)

    # Record the request context while distinguishing the actor from event subjects.
    parts = ["event=" + json.dumps(str(event))]
    if request is not None:
        actor_user_id = "anonymous"
        if hasattr(request, "user") and request.user.is_authenticated:
            actor_user_id = str(request.user.id)
        parts.extend(
            [
                "ip=" + json.dumps(get_client_ip(request)),
                "actor_user_id=" + json.dumps(actor_user_id),
                "request_id=" + json.dumps(request_id),
                "path=" + json.dumps(path),
                "method=" + json.dumps(request.method),
            ]
        )

    # Sort fields and encode after limiting their size, keeping every value valid JSON.
    for key in sorted(details):
        value = json.dumps(str(details[key])[:500])
        parts.append(str(key) + "=" + value)

    # Join first so untrusted values are never used as a logging format string.
    line = " ".join(parts)
    security_logger.log(level, line)


def permission_denied_view(request, exception):
    """Show a generic denial page and record the denied request.

    Who can reach it: Any user whose request is denied, including anonymous users.
    Security: Logs a bounded reason and request context without revealing details.
    """
    # Keep the exception detail short so unexpected messages cannot flood logs.
    reason = str(exception)[:200]
    log_security_event(request, "access.denied", {"reason": reason}, logging.WARNING)
    return render(request, "403.html", status=403)


def csrf_failure_view(request, reason=""):
    """Show a generic page when Django rejects a request's CSRF token.

    Who can reach it: Any user submitting a request that fails CSRF validation.
    Security: Logs only a short framework reason and never displays it to the user.
    """
    # Record the CSRF denial for investigation without exposing the reason in the page.
    log_security_event(request, "access.csrf_failed", {"reason": str(reason)[:200]}, logging.WARNING)
    return render(request, "403.html", status=403)

def queue_email(event_key, to_email, subject, body):
    """
    Puts one email in the outbox (OutgoingEmail) for send_queued_emails to send.
    Used by the password reset and by every notification.
    Security: event_key is unique in the database, so the same event (for
    example "reminder-24h:<assessment>:<student>") is never emailed twice, even
    if two requests or jobs try at the same moment. The subject is squeezed onto
    one line, so text from a title can never add extra email headers.
    """
    # One line only, at most 200 characters.
    one_line_subject = " ".join(subject.split())[:200]

    # Create each notification only once, and report only when this call created it.
    email_record, created = OutgoingEmail.objects.get_or_create(
        event_key=event_key[:255],
        defaults={"to_email": to_email, "subject": one_line_subject, "body": body},
    )
    if created:
        event_key_prefix = email_record.event_key.split(":", 1)[0]
        log_security_event(None, "email.queued", {"event_key_prefix": event_key_prefix})
    return created


def queue_assessment_notification(assessment, event_name, subject, opening_line):
    """
    Emails every actively enrolled student of the assessment's course about it.
    Used for "new assessment" (create view and module made visible) and
    "dates changed" (edit view).
    Security: only when students can actually see the assessment (its section
    and module are visible), never with scores or answers, and each student is
    emailed at most once per event (event_key "<event_name>:<assessment>:<student>").
    """
    section = assessment.section
    module = section.module
    course = module.course

    # Hidden work stays hidden: no email until students can see it.
    if not (section.is_visible and module.is_visible):
        return

    # The same text for every student. The link uses the fixed SITE_URL, never
    # the Host header of the request.
    link = settings.SITE_URL + reverse("kura:assessment_detail", kwargs={"assessment_id": assessment.id})
    opens_text = timezone.localtime(assessment.opens_at).strftime("%d %b %Y, %H:%M")
    due_text = timezone.localtime(assessment.due_date).strftime("%d %b %Y, %H:%M")
    body = (
        f"Hello,\n\n{opening_line}\n\n"
        f"{assessment.get_component_type_display()}: {assessment.title}\n"
        f"Course: {course.code} {course.title}\n"
        f"Opens: {opens_text}\n"
        f"Due: {due_text}\n\n"
        f"Log in to Kura to see the details:\n{link}\n\n"
        "This is an automatic message from Kura. Please do not reply."
    )

    # One email per actively enrolled student.
    enrollments = Enrollment.objects.filter(
        course=course, status=EnrollmentStatus.ACTIVE, student__is_active=True
    ).select_related("student")
    for enrollment in enrollments:
        queue_email(
            f"{event_name}:{assessment.id}:{enrollment.student_id}",
            enrollment.student.email,
            subject,
            body,
        )


def verify_totp_code(device, user, code):
    """
    Checks a 6-digit authenticator-app code for one TOTP device.
    Used in three places: the login MFA step, MFA setup and grade release.
    Security:
    - The real seed is read from User.mfa_secret and decrypted by Vault in
      memory. TOTPDevice.key only holds a random placeholder, so the database
      never contains a usable seed.
    - Keeps django-otp's protections: throttling (a delay after wrong codes)
      and replay protection (an accepted code cannot be used a second time).
    - If Vault cannot be reached the code is refused (fail closed). Recovery
      codes still work, because they do not need Vault (see hash_recovery_code).
    """
    # django-otp throttling: after wrong codes, the user must wait before trying again.
    verify_allowed, _ = device.verify_is_allowed()
    if not verify_allowed:
        return False

    # Ask Vault to decrypt the seed. A Vault failure is logged inside
    # decrypt_mfa_secret and must not count as the user's mistake.
    try:
        seed_hex = decrypt_mfa_secret(user.mfa_secret)
    except ValidationError:
        # Vault errors are system failures, not failed user verification attempts.
        log_security_event(None, "auth.mfa.vault_unavailable", {}, logging.ERROR)
        return False

    # The user must have a seed, and the code must be plain digits.
    if not seed_hex or not (code.isascii() and code.isdigit()):
        device.throttle_increment(commit=True)
        return False

    # Work out the expected code for the current 30-second window (and the
    # allowed windows either side for clock drift) and compare. min_t is one
    # past the last accepted window, so an old code cannot be replayed.
    totp = TOTP(bytes.fromhex(seed_hex), device.step, device.t0, device.digits, device.drift)
    totp.time = time.time()
    if not totp.verify(int(code), device.tolerance, device.last_t + 1):
        device.throttle_increment(commit=True)
        return False

    # Correct code: remember this window (blocks replay), keep the clock drift,
    # clear the wrong-code counter and record when the device was last used.
    device.last_t = totp.t()
    device.drift = totp.drift
    device.throttle_reset(commit=False)
    device.set_last_used_timestamp(commit=False)
    device.save()
    return True


def hash_recovery_code(code):
    """
    Turns a recovery code into the value stored in StaticToken.token.
    Used in three places: MFA setup (saving new codes), the login MFA step and
    grade release (checking a typed code).
    Security:
    - The database never holds the codes themselves, only this keyed hash
      (HMAC-SHA256 with Django's SECRET_KEY). A plain SHA-256 would not be
      enough: codes are only 8 hex characters (about 4 billion options), so
      someone with a copy of the database could try them all in seconds.
      Without SECRET_KEY they cannot even start.
    - It does not need Vault, so recovery codes still work when Vault is down
      (that is what they are for).
    - Changing SECRET_KEY makes every saved recovery code stop working; users
      then create new codes on the MFA setup page.
    """
    # Ignore spaces and letter case, so "abcd 1234" matches the code shown as "ABCD1234".
    normalized_code = code.replace(" ", "").upper()

    # Django's salted_hmac computes HMAC-SHA256 with SECRET_KEY. The first
    # argument (the "salt") keeps this hash different from Django's other uses
    # of SECRET_KEY, such as session and password-reset signatures.
    full_hash = salted_hmac("kura.recovery_code", normalized_code, algorithm="sha256").hexdigest()

    # StaticToken.token holds at most 16 characters, so keep the first 16 hex
    # characters (64 bits): far more than enough to tell 10 codes apart.
    return full_hash[:16]


def create_user_session(request, user):
    """
    Creates a new tracked UserSession record for an authenticated user.
    Records client IP address, browser user-agent, and a 14-day expiry.
    """
    # Generate random bytes for the session bearer token hash.
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Read the real visitor's IP address (not the WAF's).
    ip_address = get_client_ip(request)

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
                        log_security_event(
                            request,
                            "auth.login.failed",
                            {"login_identifier": email[:254], "reason": "deactivated"},
                            logging.WARNING,
                        )
                        messages.error(request, "This account has been deactivated. Contact the administrator.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                    # Include the lock expiry so a locked user knows when to try again.
                    if password_matched_user.locked_until and password_matched_user.locked_until > timezone.now():
                        log_security_event(
                            request,
                            "auth.login.failed",
                            {"login_identifier": email[:254], "reason": "locked"},
                            logging.WARNING,
                        )
                        lock_time = timezone.localtime(password_matched_user.locked_until).strftime("%d %b, %H:%M")
                        messages.error(request, f"This account is currently locked until {lock_time}.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                    # Keep automatic Axes lockouts understandable without exposing account details to wrong passwords.
                    is_locked_by_axes = AxesProxyHandler.is_locked(request, {"username": email})
                    if is_locked_by_axes:
                        request.axes_locked_out = False
                        log_security_event(
                            request,
                            "auth.login.failed",
                            {"login_identifier": email[:254], "reason": "axes_lockout"},
                            logging.WARNING,
                        )
                        messages.error(request, "This account is currently locked. Contact the administrator.")
                        return render(request, "kura/accounts/login.html", {"form": form})

                # Keep the same response for unknown emails and incorrect passwords.
                log_security_event(
                    request,
                    "auth.login.failed",
                    {"login_identifier": email[:254], "reason": "bad_credentials"},
                    logging.WARNING,
                )
                messages.error(request, "Invalid email or password.")
                return render(request, "kura/accounts/login.html", {"form": form})

            # Catch an account status change that happened just after authentication.
            if not user.is_active:
                log_security_event(
                    request,
                    "auth.login.failed",
                    {"login_identifier": email[:254], "reason": "inactive"},
                    logging.WARNING,
                )
                messages.error(request, "This account has been deactivated. Contact the administrator.")
                return render(request, "kura/accounts/login.html", {"form": form})

            # Show the lock expiry if an administrator locked the account during authentication.
            if user.locked_until and user.locked_until > timezone.now():
                log_security_event(
                    request,
                    "auth.login.failed",
                    {"login_identifier": email[:254], "reason": "locked"},
                    logging.WARNING,
                )
                lock_time = timezone.localtime(user.locked_until).strftime("%d %b, %H:%M")
                messages.error(request, f"This account is currently locked until {lock_time}.")
                return render(request, "kura/accounts/login.html", {"form": form})

            log_security_event(request, "auth.login.password_ok", {"user_id": user.id})

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


def mfa_verify_view(request):
    """
    Verifies the TOTP code, backup code, or WebAuthn/FIDO2 Passkey during two-factor login.
    Who can use it: Users who successfully passed password authentication.
    Security: Validates one-time code or WebAuthn assertion challenge against enrolled credentials.
    Recovery codes are compared by keyed hash and deleted after one use.
"""
    # Retrieve user ID stored during step 1 authentication.
    user_id = request.session.get("pre_mfa_user_id")
    if not user_id:
        return redirect("kura:login")

    user = get_object_or_404(User, id=user_id)
    # Store base_username so django-mfa2 WebAuthn endpoints know which user is authenticating
    request.session["base_username"] = user.email

    from mfa.models import User_Keys

    has_passkeys = User_Keys.objects.filter(username=user.email, key_type="FIDO2", enabled=True).exists()

    form = MFAVerifyForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"].strip()

        # Check TOTP devices first.
        verified = False
        verification_method = "totp"
        for device in TOTPDevice.objects.filter(user=user, confirmed=True):
            if verify_totp_code(device, user, code):
                verified = True
                break

        # Check static recovery backup codes if TOTP did not match.
        if not verified:
            verification_method = "recovery_code"
            # Codes are saved only as keyed hashes, so hash the typed code and look
            # for that. django-otp's verify_token still deletes the used code (single
            # use) and slows down repeated wrong guesses (throttling).
            code_hash = hash_recovery_code(code)
            for static_device in StaticDevice.objects.filter(user=user, confirmed=True):
                if static_device.verify_token(code_hash):
                    verified = True
                    break

        # Reject invalid codes with generic error.
        if not verified:
            log_security_event(
                request,
                "auth.mfa.failed",
                {"method_tried": "totp_or_recovery_code"},
                logging.WARNING,
            )
            messages.error(request, "Invalid security code.")
            return render(request, "kura/accounts/mfa_verify.html", {"form": form, "has_passkeys": has_passkeys})

        # Complete login and clean up pre-mfa session marker.
        log_security_event(request, "auth.mfa.ok", {"method": verification_method})
        request.session.pop("pre_mfa_user_id", None)
        request.session.pop("base_username", None)
        login(request, user, backend="kura.backends.KuraAuthBackend")
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])
        create_user_session(request, user)

        # Handle first-login password rotation if needed.
        if user.must_change_password:
            return redirect("kura:password_change")

        return redirect("kura:home")

    return render(request, "kura/accounts/mfa_verify.html", {"form": form, "has_passkeys": has_passkeys})


def mfa_login_callback(request, username):
    """
    Callback executed by django-mfa2 upon successful FIDO2 / Passkey authentication.
    Who can use it: System internal auth callback.
    Security: Establishes session for the authenticated user and cleans up pre-mfa markers.
    """
    user = get_object_or_404(User, email=username)
    login(request, user, backend="kura.backends.KuraAuthBackend")
    user.last_login = timezone.now()
    user.save(update_fields=["last_login"])
    create_user_session(request, user)

    request.session.pop("pre_mfa_user_id", None)
    request.session.pop("base_username", None)

    log_security_event(request, "auth.mfa.ok", {"method": "passkey"})

    if user.must_change_password:
        return redirect("kura:password_change")

    return redirect("kura:home")


@login_required
def passkey_manage_view(request):
    """
    Displays the user's enrolled WebAuthn / FIDO2 passkeys and allows enrolling new ones.
    Who can use it: Any authenticated user.
    Security: Strictly filters User_Keys by request.user.email.
"""
    from mfa.models import User_Keys

    keys = User_Keys.objects.filter(username=request.user.email, key_type="FIDO2").order_by("-added_on")
    return render(request, "kura/accounts/passkeys.html", {"keys": keys})


@login_required
def passkey_register_complete_view(request):
    """
    Finishes adding a new passkey, then records it in the security log.
    Who can use it: Any authenticated user adding a passkey to their own account.
    Security: all the real checks (the FIDO2 challenge kept in the session and
    the authenticator's signature) are done by django-mfa2's own
    FIDO2.complete_reg, which this view simply calls. The library has no hook
    for "a key was added", so this wrapper sits on the same URL to add the
    auth.passkey.added audit event when the library reports success.
    """
    from mfa import FIDO2
    from mfa.models import User_Keys

    # Let django-mfa2 verify and save the new key exactly as before.
    response = FIDO2.complete_reg(request)

    # The library answers with JSON: "OK" (or "RECOVERY") means the key was saved.
    result = json.loads(response.content)
    if result.get("status") in ("OK", "RECOVERY"):
        newest_key = (
            User_Keys.objects.filter(username=request.user.username, key_type="FIDO2").order_by("-id").first()
        )
        key_id = "-"
        if newest_key:
            key_id = newest_key.id
        log_security_event(request, "auth.passkey.added", {"key_id": key_id})
    return response


@login_required
def passkey_delete_view(request, key_id):
    """
    Deletes an enrolled passkey (FIDO2 / WebAuthn key).
    Who can use it: The owner of the passkey.
    Security: Checks key belongs to request.user.email, POST only with CSRF.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    from mfa.models import User_Keys

    key = get_object_or_404(User_Keys, id=key_id, username=request.user.email)
    key.delete()
    log_security_event(request, "auth.passkey.removed", {"key_id": key_id})
    messages.success(request, "Passkey removed successfully.")
    return redirect("kura:passkey_manage")


@login_required
def logout_view(request):
    """
    Logs out the user and revokes their active session record.
    Who can use it: Authenticated users.
    Security: POST only with CSRF token to prevent forced logout attacks.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Revoke current UserSession in database.
    log_security_event(request, "auth.logout", {})
    session_id = request.session.get("user_session_id")
    if session_id:
        revoked_count = UserSession.objects.filter(id=session_id, user=request.user).update(revoked_at=timezone.now())
        if revoked_count:
            log_security_event(
                request,
                "session.revoked",
                {"target_user_id": request.user.id, "count": revoked_count, "by": "self"},
            )

    # Clear Django authentication session.
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("kura:login")


@login_required
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


@login_required
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
        log_security_event(request, "auth.password.changed", {})

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

        # At most 2 reset emails per account every 5 minutes, so nobody can flood
        # someone's inbox. Extra requests are ignored without telling the visitor.
        recent_requests = 0
        if user:
            recent_requests = PasswordResetToken.objects.filter(
                user=user, created_at__gte=timezone.now() - timezone.timedelta(minutes=5)
            ).count()

        # If the user exists, create a single-use token valid for 30 minutes.
        queued = False
        if user and recent_requests < 2:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            expires_at = timezone.now() + timezone.timedelta(minutes=30)

            reset_token = PasswordResetToken.objects.create(
                user=user,
                token_hash=token_hash,
                expires_at=expires_at,
            )

            # Put the email in the outbox instead of sending it here, so the page
            # answers just as fast whether or not the account exists. The link
            # uses the fixed SITE_URL, never the Host header the visitor sent.
            reset_url = settings.SITE_URL + reverse("kura:password_reset_confirm", kwargs={"token": raw_token})
            queued = queue_email(
                f"password-reset:{reset_token.id}",
                user.email,
                "Kura Password Reset Request",
                f"Hello,\n\nPlease reset your password using this link:\n{reset_url}\n\n"
                "This link expires in 30 minutes. If you did not ask for this, ignore this email.",
            )

        # Record only the generic outcome; never include the reset token or address.
        reason = "ok"
        if not user:
            reason = "unknown_email"
        elif recent_requests >= 2:
            reason = "rate_limited"
        log_security_event(request, "auth.password.reset_requested", {"queued": queued, "reason": reason})

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
        # The URL contains a secret token, so log only the redacted request path.
        log_security_event(request, "auth.password.reset_invalid_token", {}, logging.WARNING)
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
        sessions_revoked = UserSession.objects.filter(user=user, revoked_at__isnull=True).update(
            revoked_at=timezone.now()
        )

        # Record the account whose password changed and how many sessions were ended.
        log_security_event(
            request,
            "auth.password.reset_completed",
            {"user_id": user.id, "sessions_revoked": sessions_revoked},
        )

        messages.success(request, "Your password has been reset. Please log in with your new password.")
        return redirect("kura:login")

    return render(request, "kura/accounts/password_reset_confirm.html", {"form": form})


@login_required
def mfa_setup_view(request):
    """
    Configures TOTP authenticator app and generates backup recovery codes.
    Who can use it: Authenticated users.
    Security: Uses local qrcode library (no external calls) and shows recovery codes once.
    Only keyed hashes of the recovery codes are saved (hash_recovery_code).
    The authenticator seed is encrypted by Vault before it is saved (User.mfa_secret);
    TOTPDevice.key is only a random placeholder. If Vault is unavailable, setup stops.
"""
    form = MFAVerifyForm(request.POST or None)

    # Fetch or create the TOTP device. It keeps django-otp's confirmed flag,
    # throttling and replay state; its own "key" is a random placeholder.
    device, _ = TOTPDevice.objects.get_or_create(
        user=request.user,
        name="default",
        defaults={"confirmed": False},
    )

    try:
        # First visit: make a new 20-byte seed and save it encrypted by Vault.
        # The database only ever receives the ciphertext ("vault:v1:...").
        if not request.user.mfa_secret:
            request.user.mfa_secret = encrypt_mfa_secret(random_hex(20))
            request.user.save(update_fields=["mfa_secret"])

        # Decrypt the seed in memory only, to draw the QR code.
        seed_hex = decrypt_mfa_secret(request.user.mfa_secret)
    except ValidationError:
        # Vault is down or sealed: show the page with a warning instead of a
        # QR code (the template shows it), and answer 503 "Service Unavailable".
        return render(request, "kura/accounts/mfa_setup.html", {"form": form, "qr_code_url": None}, status=503)

    # Build the standard "otpauth://" link that authenticator apps read from the
    # QR code (Base32 seed, SHA1, 6 digits, 30-second period, issuer "Kura").
    otpauth_query = urllib.parse.urlencode(
        {
            "secret": b32encode(bytes.fromhex(seed_hex)).decode("ascii"),
            "algorithm": "SHA1",
            "digits": device.digits,
            "period": device.step,
            "issuer": "Kura",
        }
    )
    otpauth_url = f"otpauth://totp/{urllib.parse.quote('Kura:' + request.user.email)}?{otpauth_query}"

    # Generate QR code in memory as an SVG data URI.
    qr_img = qrcode.make(otpauth_url, image_factory=qrcode.image.svg.SvgPathImage)
    svg_data = qr_img.to_string().decode("utf-8")
    qr_code_data_uri = f"data:image/svg+xml;utf8,{urllib.parse.quote(svg_data)}"

    if request.method == "POST" and form.is_valid():
        code = form.cleaned_data["code"].strip()

        # Verify the user correctly entered the code from their authenticator app.
        if verify_totp_code(device, request.user, code):
            device.confirmed = True
            device.save()

            # Set mfa_enabled on the user model.
            request.user.mfa_enabled = True
            request.user.save(update_fields=["mfa_enabled"])
            log_security_event(request, "auth.mfa.setup_completed", {})

            # Create or get static device for 10 single-use recovery codes.
            static_device, _ = StaticDevice.objects.get_or_create(
                user=request.user,
                name="recovery",
                defaults={"confirmed": True},
            )
            # Remove any previous recovery tokens.
            StaticToken.objects.filter(device=static_device).delete()

            # Generate 10 new random 8-character recovery codes. The user sees the
            # codes once; the database only gets their keyed hashes.
            recovery_codes = []
            for _ in range(10):
                token_val = secrets.token_hex(4).upper()
                StaticToken.objects.create(device=static_device, token=hash_recovery_code(token_val))
                recovery_codes.append(token_val)

            # Record regeneration without ever recording the recovery codes themselves.
            log_security_event(request, "auth.recovery_codes.regenerated", {})

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


@login_required
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


@login_required
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


@login_required
def quarantine_list_view(request):
    """
    Lists uploads that ClamAV rejected and quarantined, newest first.
    Who can use it: Admins only.
    Security: checks the Admin role first; shows only details (who, when, file
    name, size, SHA-256, detection), never the file itself. There is no download.
    """
    # Only Admins may see quarantined uploads.
    if not can_manage_quarantine(request.user):
        raise PermissionDenied

    # Load the newest 200 records. defer("content") leaves the infected bytes
    # in the database: the list never needs them.
    quarantined_files = (
        QuarantinedFile.objects.select_related("uploaded_by").defer("content").order_by("-created_at")[:200]
    )
    return render(request, "kura/accounts/quarantine_list.html", {"quarantined_files": quarantined_files})


@login_required
def quarantine_delete_view(request, quarantined_file_id):
    """
    Permanently deletes one quarantined upload after an Admin has looked at it.
    Who can use it: Admins only.
    Security: POST only with CSRF token, Admin role check, explicit confirmation
    checkbox (DeleteConfirmationForm), and the deletion is written to the security log.
    """
    # Deleting changes data, so only POST is allowed.
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Only Admins may delete quarantined uploads.
    if not can_manage_quarantine(request.user):
        raise PermissionDenied

    # Load the record without its bytes, or show a 404 page.
    quarantined_file = get_object_or_404(QuarantinedFile.objects.defer("content"), id=quarantined_file_id)

    # The Admin must tick the confirmation box.
    form = DeleteConfirmationForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Tick the box to confirm the deletion.")
        return redirect("kura:quarantine_list")

    # Delete it and record who deleted which file (by hash) in the security log.
    sha256_hash = quarantined_file.sha256_hash
    quarantined_file.delete()
    log_security_event(request, "quarantine.deleted", {"sha256": sha256_hash})

    messages.success(request, "Quarantined file deleted.")
    return redirect("kura:quarantine_list")


@login_required
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


@login_required
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
        target_user_id = target.user_id
        sessions = UserSession.objects.filter(id=target.id)
    elif action == "all" and form.cleaned_data["user_id"]:
        target_user = get_object_or_404(User, id=form.cleaned_data["user_id"])
        target_user_id = target_user.id
        sessions = UserSession.objects.filter(user=target_user)
    else:
        messages.error(request, "Could not end the selected session.")
        return redirect("kura:admin_sessions")

    # Mark each active session revoked and count the rows changed by this action.
    revoked_count = 0
    for session in sessions.filter(revoked_at__isnull=True, expires_at__gt=timezone.now()):
        changed = UserSession.objects.filter(
            id=session.id,
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
        ).update(revoked_at=timezone.now())
        revoked_count += changed
    if revoked_count:
        # One event summarizes the action while keeping the affected user explicit.
        log_security_event(
            request,
            "session.revoked",
            {"target_user_id": target_user_id, "count": revoked_count, "by": "admin"},
        )
    messages.success(request, "Selected sessions ended.")
    return redirect("kura:admin_sessions")


# ==========================================
# Admin features (staff & roles)
# ==========================================


@login_required
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


@login_required
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
        room = form.cleaned_data["room"]
        office_location = str(room) if room else ""

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

        # Record only the new account ID and role names, never its temporary password.
        role_names = list(UserRole.objects.filter(user=new_user).values_list("role__name", flat=True))
        log_security_event(request, "admin.user.created", {"target_user_id": new_user.id, "roles": role_names})

        messages.success(request, f"Staff account created for {email}. Temporary password: {temporary_password}")
        return redirect("kura:staff_list")

    rooms = list(Room.objects.order_by("building__name", "name").values("id", "building_id", "name"))
    return render(request, "kura/accounts/staff_create.html", {"form": form, "office_rooms": rooms})


@login_required
def staff_settings_view(request):
    """Manage departments and office locations. Admin only; POST and form validation protect changes."""
    if not has_role(request.user, "Admin"):
        raise PermissionDenied

    # Bind only the submitted form so unrelated forms remain usable.
    kind = request.POST.get("kind") if request.method == "POST" else None
    department_form = DepartmentForm(request.POST if kind == "department" else None)
    building_form = BuildingForm(request.POST if kind == "building" else None)
    room_form = RoomForm(request.POST if kind == "room" else None)
    forms = {"department": department_form, "building": building_form, "room": room_form}
    if request.method == "POST" and kind in forms and forms[kind].is_valid():
        forms[kind].save()
        messages.success(request, "Saved successfully.")
        return redirect("kura:staff_settings")
    return render(request, "kura/accounts/staff_settings.html", {
        "department_form": department_form, "building_form": building_form, "room_form": room_form,
        "departments": Department.objects.order_by("name"),
        "buildings": Building.objects.order_by("name"),
        "rooms": Room.objects.select_related("building").order_by("building__name", "name"),
    })


@login_required
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

    # Record the account change and how many sessions were invalidated.
    log_security_event(
        request,
        "admin.user.deactivated",
        {"target_user_id": target_user.id},
        logging.WARNING,
    )

    # Tell the administrator how many sessions were ended by the deactivation.
    if ended_session_count == 1:
        session_label = "session"
    else:
        session_label = "sessions"
    messages.success(request, f"Account deactivated, {ended_session_count} {session_label} ended.")
    return redirect("kura:staff_list")


@login_required
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
        event_name = "admin.user.unlocked"
        messages.success(request, "Account unlocked.")
    else:
        target_user.locked_until = timezone.now() + timezone.timedelta(days=1)
        event_name = "admin.user.locked"
        lock_time = timezone.localtime(target_user.locked_until).strftime("%d %b, %H:%M")
        messages.success(request, f"Account locked until {lock_time}.")

    target_user.save()
    # Record the account ID but never the lock timestamp or account email.
    log_security_event(request, event_name, {"target_user_id": target_user.id}, logging.WARNING)
    return redirect("kura:staff_list")


@login_required
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
        added_roles = []
        removed_roles = []

        if action == "assign":
            # Rule: Block assigning Admin to an Instructor or Teaching Assistant.
            if target_role.name == "Admin" and any(r in ("Instructor", "Teaching assistant") for r in existing_roles):
                messages.error(request, "Separation of duty: Administrators cannot hold grading roles.")
                return redirect("kura:user_roles", user_id=target_user.id)

            # Rule: Block assigning Instructor or TA to an Administrator.
            if target_role.name in ("Instructor", "Teaching assistant") and "Admin" in existing_roles:
                messages.error(request, "Separation of duty: Administrators cannot hold grading roles.")
                return redirect("kura:user_roles", user_id=target_user.id)

            _, created = UserRole.objects.get_or_create(
                user=target_user,
                role=target_role,
                defaults={"assigned_by": request.user},
            )
            if created:
                added_roles.append(target_role.name)
            messages.success(request, f"Assigned role {target_role.name} to {target_user.email}.")

        elif action == "remove":
            deleted_count, _ = UserRole.objects.filter(user=target_user, role=target_role).delete()
            if deleted_count:
                removed_roles.append(target_role.name)
            messages.success(request, f"Removed role {target_role.name} from {target_user.email}.")

        if added_roles or removed_roles:
            log_security_event(
                request,
                "admin.role.changed",
                {"target_user_id": target_user.id, "added": added_roles, "removed": removed_roles},
                logging.WARNING,
            )
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


# ==========================================
# Registrar features (students & enrollment)
# ==========================================


@login_required
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

        # The new student's role and ID are safe audit details; do not record credentials.
        log_security_event(
            request,
            "admin.user.created",
            {"target_user_id": new_user.id, "roles": ["Student"]},
        )

        messages.success(request, f"Student account created for {email}. Temporary password: {temporary_password}")
        return redirect("kura:enrollment_list")

    return render(request, "kura/accounts/student_create.html", {"form": form})


@login_required
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


@login_required
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


@login_required
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
    for value in (f"user:{request.user.id}", f"ip:{get_client_ip(request)}"):
        key = "enrollment-search:" + hashlib.sha256(value.encode()).hexdigest() + f":{window}"
        # A short-lived lock makes the database cache's non-atomic increment safe.
        lock = key + ":lock"
        if not cache.add(lock, 1, timeout=120):
            # Log only the kind of limit; do not include the search term.
            log_security_event(request, "ratelimit.hit", {"bucket": "enrollment_search"}, logging.WARNING)
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
            # Keep the query out of logs because it may contain personal information.
            log_security_event(request, "ratelimit.hit", {"bucket": "enrollment_search"}, logging.WARNING)
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


@login_required
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


@login_required
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
            log_security_event(
                request,
                "enrollment.created",
                {"course_id": course.id, "student_id": student.id},
            )
            messages.success(request, f"Re-enrolled {student.email} in {course.code}.")
            return redirect("kura:enrollment_list")

        # Create new active enrollment record.
        Enrollment.objects.create(
            course=course,
            student=student,
            status=EnrollmentStatus.ACTIVE,
            enrolled_by=request.user,
        )
        log_security_event(request, "enrollment.created", {"course_id": course.id, "student_id": student.id})
        messages.success(request, f"Enrolled {student.email} in {course.code}.")
        return redirect("kura:enrollment_list")

    return render(request, "kura/accounts/enrollment_create.html", {"form": form})


@login_required
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
    log_security_event(
        request,
        "enrollment.dropped",
        {"course_id": enrollment.course_id, "student_id": enrollment.student_id},
    )

    messages.success(request, f"Dropped {enrollment.student.email} from {enrollment.course.code}.")
    return redirect("kura:enrollment_list")


# ==========================================
# Courses & content management
# ==========================================


@login_required
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


@login_required
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
        log_security_event(request, "admin.course.created", {"course_id": course.id})
        messages.success(request, "Course draft created.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/admin_course_form.html", {"form": form, "editing": False})


@login_required
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
        log_security_event(request, "admin.course.edited", {"course_id": course.id})
        messages.success(request, "Course updated.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/admin_course_form.html", {"form": form, "editing": True, "course": course})


@login_required
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


@login_required
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


@login_required
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
    if course.is_published:
        event_name = "admin.course.published"
    else:
        event_name = "admin.course.unpublished"
    log_security_event(request, event_name, {"course_id": course.id})
    return redirect("kura:course_detail", course_id=course.id)


@login_required
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
        log_security_event(
            request,
            "admin.staff.assigned",
            {
                "course_id": course.id,
                "target_user_id": user.id,
                "staff_role": "teaching_assistant",
                "can_release_grades": False,
            },
        )
        # Record the course assignment without recording the staff member's email.
        log_security_event(
            request,
            "admin.staff.assigned",
            {
                "course_id": course.id,
                "target_user_id": user.id,
                "staff_role": staff_role,
                "can_release_grades": can_release,
            },
        )
        messages.success(request, f"Assigned {user.email} as {staff_role} in {course.code}.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/courses/staff_assign.html", {"form": form, "course": course})


@login_required
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


@login_required
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


@login_required
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
        log_security_event(request, "course.module.deleted", {"module_id": module_id})
    messages.success(request, "Module deleted.")
    return redirect("kura:course_detail", course_id=course.id)


@login_required
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

        # If the module is visible now, tell students about its assessments.
        # Students already told (event_key) are not emailed again.
        if module.is_visible:
            for assessment in Assessment.objects.filter(section__module=module).select_related("section__module__course"):
                queue_assessment_notification(
                    assessment, "assessment-new", f"New {assessment.get_component_type_display()}: {assessment.title}",
                    "A new assessment has been published in one of your courses.",
                )
        messages.success(request, "Module updated.")
        return redirect("kura:course_detail", course_id=course.id)
    return render(request, "kura/courses/module_create.html", {"form": form, "course": course, "editing": True})


@login_required
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


@login_required
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


@login_required
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
            log_security_event(request, "course.section.hidden", {"section_id": section.id})
        else:
            section_id = section.id
            section.delete()
            log_security_event(request, "course.section.deleted", {"section_id": section_id})
            messages.success(request, "Section deleted.")
    return redirect("kura:course_detail", course_id=course.id)


@login_required
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
    log_security_event(request, "course.section.visibility_changed", {"section_id": section.id})
    messages.success(request, "Section visibility updated.")
    return redirect("kura:course_detail", course_id=course.id)


@login_required
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


@login_required
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
    log_security_event(request, "course.item.deleted", {"item_id": item_id})
    messages.success(request, "Item deleted.")
    return redirect("kura:course_detail", course_id=course.id)


@login_required
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


@login_required
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


@login_required
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


@login_required
def file_download_view(request, course_id, file_id):
    """
    Permission-checked view for downloading course material files.
    Who can use it: Enrolled students with matching academic level, assigned staff, department heads.
    Security: checks course and item release access, prevents IDOR, and uses safe download headers.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Admins cannot download course materials through another course relationship.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    course = get_object_or_404(Course, id=course_id)
    stored_file = get_object_or_404(StoredFile, id=file_id)

    # Verify this file is attached to an item in this course.
    item_file = get_object_or_404(
        SectionItemFile.objects.select_related("section_item__section__module"),
        file=stored_file,
        section_item__section__module__course=course,
    )
    # Keep the parent item so the student release state can be checked before sending its file.
    section_item = item_file.section_item
    module = item_file.section_item.section.module

    is_head = is_department_head(request.user, course.department)
    is_staff = is_course_staff(request.user, course)
    enrolled = is_enrolled(request.user, course)

    # Access check: staff/head or actively enrolled student.
    if not (is_head or is_staff or (enrolled and course.is_published and module.is_visible)):
        raise PermissionDenied

    # Students can download an item's file only after the item is visible and its release time passes.
    if not (is_head or is_staff):
        if not section_item.section.is_visible:
            raise PermissionDenied
        if not section_item.is_visible:
            raise PermissionDenied
        if section_item.released_at and section_item.released_at > timezone.now():
            raise PermissionDenied

    # For students, enforce academic target level requirements.
    if not (is_head or is_staff):
        student_profile = StudentProfile.objects.filter(user=request.user).first()
        student_level = None
        if student_profile:
            student_level = student_profile.current_level
        target_levels = list(module.target_levels.values_list("target_level", flat=True))
        if target_levels and (not student_level or student_level not in target_levels):
            raise PermissionDenied

    # Record the permitted course-file download without logging its filename or contents.
    log_security_event(
        request,
        "file.downloaded",
        {"file_id": stored_file.id, "sha256": stored_file.sha256_hash, "context": "course"},
    )
    return create_download_response(stored_file)


# ==========================================
# Schedules & attendance
# ==========================================


@login_required
def schedule_list_view(request):
    """
    Displays the academic meeting schedule and timetable.
    Who can use it: Students (enrolled courses), Staff (assigned courses), Department Heads.
    Security: Only shows meeting slots for courses the user is permitted to see.
"""
    if has_role(request.user, "Department head"):
        dept_ids = Department.objects.filter(head_user=request.user).values_list("id", flat=True)
        schedules = Schedule.objects.filter(course__department_id__in=dept_ids)
    elif has_role(request.user, "Instructor") or has_role(request.user, "Teaching assistant"):
        # Only assignments matching the user's current roles grant schedule access.
        staff_roles = []
        if has_role(request.user, "Instructor"):
            staff_roles.extend(["lead_instructor", "co_instructor"])
        if has_role(request.user, "Teaching assistant"):
            staff_roles.append("teaching_assistant")
        staff_courses = CourseStaff.objects.filter(user=request.user, staff_role__in=staff_roles).values_list(
            "course_id", flat=True
        )
        schedules = Schedule.objects.filter(course_id__in=staff_courses)
    elif has_role(request.user, "Student"):
        enrolled_courses = Enrollment.objects.filter(student=request.user, status=EnrollmentStatus.ACTIVE).values_list(
            "course_id", flat=True
        )
        schedules = Schedule.objects.filter(course_id__in=enrolled_courses, course__is_published=True)
    else:
        schedules = Schedule.objects.filter(course__is_published=True)

    schedules = schedules.select_related("course", "instructor").order_by("day", "start_time")
    # Show edit controls only for courses this non-admin user is assigned to or heads.
    # Recheck each schedule's exact course before displaying management controls.
    headed_department_ids = set(Department.objects.filter(head_user=request.user).values_list("id", flat=True))
    is_admin = is_admin_course_manager(request.user)
    is_head = has_role(request.user, "Department head")
    for schedule in schedules:
        schedule.can_manage = not is_admin and (
            is_course_staff(request.user, schedule.course)
            or (is_head and schedule.course.department_id in headed_department_ids)
        )
    return render(request, "kura/attendance/schedule_list.html", {"schedules": schedules})


@login_required
def schedule_create_view(request, course_id):
    """
    Creates a recurring meeting schedule for a course.
    Who can use it: Course instructors and Department Heads.
    Security: Enforces course staff assignment; validates end_time > start_time.
"""
    course = get_object_or_404(Course, id=course_id)

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = ScheduleForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        Schedule.objects.create(
            course=course,
            instructor=form.cleaned_data["instructor"],
            session_type=form.cleaned_data["session_type"],
            day=form.cleaned_data["day"],
            start_time=form.cleaned_data["start_time"],
            end_time=form.cleaned_data["end_time"],
            location=form.cleaned_data["location"],
            recurrence_start=form.cleaned_data["recurrence_start"],
            recurrence_end=form.cleaned_data["recurrence_end"],
            created_by=request.user,
        )
        messages.success(request, f"Class schedule created for {course.code}.")
        return redirect("kura:course_detail", course_id=course.id)

    return render(request, "kura/attendance/schedule_create.html", {"form": form, "course": course})


@login_required
def schedule_edit_view(request, schedule_id):
    """
    Edits a recurring course schedule.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: Checks the exact course and validates every field before saving.
"""
    # Only authorized staff may edit this course's schedule.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    schedule = get_object_or_404(Schedule.objects.select_related("course__department"), id=schedule_id)
    course = schedule.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    initial = {
        "instructor": schedule.instructor_id,
        "session_type": schedule.session_type,
        "day": schedule.day,
        "start_time": schedule.start_time,
        "end_time": schedule.end_time,
        "location": schedule.location,
        "recurrence_start": schedule.recurrence_start,
        "recurrence_end": schedule.recurrence_end,
    }
    form = ScheduleForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        # Copy only validated, explicitly allowed fields into the existing schedule.
        schedule.instructor = form.cleaned_data["instructor"]
        schedule.session_type = form.cleaned_data["session_type"]
        schedule.day = form.cleaned_data["day"]
        schedule.start_time = form.cleaned_data["start_time"]
        schedule.end_time = form.cleaned_data["end_time"]
        schedule.location = form.cleaned_data["location"]
        schedule.recurrence_start = form.cleaned_data["recurrence_start"]
        schedule.recurrence_end = form.cleaned_data["recurrence_end"]
        schedule.save()
        messages.success(request, "Schedule updated.")
        return redirect("kura:schedule_list")
    return render(request, "kura/attendance/schedule_create.html", {"form": form, "course": course, "editing": True})


@login_required
def schedule_delete_view(request, schedule_id):
    """
    Deletes a schedule without deleting attendance sessions.
    Who can use it: Assigned staff and the department head, except Admins.
    Security: Requires POST, confirmation, course permission, and deletion logging.
"""
    # Verify permission and require confirmation before changing the schedule.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    schedule = get_object_or_404(Schedule.objects.select_related("course__department"), id=schedule_id)
    course = schedule.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if not DeleteConfirmationForm(request.POST).is_valid():
        messages.error(request, "Confirm schedule deletion first.")
        return redirect("kura:schedule_list")
    # Attendance sessions remain recorded; Django clears their optional schedule link.
    schedule.delete()
    log_security_event(request, "course.schedule.deleted", {"schedule_id": schedule_id})
    messages.success(request, "Schedule deleted.")
    return redirect("kura:schedule_list")


@login_required
def attendance_session_start_view(request, module_id):
    """
    Launches a live attendance check-in session with a rotating passcode and QR code.
    Who can use it: Course instructors and Teaching Assistants.
    Security: Server generates random 6-character passcode and stores only its SHA-256 hash.
"""
    module = get_object_or_404(Module.objects.select_related("course"), id=module_id)
    course = module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = AttendanceSessionStartForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        title = form.cleaned_data["title"]
        duration = form.cleaned_data["duration_minutes"]

        # Generate a random 6-character passcode.
        raw_passcode = secrets.token_hex(3).upper()
        passcode_hash = hashlib.sha256(raw_passcode.encode("utf-8")).hexdigest()
        expires_at = timezone.now() + timezone.timedelta(minutes=duration)

        session = ModuleAttendanceSession.objects.create(
            module=module,
            created_by=request.user,
            title=title,
            passcode_hash=passcode_hash,
            expires_at=expires_at,
            is_active=True,
        )

        # Store raw passcode in request session temporarily to display on projector screen.
        request.session[f"session_passcode_{session.id}"] = raw_passcode

        messages.success(request, f"Attendance roll started for {title}.")
        return redirect("kura:attendance_session_detail", session_id=session.id)

    return render(request, "kura/attendance/session_start.html", {"form": form, "module": module})


@login_required
def attendance_session_detail_view(request, session_id):
    """
    Displays live attendance roll for staff, including active passcode and QR code.
    Who can use it: Course staff and Department Heads.
    Security: Live roll monitor displaying real-time check-in records.
"""
    session = get_object_or_404(
        ModuleAttendanceSession.objects.select_related("module__course__department"),
        id=session_id,
    )
    course = session.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    # Check if session is still unexpired and active.
    is_live = session.is_active and session.expires_at > timezone.now()

    # Retrieve temporary raw passcode from staff session if available.
    passcode = None
    if is_live:
        passcode = request.session.get(f"session_passcode_{session.id}")

    # Generate QR code URL if session is live and passcode is known.
    qr_code_data_uri = None
    if is_live and passcode:
        checkin_url = request.build_absolute_uri(
            reverse("kura:student_checkin", kwargs={"session_id": session.id}) + f"?code={passcode}"
        )
        qr_img = qrcode.make(checkin_url, image_factory=qrcode.image.svg.SvgPathImage)
        svg_data = qr_img.to_string().decode("utf-8")
        qr_code_data_uri = f"data:image/svg+xml;utf8,{urllib.parse.quote(svg_data)}"

    # Load recorded attendance entries.
    records = (
        AttendanceRecord.objects.filter(session=session)
        .select_related("student", "recorded_by")
        .order_by("-verified_at")
    )
    manual_form = ManualAttendanceForm()

    context = {
        "session": session,
        "is_live": is_live,
        "passcode": passcode,
        "qr_code_url": qr_code_data_uri,
        "records": records,
        "manual_form": manual_form,
    }
    return render(request, "kura/attendance/session_detail.html", context)


@login_required
def attendance_session_close_view(request, session_id):
    """
    Closes an active attendance check-in session immediately.
    Who can use it: Course staff and Department Heads.
    Security: POST only; marks is_active=False.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    session = get_object_or_404(ModuleAttendanceSession.objects.select_related("module__course"), id=session_id)
    course = session.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    session.is_active = False
    session.save(update_fields=["is_active"])

    messages.success(request, f"Attendance roll closed for {session.title}.")
    return redirect("kura:attendance_session_detail", session_id=session.id)


@login_required
def student_checkin_view(request, session_id):
    """
    Student attendance check-in using a dynamic passcode or QR scan.
    Who can use it: Enrolled students.
    Security: Validates passcode hash, expiry, enrollment, single check-in, and sets method on server.
"""
    session = get_object_or_404(
        ModuleAttendanceSession.objects.select_related("module__course"),
        id=session_id,
    )
    course = session.module.course

    # Verify student is actively enrolled in the course.
    if not is_enrolled(request.user, course):
        raise PermissionDenied

    # Verify session is currently active and unexpired.
    if not session.is_active or session.expires_at <= timezone.now():
        messages.error(request, "This attendance session is closed or has expired.")
        return redirect("kura:attendance_history")

    # Check if student already checked in (enforce one record per student per session).
    if AttendanceRecord.objects.filter(session=session, student=request.user).exists():
        messages.warning(request, "You have already checked in for this attendance session.")
        return redirect("kura:attendance_history")

    # Check if passcode was provided in QR code URL query parameter.
    qr_code_param = request.GET.get("code")
    initial_code = ""
    if qr_code_param:
        initial_code = qr_code_param.strip().upper()

    # Scanning a QR code pre-fills the form, but does not record attendance on GET.
    form = StudentCheckinForm(request.POST or None, initial={"passcode": initial_code})

    if request.method == "POST":
        if form.is_valid():
            submitted_code = form.cleaned_data["passcode"].strip().upper()
            submitted_hash = hashlib.sha256(submitted_code.encode("utf-8")).hexdigest()

            # Verify passcode matches.
            if submitted_hash != session.passcode_hash:
                messages.error(request, "Invalid attendance passcode.")
                return render(request, "kura/attendance/checkin.html", {"form": form, "session": session})

            # Server sets check-in method: QR_CODE if scanned via query param, otherwise PASSCODE.
            if qr_code_param:
                method = AttendanceMethod.QR_CODE
            else:
                method = AttendanceMethod.PASSCODE
            client_ip = get_client_ip(request)

            # Create attendance record.
            AttendanceRecord.objects.create(
                session=session,
                student=request.user,
                status=AttendanceStatus.PRESENT,
                method=method,
                ip_address=client_ip,
            )

            messages.success(request, f"Attendance verified for {session.title}!")
            return redirect("kura:attendance_history")

    return render(request, "kura/attendance/checkin.html", {"form": form, "session": session})


@login_required
def attendance_manual_record_view(request, session_id):
    """
    Manually logs or adjusts an attendance entry with a required written justification.
    Who can use it: Course instructors and Teaching Assistants.
    Security: Server sets method=manual, records staff ID, and enforces non-empty override_reason.
"""
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    session = get_object_or_404(ModuleAttendanceSession.objects.select_related("module__course"), id=session_id)
    course = session.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = ManualAttendanceForm(request.POST)

    if form.is_valid():
        student = form.cleaned_data["student"]
        status = form.cleaned_data["status"]
        override_reason = form.cleaned_data["override_reason"]

        # A course attendance roll cannot contain an unrelated student.
        if not is_enrolled(student, course):
            messages.error(request, "Unable to record attendance for this student.")
            return redirect("kura:attendance_session_detail", session_id=session.id)

        AttendanceRecord.objects.update_or_create(
            session=session,
            student=student,
            defaults={
                "status": status,
                "method": AttendanceMethod.MANUAL,
                "recorded_by": request.user,
                "override_reason": override_reason,
            },
        )
        messages.success(request, f"Manual attendance recorded for {student.email}.")
    else:
        messages.error(request, "A written justification reason is required for manual roll entries.")

    return redirect("kura:attendance_session_detail", session_id=session.id)


@login_required
def attendance_history_view(request):
    """
    Displays attendance records.
    Who can use it: Students (own records only), Staff (assigned courses).
    Security: IDOR protection; students are strictly restricted to their own attendance entries.
"""
    if has_role(request.user, "Student"):
        # Students strictly see only their own attendance records.
        records = (
            AttendanceRecord.objects.filter(
                student=request.user,
            )
            .select_related("session__module__course")
            .order_by("-verified_at")
        )
        is_staff_view = False
    else:
        # Staff see records for their taught courses.
        # Stale staff assignments must not reveal student attendance.
        staff_roles = []
        if has_role(request.user, "Instructor"):
            staff_roles.extend(["lead_instructor", "co_instructor"])
        if has_role(request.user, "Teaching assistant"):
            staff_roles.append("teaching_assistant")
        staff_courses = CourseStaff.objects.filter(user=request.user, staff_role__in=staff_roles).values_list(
            "course_id", flat=True
        )
        records = (
            AttendanceRecord.objects.filter(
                session__module__course_id__in=staff_courses,
            )
            .select_related("student", "session__module__course", "recorded_by")
            .order_by("-verified_at")
        )
        is_staff_view = True

    return render(
        request,
        "kura/attendance/history.html",
        {
            "records": records,
            "is_staff_view": is_staff_view,
        },
    )


# ==========================================
# Assessments, attempts & grading
# ==========================================


def evaluate_attempt(attempt):
    """
    Evaluates student assessment responses against the isolated exam answer key.
    Auto-grades multiple choice and matching questions; flags essays for manual grading.
    Updates summary_score_json, status, and creates/updates a draft Grade record.
    """
    # Scanned papers are never automatically marked as a zero-point online exam.
    if attempt.assessment.delivery_mode == AssessmentDeliveryMode.PAPER_SCANNED:
        attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
        attempt.summary_score_json = None
        attempt.save(update_fields=["status", "summary_score_json", "submitted_at", "submission_hash"])
        return

    # Load the answer key; Vault decrypts it in memory only. If Vault cannot be
    # reached, the submission is still kept (its time and hash are already set)
    # and goes to the instructor for manual grading, instead of failing or
    # being marked as zero.
    answer_key_obj = ExamAnswerKey.objects.filter(assessment=attempt.assessment).first()
    answer_key_dict = {}
    if answer_key_obj:
        try:
            answer_key_dict = decrypt_answer_key(answer_key_obj.answer_key_json)
        except ValidationError:
            log_security_event(None, "assessment.answer_key_unavailable", {"attempt_id": attempt.id}, logging.ERROR)
            attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
            attempt.summary_score_json = None
            attempt.save(update_fields=["status", "summary_score_json", "submitted_at", "submission_hash"])
            return

    auto_graded_points = Decimal("0.00")
    total_max_points = Decimal("0.00")
    has_manual_questions = False

    answers = attempt.answers_json or []
    answers_by_id = {ans.get("question_id"): ans for ans in answers}

    updated_answers = []
    questions = attempt.assessment.questions_json or []

    for q in questions:
        q_id = q.get("question_id")
        q_type = q.get("type")
        q_points = Decimal(str(q.get("points", 0)))
        total_max_points += q_points

        student_ans = answers_by_id.get(q_id, {"question_id": q_id, "type": q_type})
        key_data = answer_key_dict.get(q_id, {})

        if q_type == "multiple_choice":
            correct_opts = set(key_data.get("correct_option_ids", []))
            selected_opts = set(student_ans.get("selected_option_ids", []))
            is_correct = bool(correct_opts and correct_opts == selected_opts)
            points_awarded = Decimal("0.00")
            if is_correct:
                points_awarded = q_points
            auto_graded_points += points_awarded

            student_ans["auto_evaluation"] = {
                "is_correct": is_correct,
                "points_awarded": float(points_awarded),
            }
            updated_answers.append(student_ans)

        elif q_type == "matching":
            correct_pairs = key_data.get("correct_pairs", {})
            submitted_matches = student_ans.get("submitted_matches", [])
            total_pairs = len(correct_pairs)

            matched_count = 0
            counted_pairs = set()
            for item in submitted_matches:
                p_id = item.get("pair_id")
                chosen_val = item.get("selected_match")
                # Old attempts may contain duplicate or unknown pair IDs; count each correct pair once.
                if p_id in correct_pairs and p_id not in counted_pairs and correct_pairs[p_id] == chosen_val:
                    matched_count += 1
                    counted_pairs.add(p_id)

            if total_pairs > 0:
                fraction = Decimal(matched_count) / Decimal(total_pairs)
                points_awarded = (q_points * fraction).quantize(Decimal("0.01"))
            else:
                points_awarded = Decimal("0.00")

            auto_graded_points += points_awarded
            student_ans["auto_evaluation"] = {
                "matched_count": matched_count,
                "total_pairs": total_pairs,
                "points_awarded": float(points_awarded),
            }
            updated_answers.append(student_ans)

        else:
            # Long essay or written response requires manual instructor grading.
            has_manual_questions = True
            updated_answers.append(student_ans)

    attempt.answers_json = updated_answers

    if has_manual_questions:
        attempt.status = AttemptStatus.REQUIRES_MANUAL_GRADING
        is_fully_graded = False
    else:
        attempt.status = AttemptStatus.FULLY_GRADED
        is_fully_graded = True

    attempt.summary_score_json = {
        "auto_graded_points": float(auto_graded_points),
        "manual_graded_points": 0.0,
        "total_score": float(auto_graded_points),
        "max_possible_points": float(total_max_points),
        "is_fully_graded": is_fully_graded,
    }
    attempt.save()

    # If fully auto-graded, create or update a draft grade record.
    if is_fully_graded:
        Grade.objects.update_or_create(
            assessment=attempt.assessment,
            student=attempt.student,
            defaults={
                "attempt": attempt,
                "score": auto_graded_points,
                "status": GradeStatus.DRAFT,
            },
        )


@login_required
def assessment_create_view(request, section_id=None, assessment_id=None):
    """
    Creates or edits an assessment and separates questions from its answer key.
    Who can use it: Assigned course staff and the department head, but not Admins.
    Security: Checks the course, locks edits after attempts, and saves the question and key together.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access assessments, even if assigned to the course.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    # An edit belongs to its existing section; a new assessment uses the requested section.
    assessment = None
    if assessment_id:
        assessment = get_object_or_404(
            Assessment.objects.select_related("section__module__course__department"),
            id=assessment_id,
        )
        section = assessment.section
    else:
        section = get_object_or_404(
            ModuleSection.objects.select_related("module__course__department"),
            id=section_id,
        )
    course = section.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    # Prepare ordinary form fields from the existing assessment and its separate key.
    initial = {}
    initial_questions = [{"type": "multiple_choice", "max_words": 500}]
    existing_keys = {}
    builder_unavailable = False
    questions_locked = False
    if assessment:
        questions_locked = AssessmentAttempt.objects.filter(assessment=assessment).exists()
        initial = {
            "title": assessment.title,
            "description": assessment.description,
            "component_type": assessment.component_type,
            "delivery_mode": assessment.delivery_mode,
            "max_score": assessment.max_score,
            "max_attempts": assessment.max_attempts,
            "opens_at": assessment.opens_at,
            "due_date": assessment.due_date,
            "duration_minutes": assessment.duration_minutes,
            "lab_cidr_allowed": assessment.lab_cidr_allowed,
            "shuffle_questions": assessment.settings_json.get("shuffle_questions", False),
            "shuffle_options": assessment.settings_json.get("shuffle_options", False),
            "allow_backtracking": assessment.settings_json.get("allow_backtracking", False),
            "autosave_interval_seconds": assessment.settings_json.get("autosave_interval_seconds", 15),
        }
        # Decrypt the saved answer key (in memory only) so the form can show it.
        # If Vault cannot be reached the edit page is not shown, because saving
        # it without the old key would wipe the correct answers.
        answer_key = ExamAnswerKey.objects.filter(assessment=assessment).first()
        existing_keys = {}
        if answer_key:
            try:
                existing_keys = decrypt_answer_key(answer_key.answer_key_json)
            except ValidationError:
                messages.error(request, "This assessment cannot be edited right now. Please try again later.")
                return redirect("kura:assessment_detail", assessment_id=assessment.id)
        initial_questions = []
        if len(assessment.questions_json) > 20:
            builder_unavailable = True
        for question in assessment.questions_json:
            key = existing_keys.get(question.get("question_id"), {})
            question_type = question.get("type")
            if question_type == "essay":
                question_type = "long_text"
            values = {
                "type": question_type,
                "prompt": question.get("prompt", ""),
                "points": question.get("points"),
                "max_words": question.get("max_words", 500),
            }
            if question_type == "multiple_choice":
                options = question.get("options", [])
                if len(options) > 8:
                    builder_unavailable = True
                for number, option in enumerate(options[:8], start=1):
                    values[f"option_{number}"] = option.get("text", "")
                    values[f"correct_{number}"] = option.get("option_id") in key.get("correct_option_ids", [])
                values["explanation"] = key.get("explanation", "")
            elif question_type == "matching":
                pairs = question.get("left_prompts", [])
                if len(pairs) > 8:
                    builder_unavailable = True
                used_matches = []
                for number, pair in enumerate(pairs[:8], start=1):
                    match = key.get("correct_pairs", {}).get(pair.get("pair_id"), "")
                    values[f"left_{number}"] = pair.get("text", "")
                    values[f"right_{number}"] = match
                    used_matches.append(match)
                extra_matches = []
                for match in question.get("available_matches", []):
                    if match not in used_matches:
                        extra_matches.append(match)
                values["extra_matches"] = "\n".join(extra_matches)
            elif question_type == "long_text":
                criteria = key.get("tutor_rubric", {}).get("criteria", [])
                descriptions = []
                for criterion in criteria:
                    descriptions.append(criterion.get("criterion") or criterion.get("name", ""))
                values["rubric"] = "\n".join(descriptions)
            else:
                builder_unavailable = True
            initial_questions.append(values)

    question_editing_disabled = questions_locked or builder_unavailable

    # The locked page accepts only title, instructions, and dates, even for forged POSTs.
    form = AssessmentCreateForm(request.POST or None, initial=initial)
    if question_editing_disabled:
        for name, field in form.fields.items():
            if name not in ("title", "description", "opens_at", "due_date"):
                field.disabled = True
    question_data = None
    if request.method == "POST" and not question_editing_disabled:
        question_data = request.POST
    question_forms = AssessmentQuestionFormSet(question_data, prefix="questions", initial=initial_questions)
    if request.method == "POST" and form.is_valid():
        delivery_mode = form.cleaned_data["delivery_mode"] or AssessmentDeliveryMode.ONLINE
        if question_editing_disabled:
            questions_valid = True
        elif delivery_mode == AssessmentDeliveryMode.PAPER_SCANNED:
            questions_valid = True
        else:
            questions_valid = question_forms.is_valid()

        if questions_valid and not question_editing_disabled and delivery_mode == AssessmentDeliveryMode.ONLINE:
            has_active_question = False
            total_points = Decimal("0")
            for data in question_forms.cleaned_data:
                if data and not data.get("DELETE"):
                    has_active_question = True
                    total_points += data["points"]

            if not has_active_question:
                form.add_error(None, "Add at least one online question.")
                questions_valid = False
            elif total_points > form.cleaned_data["max_score"]:
                # The combined question points must not exceed the assessment's maximum score.
                form.add_error("max_score", "Maximum score cannot be less than the total question points.")
                questions_valid = False
        if questions_valid:
            # Build separate documents; only explicitly chosen fields enter student-visible questions.
            questions = []
            answer_keys = {}
            if not question_editing_disabled and delivery_mode == AssessmentDeliveryMode.ONLINE:
                for question_form in question_forms.ordered_forms:
                    index = question_forms.forms.index(question_form)
                    data = question_form.cleaned_data
                    if not data or data.get("DELETE"):
                        continue
                    question_id = f"q_{uuid.uuid4().hex}"
                    question = {
                        "question_id": question_id,
                        "type": data["type"],
                        "prompt": data["prompt"],
                        "points": float(data["points"]),
                    }
                    if data["type"] == "multiple_choice":
                        question["options"] = []
                        correct_options = []
                        for number in range(1, 9):
                            option = data.get(f"option_{number}")
                            if option:
                                option_id = f"opt_{number}"
                                question["options"].append({"option_id": option_id, "text": option})
                                if data.get(f"correct_{number}"):
                                    correct_options.append(option_id)
                        answer_keys[question_id] = {
                            "correct_option_ids": correct_options,
                            "explanation": data.get("explanation", ""),
                        }
                    elif data["type"] == "matching":
                        question["left_prompts"] = []
                        question["available_matches"] = []
                        correct_pairs = {}
                        for number in range(1, 9):
                            if data.get(f"left_{number}"):
                                pair_id = f"pair_{number}"
                                question["left_prompts"].append({"pair_id": pair_id, "text": data[f"left_{number}"]})
                                if data[f"right_{number}"] not in question["available_matches"]:
                                    question["available_matches"].append(data[f"right_{number}"])
                                correct_pairs[pair_id] = data[f"right_{number}"]
                        for match in data.get("extra_matches", "").splitlines():
                            match = match.strip()
                            if match and match not in question["available_matches"]:
                                question["available_matches"].append(match)
                        # Alphabetical order does not reveal which left item matches which answer.
                        question["available_matches"].sort()
                        answer_keys[question_id] = {"correct_pairs": correct_pairs}
                    else:
                        question["max_words"] = data["max_words"]
                        criteria = []
                        for line in data["rubric"].splitlines():
                            if line.strip():
                                criteria.append({"criterion": line.strip()})
                        # Preserve existing detailed marking criteria when their text was not changed.
                        rubric = {}
                        if (
                            assessment
                            and index < len(initial_questions)
                            and data["rubric"] == initial_questions[index].get("rubric", "")
                        ):
                            old_id = assessment.questions_json[index].get("question_id")
                            old_rubric = existing_keys.get(old_id, {}).get("tutor_rubric", {})
                            rubric = old_rubric.copy()
                            criteria = old_rubric.get("criteria", criteria)
                        rubric["max_words"] = data["max_words"]
                        rubric["criteria"] = criteria
                        answer_keys[question_id] = {"tutor_rubric": rubric}
                    questions.append(question)

            # Save both documents together so an assessment never has a half-written key.
            raw_proctor = form.cleaned_data["proctor_code"]
            settings_doc = {}
            for name in (
                "shuffle_questions",
                "shuffle_options",
                "allow_backtracking",
                "autosave_interval_seconds",
            ):
                settings_doc[name] = form.cleaned_data[name]
            # Remember whether this is new, and the old dates, for the notifications below.
            is_new_assessment = assessment is None
            old_dates = None
            if assessment:
                old_dates = (assessment.opens_at, assessment.due_date)
            # Encrypt the answer key with Vault before saving anything. If Vault is
            # down, nothing is saved and the form is shown again with what was typed.
            stored_answer_keys = {}
            if not question_editing_disabled:
                try:
                    stored_answer_keys = encrypt_answer_key(answer_keys)
                except ValidationError:
                    form.add_error(None, "The answer key could not be saved securely right now. Please try again later.")
                    return render(
                        request,
                        "kura/assessments/assessment_create.html",
                        {
                            "form": form,
                            "section": section,
                            "question_forms": question_forms,
                            "assessment": assessment,
                            "questions_locked": questions_locked,
                            "builder_unavailable": builder_unavailable,
                        },
                    )
            with transaction.atomic():
                if assessment:
                    # A student start takes this same lock, so an attempt cannot slip past this check.
                    assessment = Assessment.objects.select_for_update().get(id=assessment.id)
                    if not questions_locked and AssessmentAttempt.objects.filter(assessment=assessment).exists():
                        messages.error(request, "Questions are locked because students have started.")
                        return redirect("kura:assessment_edit", assessment_id=assessment.id)
                else:
                    assessment = Assessment(section=section, created_by=request.user)
                assessment.title = form.cleaned_data["title"]
                assessment.description = form.cleaned_data["description"]
                assessment.opens_at = form.cleaned_data["opens_at"]
                assessment.due_date = form.cleaned_data["due_date"]
                if not question_editing_disabled:
                    assessment.component_type = form.cleaned_data["component_type"]
                    assessment.delivery_mode = delivery_mode
                    assessment.max_score = form.cleaned_data["max_score"]
                    assessment.max_attempts = form.cleaned_data["max_attempts"]
                    assessment.duration_minutes = form.cleaned_data["duration_minutes"]
                    assessment.settings_json = settings_doc
                    assessment.questions_json = questions
                    assessment.lab_cidr_allowed = form.cleaned_data["lab_cidr_allowed"] or None
                    if raw_proctor:
                        assessment.proctor_code_hash = hashlib.sha256(raw_proctor.encode("utf-8")).hexdigest()
                assessment.save()
                if not question_editing_disabled:
                    ExamAnswerKey.objects.update_or_create(
                        assessment=assessment,
                        defaults={"answer_key_json": stored_answer_keys},
                        create_defaults={"answer_key_json": stored_answer_keys, "created_by": request.user},
                    )
            # Email the enrolled students: a new assessment, or its dates moved.
            # The dates are part of the event name, so each change is emailed once.
            new_dates = (assessment.opens_at, assessment.due_date)
            if is_new_assessment:
                event_name = "assessment.created"
            else:
                event_name = "assessment.edited"
            log_security_event(
                request,
                event_name,
                {
                    "assessment_id": assessment.id,
                    "component_type": assessment.component_type,
                    "dates_changed": old_dates != new_dates if old_dates else False,
                },
            )
            if is_new_assessment:
                queue_assessment_notification(
                    assessment, "assessment-new", f"New {assessment.get_component_type_display()}: {assessment.title}",
                    "A new assessment has been published in one of your courses.",
                )
            elif old_dates != new_dates:
                queue_assessment_notification(
                    assessment,
                    f"assessment-dates-{int(new_dates[0].timestamp())}-{int(new_dates[1].timestamp())}",
                    f"Dates changed: {assessment.title}",
                    "The opening or due date of an assessment has changed. The new dates are below.",
                )
            messages.success(request, "Assessment saved.")
            return redirect("kura:assessment_detail", assessment_id=assessment.id)

    return render(
        request,
        "kura/assessments/assessment_create.html",
        {
            "form": form,
            "section": section,
            "question_forms": question_forms,
            "assessment": assessment,
            "questions_locked": questions_locked,
            "builder_unavailable": builder_unavailable,
        },
    )


@login_required
def assessment_question_form_view(request, section_id):
    """
    Returns one blank question card for the assessment builder.
    Who can use it: Assigned course staff and the department head, but not Admins.
    Security: Checks access to the exact section and validates the form index and type.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Prevent Admins and unrelated users from accessing assessment authoring.
    if has_role(request.user, "Admin"):
        raise PermissionDenied
    section = get_object_or_404(ModuleSection.objects.select_related("module__course__department"), id=section_id)
    course = section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    # Limit both the selected type and index before rendering a new card.
    add_form = AssessmentQuestionAddForm(
        {"type": request.GET.get("type"), "index": request.GET.get("questions-TOTAL_FORMS")}
    )
    if not add_form.is_valid():
        return HttpResponse("Unable to add another question.", status=400)
    index = add_form.cleaned_data["index"]
    initial = [{} for unused in range(index)]
    initial.append({"type": add_form.cleaned_data["type"], "max_words": 500})
    question_form = AssessmentQuestionFormSet(prefix="questions", initial=initial).forms[index]
    return render(
        request,
        "kura/assessments/_question_form.html",
        {
            "question_form": question_form,
            "new_total": index + 1,
        },
    )


@login_required
def assessment_delete_view(request, assessment_id):
    """
    Deletes an assessment only if no student has started it.
    Who can use it: Assigned course staff and the department head, except Admins.
    Security: Requires POST, confirmation, course permission, and a lock against new attempts.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Check the role, method, and exact course before handling the confirmation.
    if is_admin_course_manager(request.user):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    assessment = get_object_or_404(
        Assessment.objects.select_related("section__module__course__department"), id=assessment_id
    )
    course = assessment.section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if not DeleteConfirmationForm(request.POST).is_valid():
        messages.error(request, "Confirm assessment deletion first.")
        return redirect("kura:assessment_detail", assessment_id=assessment.id)
    # Share the start-attempt lock to ensure attempts cannot be deleted by a race.
    with transaction.atomic():
        assessment = Assessment.objects.select_for_update().get(id=assessment.id)
        if AssessmentAttempt.objects.filter(assessment=assessment).exists():
            messages.error(request, "This assessment has attempts and cannot be deleted.")
            return redirect("kura:assessment_detail", assessment_id=assessment.id)
        assessment_id = assessment.id
        assessment.delete()
        log_security_event(
            request,
            "assessment.deleted",
            {"assessment_id": assessment_id, "component_type": assessment.component_type, "dates_changed": False},
        )
    messages.success(request, "Assessment deleted.")
    return redirect("kura:course_detail", course_id=course.id)


@login_required
def assessment_detail_view(request, assessment_id):
    """
    Displays assessment overview, materials, and student attempt status.
    Who can use it: Enrolled students, Course staff, Department Heads.
    Security: Restricts view to authorized course members; shows student only their own attempts.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access assessments, even if assigned to the course.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    assessment = get_object_or_404(
        Assessment.objects.select_related("section__module__course__department"),
        id=assessment_id,
    )
    course = assessment.section.module.course

    is_head = is_department_head(request.user, course.department)
    is_staff = is_course_staff(request.user, course)
    enrolled = is_enrolled(request.user, course)

    if not (is_head or is_staff or enrolled):
        raise PermissionDenied
    if not (is_head or is_staff) and not assessment.section.is_visible:
        raise PermissionDenied

    now = timezone.now()
    is_open = assessment.opens_at <= now <= assessment.due_date

    # Load attempts: staff sees all, students see strictly their own attempts.
    if is_head or is_staff:
        attempts = (
            AssessmentAttempt.objects.filter(assessment=assessment).select_related("student").order_by("-started_at")
        )
        user_attempts_count = 0
        can_start_attempt = False
    else:
        attempts = AssessmentAttempt.objects.filter(assessment=assessment, student=request.user).order_by("-started_at")
        user_attempts_count = attempts.count()
        can_start_attempt = is_open and (user_attempts_count < assessment.max_attempts)

    # Load attached files.
    attached_files = AssessmentFile.objects.filter(assessment=assessment).select_related("file")
    start_form = AssessmentAttemptStartForm()
    file_upload_form = AssessmentFileUploadForm()
    scanned_upload_form = ScannedPaperStaffUploadForm()
    if is_head or is_staff:
        # Only active students enrolled in this course may be selected for a scanned script.
        scanned_upload_form.fields["student"].queryset = (
            User.objects.filter(
                is_active=True,
                enrollments__course=course,
                enrollments__status=EnrollmentStatus.ACTIVE,
                user_roles__role__name="Student",
            )
            .exclude(user_roles__role__name="Admin")
            .distinct()
        )

    context = {
        "assessment": assessment,
        "is_staff": is_head or is_staff,
        "is_open": is_open,
        "attempts": attempts,
        "attached_files": attached_files,
        "can_start_attempt": can_start_attempt,
        "start_form": start_form,
        "file_upload_form": file_upload_form,
        "scanned_upload_form": scanned_upload_form,
    }
    return render(request, "kura/assessments/assessment_detail.html", context)


@login_required
def scanned_paper_staff_upload_view(request, assessment_id):
    """
    Submits a scanned script on behalf of an enrolled student for manual marking.
    Who can use it: Assigned course staff and the course's department head, not Admins.
    Security: POST and CSRF, validates student enrollment and scanned file type, and saves atomically.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Reject administrators and non-POST requests before accessing assessment content.
    if has_role(request.user, "Admin"):
        raise PermissionDenied
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])
    assessment = get_object_or_404(
        Assessment.objects.select_related("section__module__course__department"), id=assessment_id
    )
    course = assessment.section.module.course
    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied
    if assessment.delivery_mode != AssessmentDeliveryMode.PAPER_SCANNED:
        raise PermissionDenied

    # Restrict the submitted student ID to active, enrolled non-admin students.
    form = ScannedPaperStaffUploadForm(request.POST, request.FILES)
    form.fields["student"].queryset = (
        User.objects.filter(
            is_active=True,
            enrollments__course=course,
            enrollments__status=EnrollmentStatus.ACTIVE,
            user_roles__role__name="Student",
        )
        .exclude(user_roles__role__name="Admin")
        .distinct()
    )
    if not form.is_valid():
        messages.error(request, "Select an enrolled student and a scanned file.")
        return redirect("kura:assessment_detail", assessment_id=assessment.id)

    # Lock the assessment while choosing the student's existing or next attempt.
    try:
        with transaction.atomic():
            assessment = Assessment.objects.select_for_update().get(id=assessment.id)
            # The delivery mode may have changed while this request waited for the lock.
            if assessment.delivery_mode != AssessmentDeliveryMode.PAPER_SCANNED:
                raise PermissionDenied
            attempts = AssessmentAttempt.objects.filter(assessment=assessment, student=form.cleaned_data["student"])
            attempt = attempts.filter(status=AttemptStatus.IN_PROGRESS).select_for_update().first()
            if not attempt:
                attempt_count = attempts.count()
                if attempt_count >= assessment.max_attempts:
                    raise ValidationError("This student has no attempts remaining.")
                attempt = AssessmentAttempt.objects.create(
                    assessment=assessment,
                    student=form.cleaned_data["student"],
                    attempt_no=attempt_count + 1,
                    expires_at=timezone.now() + timezone.timedelta(minutes=assessment.duration_minutes),
                    ip_address=get_client_ip(request),
                )

            # Inspect and attach only a PDF or image before sealing the attempt.
            stored_file = validate_and_save_upload(form.cleaned_data["file"], request.user)
            if stored_file.mime_type not in {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp"}:
                raise ValidationError("Upload a PDF or image of the scanned paper.")
            AttemptFile.objects.create(attempt=attempt, file=stored_file)
            attempt.submitted_at = timezone.now()
            payload = (
                f"{attempt.id}:{json.dumps(attempt.answers_json, sort_keys=True)}:{attempt.submitted_at.isoformat()}"
            )
            attempt.submission_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            evaluate_attempt(attempt)
    except ValidationError as error:
        if hasattr(error, "message"):
            error_message = str(error.message)
        else:
            error_message = str(error)
        messages.error(request, error_message)
        return redirect("kura:assessment_detail", assessment_id=assessment.id)

    # Record the action without logging the submitted file or its contents.
    log_security_event(
        request,
        "attempt.submitted",
        {"attempt_id": attempt.id, "submission_hash": attempt.submission_hash},
    )
    messages.success(request, "Scanned paper submitted for manual marking.")
    return redirect("kura:assessment_detail", assessment_id=assessment.id)


@login_required
def attempt_file_download_view(request, attempt_id, file_id):
    """
    Downloads a file attached to an assessment attempt.
    Who can use it: The student who submitted it, assigned staff, and the department head.
    Security: Denies Admins and checks the file belongs to this exact authorized attempt.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access attempts or scanned scripts.
    if has_role(request.user, "Admin"):
        raise PermissionDenied
    attempt = get_object_or_404(
        AssessmentAttempt.objects.select_related("assessment__section__module__course__department"),
        id=attempt_id,
    )
    course = attempt.assessment.section.module.course
    if not (
        attempt.student_id == request.user.id
        or is_course_staff(request.user, course)
        or is_department_head(request.user, course.department)
    ):
        raise PermissionDenied
    if (
        not (is_course_staff(request.user, course) or is_department_head(request.user, course.department))
        and not attempt.assessment.section.is_visible
    ):
        raise PermissionDenied

    # Bind the file to this attempt before sending the protected download response.
    attachment = get_object_or_404(AttemptFile.objects.select_related("file"), attempt=attempt, file_id=file_id)
    # Record the authorized attempt-file download without logging the file contents.
    log_security_event(
        request,
        "file.downloaded",
        {"file_id": attachment.file_id, "sha256": attachment.file.sha256_hash, "context": "attempt"},
    )
    return create_download_response(attachment.file)


@login_required
def assessment_file_upload_view(request, assessment_id):
    """
    Uploads course material files attached to an assessment.
    Who can use it: Course staff and Department Heads.
    Security: POST only; validates file magic bytes, MIME type, size cap, and hashes.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access assessment materials.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    assessment = get_object_or_404(
        Assessment.objects.select_related("section__module__course__department"),
        id=assessment_id,
    )
    course = assessment.section.module.course

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = AssessmentFileUploadForm(request.POST, request.FILES)
    if form.is_valid():
        uploaded_file = form.cleaned_data["file"]
        try:
            stored_file = validate_and_save_upload(uploaded_file, request.user)
            AssessmentFile.objects.create(assessment=assessment, file=stored_file)
            messages.success(request, f"Attached {stored_file.original_filename} to assessment.")
        except ValidationError as e:
            if hasattr(e, "message"):
                error_message = str(e.message)
            else:
                error_message = str(e)
            messages.error(request, error_message)

    return redirect("kura:assessment_detail", assessment_id=assessment.id)


@login_required
def assessment_file_download_view(request, assessment_id, file_id):
    """
    Downloads files attached to an assessment.
    Who can use it: Course staff and enrolled students.
    Security: For exams, students can download only during an active In_Progress attempt.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot download assessment materials.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    assessment = get_object_or_404(
        Assessment.objects.select_related("section__module__course__department"),
        id=assessment_id,
    )
    course = assessment.section.module.course
    stored_file = get_object_or_404(StoredFile, id=file_id)

    # Verify file is attached to this assessment.
    get_object_or_404(AssessmentFile, assessment=assessment, file=stored_file)

    is_head = is_department_head(request.user, course.department)
    is_staff = is_course_staff(request.user, course)

    if not (is_head or is_staff):
        if not is_enrolled(request.user, course):
            raise PermissionDenied
        if not assessment.section.is_visible:
            raise PermissionDenied
        # Students cannot download before the assessment opens.
        if timezone.now() < assessment.opens_at:
            raise PermissionDenied
        # For exams or proctored assessments, verify student has an active In_Progress attempt.
        if assessment.component_type == "exam" or assessment.proctor_code_hash or assessment.lab_cidr_allowed:
            has_active_attempt = AssessmentAttempt.objects.filter(
                assessment=assessment,
                student=request.user,
                status=AttemptStatus.IN_PROGRESS,
                expires_at__gt=timezone.now(),
            ).exists()
            if not has_active_attempt:
                raise PermissionDenied

    # Record the authorized assessment-file download without logging its contents.
    log_security_event(
        request,
        "file.downloaded",
        {"file_id": stored_file.id, "sha256": stored_file.sha256_hash, "context": "assessment"},
    )
    return create_download_response(stored_file)


@login_required
def assessment_attempt_start_view(request, assessment_id):
    """
    Initiates a new assessment attempt for an enrolled student.
    Who can use it: Enrolled students with remaining attempt allowances.
    Security: Validates opening window, max attempts, lab CIDR subnet, and whiteboard proctor code.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot start assessment attempts.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Lock the assessment before reading its settings and creating the first attempt.
    # The edit view uses the same lock, so a concurrent edit cannot change started questions.
    with transaction.atomic():
        assessment = get_object_or_404(Assessment.objects.select_for_update(), id=assessment_id)
        course = assessment.section.module.course
        if not is_enrolled(request.user, course):
            raise PermissionDenied
        if not assessment.section.is_visible:
            raise PermissionDenied

        now = timezone.now()
        if now < assessment.opens_at or now > assessment.due_date:
            log_security_event(
                request,
                "attempt.start_blocked",
                {"assessment_id": assessment.id, "reason": "closed_window"},
                logging.WARNING,
            )
            messages.error(request, "This assessment is currently closed.")
            return redirect("kura:assessment_detail", assessment_id=assessment.id)
        existing_count = AssessmentAttempt.objects.filter(assessment=assessment, student=request.user).count()
        if existing_count >= assessment.max_attempts:
            log_security_event(
                request,
                "attempt.start_blocked",
                {"assessment_id": assessment.id, "reason": "max_attempts"},
                logging.WARNING,
            )
            messages.error(request, "You have reached the maximum allowed attempts for this assessment.")
            return redirect("kura:assessment_detail", assessment_id=assessment.id)

        # Check the current lab restriction and the submitted proctor code while locked.
        client_ip = get_client_ip(request)
        if assessment.lab_cidr_allowed:
            try:
                allowed_network = ipaddress.ip_network(str(assessment.lab_cidr_allowed), strict=False)
                if ipaddress.ip_address(client_ip) not in allowed_network:
                    log_security_event(
                        request,
                        "attempt.start_blocked",
                        {"assessment_id": assessment.id, "reason": "lab_cidr"},
                        logging.WARNING,
                    )
                    messages.error(request, "Attempt must be initiated from an authorized university lab subnet.")
                    return redirect("kura:assessment_detail", assessment_id=assessment.id)
            except ValueError:
                log_security_event(
                    request,
                    "attempt.start_blocked",
                    {"assessment_id": assessment.id, "reason": "lab_cidr_invalid"},
                    logging.WARNING,
                )
                messages.error(request, "Network verification failure.")
                return redirect("kura:assessment_detail", assessment_id=assessment.id)
        form = AssessmentAttemptStartForm(request.POST)
        if assessment.proctor_code_hash:
            if not form.is_valid():
                log_security_event(
                    request,
                    "attempt.start_blocked",
                    {"assessment_id": assessment.id, "reason": "proctor_code_missing"},
                    logging.WARNING,
                )
                messages.error(request, "Proctor code is required.")
                return redirect("kura:assessment_detail", assessment_id=assessment.id)
            submitted_code = form.cleaned_data.get("proctor_code", "").strip()
            if hashlib.sha256(submitted_code.encode("utf-8")).hexdigest() != assessment.proctor_code_hash:
                log_security_event(
                    request,
                    "attempt.start_blocked",
                    {"assessment_id": assessment.id, "reason": "proctor_code_invalid"},
                    logging.WARNING,
                )
                messages.error(request, "Invalid whiteboard proctor code.")
                return redirect("kura:assessment_detail", assessment_id=assessment.id)

        # Create the attempt before releasing the row lock.
        timer_expires = now + timezone.timedelta(minutes=assessment.duration_minutes)
        attempt = AssessmentAttempt.objects.create(
            assessment=assessment,
            student=request.user,
            attempt_no=existing_count + 1,
            status=AttemptStatus.IN_PROGRESS,
            expires_at=min(assessment.due_date, timer_expires),
            ip_address=client_ip,
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
        )
        # Record the new attempt only after it is safely stored.
        log_security_event(request, "attempt.started", {"assessment_id": assessment.id, "attempt_id": attempt.id})
    return redirect("kura:assessment_take", attempt_id=attempt.id)


@login_required
def assessment_take_view(request, attempt_id):
    """
    Renders the live exam interface with server timer countdown and autosave.
    Who can use it: The attempting student.
    Security: Verifies attempt ownership and never changes an attempt on GET.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot take assessments, even if enrolled in the course.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    attempt = get_object_or_404(
        AssessmentAttempt.objects.select_related("assessment__section__module__course"),
        id=attempt_id,
        student=request.user,
    )
    # A hidden section cannot be accessed through a previously started attempt.
    if not attempt.assessment.section.is_visible:
        raise PermissionDenied

    # GET must never submit an attempt; the scheduled job handles expired attempts.
    if attempt.status != AttemptStatus.IN_PROGRESS or timezone.now() >= attempt.expires_at:
        return redirect("kura:attempt_detail", attempt_id=attempt.id)

    answers_map = {ans.get("question_id"): ans for ans in (attempt.answers_json or [])}
    attempt_files = AttemptFile.objects.filter(attempt=attempt).select_related("file")

    # Pair each displayed question with this student's saved response, never the answer key.
    questions = []
    for saved_question in attempt.assessment.questions_json:
        question = saved_question.copy()
        question["saved_answer"] = answers_map.get(question.get("question_id"), {})
        if question.get("type") == "matching":
            left_prompts = []
            for saved_pair in question.get("left_prompts", []):
                pair = saved_pair.copy()
                for match in question["saved_answer"].get("submitted_matches", []):
                    if match.get("pair_id") == pair.get("pair_id"):
                        pair["selected_match"] = match.get("selected_match")
                left_prompts.append(pair)
            question["left_prompts"] = left_prompts
        questions.append(question)

    context = {
        "attempt": attempt,
        "assessment": attempt.assessment,
        "questions": questions,
        "answers_map": answers_map,
        "attempt_files": attempt_files,
        "file_form": AssessmentFileUploadForm(),
    }
    return render(request, "kura/assessments/assessment_take.html", context)


@login_required
def assessment_autosave_view(request, attempt_id):
    """
    Receives periodic background response autosaves via HTMX.
    Who can use it: The attempting student.
    Security: Enforces server-side deadline; rejects updates if expires_at is passed; tracks focus loss.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot submit assessment responses.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Validate the question identifier before using it to find the student's question.
    lookup = AssessmentAutosaveForm(request.POST)
    if not lookup.is_valid():
        return HttpResponse("Unable to save this response.", status=400)

    # The same attempt lock is used by submission, uploads, and the deadline job.
    with transaction.atomic():
        attempt = get_object_or_404(AssessmentAttempt.objects.select_for_update(), id=attempt_id, student=request.user)
        if not attempt.assessment.section.is_visible:
            raise PermissionDenied
        if attempt.status != AttemptStatus.IN_PROGRESS or timezone.now() >= attempt.expires_at:
            # This direct 403 bypasses Django's permission-exception handler.
            log_security_event(
                request,
                "access.denied",
                {"reason": "assessment_deadline_expired"},
                logging.WARNING,
            )
            return HttpResponseForbidden("Assessment deadline has expired.")
        if lookup.cleaned_data["focus_lost"]:
            attempt.tab_focus_lost_count += 1
            attempt.save(update_fields=["tab_focus_lost_count"])
            # Count focus changes without recording answer text or question identifiers.
            log_security_event(
                request,
                "attempt.focus_lost",
                {"attempt_id": attempt.id, "count": attempt.tab_focus_lost_count},
            )
            return render(request, "kura/assessments/_autosave_status.html", {"status": "saved"})

        # Find the question in this assessment and reject invented IDs or response types.
        question = None
        for item in attempt.assessment.questions_json:
            if item.get("question_id") == lookup.cleaned_data["question_id"]:
                question = item
                break
        if not question:
            return HttpResponse("Unable to save this response.", status=400)
        question_type = question.get("type")
        if question_type == "essay":
            question_type = "long_text"
        if lookup.cleaned_data["response_type"] != question_type:
            return HttpResponse("Unable to save this response.", status=400)
        response_form = AssessmentAnswerForm(request.POST, question)
        if not response_form.is_valid():
            return HttpResponse("Unable to save this response.", status=400)

        # Only fields for the real question are stored; forged extra pair names are ignored.
        question_id = question["question_id"]
        answer = {"question_id": question_id, "type": question_type, "last_updated_at": timezone.now().isoformat()}
        if question_type == "multiple_choice":
            answer["selected_option_ids"] = response_form.cleaned_data["selected_options"]
        elif question_type == "matching":
            answer["submitted_matches"] = []
            for pair in question.get("left_prompts", []):
                pair_id = pair["pair_id"]
                answer["submitted_matches"].append(
                    {
                        "pair_id": pair_id,
                        "selected_match": response_form.cleaned_data[f"match_{pair_id}"],
                    }
                )
        elif question_type == "long_text":
            answer["response_text"] = response_form.cleaned_data["response_text"]
        else:
            return HttpResponse("Unable to save this response.", status=400)
        existing_answers = {item.get("question_id"): item for item in (attempt.answers_json or [])}
        existing_answers[question_id] = answer
        attempt.answers_json = list(existing_answers.values())
        attempt.last_autosave_at = timezone.now()
        attempt.save(update_fields=["answers_json", "last_autosave_at"])

    return render(request, "kura/assessments/_autosave_status.html", {"status": "saved"})


@login_required
def assessment_attempt_file_upload_view(request, attempt_id):
    """
    Uploads a student coursework submission file for an in-progress attempt.
    Who can use it: The attempting student.
    Security: Validates attempt is active and unexpired; database trigger also locks files on submit.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot upload assessment attempt files.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    attempt = get_object_or_404(AssessmentAttempt, id=attempt_id, student=request.user)
    if not attempt.assessment.section.is_visible:
        raise PermissionDenied

    form = AssessmentFileUploadForm(request.POST, request.FILES)
    if form.is_valid():
        uploaded_file = form.cleaned_data["file"]
        try:
            # Lock the attempt so submission cannot seal it while this file is being added.
            with transaction.atomic():
                attempt = AssessmentAttempt.objects.select_for_update().get(id=attempt.id, student=request.user)
                if attempt.status != AttemptStatus.IN_PROGRESS or timezone.now() >= attempt.expires_at:
                    raise ValidationError("Files cannot be uploaded: attempt is closed or deadline has passed.")
                stored_file = validate_and_save_upload(uploaded_file, request.user)
                if attempt.assessment.delivery_mode == AssessmentDeliveryMode.PAPER_SCANNED:
                    allowed_scan_types = {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp"}
                    if stored_file.mime_type not in allowed_scan_types:
                        raise ValidationError("Upload a PDF or image of the scanned paper.")
                if timezone.now() >= attempt.expires_at:
                    raise ValidationError("Files cannot be uploaded: attempt is closed or deadline has passed.")
                AttemptFile.objects.create(attempt=attempt, file=stored_file)
            messages.success(request, f"Uploaded {stored_file.original_filename}.")
        except ValidationError as e:
            if hasattr(e, "message"):
                error_message = str(e.message)
            else:
                error_message = str(e)
            messages.error(request, error_message)

    return redirect("kura:assessment_take", attempt_id=attempt.id)


@login_required
def assessment_submit_view(request, attempt_id):
    """
    Submits an assessment attempt, computes submission hash, and triggers auto-grading.
    Who can use it: The attempting student.
    Security: POST only; computes SHA-256 submission hash; locks further changes.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot submit assessment attempts.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Serialize submission with file uploads and the expiry job.
    with transaction.atomic():
        attempt = get_object_or_404(AssessmentAttempt.objects.select_for_update(), id=attempt_id, student=request.user)
        if not attempt.assessment.section.is_visible:
            raise PermissionDenied
        if attempt.status != AttemptStatus.IN_PROGRESS:
            messages.warning(request, "This attempt has already been submitted.")
            return redirect("kura:attempt_detail", attempt_id=attempt.id)

        # A scanned-paper attempt needs an attached script before submission.
        if (
            attempt.assessment.delivery_mode == AssessmentDeliveryMode.PAPER_SCANNED
            and not AttemptFile.objects.filter(attempt=attempt).exists()
        ):
            messages.error(request, "Upload a PDF or image of the scanned paper.")
            return redirect("kura:assessment_take", attempt_id=attempt.id)

        # Seal the attempt and its grade together, capping the time at the deadline.
        attempt.submitted_at = min(timezone.now(), attempt.expires_at)
        raw_payload = (
            f"{attempt.id}:{json.dumps(attempt.answers_json, sort_keys=True)}:{attempt.submitted_at.isoformat()}"
        )
        attempt.submission_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        evaluate_attempt(attempt)

        # Email a receipt: when it was submitted, its integrity hash and the
        # SHA-256 of each attached file. The student can use it as proof later.
        receipt_lines = [
            "Hello,",
            "",
            f"Kura received your submission for: {attempt.assessment.title}",
            f"Submitted at: {timezone.localtime(attempt.submitted_at).strftime('%d %b %Y, %H:%M:%S')}",
            f"Submission integrity hash (SHA-256): {attempt.submission_hash}",
        ]
        for attempt_file in AttemptFile.objects.filter(attempt=attempt).select_related("file"):
            receipt_lines.append(f"File: {attempt_file.file.original_filename}  SHA-256: {attempt_file.file.sha256_hash}")
        receipt_lines += ["", "Keep this email as your receipt. This is an automatic message from Kura."]
        queue_email(
            f"submission-receipt:{attempt.id}",
            request.user.email,
            f"Submission received: {attempt.assessment.title}",
            "\n".join(receipt_lines),
        )

    messages.success(request, f"Assessment submitted! Integrity Hash: {attempt.submission_hash[:16]}...")
    # Record the submission integrity hash without logging raw answers or scores.
    log_security_event(
        request,
        "attempt.submitted",
        {"attempt_id": attempt.id, "submission_hash": attempt.submission_hash},
    )
    return redirect("kura:attempt_detail", attempt_id=attempt.id)


@login_required
def attempt_detail_view(request, attempt_id):
    """
    Displays completed assessment attempt review and score telemetry.
    Who can use it: The attempting student, Course staff, Department Heads.
    Security: IDOR protection ensures students cannot inspect other students' attempts.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot view attempts or their marks.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    attempt = get_object_or_404(
        AssessmentAttempt.objects.select_related("assessment__section__module__course__department", "student"),
        id=attempt_id,
    )
    course = attempt.assessment.section.module.course

    is_head = is_department_head(request.user, course.department)
    is_staff = is_course_staff(request.user, course)

    # Only course staff/head or the attempting student can view this attempt.
    if not (is_head or is_staff or attempt.student_id == request.user.id):
        raise PermissionDenied
    if not (is_head or is_staff) and not attempt.assessment.section.is_visible:
        raise PermissionDenied

    # Staff may see the marking breakdown; students may see only the released grade.
    summary = {}
    released_grade = None
    if (is_head or is_staff) and attempt.student_id != request.user.id:
        summary = attempt.summary_score_json or {}
    else:
        released_grade = Grade.objects.filter(
            attempt=attempt,
            student=request.user,
            status=GradeStatus.RELEASED,
        ).first()

    attempt_files = AttemptFile.objects.filter(attempt=attempt).select_related("file")

    context = {
        "attempt": attempt,
        "assessment": attempt.assessment,
        "is_staff": is_head or is_staff,
        "attempt_files": attempt_files,
        "summary": summary,
        "released_grade": released_grade,
    }
    return render(request, "kura/assessments/attempt_detail.html", context)


# ==========================================
# Grades, appeals & transcripts
# ==========================================


@login_required
def course_grades_view(request, course_id):
    """
    Displays grade rosters and status for course staff and instructors.
    Who can use it: Course staff and Department Heads (Admins are strictly denied).
    Security: Admins forbidden; restricts access to assigned course staff.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    course = get_object_or_404(Course.objects.select_related("department"), id=course_id)

    # Admins are strictly barred from viewing grade records.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    grades = (
        Grade.objects.filter(assessment__section__module__course=course)
        .select_related("assessment", "student", "attempt")
        .order_by("-graded_at")
    )
    can_release = can_release_grades(request.user, course)
    grade_schemes = CourseGradeScheme.objects.filter(course=course)
    course_results = CourseResult.objects.filter(course=course).select_related("student")

    # A staff member who is also a student must not see their own draft marks here.
    grades = grades.exclude(student=request.user)
    course_results = course_results.exclude(student=request.user)

    context = {
        "course": course,
        "grades": grades,
        "can_release": can_release,
        "can_enter_grade": is_course_staff(request.user, course)
        and (has_role(request.user, "Instructor") or has_role(request.user, "Teaching assistant")),
        "can_finalize_grade": is_course_staff(request.user, course) and has_role(request.user, "Instructor"),
        "grade_schemes": grade_schemes,
        "course_results": course_results,
    }
    return render(request, "kura/grades/course_grades.html", context)


@login_required
def grade_entry_view(request, attempt_id):
    """
    Enters or edits draft grading scores and feedback for an assessment attempt.
    Who can use it: Teaching Assistants and Course Instructors.
    Security: Creates draft grade and logs modification in GradeHistory audit ledger.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    attempt = get_object_or_404(
        AssessmentAttempt.objects.select_related("assessment__section__module__course__department", "student"),
        id=attempt_id,
    )
    course = attempt.assessment.section.module.course

    if has_role(request.user, "Admin"):
        raise PermissionDenied

    # Only assigned instructors and teaching assistants may enter initial grades.
    if not is_course_staff(request.user, course) or not (
        has_role(request.user, "Instructor") or has_role(request.user, "Teaching assistant")
    ):
        raise PermissionDenied

    # A student cannot use a staff assignment to mark their own attempt.
    if attempt.student_id == request.user.id:
        raise PermissionDenied

    # A scanned paper must be submitted with a file before staff can mark it.
    if attempt.assessment.delivery_mode == AssessmentDeliveryMode.PAPER_SCANNED:
        if attempt.status == AttemptStatus.IN_PROGRESS or not AttemptFile.objects.filter(attempt=attempt).exists():
            raise PermissionDenied

    existing_grade = Grade.objects.filter(attempt=attempt).first()
    initial_score = None
    if existing_grade:
        initial_score = existing_grade.score

    form = GradeEntryForm(request.POST or None, initial={"score": initial_score})

    # A manual score must fit within the assessment's configured maximum.
    if request.method == "POST" and form.is_valid() and form.cleaned_data["score"] > attempt.assessment.max_score:
        form.add_error("score", "Score cannot exceed the assessment maximum.")

    if request.method == "POST" and form.is_valid():
        new_score = form.cleaned_data["score"]
        # Lock the attempt and existing grade so finalization cannot race this update.
        with transaction.atomic():
            AssessmentAttempt.objects.select_for_update().get(id=attempt.id)
            existing_grade = Grade.objects.select_for_update().filter(attempt=attempt).first()
            if existing_grade and existing_grade.status != GradeStatus.DRAFT:
                messages.error(request, "Only draft grades can be edited here.")
                return redirect("kura:course_grades", course_id=course.id)
            old_score = None
            old_status = None
            if existing_grade:
                old_score = existing_grade.score
                old_status = existing_grade.status
            grade, _ = Grade.objects.update_or_create(
                attempt=attempt,
                defaults={
                    "assessment": attempt.assessment,
                    "student": attempt.student,
                    "grader": request.user,
                    "score": new_score,
                    "status": GradeStatus.DRAFT,
                },
            )

            # Record change in immutable grade history.
            GradeHistory.objects.create(
                grade=grade,
                old_score=old_score,
                new_score=new_score,
                old_status=old_status,
                new_status=GradeStatus.DRAFT,
                changed_by=request.user,
                reason="Manual grade entry / review update.",
            )

        messages.success(request, f"Draft grade saved for {attempt.student.email}.")
        # Record the grade entry without including the numeric score.
        log_security_event(
            request,
            "grade.entered",
            {
                "grade_id": grade.id,
                "assessment_id": attempt.assessment_id,
                "student_id": attempt.student_id,
            },
        )
        return redirect("kura:course_grades", course_id=course.id)

    return render(request, "kura/grades/grade_entry.html", {"form": form, "attempt": attempt})


@login_required
def grade_finalize_view(request, grade_id):
    """
    Finalizes a draft grade in preparation for student release.
    Who can use it: Instructors assigned to the course.
    Security: Checks the instructor role and course, locks the draft, and logs the change.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access or change grade records.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    # Only instructors may finalize grades, even when the grade is hidden by database row security.
    if not has_role(request.user, "Instructor"):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    grade = get_object_or_404(
        Grade.objects.select_related("assessment__section__module__course__department"),
        id=grade_id,
    )
    course = grade.assessment.section.module.course

    # A student cannot finalize their own grade through a staff assignment.
    if grade.student_id == request.user.id:
        raise PermissionDenied

    # Only an instructor assigned to this course may finalize an initial grade.
    is_instructor = is_course_staff(request.user, course)
    if not is_instructor:
        raise PermissionDenied

    # Lock the row and check its current status before changing it and its history.
    with transaction.atomic():
        grade = Grade.objects.select_for_update().get(id=grade_id)
        if grade.status != GradeStatus.DRAFT:
            messages.error(request, "Only draft grades can be finalized.")
            return redirect("kura:course_grades", course_id=course.id)
        old_status = grade.status
        old_score = grade.score
        grade.status = GradeStatus.FINALIZED
        grade.finalized_by = request.user
        grade.finalized_at = timezone.now()
        grade.save(update_fields=["status", "finalized_by", "finalized_at"])

        GradeHistory.objects.create(
            grade=grade,
            old_score=old_score,
            new_score=grade.score,
            old_status=old_status,
            new_status=GradeStatus.FINALIZED,
            changed_by=request.user,
            reason="Grade finalized by instructor.",
        )

    messages.success(request, f"Grade for {grade.student.email} finalized.")
    log_security_event(
        request,
        "grade.finalized",
        {
            "grade_id": grade.id,
            "assessment_id": grade.assessment_id,
            "student_id": grade.student_id,
        },
    )
    return redirect("kura:course_grades", course_id=course.id)


@login_required
def grade_release_view(request, grade_id):
    """
    Releases a finalized grade to the student with step-up MFA verification.
    Who can use it: Instructors assigned to the course with can_release_grades=True.
    Security: Checks permission; enforces step-up OTP token (or a recovery code, compared
    by keyed hash and used once); grade must be finalized.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    grade = get_object_or_404(
        Grade.objects.select_related("assessment__section__module__course__department"),
        id=grade_id,
    )
    course = grade.assessment.section.module.course

    if grade.student_id == request.user.id or not can_release_grades(request.user, course):
        raise PermissionDenied

    if grade.status != GradeStatus.FINALIZED:
        messages.error(request, "Only finalized grades can be released.")
        return redirect("kura:course_grades", course_id=course.id)

    form = GradeReleaseForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        token = form.cleaned_data["otp_token"].strip()

        # Step-up authentication: verify OTP token against user's TOTP or static device.
        totp_device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
        is_verified = False
        if totp_device and verify_totp_code(totp_device, request.user, token):
            is_verified = True
        else:
            # Recovery codes are saved as keyed hashes, so compare the hash of the typed code.
            static_device = StaticDevice.objects.filter(user=request.user, confirmed=True).first()
            if static_device and static_device.verify_token(hash_recovery_code(token)):
                is_verified = True

        if not is_verified:
            log_security_event(
                request,
                "grade.release_mfa_failed",
                {"grade_id": grade.id},
                logging.WARNING,
            )
            messages.error(request, "Invalid MFA security token for grade release authorization.")
            return render(request, "kura/grades/grade_release.html", {"form": form, "grade": grade})

        old_status = grade.status
        with transaction.atomic():
            grade.status = GradeStatus.RELEASED
            grade.released_by = request.user
            grade.released_at = timezone.now()
            grade.save(update_fields=["status", "released_by", "released_at"])

            GradeHistory.objects.create(
                grade=grade,
                old_score=grade.score,
                new_score=grade.score,
                old_status=old_status,
                new_status=GradeStatus.RELEASED,
                changed_by=request.user,
                reason="Grade released to student with MFA verification.",
            )

            # Tell the student a grade is ready. No score in the email: they log in to see it.
            grades_link = settings.SITE_URL + reverse("kura:student_grades")
            queue_email(
                f"grade-released:{grade.id}",
                grade.student.email,
                f"Grade released: {grade.assessment.title}",
                f"Hello,\n\nA grade has been released for: {grade.assessment.title}\n\n"
                f"Log in to Kura to see it:\n{grades_link}\n\n"
                "This is an automatic message from Kura. Please do not reply.",
            )

        messages.success(request, f"Grade for {grade.student.email} released successfully.")
        log_security_event(
            request,
            "grade.released",
            {
                "grade_id": grade.id,
                "assessment_id": grade.assessment_id,
                "student_id": grade.student_id,
            },
        )
        return redirect("kura:course_grades", course_id=course.id)

    return render(request, "kura/grades/grade_release.html", {"form": form, "grade": grade})


@login_required
def student_grades_view(request):
    """
    Displays released assessment grades for the logged-in student.
    Who can use it: Students.
    Security: Strictly filters by status=RELEASED and student=request.user (IDOR defense).
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # An Admin role must not grant access to marks, even alongside a Student role.
    if has_role(request.user, "Admin") or not has_role(request.user, "Student"):
        raise PermissionDenied

    # Students strictly see only their own released grades.
    released_grades = (
        Grade.objects.filter(
            student=request.user,
            status=GradeStatus.RELEASED,
        )
        .select_related("assessment__section__module__course")
        .order_by("-released_at")
    )

    # Load existing appeals submitted by this student.
    appeals = GradeAppeal.objects.filter(grade__student=request.user).select_related("grade__assessment")

    return render(
        request,
        "kura/grades/student_grades.html",
        {
            "grades": released_grades,
            "appeals": appeals,
        },
    )


@login_required
def grade_appeal_create_view(request, grade_id):
    """
    Files a formal student appeal disputing an assessment score.
    Who can use it: The evaluated student on a released grade.
    Security: Verifies grade.student == request.user and grade is RELEASED (prevents IDOR).
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access grades through an appeal.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    grade = get_object_or_404(
        Grade.objects.select_related("assessment__section__module__course"),
        id=grade_id,
        student=request.user,
    )

    if grade.status != GradeStatus.RELEASED:
        raise PermissionDenied

    form = GradeAppealForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        reason = form.cleaned_data["reason"].strip()
        appeal = GradeAppeal.objects.create(
            grade=grade,
            reason=reason,
            status=AppealStatus.PENDING,
        )
        # Record the appeal ID and state, never the student's written reason.
        log_security_event(request, "appeal.created", {"appeal_id": appeal.id, "status": appeal.status})
        messages.success(request, "Your grade appeal has been submitted for instructor review.")
        return redirect("kura:student_grades")

    return render(request, "kura/grades/appeal_create.html", {"form": form, "grade": grade})


@login_required
def grade_appeal_review_view(request, appeal_id):
    """
    Reviews a student grade appeal and writes a formal verdict.
    Who can use it: Course instructors and Department Heads.
    Security: Restricts access to assigned course staff; records reviewer notes and timestamp.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access grades through an appeal.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    appeal = get_object_or_404(
        GradeAppeal.objects.select_related("grade__assessment__section__module__course__department", "grade__student"),
        id=appeal_id,
    )
    course = appeal.grade.assessment.section.module.course

    # A student cannot review their own appeal as course staff.
    if appeal.grade.student_id == request.user.id:
        raise PermissionDenied

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    form = GradeAppealReviewForm(request.POST or None, initial={"status": appeal.status, "response": appeal.response})

    if request.method == "POST" and form.is_valid():
        appeal.status = form.cleaned_data["status"]
        appeal.response = form.cleaned_data["response"].strip()
        appeal.reviewed_by = request.user
        appeal.resolved_at = timezone.now()
        appeal.save(update_fields=["status", "response", "reviewed_by", "resolved_at"])
        # Record the decision status without logging the private response text.
        log_security_event(request, "appeal.decided", {"appeal_id": appeal.id, "status": appeal.status})

        # Tell the student their appeal was decided (each decision once).
        grades_link = settings.SITE_URL + reverse("kura:student_grades")
        queue_email(
            f"appeal-decided:{appeal.id}:{int(appeal.resolved_at.timestamp())}",
            appeal.grade.student.email,
            f"Grade appeal decided: {appeal.grade.assessment.title}",
            f"Hello,\n\nYour grade appeal for {appeal.grade.assessment.title} has been reviewed "
            f"(status: {appeal.get_status_display()}).\n\n"
            f"Log in to Kura to read the response:\n{grades_link}\n\n"
            "This is an automatic message from Kura. Please do not reply.",
        )

        messages.success(request, f"Appeal verdict recorded for {appeal.grade.student.email}.")
        return redirect("kura:course_grades", course_id=course.id)

    return render(request, "kura/grades/appeal_review.html", {"form": form, "appeal": appeal})


@login_required
def grade_change_request_create_view(request, grade_id):
    """
    Submits a formal request to alter an already released grade.
    Who can use it: Course instructors.
    Security: Restricted to released grades; enforces one pending request per grade.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot access grades through change requests.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    grade = get_object_or_404(
        Grade.objects.select_related("assessment__section__module__course__department", "student"),
        id=grade_id,
    )
    course = grade.assessment.section.module.course

    # A student cannot manage their own grade through a staff assignment.
    if grade.student_id == request.user.id:
        raise PermissionDenied

    if not is_course_staff(request.user, course):
        raise PermissionDenied

    if grade.status != GradeStatus.RELEASED:
        messages.error(request, "Grade change requests only apply to already released grades.")
        return redirect("kura:course_grades", course_id=course.id)

    # Check for existing pending request.
    if GradeChangeRequest.objects.filter(grade=grade, status=ChangeRequestStatus.PENDING).exists():
        messages.warning(request, "A pending change request already exists for this grade.")
        return redirect("kura:course_grades", course_id=course.id)

    form = GradeChangeRequestForm(request.POST or None, initial={"proposed_score": grade.score})

    if request.method == "POST" and form.is_valid():
        proposed = form.cleaned_data["proposed_score"]
        reason = form.cleaned_data["reason"].strip()

        change_request = GradeChangeRequest.objects.create(
            grade=grade,
            requested_by=request.user,
            current_score=grade.score,
            proposed_score=proposed,
            reason=reason,
            status=ChangeRequestStatus.PENDING,
        )
        # Record the request ID and decision state, never the proposed score or reason.
        log_security_event(
            request,
            "grade.change_requested",
            {"request_id_obj": change_request.id, "decision": change_request.status},
        )
        messages.success(request, "Grade change request submitted for Department Head approval.")
        return redirect("kura:course_grades", course_id=course.id)

    return render(request, "kura/grades/change_request_create.html", {"form": form, "grade": grade})


@login_required
def grade_change_request_review_view(request, request_id):
    """
    Department Head decision on a post-release grade change request.
    Who can use it: Department Head of the course's department.
    Security: Enforces no self-approval; on approval, updates grade and logs GradeHistory.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot review requests containing grades.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    change_request = get_object_or_404(
        GradeChangeRequest.objects.select_related(
            "grade__assessment__section__module__course__department", "requested_by"
        ),
        id=request_id,
    )
    course = change_request.grade.assessment.section.module.course
    dept = course.department

    # A student cannot review a change to their own grade.
    if change_request.grade.student_id == request.user.id:
        raise PermissionDenied

    if not is_department_head(request.user, dept):
        raise PermissionDenied

    # Security rule from spec: no self-approval.
    if change_request.requested_by_id == request.user.id:
        raise PermissionDenied

    form = GradeChangeRequestReviewForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        decision = form.cleaned_data["decision"]
        review_note = form.cleaned_data["review_note"].strip()

        with transaction.atomic():
            change_request.status = decision
            change_request.reviewed_by = request.user
            change_request.review_note = review_note
            change_request.reviewed_at = timezone.now()
            change_request.save()

            # Record the decision without logging review notes or score values.
            log_security_event(
                request,
                "grade.change_decided",
                {"request_id_obj": change_request.id, "decision": decision},
            )

            if decision == ChangeRequestStatus.APPROVED:
                grade = change_request.grade
                old_score = grade.score
                grade.score = change_request.proposed_score
                grade.save(update_fields=["score"])

                # Immutable audit log with department head approval.
                GradeHistory.objects.create(
                    grade=grade,
                    old_score=old_score,
                    new_score=grade.score,
                    old_status=GradeStatus.RELEASED,
                    new_status=GradeStatus.RELEASED,
                    changed_by=change_request.requested_by,
                    approved_by=request.user,
                    reason=change_request.reason,
                    change_request=change_request,
                )

        messages.success(request, f"Grade change request {decision.lower()} successfully.")
        return redirect("kura:course_grades", course_id=course.id)

    return render(request, "kura/grades/change_request_review.html", {"form": form, "change_request": change_request})


@login_required
def course_result_calculate_view(request, course_id):
    """
    Calculates cumulative course results from released grades and grading schemes.
    Who can use it: Course instructors and Department Heads.
    Security: Only aggregates released grades; enforces final_score 0 to 100 constraint.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Administrators cannot calculate results from grades.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    # Calculating results changes records and therefore requires a POST.
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    course = get_object_or_404(Course.objects.select_related("department"), id=course_id)

    if not (is_course_staff(request.user, course) or is_department_head(request.user, course.department)):
        raise PermissionDenied

    schemes = CourseGradeScheme.objects.filter(course=course)
    enrollments = Enrollment.objects.filter(course=course, status=EnrollmentStatus.ACTIVE).select_related("student")

    with transaction.atomic():
        # Serialize result calculation and release for this course.
        Course.objects.select_for_update().get(id=course.id)
        for enr in enrollments:
            student = enr.student
            # Released results are already on transcripts and must never be overwritten.
            if CourseResult.objects.filter(course=course, student=student, status=GradeStatus.RELEASED).exists():
                continue
            cumulative_score = Decimal("0.00")

            for scheme in schemes:
                comp_type = scheme.component_type
                weight = scheme.weight_percentage

                # Find all released grades for assessments of this component type.
                comp_grades = Grade.objects.filter(
                    assessment__section__module__course=course,
                    assessment__component_type=comp_type,
                    student=student,
                    status=GradeStatus.RELEASED,
                ).select_related("assessment")

                if comp_grades.exists():
                    # Calculate average percentage for this component.
                    total_pct = sum((g.score / g.assessment.max_score * 100) for g in comp_grades)
                    avg_pct = total_pct / comp_grades.count()
                    cumulative_score += avg_pct * (weight / 100)

            final_val = min(Decimal("100.00"), max(Decimal("0.00"), cumulative_score.quantize(Decimal("0.01"))))

            CourseResult.objects.update_or_create(
                course=course,
                student=student,
                defaults={
                    "final_score": final_val,
                    "status": GradeStatus.DRAFT,
                },
            )

    messages.success(request, "Course results calculated from released grades.")
    return redirect("kura:course_grades", course_id=course.id)


@login_required
def course_result_release_view(request, course_id):
    """
    Releases cumulative course results to students.
    Who can use it: Instructors with can_release_grades=True.
    Security: Requires grade release authorization; marks results as released.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    course = get_object_or_404(Course, id=course_id)

    if not can_release_grades(request.user, course):
        raise PermissionDenied

    # Use the same course lock as calculation so the two actions cannot race.
    with transaction.atomic():
        Course.objects.select_for_update().get(id=course.id)
        now = timezone.now()
        CourseResult.objects.filter(course=course).exclude(status=GradeStatus.RELEASED).update(
            status=GradeStatus.RELEASED,
            finalized_by=request.user,
            finalized_at=now,
            released_at=now,
        )
    messages.success(request, "Course results released to transcripts.")
    return redirect("kura:course_grades", course_id=course.id)


@login_required
def student_transcript_view(request):
    """
    Displays the official academic transcript for the student.
    Who can use it: Students.
    Security: Strictly filters CourseResult by student=request.user and status=RELEASED.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # An Admin role must not grant access to results through a Student role.
    if has_role(request.user, "Admin") or not has_role(request.user, "Student"):
        raise PermissionDenied

    results = (
        CourseResult.objects.filter(
            student=request.user,
            status=GradeStatus.RELEASED,
        )
        .select_related("course__department")
        .order_by("-course__academic_year", "course__semester")
    )

    student_profile = StudentProfile.objects.filter(user=request.user).first()

    return render(
        request,
        "kura/grades/transcript.html",
        {
            "results": results,
            "student_profile": student_profile,
        },
    )


@login_required
def department_reports_view(request, department_id):
    """
    Institutional reporting dashboard for Department Heads.
    Who can use it: Department Heads for their own department.
    Security: Cross-department access strictly forbidden.
"""
    # Admins and Registrars cannot access instructional content or grades.
    if not can_access_learning_records(request.user):
        raise PermissionDenied

    # Department reports include marks, so administrators cannot view them.
    if has_role(request.user, "Admin"):
        raise PermissionDenied

    department = get_object_or_404(Department, id=department_id)

    if not is_department_head(request.user, department):
        raise PermissionDenied

    courses = Course.objects.filter(department=department).order_by("code")
    enrollment_count = Enrollment.objects.filter(course__department=department, status=EnrollmentStatus.ACTIVE).count()
    results = CourseResult.objects.filter(course__department=department, status=GradeStatus.RELEASED)
    avg_score = None
    if results.exists():
        avg_score = sum(r.final_score for r in results) / results.count()

    rounded_average = None
    if avg_score:
        rounded_average = round(avg_score, 2)
    context = {
        "department": department,
        "courses": courses,
        "enrollment_count": enrollment_count,
        "avg_score": rounded_average,
    }
    return render(request, "kura/grades/department_report.html", context)

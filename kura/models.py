"""Database models for Kura.

Groups, in order: custom column types, enumerations, the user model, departments
and roles, profiles, sessions and tokens, courses, files, attendance, assessments,
grades, and the single-row security policy.

Database CHECK constraints repeat the main business rules (file size, score range,
date order) so a bug in the application cannot store invalid data. Row-level
security policies on the sensitive tables live in the migrations.
"""

import ipaddress
import uuid
from decimal import Decimal
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import DatabaseError, models


# Custom PostgreSQL column types


class FixedCharField(models.CharField):
    """
    Fixed-width character column for 64-character SHA-256 hex digests.
    It stores hashes for password resets, sessions, file checksums, and exam submissions.
    """

    def db_type(self, connection):
        """Return the PostgreSQL column type for this fixed-width character field."""
        return f"char({self.max_length})"


def validate_cidr(value):
    """Check that a value is a valid CIDR network address."""
    try:
        ipaddress.ip_network(str(value), strict=True)
    except ValueError:
        raise ValidationError("Enter a valid CIDR network, for example 10.20.0.0/24.")


class CIDRField(models.Field):
    """
    Network address column that validates and stores IPv4 and IPv6 CIDR blocks.
    It restricts exam access to authorized on-campus laboratory subnets like 10.20.0.0/24.
    """

    description = "PostgreSQL CIDR network"

    def __init__(self, *args, **kwargs):
        """Initializes a CIDR database field with its maximum string length and validator."""
        kwargs.setdefault("max_length", 43)
        super().__init__(*args, **kwargs)
        self.validators.append(validate_cidr)

    def db_type(self, connection):
        """Return the database column type used to store this network field."""
        return "cidr"

    def from_db_value(self, value, expression, connection):
        """Converts a CIDR value loaded from the database into a Python string."""
        if value is None:
            return None
        return str(value)

    def to_python(self, value):
        """Converts an assigned CIDR value into the field's Python representation."""
        if value in (None, ""):
            return None
        return str(value)

    def get_prep_value(self, value):
        """Prepares a CIDR value for saving to PostgreSQL."""
        if value in (None, ""):
            return None
        return str(ipaddress.ip_network(str(value), strict=True))


SHA256_HEX = 64

ALLOWED_UPLOAD_MIME_TYPES = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/png",
    "image/jpeg",
    "text/plain",
    "application/msword",
    "application/vnd.ms-powerpoint",
    "application/vnd.ms-excel",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.spreadsheet",
    "text/csv",
    "text/markdown",
    "image/gif",
    "image/webp",
    "video/mp4",
    "audio/mpeg",
    # Zip archives are stored as-is and never extracted on the server.
    "application/zip",
]

# 25 MiB upload ceiling enforced by Django validation and reverse proxies.
MAX_UPLOAD_BYTES = 26214400


# Enumerations


class AcademicLevel(models.TextChoices):
    """
    Academic standing levels from foundation year through master's study.
    These values control student access to module content and track progression.
    """

    FOUNDATION = "level_3", "Foundation (Level 3)"
    YEAR_1 = "level_4", "Year 1 (Level 4)"
    YEAR_2 = "level_5", "Year 2 (Level 5)"
    YEAR_3 = "level_6", "Year 3 (Level 6)"
    YEAR_4 = "level_7", "Year 4 (Level 7)"
    MASTERS = "level_8", "Masters (Level 8)"


class SemesterType(models.TextChoices):
    """
    Numbered university semesters used to separate academic course periods.
    """

    SEMESTER_1 = "1", "Semester 1"
    SEMESTER_2 = "2", "Semester 2"
    SEMESTER_3 = "3", "Semester 3"


class CourseStaffRole(models.TextChoices):
    """
    Instructional roles assigned to course staff.
    Lead instructors manage the course and release final grades.
    Teaching assistants handle attendance rolls and enter draft scores.
    """

    LEAD_INSTRUCTOR = "lead_instructor", "Lead Instructor"
    CO_INSTRUCTOR = "co_instructor", "Co-Instructor"
    TEACHING_ASSISTANT = "teaching_assistant", "Teaching Assistant"


class GradeComponentType(models.TextChoices):
    """
    Syllabus grading categories.
    Each category has an assigned percentage weight that contributes to the final course grade.
    """

    COURSEWORK = "coursework", "Coursework"
    QUIZ = "quiz", "Quiz"
    EXAM = "exam", "Exam"
    ASSIGNMENT = "assignment", "Assignment"
    LAB = "lab", "Lab"


class EnrollmentStatus(models.TextChoices):
    """
    Student registration statuses within a course.
    Records track whether a student is actively enrolled, dropped, completed, or withdrawn.
    """

    ACTIVE = "active", "Active"
    DROPPED = "dropped", "Dropped"
    COMPLETED = "completed", "Completed"
    WITHDRAWN = "withdrawn", "Withdrawn"


class SessionType(models.TextChoices):
    """
    Class meeting formats for timetables.
    Options distinguish lectures from laboratory sessions, tutorials, and seminars.
    """

    LECTURE = "lecture", "Lecture"
    LAB = "lab", "Lab"
    TUTORIAL = "tutorial", "Tutorial"
    SEMINAR = "seminar", "Seminar"


class DayOfWeek(models.TextChoices):
    """
    Days of the week used for recurring timetable schedules.
    """

    MONDAY = "monday", "Monday"
    TUESDAY = "tuesday", "Tuesday"
    WEDNESDAY = "wednesday", "Wednesday"
    THURSDAY = "thursday", "Thursday"
    FRIDAY = "friday", "Friday"
    SATURDAY = "saturday", "Saturday"
    SUNDAY = "sunday", "Sunday"


class AttendanceMethod(models.TextChoices):
    """
    Check-in mechanisms for student attendance.
    Students scan a dynamic QR code or enter a passcode. Staff can also log attendance manually.
    """

    PASSCODE = "passcode", "Dynamic Passcode"
    QR_CODE = "qr_code", "Quick Response Code"
    MANUAL = "manual", "Manual Roll"


class AttendanceStatus(models.TextChoices):
    """
    Outcomes for individual attendance records.
    Options record whether a student was present, absent, late, or excused.
    """

    PRESENT = "present", "Present"
    ABSENT = "absent", "Absent"
    LATE = "late", "Late"
    EXCUSED = "excused", "Excused"


class AttemptStatus(models.TextChoices):
    """
    Lifecycle stages for an assessment attempt.
    Attempts start in progress, move to manual grading when needed, and finish once scored.
    """

    IN_PROGRESS = "In_Progress", "In Progress"
    REQUIRES_MANUAL_GRADING = "Requires_Manual_Grading", "Requires Manual Grading"
    FULLY_GRADED = "Fully_Graded", "Fully Graded"


class GradeStatus(models.TextChoices):
    """
    Approval stages for grades and final course results.
    Marks move from draft scores to finalized grades, and then to released results.
    """

    DRAFT = "draft", "Draft"
    FINALIZED = "finalized", "Finalized"
    RELEASED = "released", "Released"


class ChangeRequestStatus(models.TextChoices):
    """
    Review stages for post-release grade change requests.
    Requests stay pending until the department head approves or rejects the change.
    """

    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"


# User Manager & Custom User Model


class UserManager(BaseUserManager):
    """
    User manager for account creation and Argon2id password hashing.
    Superuser creation assigns the Kura Admin role, which has administrative rights without grade access.
    """

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a user account with a normalized email address."""
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        # Password complexity/HIBP validation runs in the calling forms before create_user; CLI/tests use create_user directly.
        if password:
            user.set_password(password)  # nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    @classmethod
    def normalize_email(cls, email):
        """Normalize account emails consistently with NFKC and lowercase ASCII handling."""
        if not email:
            return ""
        import unicodedata

        return unicodedata.normalize("NFKC", str(email).strip()).strip().lower()

    def create_superuser(self, email, password=None, **extra_fields):
        """Create a user with active status and the Admin system role."""
        extra_fields.setdefault("is_active", True)
        user = self.create_user(email, password, **extra_fields)
        admin_role, _ = Role.objects.get_or_create(
            name="Admin",
            defaults={"description": "System administrator (no grade access)"},
        )
        UserRole.objects.get_or_create(user=user, role=admin_role)
        return user


class User(AbstractBaseUser):
    """
    User accounts, authentication credentials, and multi-factor settings.
    Passwords use Argon2id hashes, and failed-login lockouts live in django-axes tables.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255, db_column="password_hash")
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    mfa_secret = models.CharField(max_length=255, null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    must_change_password = models.BooleanField(default=True)
    # Admin-imposed lock from the user management interface.
    # Failed login attempts use separate, temporary locks tracked in django-axes.
    locked_until = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True, db_column="last_login_at")
    password_changed_at = models.DateTimeField(null=True, blank=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    is_processing_restricted = models.BooleanField(default=False)
    erasure_requested_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="created_users"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    @property
    def username(self):
        """Provides the email through Django integrations expecting a username property."""
        return self.email

    class Meta:
        db_table = "users"
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        """Formats this user's name and email for readable display."""
        return f"{self.first_name} {self.last_name} ({self.email})"

    @property
    def last_login_at(self):
        """Exposes Django's last_login value under the project's legacy property name."""
        return self.last_login

    @last_login_at.setter
    def last_login_at(self, value):
        """Set Django's last_login field through the legacy property name."""
        self.last_login = value

    # Authorization runs through Kura's custom roles and permissions layer.
    # Standard Django model permissions default to False.
    def has_perm(self, perm, obj=None):
        """Denies Django model permissions for this custom user model."""
        return False

    def has_module_perms(self, app_label):
        """Denies Django module permissions for this custom user model."""
        return False


# Departments & Roles & Permissions


class Department(models.Model):
    """
    Academic departments and their appointed department heads.
    Department heads manage departmental courses, staff assignments, and post-release grade approvals.
    """

    id = models.AutoField(primary_key=True)
    code = models.CharField(max_length=10, unique=True)
    name = models.CharField(max_length=150)
    head_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="headed_departments",
        db_column="head_user_id",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "departments"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.code} - {self.name}"


class Building(models.Model):
    """A building that contains staff offices."""

    name = models.CharField(max_length=80, unique=True)

    def __str__(self):
        return self.name


class Room(models.Model):
    """An office room in a building."""

    building = models.ForeignKey(Building, on_delete=models.PROTECT, related_name="rooms")
    name = models.CharField(max_length=80)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["building", "name"], name="unique_building_room")]

    def __str__(self):
        return f"{self.building.name}, {self.name}"


class Role(models.Model):
    """
    System roles with distinct permissions across the platform.
    Roles isolate responsibilities, such as keeping administrators from reading student grade records.
    """

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "roles"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return self.name


class UserRole(models.Model):
    """
    User-to-role assignments with audit details.
    Users can hold multiple roles simultaneously, such as a student working as a teaching assistant.
    """

    pk = models.CompositePrimaryKey("user", "role")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="user_roles")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_roles")
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_user_roles"
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_roles"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.user} - {self.role}"


class SystemPermission(models.Model):
    """
    Fine-grained permissions defined by an action, a resource, and a visibility scope.
    Scopes restrict operations to a single course, a department, or the entire institution.
    """

    id = models.AutoField(primary_key=True)
    action = models.CharField(max_length=30)
    resource = models.CharField(max_length=50)
    scope = models.CharField(max_length=50)
    description = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "permissions"
        unique_together = (("action", "resource", "scope"),)

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.action}:{self.resource}:{self.scope}"


class RolePermission(models.Model):
    """
    Permissions granted to specific system roles.
    Middleware evaluates these pairs on every request to enforce access controls.
    """

    pk = models.CompositePrimaryKey("role", "permission")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="role_permissions")
    permission = models.ForeignKey(SystemPermission, on_delete=models.CASCADE, related_name="role_permissions")

    class Meta:
        db_table = "role_permissions"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.role} -> {self.permission}"


# Profiles


class StudentProfile(models.Model):
    """
    Student academic records, including matriculation year and current standing.
    Modules check this level against target rules to restrict advanced coursework.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="student_profile",
        db_column="user_id",
    )
    department = models.ForeignKey(Department, on_delete=models.PROTECT, related_name="student_profiles")
    current_level = models.CharField(max_length=30, choices=AcademicLevel.choices)
    matriculation_year = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "student_profiles"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Student: {self.user} ({self.current_level})"


class StaffProfile(models.Model):
    """
    Staff employment details, including titles, office locations, and home departments.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="staff_profile",
        db_column="user_id",
    )
    department = models.ForeignKey(
        Department, on_delete=models.SET_NULL, null=True, blank=True, related_name="staff_profiles"
    )
    staff_title = models.CharField(max_length=100)
    office_location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "staff_profiles"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Staff: {self.user} - {self.staff_title}"


# Auth Tokens, Sessions & Login Tracking


class PasswordResetToken(models.Model):
    """
    Single-use password reset tokens stored as SHA-256 hashes.
    Tokens expire after 30 minutes, and redeeming a token revokes active user sessions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token_hash = FixedCharField(max_length=SHA256_HEX, unique=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "password_reset_tokens"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"ResetToken for {self.user} (Expires: {self.expires_at})"


class UserSession(models.Model):
    """
    Active user sessions tracked with SHA-256 bearer token hashes.
    Records store client IP addresses and user agents, and allow immediate session revocation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="user_sessions")
    session_token_hash = FixedCharField(max_length=SHA256_HEX, unique=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "user_sessions"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Session {self.id} - {self.user}"


# Courses & Staff


class Course(models.Model):
    """
    Course catalog entries organized by academic year, semester, and department.
    Draft courses remain hidden from student catalogs until an instructor publishes them.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    department = models.ForeignKey(Department, on_delete=models.PROTECT, related_name="courses")
    code = models.CharField(max_length=30, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    semester = models.CharField(max_length=20, choices=SemesterType.choices)
    academic_year = models.IntegerField()
    is_published = models.BooleanField(default=False)
    # Department head who approved and published the course.
    published_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="published_courses"
    )
    published_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_courses"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "courses"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(is_published=False)
                | (models.Q(published_by__isnull=False) & models.Q(published_at__isnull=False)),
                name="published_course_records_publisher",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.code} - {self.title}"


class CourseStaff(models.Model):
    """
    Staff assignments for a course, including instructors and teaching assistants.
    The can_release_grades flag controls whether a staff member can publish final marks.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="course_staff")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="course_staff_assignments"
    )
    staff_role = models.CharField(max_length=30, choices=CourseStaffRole.choices)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_course_staff"
    )
    can_release_grades = models.BooleanField(default=False)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "course_staff"
        unique_together = (("course", "user"),)

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.user} as {self.staff_role} in {self.course}"


class Enrollment(models.Model):
    """
    Student registrations in courses.
    The record tracks registration status and logs the registrar who handled enrollment or drop actions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="enrollments")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="enrollments")
    status = models.CharField(max_length=20, choices=EnrollmentStatus.choices, default=EnrollmentStatus.ACTIVE)
    enrolled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="processed_enrollments"
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)
    # Registrar who processed the student drop.
    dropped_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="processed_drops"
    )
    dropped_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "enrollments"
        unique_together = (("course", "student"),)
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(status=EnrollmentStatus.DROPPED)
                | (models.Q(dropped_by__isnull=False) & models.Q(dropped_at__isnull=False)),
                name="dropped_enrollment_records_registrar",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.student} in {self.course} ({self.status})"


# Course materials


class CourseFile(models.Model):
    """
    A course material file (slides, notes, handouts) listed on the course page.
    Students can download it only when the course is published and the file is visible.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="course_files")
    file = models.OneToOneField(
        "StoredFile", on_delete=models.CASCADE, related_name="course_attachment", db_column="file_id"
    )
    title = models.CharField(max_length=255)
    is_visible = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "course_files"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.course.code} - {self.title}"


# File Storage (Metadata & Binaries)


class StoredFile(models.Model):
    """
    Metadata for uploaded files, including original filenames, MIME types, and SHA-256 hashes.
    Files have a 25 MiB cap, and binaries reside separately in the file contents table.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="uploaded_files")
    original_filename = models.CharField(max_length=255)
    mime_type = models.CharField(max_length=100)
    # Enforces a maximum file size of 25 MiB.
    size_bytes = models.BigIntegerField(validators=[MinValueValidator(1), MaxValueValidator(MAX_UPLOAD_BYTES)])
    sha256_hash = FixedCharField(max_length=SHA256_HEX)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "stored_files"
        # Database-level copies of the upload rules, so a bug in the app cannot store an oversize or unlisted file type.
        constraints = [
            models.CheckConstraint(
                condition=models.Q(size_bytes__gt=0) & models.Q(size_bytes__lte=MAX_UPLOAD_BYTES),
                name="stored_file_size_within_limit",
            ),
            models.CheckConstraint(
                condition=models.Q(mime_type__in=ALLOWED_UPLOAD_MIME_TYPES),
                name="stored_file_mime_type_allowlisted",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.original_filename} ({self.size_bytes} bytes)"


class FileContent(models.Model):
    """
    Raw file binaries stored in a PostgreSQL bytea column.
    Keeping binaries separate lets maintenance and reporting roles read metadata without loading files.
    """

    file = models.OneToOneField(
        StoredFile, on_delete=models.CASCADE, primary_key=True, related_name="content", db_column="file_id"
    )
    # With Vault on, `content` is AES-256-GCM ciphertext. `wrapped_key` is the per-file data key encrypted by Vault,
    # and `nonce` is the GCM nonce. encryption_version 0 marks a legacy or development row stored as plain bytes.
    content = models.BinaryField()
    wrapped_key = models.TextField(blank=True, default="")
    nonce = models.BinaryField(max_length=12, blank=True, default=b"")
    encryption_version = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "file_contents"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Binary Content for {self.file_id}"


class OutgoingEmailStatus(models.TextChoices):
    """
    Where an email is in the outbox: waiting, pending lookup, sent, or given up on.
    """

    PENDING = "pending", "Pending"
    PENDING_LOOKUP = "pending_lookup", "Pending lookup"
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"


class OutgoingEmail(models.Model):
    """
    The outbox. Views never send email themselves: they save a row here and
    answer straight away (so a password-reset page answers just as fast whether
    or not the account exists). The send_queued_emails command sends pending rows.
    event_key is unique, so the database refuses a second copy of the same
    notification (for example "reminder-24h:<assessment>:<student>").
    The body is wiped once the email is sent or given up on, because it can
    contain a password-reset link.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_key = models.CharField(max_length=255, unique=True)
    to_email = models.EmailField(max_length=255)
    subject = models.CharField(max_length=200)
    body = models.TextField()
    status = models.CharField(max_length=20, choices=OutgoingEmailStatus.choices, default=OutgoingEmailStatus.PENDING)
    attempts = models.PositiveSmallIntegerField(default=0)
    last_error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "outgoing_emails"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.event_key} ({self.status})"


class QuarantinedFile(models.Model):
    """
    An upload that ClamAV rejected (a virus, an encrypted file, or a macro).
    The bytes are kept for 7 days so an Admin can investigate, then deleted by
    the purge_quarantine command. Kept apart from stored_files on purpose: the
    normal download view only serves StoredFile, so these bytes can never be
    downloaded through the website.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="quarantined_files"
    )
    original_filename = models.CharField(max_length=255)
    # Same 25 MiB ceiling as normal uploads.
    size_bytes = models.BigIntegerField(validators=[MinValueValidator(1), MaxValueValidator(MAX_UPLOAD_BYTES)])
    sha256_hash = FixedCharField(max_length=SHA256_HEX)
    # What ClamAV reported, e.g. "Eicar-Test-Signature" or "Heuristics.Encrypted.Zip".
    detection = models.CharField(max_length=255)
    content = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "quarantined_files"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(size_bytes__gt=0) & models.Q(size_bytes__lte=MAX_UPLOAD_BYTES),
                name="quarantined_file_size_within_limit",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Quarantined {self.original_filename} ({self.detection})"


# Schedules & Attendance


class Schedule(models.Model):
    """
    Recurring meeting slots, session formats, and classroom locations for courses.
    End times must be later than start times.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="schedules")
    instructor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="instructor_schedules"
    )
    session_type = models.CharField(max_length=20, choices=SessionType.choices)
    day = models.CharField(max_length=20, choices=DayOfWeek.choices)
    start_time = models.TimeField()
    end_time = models.TimeField()
    location = models.CharField(max_length=150)
    recurrence_start = models.DateField()
    recurrence_end = models.DateField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_schedules"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "schedules"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(end_time__gt=models.F("start_time")), name="schedule_end_time_after_start"
            )
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.course.code} - {self.day} {self.start_time}-{self.end_time} at {self.location}"


class ModuleAttendanceSession(models.Model):
    """
    Time-limited attendance check-in windows.
    Sessions generate rotating passcodes and QR codes that expire when the session ends.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="attendance_sessions")
    schedule = models.ForeignKey(
        Schedule, on_delete=models.SET_NULL, null=True, blank=True, related_name="attendance_sessions"
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="initiated_attendance_sessions"
    )
    title = models.CharField(max_length=150)
    # Attendance sessions accept QR code, passcode, and manual roll.
    # The QR code encodes the dynamic passcode.
    passcode_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "module_attendance_sessions"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.title} - Active: {self.is_active}"


class AttendanceRecord(models.Model):
    """
    Student check-in records, capturing check-in methods, timestamps, and client IP addresses.
    Manual corrections require an instructor foreign key and a written reason.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(ModuleAttendanceSession, on_delete=models.CASCADE, related_name="records")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="attendance_records")
    status = models.CharField(max_length=20, choices=AttendanceStatus.choices, default=AttendanceStatus.PRESENT)
    # Determined by the server from the check-in endpoint used.
    method = models.CharField(max_length=20, choices=AttendanceMethod.choices)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="recorded_attendance_entries",
    )
    override_reason = models.TextField(null=True, blank=True)
    verified_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "attendance_records"
        unique_together = (("session", "student"),)
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(method=AttendanceMethod.MANUAL)
                | (
                    models.Q(recorded_by__isnull=False)
                    & models.Q(override_reason__isnull=False)
                    & ~models.Q(override_reason="")
                ),
                name="manual_attendance_requires_staff_and_reason",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.student} - {self.session.title}: {self.status}"


# Assessments & Submissions


class Assessment(models.Model):
    """
    Coursework briefs that students answer by uploading files.
    Each assessment belongs to one course and has an opening time and a due date.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="assessments")
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    component_type = models.CharField(max_length=30, choices=GradeComponentType.choices)
    max_score = models.DecimalField(max_digits=6, decimal_places=2, default=Decimal("100.00"))
    max_attempts = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    opens_at = models.DateTimeField()
    due_date = models.DateTimeField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_assessments"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "assessments"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(due_date__gt=models.F("opens_at")), name="assessment_due_date_after_opens_at"
            ),
            models.CheckConstraint(
                condition=models.Q(max_attempts__gte=1),
                name="assessment_max_attempts_min_1",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.title} ({self.component_type})"


class AssessmentFile(models.Model):
    """
    Staff-uploaded materials attached to an assessment, such as briefs or datasets.
    Enrolled students can download them while the course is published.
    """

    pk = models.CompositePrimaryKey("assessment", "file")
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name="assessment_files")
    file = models.OneToOneField(
        StoredFile, on_delete=models.CASCADE, related_name="assessment_attachment", db_column="file_id"
    )
    attached_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "assessment_files"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"File {self.file_id} attached to Assessment {self.assessment_id}"


class AssessmentAttempt(models.Model):
    """
    One student's submission for an assessment, with the files they uploaded.
    Submitting generates a SHA-256 hash for non-repudiation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name="attempts")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="assessment_attempts")
    attempt_no = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    status = models.CharField(max_length=30, choices=AttemptStatus.choices, default=AttemptStatus.IN_PROGRESS)
    started_at = models.DateTimeField(auto_now_add=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    # Set when the attempt is sealed. The hash covers the files, and the signature covers the hash plus identifiers
    # (see kura/signing.py), so a later edit to either is detectable.
    submission_hash = FixedCharField(max_length=SHA256_HEX, null=True, blank=True)
    submission_signature = models.TextField(blank=True, default="")

    class Meta:
        db_table = "assessment_attempts"
        unique_together = (("assessment", "student", "attempt_no"),)
        constraints = [
            models.CheckConstraint(
                condition=models.Q(attempt_no__gte=1),
                name="attempt_no_min_1",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.student} - {self.assessment.title} (Attempt #{self.attempt_no})"


class AttemptFile(models.Model):
    """
    Student coursework files attached to an assessment attempt.
    Students can add or replace files while the attempt is in progress, and uploads lock upon submission.
    """

    pk = models.CompositePrimaryKey("attempt", "file")
    attempt = models.ForeignKey(AssessmentAttempt, on_delete=models.CASCADE, related_name="attempt_files")
    file = models.OneToOneField(
        StoredFile, on_delete=models.CASCADE, related_name="attempt_attachment", db_column="file_id"
    )
    attached_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "attempt_files"

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"File {self.file_id} attached to Attempt {self.attempt_id}"


# Grades, Grade History & Results


class Grade(models.Model):
    """
    Assessment scores across draft, finalized, and released approval states.
    Teaching assistants enter draft marks, and instructors finalize and release scores.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name="grades")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="grades")
    attempt = models.OneToOneField(AssessmentAttempt, on_delete=models.CASCADE, related_name="grade")
    grader = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="graded_grades"
    )
    score = models.DecimalField(max_digits=6, decimal_places=2, validators=[MinValueValidator(0)])
    # Written comments from the marker.
    # Students see them only once the grade is released.
    feedback = models.TextField(blank=True, default="")
    status = models.CharField(max_length=20, choices=GradeStatus.choices, default=GradeStatus.DRAFT)
    graded_at = models.DateTimeField(auto_now_add=True)
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="finalized_grades"
    )
    finalized_at = models.DateTimeField(null=True, blank=True)
    # Signatures made when the grade was finalized and released. They let a later check detect a score changed in the database.
    finalization_signature = models.TextField(blank=True, default="")
    released_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="released_grades"
    )
    released_at = models.DateTimeField(null=True, blank=True)
    release_signature = models.TextField(blank=True, default="")

    class Meta:
        db_table = "grades"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(score__gte=0),
                name="grade_score_non_negative",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.student} - {self.assessment.title}: {self.score} ({self.status})"


class GradeHistory(models.Model):
    """
    Append-only audit ledger of grade modifications and status changes.
    Changing a released grade requires written department head approval and an explanation.
    """

    id = models.BigAutoField(primary_key=True)
    grade = models.ForeignKey(Grade, on_delete=models.CASCADE, related_name="history")
    old_score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    new_score = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    old_status = models.CharField(max_length=20, choices=GradeStatus.choices, null=True, blank=True)
    new_status = models.CharField(max_length=20, choices=GradeStatus.choices, null=True, blank=True)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="grade_changes")
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="approved_grade_changes"
    )
    reason = models.TextField(null=True, blank=True)
    # Approved change request authorizing a post-release grade modification.
    change_request = models.ForeignKey(
        "GradeChangeRequest", on_delete=models.PROTECT, null=True, blank=True, related_name="history_entries"
    )
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "grade_history"
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(old_status=GradeStatus.RELEASED)
                | (
                    models.Q(approved_by__isnull=False)
                    & models.Q(reason__isnull=False)
                    & ~models.Q(reason="")
                ),
                name="released_grade_change_requires_approval_and_reason",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"History #{self.id} for Grade {self.grade_id} ({self.old_score} -> {self.new_score})"


class GradeChangeRequest(models.Model):
    """
    Formal requests to alter released grades.
    Course instructors submit requests, and department heads approve or reject them. Self-approval is blocked.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    grade = models.ForeignKey(Grade, on_delete=models.CASCADE, related_name="change_requests")
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="requested_grade_changes"
    )
    current_score = models.DecimalField(max_digits=6, decimal_places=2)
    proposed_score = models.DecimalField(max_digits=6, decimal_places=2)
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=ChangeRequestStatus.choices, default=ChangeRequestStatus.PENDING)
    # Department head reviewing the change request.
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name="reviewed_grade_changes"
    )
    review_note = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "grade_change_requests"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(proposed_score__gte=0),
                name="change_request_score_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(status=ChangeRequestStatus.PENDING)
                | (models.Q(reviewed_by__isnull=False) & models.Q(reviewed_at__isnull=False)),
                name="change_request_decision_records_reviewer",
            ),
            models.CheckConstraint(
                condition=~models.Q(requested_by=models.F("reviewed_by")),
                name="change_request_no_self_approval",
            ),
            models.UniqueConstraint(
                fields=["grade"],
                condition=models.Q(status=ChangeRequestStatus.PENDING),
                name="one_pending_change_request_per_grade",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"Change request on Grade {self.grade_id}: {self.current_score} -> {self.proposed_score} ({self.status})"


class CourseResult(models.Model):
    """
    Weighted final scores and official transcript release statuses for a course.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name="results")
    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="course_results")
    final_score = models.DecimalField(
        max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    status = models.CharField(max_length=20, choices=GradeStatus.choices, default=GradeStatus.DRAFT)
    finalized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finalized_course_results",
    )
    finalized_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "course_results"
        unique_together = (("course", "student"),)
        constraints = [
            models.CheckConstraint(
                condition=models.Q(final_score__gte=0) & models.Q(final_score__lte=100),
                name="course_result_final_score_0_to_100",
            ),
        ]

    def __str__(self):
        """Formats this model's identifying fields for readable display."""
        return f"{self.student} in {self.course}: {self.final_score} ({self.status})"


class PasswordHistory(models.Model):
    """Previous password hashes, used to block reuse of recent passwords (AUTH-06)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_history")
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "password_history"
        ordering = ["-created_at"]


class SecurityPolicy(models.Model):
    """Single-row configurable security policy edited by Admins with step-up MFA (O6)."""

    # The primary key is always 1 (see the singleton constraint below). The validators set the safe range an Admin may choose.
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    min_password_length = models.PositiveSmallIntegerField(
        default=12, validators=[MinValueValidator(12), MaxValueValidator(128)]
    )
    password_history_count = models.PositiveSmallIntegerField(
        default=5, validators=[MinValueValidator(1), MaxValueValidator(24)]
    )
    axes_failure_limit = models.PositiveSmallIntegerField(
        default=5, validators=[MinValueValidator(3), MaxValueValidator(20)]
    )
    axes_cooloff_hours = models.PositiveSmallIntegerField(
        default=1, validators=[MinValueValidator(1), MaxValueValidator(24)]
    )
    session_idle_minutes = models.PositiveSmallIntegerField(
        default=30, validators=[MinValueValidator(5), MaxValueValidator(240)]
    )
    session_absolute_hours = models.PositiveSmallIntegerField(
        default=12, validators=[MinValueValidator(1), MaxValueValidator(72)]
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_security_policies",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "security_policies"
        constraints = [
            models.CheckConstraint(condition=models.Q(id=1), name="security_policy_singleton"),
            models.CheckConstraint(
                condition=models.Q(min_password_length__gte=12) & models.Q(min_password_length__lte=128),
                name="security_policy_min_pw_bounds",
            ),
            models.CheckConstraint(
                condition=models.Q(password_history_count__gte=1) & models.Q(password_history_count__lte=24),
                name="security_policy_pw_history_bounds",
            ),
            models.CheckConstraint(
                condition=models.Q(axes_failure_limit__gte=3) & models.Q(axes_failure_limit__lte=20),
                name="security_policy_axes_limit_bounds",
            ),
            models.CheckConstraint(
                condition=models.Q(axes_cooloff_hours__gte=1) & models.Q(axes_cooloff_hours__lte=24),
                name="security_policy_axes_cooloff_bounds",
            ),
            models.CheckConstraint(
                condition=models.Q(session_idle_minutes__gte=5) & models.Q(session_idle_minutes__lte=240),
                name="security_policy_idle_bounds",
            ),
            models.CheckConstraint(
                condition=models.Q(session_absolute_hours__gte=1) & models.Q(session_absolute_hours__lte=72),
                name="security_policy_absolute_bounds",
            ),
        ]

    def __str__(self):
        return "Active Security Policy"


def get_security_policy():
    """Return active SecurityPolicy values from the DB, falling back to settings defaults."""
    # Defaults come from settings, so the site still works before the policy row exists or while the database is down.
    min_pw = 12
    for validator in getattr(settings, "AUTH_PASSWORD_VALIDATORS", []):
        if validator["NAME"].endswith("MinimumLengthValidator"):
            min_pw = validator.get("OPTIONS", {}).get("min_length", 12)

    raw_limit = getattr(settings, "AXES_FAILURE_LIMIT", 5)
    default_limit = raw_limit if isinstance(raw_limit, int) else 5

    raw_cooloff = getattr(settings, "AXES_COOLOFF_TIME", 1)
    default_cooloff = raw_cooloff if isinstance(raw_cooloff, int) else 1

    defaults = {
        "min_password_length": min_pw,
        "password_history_count": getattr(settings, "PASSWORD_HISTORY_COUNT", 5),
        "axes_failure_limit": default_limit,
        "axes_cooloff_hours": default_cooloff,
        "session_idle_minutes": max(1, getattr(settings, "SESSION_COOKIE_AGE", 1800) // 60),
        "session_absolute_hours": getattr(settings, "SESSION_ABSOLUTE_HOURS", 12),
    }
    # A saved policy row overrides the defaults.
    try:
        row = SecurityPolicy.objects.filter(pk=1).first()
    except DatabaseError:
        return defaults
    if row is None:
        return defaults
    return {
        "min_password_length": row.min_password_length,
        "password_history_count": row.password_history_count,
        "axes_failure_limit": row.axes_failure_limit,
        "axes_cooloff_hours": row.axes_cooloff_hours,
        "session_idle_minutes": row.session_idle_minutes,
        "session_absolute_hours": row.session_absolute_hours,
    }

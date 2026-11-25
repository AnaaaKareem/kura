import logging

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .logging_utils import log_security_event
from .models import (
    AcademicLevel,
    Assessment,
    AttendanceStatus,
    ChangeRequestStatus,
    Course,
    DayOfWeek,
    Department,
    Building,
    Room,
    GradeComponentType,
    GradeStatus,
    EnrollmentStatus,
    PasswordHistory,
    Role,
    SecurityPolicy,
    SemesterType,
    SessionType,
    User,
    get_security_policy,
)
from .text_safety import has_mixed_scripts, normalize_email, normalize_text


class SafeTextMixin:
    """Normalize and validate Unicode text/email inputs before field validators run (G08).

    Who can use it: All non-password text/email forms in kura/forms.py.
    Security: Applies NFKC normalization, blocks bidi/control characters, requires ASCII
    for EmailField, and logs mixed-script tokens without modifying PasswordInput values.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.PasswordInput):
                continue
            if isinstance(field, forms.EmailField):
                orig_to_python = field.to_python

                def _safe_email_to_python(value, _orig=orig_to_python):
                    coerced = _orig(value)
                    return normalize_email(coerced)

                field.to_python = _safe_email_to_python
            elif isinstance(field, forms.CharField):
                orig_to_python = field.to_python
                is_multiline = isinstance(field.widget, forms.Textarea)

                def _safe_text_to_python(
                    value,
                    _orig=orig_to_python,
                    _multiline=is_multiline,
                    _fname=field_name,
                    _form_cls=self.__class__.__name__,
                ):
                    coerced = _orig(value)
                    if not coerced:
                        return coerced
                    normalized = normalize_text(coerced, multiline=_multiline)
                    if has_mixed_scripts(normalized):
                        log_security_event(
                            None,
                            "input.mixed_script",
                            {"field": _fname, "form": _form_cls},
                            level=logging.INFO,
                        )
                    return normalized

                field.to_python = _safe_text_to_python


def password_was_used_recently(user, raw_password):
    """Return True if raw_password matches the current password or recent history (AUTH-06)."""
    if user.check_password(raw_password):
        return True
    history_limit = get_security_policy()["password_history_count"]
    recent_hashes = PasswordHistory.objects.filter(user=user).order_by("-created_at", "-id")[:history_limit]
    for entry in recent_hashes:
        if check_password(raw_password, entry.password_hash):
            return True
    return False


def validate_password_policy(raw_password, user=None):
    """Validate raw_password against Django validators and the live SecurityPolicy min length."""
    validate_password(raw_password, user)
    min_length = get_security_policy()["min_password_length"]
    if len(raw_password) < min_length:
        raise ValidationError(
            f"This password is too short. It must contain at least {min_length} characters.",
            code="password_too_short",
        )


class AdminCourseFilterForm(forms.Form):
    """Validate administrator course catalog filters."""

    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False)
    semester = forms.ChoiceField(choices=[("", "All semesters")] + list(SemesterType.choices), required=False)
    year = forms.IntegerField(required=False, min_value=1900, max_value=9999)
    published = forms.ChoiceField(choices=[("", "All statuses"), ("yes", "Published"), ("no", "Draft")], required=False)


class AdminStaffFilterForm(SafeTextMixin, forms.Form):
    """Validate administrator staff account filters."""

    q = forms.CharField(required=False, max_length=150, label="Name or email")
    role = forms.ChoiceField(
        required=False,
        choices=[
            ("", "All roles"),
            ("Admin", "Admin"),
            ("Registrar", "Registrar"),
            ("Department head", "Department head"),
            ("Instructor", "Instructor"),
            ("Teaching assistant", "Teaching assistant"),
        ],
    )
    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False)
    status = forms.ChoiceField(
        required=False,
        choices=[("", "All statuses"), ("active", "Active"), ("locked", "Locked"), ("deactivated", "Deactivated")],
    )


class AdminUserFilterForm(SafeTextMixin, forms.Form):
    """Validate administrator all-account directory filters (no grade data)."""

    q = forms.CharField(required=False, max_length=150, label="Name or email")
    role = forms.ChoiceField(
        required=False,
        choices=[
            ("", "All roles"),
            ("Admin", "Admin"),
            ("Registrar", "Registrar"),
            ("Department head", "Department head"),
            ("Instructor", "Instructor"),
            ("Teaching assistant", "Teaching assistant"),
            ("Student", "Student"),
        ],
    )
    status = forms.ChoiceField(
        required=False,
        choices=[("", "All statuses"), ("active", "Active"), ("locked", "Locked"), ("deactivated", "Deactivated")],
    )


class AdminSessionFilterForm(SafeTextMixin, forms.Form):
    """Validate the search and filters for the administrator's session list."""

    # Limit the inputs used to search session records.
    q = forms.CharField(required=False, max_length=150, label="Name or email")
    ip = forms.CharField(required=False, max_length=45, label="IP address starts with")
    role = forms.ChoiceField(
        required=False,
        choices=[
            ("", "All roles"),
            ("Admin", "Admin"),
            ("Registrar", "Registrar"),
            ("Department head", "Department head"),
            ("Instructor", "Instructor"),
            ("Teaching assistant", "Teaching assistant"),
            ("Student", "Student"),
        ],
    )
    state = forms.ChoiceField(
        required=False,
        choices=[
            ("active", "Active"),
            ("revoked", "Revoked"),
            ("expired", "Expired"),
        ],
        initial="active",
    )


class AdminSessionRevokeForm(forms.Form):
    """Validate which session or user's sessions an administrator wants to end."""

    # Use UUID fields so malformed identifiers cannot reach the database lookup.
    action = forms.ChoiceField(choices=[("one", "One session"), ("all", "All sessions")])
    session_id = forms.UUIDField(required=False)
    user_id = forms.UUIDField(required=False)


class UserRoleChangeForm(forms.Form):
    """Validate an administrator's request to assign or remove a system role."""

    # Only these two actions are allowed; an unknown action is rejected by the form.
    action = forms.ChoiceField(choices=[("assign", "Assign"), ("remove", "Remove")])

    # ModelChoiceField rejects a non-existent or non-numeric role ID before any query change.
    role_id = forms.ModelChoiceField(queryset=Role.objects.all())


class LoginForm(SafeTextMixin, forms.Form):
    """
    Form for user authentication with email and password.
    """

    # Email address of the user attempting to log in.
    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "name@example.com",
                "autocomplete": "email",
            }
        ),
    )

    # Password for authentication.
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your password",
                "autocomplete": "current-password",
            }
        ),
    )


class PasswordChangeForm(forms.Form):
    """
    Form for changing an account password.
    Enforces minimum length of 12 characters and breach checks.
    """

    # Current account password to confirm identity.
    old_password = forms.CharField(
        label="Current password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "current-password",
            }
        ),
    )

    # New password to replace the current one.
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    # Confirmation entry to prevent typing mistakes.
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    def __init__(self, user, *args, request=None, **kwargs):
        """Connect this password-change form to the account being updated.
        The request is optional so direct form use still works; when present,
        django-axes can count a wrong current password.
        """
        self.user = user
        self.request = request
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        """Check that the submitted current password matches this user's password."""
        # Use authenticate() so django-axes counts wrong current passwords toward AXES_FAILURE_LIMIT (AUTH-07).
        old_password = self.cleaned_data.get("old_password")
        if self.request is not None:
            authenticated_user = authenticate(
                self.request, username=self.user.email, password=old_password
            )
            password_matches = authenticated_user is not None
        else:
            password_matches = self.user.check_password(old_password)
        if not password_matches:
            raise forms.ValidationError("Current password is not correct.")
        return old_password

    def clean(self):
        """Check that both new-password entries match and meet configured password rules."""
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        # Make sure both password fields match.
        if new_password and confirm_password and new_password != confirm_password:
            self.add_error("confirm_password", "The two password fields did not match.")

        # Refuse reusing the current password or any recent password in history (AUTH-06).
        if new_password and password_was_used_recently(self.user, new_password):
            self.add_error("new_password", "Choose a password you have not used recently.")

        # Run configured Django password validators and live SecurityPolicy min length.
        if new_password:
            try:
                validate_password_policy(new_password, self.user)
            except ValidationError as error:
                self.add_error("new_password", error)

        return cleaned_data


class PasswordResetRequestForm(SafeTextMixin, forms.Form):
    """
    Form to start a password reset. Kura always emails a reset link (AUTH-03);
    users with MFA must also enter a second-factor code after opening it.
    """

    # Email address associated with the account.
    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "name@example.com",
                "autocomplete": "email",
            }
        ),
    )


class PasswordResetConfirmForm(forms.Form):
    """
    Form to set a new password after opening a valid reset link.
    """

    # MFA accounts also need this code, so access to the inbox alone cannot reset the password (AUTH-03).
    code = forms.CharField(
        label="Authenticator or recovery code",
        required=False,
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-monospace",
                "placeholder": "123456",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
            }
        ),
    )

    # New password meeting security requirements.
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    # Confirmation to prevent typos.
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
            }
        ),
    )

    def __init__(self, user, *args, **kwargs):
        """Connect this password-reset form to the account receiving the new password."""
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        """Check matching password entries and apply Django's configured validators."""
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        # Check matching fields.
        if new_password and confirm_password and new_password != confirm_password:
            self.add_error("confirm_password", "The two password fields did not match.")

        # Refuse reusing the current password or any recent password in history (AUTH-06).
        if new_password and password_was_used_recently(self.user, new_password):
            self.add_error("new_password", "Choose a password you have not used recently.")

        # Run validators against password rules and live SecurityPolicy min length.
        if new_password:
            validate_password_policy(new_password, self.user)

        return cleaned_data


class MFAVerifyForm(forms.Form):
    """
    Form for submitting a TOTP authenticator code or recovery backup token.
    """

    # Numeric code from authenticator app or backup token.
    code = forms.CharField(
        label="Security code",
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-monospace text-center",
                "placeholder": "123456",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "autofocus": "autofocus",
            }
        ),
    )


class DepartmentForm(SafeTextMixin, forms.ModelForm):
    """Validate the department code, name, and optional Department Head (M11)."""

    class Meta:
        model = Department
        fields = ["code", "name", "head_user"]
        labels = {
            "head_user": "Department Head (Optional)",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only active Department Head accounts without Admin/Registrar roles may head a department.
        self.fields["head_user"].required = False
        self.fields["head_user"].empty_label = "No head assigned"
        self.fields["head_user"].queryset = (
            User.objects.filter(
                is_active=True,
                user_roles__role__name="Department head",
            )
            .exclude(user_roles__role__name__in=["Admin", "Registrar"])
            .distinct()
            .order_by("email")
        )


class DepartmentHeadAssignForm(forms.Form):
    """Appoint or update the Department Head for an existing department (M11)."""

    department = forms.ModelChoiceField(
        queryset=Department.objects.order_by("name"),
        widget=forms.Select(attrs={"class": "form-select form-select-sm"}),
    )
    head_user = forms.ModelChoiceField(
        label="Department Head",
        required=False,
        empty_label="No head assigned",
        queryset=User.objects.none(),
        widget=forms.Select(attrs={"class": "form-select form-select-sm"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["head_user"].queryset = (
            User.objects.filter(
                is_active=True,
                user_roles__role__name="Department head",
            )
            .exclude(user_roles__role__name__in=["Admin", "Registrar"])
            .distinct()
            .order_by("email")
        )


class BuildingForm(SafeTextMixin, forms.ModelForm):
    """Validate a building name."""

    class Meta:
        model = Building
        fields = ["name"]


class RoomForm(SafeTextMixin, forms.ModelForm):
    """Validate a room and its building."""

    class Meta:
        model = Room
        fields = ["building", "name"]


class StaffCreateForm(SafeTextMixin, forms.Form):
    """
    Form used by administrators to provision a new staff account.
    Creates a User record and an associated StaffProfile.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "staff@example.com",
                "autocomplete": "email",
            }
        ),
    )

    first_name = forms.CharField(
        label="First name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control", "autocomplete": "given-name"}),
    )

    last_name = forms.CharField(
        label="Last name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control", "autocomplete": "family-name"}),
    )

    department = forms.ModelChoiceField(
        label="Department",
        queryset=Department.objects.all(),
        widget=forms.Select(attrs={"class": "form-select", "autocomplete": "off"}),
    )

    staff_title = forms.ChoiceField(
        label="Staff title",
        choices=[("", "Select a title")] + [(name, name) for name in
                 ["Admin", "Registrar", "Department head", "Instructor", "Teaching assistant"]],
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    building = forms.ModelChoiceField(queryset=Building.objects.order_by("name"), required=False,
                                      widget=forms.Select(attrs={"class": "form-select", "data-office-building": ""}))
    room = forms.ModelChoiceField(queryset=Room.objects.none(), required=False,
                                  widget=forms.Select(attrs={"class": "form-select", "data-office-room": ""}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # A room is valid only when it belongs to the selected building.
        building_id = self.data.get("building")
        if building_id and str(building_id).isdigit():
            self.fields["room"].queryset = Room.objects.filter(building_id=building_id).order_by("name")

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("building") and not cleaned.get("room"):
            self.add_error("room", "Select a room in this building.")
        if cleaned.get("room") and not cleaned.get("building"):
            self.add_error("building", "Select a building.")
        if cleaned.get("room") and len(str(cleaned["room"])) > 100:
            self.add_error("room", "The building and room names together must fit within 100 characters.")
        return cleaned

    def clean_email(self):
        """Normalize a new staff member's email and reject duplicates."""
        # Ensure email is unique across the system.
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class StudentCreateForm(SafeTextMixin, forms.Form):
    """
    Form used by the registrar to provision a new student account.
    Creates a User record and an associated StudentProfile.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "student@example.com",
            }
        ),
    )

    first_name = forms.CharField(
        label="First name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )

    last_name = forms.CharField(
        label="Last name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )

    department = forms.ModelChoiceField(
        label="Department",
        queryset=Department.objects.all(),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    current_level = forms.ChoiceField(
        label="Academic level",
        choices=AcademicLevel.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    matriculation_year = forms.IntegerField(
        label="Matriculation year",
        min_value=2000,
        max_value=2100,
        widget=forms.NumberInput(
            attrs={
                "class": "form-control",
                "placeholder": "2026",
            }
        ),
    )

    def clean_email(self):
        """Normalize a new student's email and reject duplicates."""
        # Ensure student email is unique.
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class StudentFilterForm(SafeTextMixin, forms.Form):
    """Validate search and filters for the registrar's student list."""

    q = forms.CharField(required=False, max_length=150, label="Student ID, name or email")
    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False)
    level = forms.ChoiceField(choices=[("", "All levels")] + list(AcademicLevel.choices), required=False)
    status = forms.ChoiceField(
        choices=[("", "All statuses"), ("active", "Active"), ("locked", "Locked"), ("deactivated", "Deactivated")],
        required=False,
    )


class EnrollmentFilterForm(forms.Form):
    """Validate filters for enrollment records."""

    course = forms.ModelChoiceField(
        queryset=Course.objects.filter(enrollments__isnull=False).distinct(), required=False
    )
    student = forms.ModelChoiceField(
        queryset=User.objects.filter(student_profile__isnull=False, enrollments__isnull=False).distinct(),
        required=False,
    )
    status = forms.ChoiceField(choices=[("", "All statuses")] + list(EnrollmentStatus.choices), required=False)
    semester = forms.ChoiceField(choices=[("", "All semesters")] + list(SemesterType.choices), required=False)
    year = forms.IntegerField(required=False, min_value=1900, max_value=9999)


class EnrollmentForm(forms.Form):
    """
    Form used by the registrar to enroll a student into an active course.
    """

    course = forms.ModelChoiceField(
        label="Course",
        queryset=Course.objects.filter(is_published=True),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    student = forms.ModelChoiceField(
        label="Student",
        queryset=User.objects.filter(student_profile__isnull=False, is_active=True),
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class AdminCourseForm(SafeTextMixin, forms.ModelForm):
    """Validate the course details an administrator may create or edit."""

    # Only these course fields can be changed by the administrator's form.
    class Meta:
        model = Course
        fields = ["department", "code", "title", "description", "semester", "academic_year"]
        # Keep the description within the form card on narrow screens.
        widgets = {
            "description": forms.Textarea(
                attrs={
                    "class": "form-control",
                }
            ),
        }

    def clean_code(self):
        """Normalize a course code before it is saved."""
        # Keep course codes consistent with the existing course-creation form.
        return self.cleaned_data["code"].strip().upper()


class CourseCreateForm(SafeTextMixin, forms.Form):
    """
    Form for Department Heads to create a new course within one of their departments (P13).
    """

    department = forms.ModelChoiceField(
        label="Department",
        queryset=Department.objects.none(),
        required=False,
        empty_label=None,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    code = forms.CharField(
        label="Course Code",
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. CS201",
            }
        ),
    )

    title = forms.CharField(
        label="Course Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. Data Structures and Algorithms",
            }
        ),
    )

    description = forms.CharField(
        label="Description",
        required=False,
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Course curriculum summary and prerequisites",
            }
        ),
    )

    semester = forms.ChoiceField(
        label="Semester",
        choices=SemesterType.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    academic_year = forms.IntegerField(
        label="Academic Year",
        min_value=2000,
        max_value=2100,
        widget=forms.NumberInput(
            attrs={
                "class": "form-control",
                "placeholder": "2026",
            }
        ),
    )

    def __init__(self, *args, head_departments=None, **kwargs):
        super().__init__(*args, **kwargs)
        if head_departments is not None:
            self._head_departments = head_departments
            self.fields["department"].queryset = head_departments
            first_dept = head_departments.first()
            if first_dept:
                self.fields["department"].initial = first_dept
            self.fields["department"].required = head_departments.count() > 1
        else:
            self._head_departments = Department.objects.none()

    def clean_department(self):
        """Ensure the selected department is headed by the requesting Department Head."""
        dept = self.cleaned_data.get("department")
        if dept is None and self._head_departments.count() == 1:
            return self._head_departments.first()
        if dept is None:
            raise forms.ValidationError("Select a department for this course.")
        return dept

    def clean_code(self):
        """Normalize a new course code and check that it is not already in use."""
        # Enforce unique course code.
        code = self.cleaned_data.get("code", "").strip().upper()
        if Course.objects.filter(code=code).exists():
            raise forms.ValidationError("A course with this code already exists.")
        return code


class CourseStaffAssignForm(forms.Form):
    """
    Form for Department Heads to assign lead or co-instructors to a departmental course.
    """

    # Restrict both displayed choices and submitted IDs to active instructors in the course department.
    user = forms.ModelChoiceField(
        label="Instructor",
        queryset=User.objects.filter(
            staff_profile__isnull=False,
            is_active=True,
            user_roles__role__name="Instructor",
        ).distinct(),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    staff_role = forms.ChoiceField(
        label="Role in Course",
        choices=[
            ("lead_instructor", "Lead Instructor"),
            ("co_instructor", "Co-Instructor"),
        ],
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    can_release_grades = forms.BooleanField(
        label="Can release final grades to students",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )

    def __init__(self, *args, department=None, **kwargs):
        super().__init__(*args, **kwargs)
        if department is not None:
            self.fields["user"].queryset = self.fields["user"].queryset.filter(
                staff_profile__department=department
            )


class TAAssignForm(forms.Form):
    """
    Form for Instructors to assign Teaching Assistants to their course.
    """

    # Restrict both displayed choices and submitted IDs to active teaching assistants in the course department.
    user = forms.ModelChoiceField(
        label="Teaching Assistant",
        queryset=User.objects.filter(
            staff_profile__isnull=False,
            is_active=True,
            user_roles__role__name="Teaching assistant",
        ).distinct(),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    def __init__(self, *args, department=None, **kwargs):
        super().__init__(*args, **kwargs)
        if department is not None:
            self.fields["user"].queryset = self.fields["user"].queryset.filter(
                staff_profile__department=department
            )


class DeleteConfirmationForm(forms.Form):
    """Require an explicit confirmation before deleting a record."""

    confirm = forms.BooleanField(required=True)


class ScheduleForm(SafeTextMixin, forms.Form):
    """
    Form for course instructors to define recurring class timetables.
    Enforces that class end time must be after start time.
    """

    session_type = forms.ChoiceField(
        label="Session Format",
        choices=SessionType.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    day = forms.ChoiceField(
        label="Day of Week",
        choices=DayOfWeek.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    start_time = forms.TimeField(
        label="Start Time",
        widget=forms.TimeInput(attrs={"class": "form-control", "type": "time"}),
    )

    end_time = forms.TimeField(
        label="End Time",
        widget=forms.TimeInput(attrs={"class": "form-control", "type": "time"}),
    )

    location = forms.CharField(
        label="Classroom / Lab Location",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. Hall A, Science Building",
            }
        ),
    )

    recurrence_start = forms.DateField(
        label="Term Start Date",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )

    recurrence_end = forms.DateField(
        label="Term End Date",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )

    instructor = forms.ModelChoiceField(
        label="Assigned Instructor",
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    def clean(self):
        """Check that a scheduled class ends after it starts."""
        cleaned_data = super().clean()
        start_time = cleaned_data.get("start_time")
        end_time = cleaned_data.get("end_time")

        # Validate that class end time is strictly after start time.
        if start_time and end_time and end_time <= start_time:
            self.add_error("end_time", "Class end time must be strictly later than start time.")

        return cleaned_data


class AttendanceSessionStartForm(SafeTextMixin, forms.Form):
    """
    Form for instructors and TAs to launch a live attendance roll session.
    """

    title = forms.CharField(
        label="Session Title",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g. Lecture 4 Attendance",
            }
        ),
    )

    duration_minutes = forms.IntegerField(
        label="Check-in Window (Minutes)",
        min_value=1,
        max_value=240,
        initial=20,
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )


class StudentCheckinForm(SafeTextMixin, forms.Form):
    """
    Form for students to submit a 6-character check-in passcode.
    """

    passcode = forms.CharField(
        label="Session Passcode",
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-monospace text-center text-uppercase",
                "placeholder": "e.g. 9B3A7F",
                "autofocus": "autofocus",
            }
        ),
    )


class ManualAttendanceForm(SafeTextMixin, forms.Form):
    """
    Form for staff to manually override or record attendance with a required reason.
    """

    student = forms.ModelChoiceField(
        label="Student",
        queryset=User.objects.filter(student_profile__isnull=False, is_active=True),
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    status = forms.ChoiceField(
        label="Attendance Status",
        choices=AttendanceStatus.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    override_reason = forms.CharField(
        label="Justification Reason (Required)",
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Explain the justification for this manual roll entry...",
            }
        ),
    )

    def clean_override_reason(self):
        """Ensure a manual attendance change includes a written reason."""
        # Override reason is mandatory for manual roll records.
        reason = self.cleaned_data.get("override_reason", "").strip()
        if not reason:
            raise forms.ValidationError("A written justification reason is required for manual roll entries.")
        return reason


class AssessmentCreateForm(SafeTextMixin, forms.Form):
    """
    Form for Instructors to author a coursework assessment that students answer with file uploads.
    """

    title = forms.CharField(
        label="Assessment Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "e.g. Coursework 1"}
        ),
    )

    description = forms.CharField(
        label="Briefing & Instructions",
        required=False,
        max_length=5000,
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 3}),
    )

    component_type = forms.ChoiceField(
        label="Assessment Category",
        choices=GradeComponentType.choices,
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    max_score = forms.DecimalField(
        label="Maximum Score",
        max_digits=6,
        decimal_places=2,
        min_value=0.01,
        initial=100.00,
        widget=forms.NumberInput(attrs={"class": "form-control", "step": "0.01"}),
    )

    max_attempts = forms.IntegerField(
        label="Max Attempts Allowed",
        min_value=1,
        initial=1,
        widget=forms.NumberInput(attrs={"class": "form-control"}),
    )

    opens_at = forms.DateTimeField(
        label="Opening Window",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M", attrs={"class": "form-control", "type": "datetime-local"}
        ),
    )

    due_date = forms.DateTimeField(
        label="Submission Due Date",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M", attrs={"class": "form-control", "type": "datetime-local"}
        ),
    )

    def clean(self):
        """Check that an assessment opens before its due date."""
        cleaned_data = super().clean()
        # The closing time must be later than the opening time.
        opens_at = cleaned_data.get("opens_at")
        due_date = cleaned_data.get("due_date")
        if opens_at and due_date and due_date <= opens_at:
            self.add_error("due_date", "Due date must be strictly later than opening time.")
        return cleaned_data


class CourseFileForm(SafeTextMixin, forms.Form):
    """
    Form for course staff to add a material file (slides, notes) to a course.
    """

    title = forms.CharField(
        label="Title", max_length=255, widget=forms.TextInput(attrs={"class": "form-control"})
    )
    file = forms.FileField(label="Choose File", widget=forms.FileInput(attrs={"class": "form-control"}))
    is_visible = forms.BooleanField(
        label="Release to students now",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
    )


class AssessmentFileUploadForm(forms.Form):
    """
    Form for uploading files attached to assessments or student attempts.
    """

    file = forms.FileField(
        label="Choose File",
        widget=forms.FileInput(attrs={"class": "form-control"}),
    )


# Grades & change requests forms


class GradeEntryForm(SafeTextMixin, forms.Form):
    """
    Form for TAs and instructors to input manual scores and feedback.
    """

    score = forms.DecimalField(
        label="Score Awarded",
        max_digits=6,
        decimal_places=2,
        min_value=0,
        widget=forms.NumberInput(attrs={"class": "form-control", "step": "0.01"}),
    )

    feedback = forms.CharField(
        label="Evaluation Feedback",
        required=False,
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Feedback for the student...",
            }
        ),
    )


class GradeReleaseForm(forms.Form):
    """
    Step-up authentication form requiring MFA OTP verification before releasing grades.
    """

    otp_token = forms.CharField(
        label="Enter 6-Digit MFA Security Code",
        max_length=8,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-monospace text-center",
                "placeholder": "123456",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "autofocus": "autofocus",
            }
        ),
    )


class GradeChangeRequestForm(SafeTextMixin, forms.Form):
    """
    Form for instructors to request a formal score change on a released grade.
    """

    proposed_score = forms.DecimalField(
        label="Proposed New Score",
        max_digits=6,
        decimal_places=2,
        min_value=0,
        widget=forms.NumberInput(attrs={"class": "form-control", "step": "0.01"}),
    )

    reason = forms.CharField(
        label="Justification for Post-Release Change",
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Provide detailed justification for department head review...",
            }
        ),
    )


class GradeChangeRequestReviewForm(SafeTextMixin, forms.Form):
    """
    Form for department heads to approve or reject a requested grade modification.
    """

    decision = forms.ChoiceField(
        label="Decision",
        choices=[
            (ChangeRequestStatus.APPROVED, "Approve Change Request"),
            (ChangeRequestStatus.REJECTED, "Reject Change Request"),
        ],
        widget=forms.Select(attrs={"class": "form-select"}),
    )

    review_note = forms.CharField(
        label="Head of Department Review Note",
        required=True,
        max_length=5000,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 2,
                "placeholder": "Required explanation for approval or rejection...",
            }
        ),
    )

    def clean_review_note(self):
        """Require a non-empty review note on every grade change decision (P13)."""
        note = (self.cleaned_data.get("review_note") or "").strip()
        if not note:
            raise forms.ValidationError("A review note is required.")
        return note


class ScheduleFilterForm(forms.Form):
    """Validate course, day, and format filters on the timetable page."""

    course = forms.ModelChoiceField(queryset=Course.objects.none(), required=False, empty_label="All courses")
    day = forms.ChoiceField(choices=[("", "All days")] + list(DayOfWeek.choices), required=False)
    session_type = forms.ChoiceField(choices=[("", "All formats")] + list(SessionType.choices), required=False, label="Format")

    def __init__(self, *args, courses=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Restrict the course dropdown to the courses this user can already see.
        if courses is not None:
            self.fields["course"].queryset = courses


class AttendanceHistoryFilterForm(SafeTextMixin, forms.Form):
    """Validate staff filters on the attendance history list."""

    q = forms.CharField(required=False, max_length=150, label="Student")
    course = forms.ModelChoiceField(queryset=Course.objects.none(), required=False, empty_label="All courses")
    status = forms.ChoiceField(choices=[("", "All statuses")] + list(AttendanceStatus.choices), required=False)
    date_from = forms.DateField(
        required=False,
        label="From date",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )
    date_to = forms.DateField(
        required=False,
        label="To date",
        widget=forms.DateInput(attrs={"class": "form-control", "type": "date"}),
    )

    def __init__(self, *args, courses=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Limit course options to courses assigned to the staff member.
        if courses is not None:
            self.fields["course"].queryset = courses


class CourseGradesFilterForm(SafeTextMixin, forms.Form):
    """Validate assessment, status, and student filters on the course gradebook."""

    q = forms.CharField(required=False, max_length=150, label="Student")
    assessment = forms.ModelChoiceField(queryset=Assessment.objects.none(), required=False, empty_label="All assessments")
    status = forms.ChoiceField(choices=[("", "All statuses")] + list(GradeStatus.choices), required=False)

    def __init__(self, *args, assessments=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Limit assessment choices to assessments belonging to this course.
        if assessments is not None:
            self.fields["assessment"].queryset = assessments


class SecurityPolicyForm(forms.ModelForm):
    """Validate editable security policy bounds for Administrators (O6)."""

    class Meta:
        model = SecurityPolicy
        fields = [
            "min_password_length",
            "password_history_count",
            "axes_failure_limit",
            "axes_cooloff_hours",
            "session_idle_minutes",
            "session_absolute_hours",
        ]
        labels = {
            "min_password_length": "Minimum password length (12 to 128 characters)",
            "password_history_count": "Password reuse history count (1 to 24)",
            "axes_failure_limit": "Failed login attempts before lockout (3 to 20)",
            "axes_cooloff_hours": "Lockout duration in hours (1 to 24)",
            "session_idle_minutes": "Session idle timeout in minutes (5 to 240)",
            "session_absolute_hours": "Session absolute limit in hours (1 to 72)",
        }
        widgets = {
            "min_password_length": forms.NumberInput(attrs={"class": "form-control", "min": 12, "max": 128}),
            "password_history_count": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 24}),
            "axes_failure_limit": forms.NumberInput(attrs={"class": "form-control", "min": 3, "max": 20}),
            "axes_cooloff_hours": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 24}),
            "session_idle_minutes": forms.NumberInput(attrs={"class": "form-control", "min": 5, "max": 240}),
            "session_absolute_hours": forms.NumberInput(attrs={"class": "form-control", "min": 1, "max": 72}),
        }

    def clean(self):
        cleaned_data = super().clean()
        idle_minutes = cleaned_data.get("session_idle_minutes")
        absolute_hours = cleaned_data.get("session_absolute_hours")
        if idle_minutes is not None and absolute_hours is not None:
            if idle_minutes > absolute_hours * 60:
                self.add_error(
                    "session_idle_minutes",
                    "Idle timeout cannot exceed the absolute session limit.",
                )
        return cleaned_data


class PrivacyErasureForm(forms.Form):
    """Require explicit confirmation before requesting GDPR account erasure (O3)."""

    confirm = forms.BooleanField(
        required=True,
        label="I understand that non-exempt personal metadata will be cleared while academic and audit records remain retained as required by law.",
    )

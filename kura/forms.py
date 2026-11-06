from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import (
    AcademicLevel,
    AssessmentDeliveryMode,
    AppealStatus,
    AttendanceStatus,
    ChangeRequestStatus,
    Course,
    DayOfWeek,
    Department,
    GradeComponentType,
    EnrollmentStatus,
    SectionType,
    SemesterType,
    SessionType,
    User,
    validate_cidr,
)


class LoginForm(forms.Form):
    """
    Form for user authentication with email and password.
    """

    # Email address of the user attempting to log in.
    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "input input-bordered w-full",
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
                "class": "input input-bordered w-full",
                "placeholder": "Enter your password",
                "autocomplete": "current-password",
            }
        ),
    )


from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

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
                "class": "input input-bordered w-full",
                "autocomplete": "current-password",
            }
        ),
    )

    # New password to replace the current one.
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(
            attrs={
                "class": "input input-bordered w-full",
                "autocomplete": "new-password",
            }
        ),
    )

    # Confirmation entry to prevent typing mistakes.
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "class": "input input-bordered w-full",
                "autocomplete": "new-password",
            }
        ),
    )

    def __init__(self, user, *args, **kwargs):
        """
        Connects this password-change form to the account being updated.
        """
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        """
        Checks that the submitted current password matches this user's password.
        """
        # Verify that the old password matches the user's current password.
        old_password = self.cleaned_data.get("old_password")
        if not self.user.check_password(old_password):
            raise forms.ValidationError("Current password is not correct.")
        return old_password

    def clean(self):
        """
        Checks that both new-password entries match and meet configured password rules.
        """
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        # Make sure both password fields match.
        if new_password and confirm_password and new_password != confirm_password:
            self.add_error("confirm_password", "The two password fields did not match.")

        # Run configured Django password validators on the new password.
        if new_password:
            try:
                validate_password(new_password, self.user)
            except ValidationError as error:
                self.add_error("new_password", error)

        return cleaned_data


class PasswordResetRequestForm(forms.Form):
    """
    Form to request a password reset email link.
    """

    # Email address associated with the account.
    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "name@example.com",
                "autocomplete": "email",
            }
        ),
    )


class PasswordResetConfirmForm(forms.Form):
    """
    Form to set a new password after opening a valid reset link.
    """

    # New password meeting security requirements.
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(
            attrs={
                "class": "input input-bordered w-full",
                "autocomplete": "new-password",
            }
        ),
    )

    # Confirmation to prevent typos.
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={
                "class": "input input-bordered w-full",
                "autocomplete": "new-password",
            }
        ),
    )

    def __init__(self, user, *args, **kwargs):
        """
        Connects this password-reset form to the account receiving the new password.
        """
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        """
        Checks matching password entries and applies Django's configured validators.
        """
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        # Check matching fields.
        if new_password and confirm_password and new_password != confirm_password:
            self.add_error("confirm_password", "The two password fields did not match.")

        # Run validators against password rules.
        if new_password:
            validate_password(new_password, self.user)

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
                "class": "input input-bordered w-full text-center tracking-widest text-lg font-mono",
                "placeholder": "123456",
                "autocomplete": "one-time-code",
                "autofocus": "autofocus",
            }
        ),
    )


class AdminSessionFilterForm(forms.Form):
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



class AdminCourseFilterForm(forms.Form):
    """Validate administrator course catalog filters."""

    department = forms.ModelChoiceField(queryset=Department.objects.all(), required=False)
    semester = forms.ChoiceField(choices=[("", "All semesters")] + list(SemesterType.choices), required=False)
    year = forms.IntegerField(required=False, min_value=1900, max_value=9999)
    published = forms.ChoiceField(choices=[("", "All statuses"), ("yes", "Published"), ("no", "Draft")], required=False)


class AdminStaffFilterForm(forms.Form):
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


class StaffCreateForm(forms.Form):
    """
    Form used by administrators to provision a new staff account.
    Creates a User record and an associated StaffProfile.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "staff@example.com",
                "autocomplete": "email",
            }
        ),
    )

    first_name = forms.CharField(
        label="First name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full", "autocomplete": "given-name"}),
    )

    last_name = forms.CharField(
        label="Last name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full", "autocomplete": "family-name"}),
    )

    department = forms.ModelChoiceField(
        label="Department",
        queryset=Department.objects.all(),
        widget=forms.Select(attrs={"class": "select select-bordered w-full", "autocomplete": "off"}),
    )

    staff_title = forms.CharField(
        label="Staff title",
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Associate Professor",
                "autocomplete": "organization-title",
            }
        ),
    )

    office_location = forms.CharField(
        label="Office location",
        max_length=100,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Building B, Room 204",
                "autocomplete": "off",
            }
        ),
    )

    def clean_email(self):
        """
        Normalizes a new staff member's email and rejects duplicates.
        """
        # Ensure email is unique across the system.
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class AdminCourseForm(forms.ModelForm):
    """Validate the course details an administrator may create or edit."""

    # Only these course fields can be changed by the administrator's form.
    class Meta:
        model = Course
        fields = ["department", "code", "title", "description", "semester", "academic_year"]
        # Keep the description within the form card on narrow screens.
        widgets = {
            "description": forms.Textarea(
                attrs={
                    "class": "textarea textarea-bordered box-border w-full min-w-0 max-w-full",
                }
            ),
        }

    def clean_code(self):
        """
        Normalizes a course code before it is saved.
        """
        # Keep course codes consistent with the existing course-creation form.
        return self.cleaned_data["code"].strip().upper()



class StudentCreateForm(forms.Form):
    """
    Form used by the registrar to provision a new student account.
    Creates a User record and an associated StudentProfile.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "student@example.com",
            }
        ),
    )

    first_name = forms.CharField(
        label="First name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full"}),
    )

    last_name = forms.CharField(
        label="Last name",
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full"}),
    )

    department = forms.ModelChoiceField(
        label="Department",
        queryset=Department.objects.all(),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    current_level = forms.ChoiceField(
        label="Academic level",
        choices=AcademicLevel.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    matriculation_year = forms.IntegerField(
        label="Matriculation year",
        min_value=2000,
        max_value=2100,
        widget=forms.NumberInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "2026",
            }
        ),
    )

    def clean_email(self):
        """
        Normalizes a new student's email and rejects duplicates.
        """
        # Ensure student email is unique.
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class StudentFilterForm(forms.Form):
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


class EnrollmentSearchForm(forms.Form):
    """Validate an enrollment search before querying private records."""

    kind = forms.ChoiceField(choices=[("student", "Student"), ("course", "Course")])
    q = forms.CharField(required=False, max_length=150)


class EnrollmentForm(forms.Form):
    """
    Form used by the registrar to enroll a student into an active course.
    """

    course = forms.ModelChoiceField(
        label="Course",
        queryset=Course.objects.filter(is_published=True),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    student = forms.ModelChoiceField(
        label="Student",
        queryset=User.objects.filter(student_profile__isnull=False, is_active=True),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )



class CourseCreateForm(forms.Form):
    """
    Form for Department Heads to create a new course within their department.
    """

    code = forms.CharField(
        label="Course Code",
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. CS201",
            }
        ),
    )

    title = forms.CharField(
        label="Course Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Data Structures and Algorithms",
            }
        ),
    )

    description = forms.CharField(
        label="Description",
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "textarea textarea-bordered w-full",
                "rows": 3,
                "placeholder": "Course curriculum summary and prerequisites",
            }
        ),
    )

    semester = forms.ChoiceField(
        label="Semester",
        choices=SemesterType.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    academic_year = forms.IntegerField(
        label="Academic Year",
        min_value=2000,
        max_value=2100,
        widget=forms.NumberInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "2026",
            }
        ),
    )

    def clean_code(self):
        """
        Normalizes a new course code and checks that it is not already in use.
        """
        # Enforce unique course code.
        code = self.cleaned_data.get("code", "").strip().upper()
        if Course.objects.filter(code=code).exists():
            raise forms.ValidationError("A course with this code already exists.")
        return code


class CourseStaffAssignForm(forms.Form):
    """
    Form for Department Heads to assign lead or co-instructors to a departmental course.
    """

    # Restrict both displayed choices and submitted IDs to active instructors.
    user = forms.ModelChoiceField(
        label="Instructor",
        queryset=User.objects.filter(
            staff_profile__isnull=False,
            is_active=True,
            user_roles__role__name="Instructor",
        ).distinct(),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    staff_role = forms.ChoiceField(
        label="Role in Course",
        choices=[
            ("lead_instructor", "Lead Instructor"),
            ("co_instructor", "Co-Instructor"),
        ],
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    can_release_grades = forms.BooleanField(
        label="Can release final grades to students",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "checkbox checkbox-primary"}),
    )



class TAAssignForm(forms.Form):
    """
    Form for Instructors to assign Teaching Assistants to their course.
    """

    # Restrict both displayed choices and submitted IDs to active teaching assistants.
    user = forms.ModelChoiceField(
        label="Teaching Assistant",
        queryset=User.objects.filter(
            is_active=True,
            user_roles__role__name="Teaching assistant",
        ).distinct(),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )


class ModuleForm(forms.Form):
    """
    Form for Instructors to create or edit a curriculum module.
    """

    title = forms.CharField(
        label="Module Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Week 1: Network Protocols",
            }
        ),
    )

    description = forms.CharField(
        label="Description",
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "textarea textarea-bordered w-full",
                "rows": 3,
            }
        ),
    )

    is_visible = forms.BooleanField(
        label="Visible to enrolled students",
        required=False,
        widget=forms.CheckboxInput(attrs={"class": "checkbox checkbox-primary"}),
    )

    target_levels = forms.MultipleChoiceField(
        label="Target Academic Levels (leave blank for all students)",
        choices=AcademicLevel.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={"class": "checkbox checkbox-sm checkbox-primary"}),
    )


class DeleteConfirmationForm(forms.Form):
    """Require an explicit confirmation before deleting a record."""

    confirm = forms.BooleanField(required=True)


class ModuleSectionForm(forms.Form):
    """
    Form for Instructors to create a section grouping within a module.
    """

    title = forms.CharField(
        label="Section Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Lecture Notes",
            }
        ),
    )

    section_type = forms.ChoiceField(
        label="Section Type",
        choices=SectionType.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )


class SectionItemForm(forms.Form):
    """
    Form for Instructors to author content items with rich text and file attachment.
    """

    title = forms.CharField(
        label="Item Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Chapter 1 Summary",
            }
        ),
    )

    content_body = forms.CharField(
        label="Content Body (Markdown)",
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "textarea textarea-bordered w-full font-mono text-sm",
                "rows": 6,
                "placeholder": "Write your notes using Markdown...",
            }
        ),
    )

    # Let staff schedule when students may access an item.
    released_at = forms.DateTimeField(
        label="Release at (optional)",
        required=False,
        input_formats=["%Y-%m-%dT%H:%M"],
        widget=forms.DateTimeInput(
            attrs={"class": "input input-bordered w-full", "type": "datetime-local"},
            format="%Y-%m-%dT%H:%M",
        ),
    )

    file = forms.FileField(
        label="Attach File (Optional, max 25 MiB)",
        required=False,
        widget=forms.FileInput(attrs={"class": "file-input file-input-bordered w-full"}),
    )

    def __init__(self, data=None, files=None, initial=None, existing_file=False):
        """
        Initializes the section-item form with its existing-attachment state.
        """
        # An existing attachment also counts when editing a file-only item.
        super().__init__(data=data, files=files, initial=initial)
        self.existing_file = existing_file

    def clean(self):
        """
        Requires the section item to contain text, a new file, or an existing attachment.
        """
        # Require something useful in the item, even though each field is optional.
        cleaned_data = super().clean()
        if not cleaned_data.get("content_body") and not cleaned_data.get("file") and not self.existing_file:
            raise forms.ValidationError("Add some content or attach a file.")
        return cleaned_data


class MarkdownPreviewForm(forms.Form):
    """Validate the Markdown text submitted for an authorized preview."""

    # Empty text is valid so staff can preview while writing.
    content_body = forms.CharField(required=False, widget=forms.Textarea)



class ScheduleForm(forms.Form):
    """
    Form for course instructors to define recurring class timetables.
    Enforces that class end time must be after start time.
    """

    session_type = forms.ChoiceField(
        label="Session Format",
        choices=SessionType.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    day = forms.ChoiceField(
        label="Day of Week",
        choices=DayOfWeek.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    start_time = forms.TimeField(
        label="Start Time",
        widget=forms.TimeInput(attrs={"class": "input input-bordered w-full", "type": "time"}),
    )

    end_time = forms.TimeField(
        label="End Time",
        widget=forms.TimeInput(attrs={"class": "input input-bordered w-full", "type": "time"}),
    )

    location = forms.CharField(
        label="Classroom / Lab Location",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Hall A, Science Building",
            }
        ),
    )

    recurrence_start = forms.DateField(
        label="Term Start Date",
        widget=forms.DateInput(attrs={"class": "input input-bordered w-full", "type": "date"}),
    )

    recurrence_end = forms.DateField(
        label="Term End Date",
        widget=forms.DateInput(attrs={"class": "input input-bordered w-full", "type": "date"}),
    )

    instructor = forms.ModelChoiceField(
        label="Assigned Instructor",
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    def clean(self):
        """
        Checks that a scheduled class ends after it starts.
        """
        cleaned_data = super().clean()
        start_time = cleaned_data.get("start_time")
        end_time = cleaned_data.get("end_time")

        # Validate that class end time is strictly after start time.
        if start_time and end_time and end_time <= start_time:
            self.add_error("end_time", "Class end time must be strictly later than start time.")

        return cleaned_data



class AttendanceSessionStartForm(forms.Form):
    """
    Form for instructors and TAs to launch a live attendance roll session.
    """

    title = forms.CharField(
        label="Session Title",
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full",
                "placeholder": "e.g. Lecture 4 Attendance",
            }
        ),
    )

    duration_minutes = forms.IntegerField(
        label="Check-in Window (Minutes)",
        min_value=1,
        max_value=240,
        initial=20,
        widget=forms.NumberInput(attrs={"class": "input input-bordered w-full"}),
    )


class StudentCheckinForm(forms.Form):
    """
    Form for students to submit a 6-character check-in passcode.
    """

    passcode = forms.CharField(
        label="Session Passcode",
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full text-center tracking-widest text-lg font-mono uppercase",
                "placeholder": "e.g. 9B3A7F",
                "autofocus": "autofocus",
            }
        ),
    )


class ManualAttendanceForm(forms.Form):
    """
    Form for staff to manually override or record attendance with a required reason.
    """

    student = forms.ModelChoiceField(
        label="Student",
        queryset=User.objects.filter(student_profile__isnull=False, is_active=True),
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    status = forms.ChoiceField(
        label="Attendance Status",
        choices=AttendanceStatus.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    override_reason = forms.CharField(
        label="Justification Reason (Required)",
        widget=forms.Textarea(
            attrs={
                "class": "textarea textarea-bordered w-full",
                "rows": 3,
                "placeholder": "Explain the justification for this manual roll entry...",
            }
        ),
    )

    def clean_override_reason(self):
        """
        Ensures a manual attendance change includes a written reason.
        """
        # Override reason is mandatory for manual roll records.
        reason = self.cleaned_data.get("override_reason", "").strip()
        if not reason:
            raise forms.ValidationError("A written justification reason is required for manual roll entries.")
        return reason


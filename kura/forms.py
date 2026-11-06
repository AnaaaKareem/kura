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


class AssessmentCreateForm(forms.Form):
    """
    Form for Instructors to author an assessment with settings, delivery parameters, and questions.
    """

    title = forms.CharField(
        label="Assessment Title",
        max_length=255,
        widget=forms.TextInput(
            attrs={"class": "input input-bordered w-full", "placeholder": "e.g. Midterm Examination"}
        ),
    )

    description = forms.CharField(
        label="Briefing & Instructions",
        required=False,
        widget=forms.Textarea(attrs={"class": "textarea textarea-bordered w-full", "rows": 3}),
    )

    component_type = forms.ChoiceField(
        label="Assessment Category",
        choices=GradeComponentType.choices,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    # Keep old submissions compatible while making the delivery choice explicit.
    delivery_mode = forms.ChoiceField(
        choices=AssessmentDeliveryMode.choices,
        required=False,
        initial=AssessmentDeliveryMode.ONLINE,
        widget=forms.Select(attrs={"class": "select select-bordered w-full"}),
    )

    max_score = forms.DecimalField(
        label="Maximum Score",
        max_digits=6,
        decimal_places=2,
        min_value=0.01,
        initial=100.00,
        widget=forms.NumberInput(attrs={"class": "input input-bordered w-full", "step": "0.01"}),
    )

    max_attempts = forms.IntegerField(
        label="Max Attempts Allowed",
        min_value=1,
        initial=1,
        widget=forms.NumberInput(attrs={"class": "input input-bordered w-full"}),
    )

    opens_at = forms.DateTimeField(
        label="Opening Window",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M", attrs={"class": "input input-bordered w-full", "type": "datetime-local"}
        ),
    )

    due_date = forms.DateTimeField(
        label="Submission Due Date",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M", attrs={"class": "input input-bordered w-full", "type": "datetime-local"}
        ),
    )

    duration_minutes = forms.IntegerField(
        label="Duration (Minutes)",
        min_value=1,
        initial=60,
        widget=forms.NumberInput(attrs={"class": "input input-bordered w-full"}),
    )

    lab_cidr_allowed = forms.CharField(
        label="Required Lab CIDR Subnet (Optional)",
        required=False,
        validators=[validate_cidr],
        widget=forms.TextInput(attrs={"class": "input input-bordered w-full", "placeholder": "e.g. 10.20.0.0/24"}),
    )

    proctor_code = forms.CharField(
        label="Whiteboard Proctor Code (Optional)",
        required=False,
        max_length=50,
        widget=forms.TextInput(
            attrs={"class": "input input-bordered w-full font-mono", "placeholder": "e.g. EXAM-8842"}
        ),
    )

    shuffle_questions = forms.BooleanField(
        label="Shuffle questions for each student",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "checkbox checkbox-primary"}),
    )

    shuffle_options = forms.BooleanField(
        label="Shuffle question options",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "checkbox checkbox-primary"}),
    )

    allow_backtracking = forms.BooleanField(
        label="Allow students to navigate back and change answers",
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={"class": "checkbox checkbox-primary"}),
    )

    autosave_interval_seconds = forms.IntegerField(
        label="Autosave Interval (seconds)",
        min_value=5,
        max_value=300,
        initial=15,
        widget=forms.NumberInput(attrs={"class": "input input-bordered w-full"}),
    )

    def clean(self):
        """
        Checks that an assessment opens before its due date.
        """
        cleaned_data = super().clean()
        # The closing time must be later than the opening time.
        opens_at = cleaned_data.get("opens_at")
        due_date = cleaned_data.get("due_date")
        if opens_at and due_date and due_date <= opens_at:
            self.add_error("due_date", "Due date must be strictly later than opening time.")
        return cleaned_data


class AssessmentQuestionForm(forms.Form):
    """Validate one online question and its staff-only answer fields."""

    # Every question has a type, a prompt, and a positive number of points.
    type = forms.ChoiceField(
        choices=[
            ("multiple_choice", "Multiple choice"),
            ("matching", "Matching"),
            ("long_text", "Written answer"),
        ]
    )
    prompt = forms.CharField(max_length=5000, widget=forms.Textarea(attrs={"rows": 2}))
    points = forms.DecimalField(max_digits=6, decimal_places=2, min_value=0.01)
    max_words = forms.IntegerField(required=False, min_value=1, max_value=100000, initial=500)
    rubric = forms.CharField(required=False, max_length=5000, widget=forms.Textarea(attrs={"rows": 3}))
    explanation = forms.CharField(required=False, max_length=5000, widget=forms.Textarea(attrs={"rows": 2}))
    extra_matches = forms.CharField(
        required=False,
        max_length=4000,
        label="Additional matching choices, one per line",
        widget=forms.Textarea(attrs={"rows": 2}),
    )

    def __init__(self, *args, **kwargs):
        """
        Builds the repeated question fields and display rows for one question form.
        """
        # Each row is a normal Django field, so every submitted value is validated.
        super().__init__(*args, **kwargs)
        for number in range(1, 9):
            self.fields[f"option_{number}"] = forms.CharField(required=False, max_length=500, label=f"Option {number}")
            self.fields[f"correct_{number}"] = forms.BooleanField(required=False, label="Correct")
            self.fields[f"left_{number}"] = forms.CharField(required=False, max_length=500, label=f"Left item {number}")
            self.fields[f"right_{number}"] = forms.CharField(
                required=False, max_length=500, label=f"Correct match {number}"
            )
        self.option_rows = []
        self.pair_rows = []
        for number in range(1, 9):
            self.option_rows.append((self[f"option_{number}"], self[f"correct_{number}"]))
            self.pair_rows.append((self[f"left_{number}"], self[f"right_{number}"]))

    def clean(self):
        """
        Checks that the submitted question has enough valid answers for its type.
        """
        # Require enough choices and a real answer; reject incomplete matching pairs.
        cleaned_data = super().clean()
        if cleaned_data.get("type") == "multiple_choice":
            options = 0
            correct = 0
            for number in range(1, 9):
                option = cleaned_data.get(f"option_{number}")
                marked = cleaned_data.get(f"correct_{number}")
                if option:
                    options += 1
                if marked and option:
                    correct += 1
                elif marked:
                    self.add_error(f"option_{number}", "Enter the marked option's text.")
            if options < 2 or correct == 0:
                raise forms.ValidationError("Add at least two options and mark at least one correct answer.")
        elif cleaned_data.get("type") == "matching":
            pairs = 0
            for number in range(1, 9):
                left = cleaned_data.get(f"left_{number}")
                right = cleaned_data.get(f"right_{number}")
                if left and right:
                    pairs += 1
                elif left or right:
                    self.add_error(f"right_{number}", "Enter both sides of this pair.")
            if not pairs:
                raise forms.ValidationError("Add at least one complete matching pair.")
        elif cleaned_data.get("type") == "long_text" and not cleaned_data.get("max_words"):
            self.add_error("max_words", "Enter a word limit.")
        return cleaned_data


# Cap the formset so a forged request cannot create an unlimited number of forms.
AssessmentQuestionFormSet = forms.formset_factory(
    AssessmentQuestionForm,
    extra=0,
    can_delete=True,
    can_order=True,
    max_num=20,
    validate_max=True,
    absolute_max=20,
)


class AssessmentQuestionAddForm(forms.Form):
    """Validate the type and formset position for a blank question card."""

    type = forms.ChoiceField(choices=AssessmentQuestionForm.base_fields["type"].choices)
    index = forms.IntegerField(min_value=0, max_value=19)


class AssessmentAttemptStartForm(forms.Form):
    """
    Form for students to initiate an attempt, validating the exam whiteboard proctor code if required.
    """

    proctor_code = forms.CharField(
        label="Enter Exam Proctor Code",
        required=False,
        max_length=50,
        widget=forms.TextInput(
            attrs={
                "class": "input input-bordered w-full font-mono text-center tracking-wider text-lg uppercase",
                "placeholder": "Enter whiteboard code",
                "autofocus": "autofocus",
            }
        ),
    )


class AssessmentAutosaveForm(forms.Form):
    """Validate which question or focus event the student is sending."""

    # Only known response types can reach the answer validation below.
    question_id = forms.CharField(required=False, max_length=255)
    response_type = forms.ChoiceField(
        required=False,
        choices=[
            ("multiple_choice", "Multiple choice"),
            ("matching", "Matching"),
            ("long_text", "Written answer"),
            ("essay", "Essay"),
        ],
    )
    focus_lost = forms.BooleanField(required=False)


class AssessmentAnswerForm(forms.Form):
    """Validate answers against the choices in the student's actual question."""

    # Limit written responses and make choice values come from the assessment itself.
    selected_options = forms.MultipleChoiceField(required=False, choices=[])
    response_text = forms.CharField(required=False, max_length=100000, strip=False)

    def __init__(self, data, question):
        """
        Builds answer fields from the actual question shown to the student.
        """
        # Add only the matching-pair fields and choices that the question really contains.
        super().__init__(data)
        self.max_words = question.get("max_words", 500)
        for option in question.get("options", []):
            option_id = option.get("option_id", "")
            self.fields["selected_options"].choices.append((option_id, option.get("text", "")))
        choices = [("", "No answer")]
        for match in question.get("available_matches", []):
            choices.append((match, match))
        for pair in question.get("left_prompts", []):
            self.fields[f"match_{pair['pair_id']}"] = forms.ChoiceField(required=False, choices=choices)

    def clean_response_text(self):
        """
        Checks that a written answer stays within the question's word limit.
        """
        # A student cannot submit more words than the question allows.
        text = self.cleaned_data["response_text"]
        if len(text.split()) > self.max_words:
            raise forms.ValidationError("The answer exceeds this question's word limit.")
        return text


class AssessmentFileUploadForm(forms.Form):
    """
    Form for uploading files attached to assessments or student attempts.
    """

    file = forms.FileField(
        label="Choose File",
        widget=forms.FileInput(attrs={"class": "file-input file-input-bordered w-full"}),
    )


class ScannedPaperStaffUploadForm(forms.Form):
    """Validate the student and scanned file selected by authorized course staff."""

    # The view restricts this empty queryset to students enrolled in its course.
    student = forms.ModelChoiceField(queryset=User.objects.none())
    file = forms.FileField()

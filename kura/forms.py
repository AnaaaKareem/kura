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



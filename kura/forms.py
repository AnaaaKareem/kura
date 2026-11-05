from django import forms

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



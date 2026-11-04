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


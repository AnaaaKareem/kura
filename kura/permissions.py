from .models import UserRole


def has_role(user, role_name):
    """
    Checks whether an active user has been assigned a specific system role.
    Returns False for anonymous or inactive accounts.
    """
    # Anonymous or inactive users cannot hold active roles.
    if not user or not user.is_authenticated or not user.is_active:
        return False

    # Check if the user has a UserRole record with this role name.
    return UserRole.objects.filter(user=user, role__name=role_name).exists()


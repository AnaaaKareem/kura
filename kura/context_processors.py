"""Context processors for Kura UI v2 ("Ledger").

Exposes nav_roles so the sidebar can deduplicate links for multi-role users
and render grouped navigation (Design System v2 Section 6.1).
"""


def nav_roles(request):
    """Returns the set of role names assigned to the active user."""
    if not hasattr(request, "user") or not request.user.is_authenticated:
        return {"nav_roles": set()}
    return {
        "nav_roles": set(request.user.user_roles.values_list("role__name", flat=True))
    }

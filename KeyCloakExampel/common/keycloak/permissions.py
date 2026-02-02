
from django.conf import settings
from rest_framework.permissions import BasePermission


def _get_roles(token: dict) -> list[str]:

    role_source = getattr(settings, "KEYCLOAK_ROLE_SOURCE", "realm")

    if role_source == "client":
        client_id = getattr(settings, "KEYCLOAK_CLIENT_ID", None)
        if not client_id:
            return []
        return (
            token.get("resource_access", {})
            .get(client_id, {})
            .get("roles", [])
        )

    return token.get("realm_access", {}).get("roles", [])


class HasRole(BasePermission):
    required_role = None
    message = "Du saknar behörighet för denna endpoint."

    def has_permission(self, request, view):
        token = request.user
        if not isinstance(token, dict):
            return False

        roles = _get_roles(token)

        if "superadmin" in roles:
            return True

        return self.required_role in roles


class IsRenter(HasRole):
    required_role = "renter"


class IsProvider(HasRole):
    required_role = "provider"


class IsAdmin(HasRole):
    required_role = "admin"


class IsSuperAdmin(HasRole):
    required_role = "superadmin"
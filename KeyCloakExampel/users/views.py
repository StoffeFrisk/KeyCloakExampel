


from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from common.keycloak.permissions import IsAdmin


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def kc_echo(request):
    """
    Test endpoint:
    - Requires a valid Bearer token
    - Returns a few token fields so you can verify integration
    """
    token = request.auth  # decoded JWT (dict)

    return Response({
        "ok": True,
        "sub": token.get("sub"),
        "username": token.get("preferred_username"),
        "issuer": token.get("iss"),
        "audience": token.get("aud"),
        "realm_roles": token.get("realm_access", {}).get("roles", []),
        "client_roles": token.get("resource_access", {}).get("api-client", {}).get("roles", []),  # (valfritt men ofta bra)
    })


@api_view(["GET"])
@permission_classes([IsAdmin])
def kc_admin_only(request):
    return Response({"ok": True, "message": "Admin access granted"})
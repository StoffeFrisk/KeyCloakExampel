import time
import requests
from jose import jwt, JWTError
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


_JWKS_CACHE = {"jwks": None, "expires_at": 0}


def _get_jwks():
    now = time.time()
    if _JWKS_CACHE["jwks"] and now < _JWKS_CACHE["expires_at"]:
        return _JWKS_CACHE["jwks"]

    jwks_url = getattr(settings, "KEYCLOAK_JWKS_URL", None)
    if not jwks_url:
        raise AuthenticationFailed("Server misconfigured: KEYCLOAK_JWKS_URL missing")

    jwks = requests.get(jwks_url, timeout=5).json()

    _JWKS_CACHE["jwks"] = jwks
    _JWKS_CACHE["expires_at"] = now + 600
    return jwks

class TokenUser:

    def __init__(self, token: dict):
        self.token = token

    @property
    def is_authenticated(self) -> bool:
        return True

    def get(self, key, default=None):
        return self.token.get(key, default)

    def __repr__(self):
        return f"<TokenUser preferred_username={self.token.get('preferred_username')!r}>"


class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        parts = auth_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationFailed("Invalid Authorization header format")

        token = parts[1]

        issuer = getattr(settings, "KEYCLOAK_ISSUER", None)
        if not issuer:
            raise AuthenticationFailed("Server misconfigured: KEYCLOAK_ISSUER missing")

        try:
            jwks = _get_jwks()
            decoded_token = jwt.decode(
                token,
                jwks,
                issuer=issuer,
                options={
                    "verify_signature": True,
                    "verify_aud": False,
                    "verify_iss": True,
                    "verify_exp": True,
                },
            )

        except JWTError:
            raise AuthenticationFailed("Invalid or expired token")
        except AuthenticationFailed:
            raise
        except Exception:
            raise AuthenticationFailed("Could not validate token")

        return (TokenUser(decoded_token), decoded_token)

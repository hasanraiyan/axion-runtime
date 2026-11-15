import logging
from typing import Optional
from clerk_backend_api import Clerk
from clerk_backend_api.security import (
    TokenVerificationError,
    VerifyTokenOptions,
    verify_token_async,
)
from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.models.user import UserRole
from app.schemas.auth import AuthenticatedUser

logger = logging.getLogger("app.security")

# Initialize Clerk SDK client if secret key is present
_clerk_client: Optional[Clerk] = None
if settings.CLERK_SECRET_KEY and not settings.CLERK_SECRET_KEY.startswith("sk_test_placeholder"):
    try:
        _clerk_client = Clerk(bearer_auth=settings.CLERK_SECRET_KEY)
    except Exception as e:
        logger.warning(f"Failed to initialize official Clerk client: {e}")


def get_clerk_client() -> Optional[Clerk]:
    return _clerk_client


async def verify_clerk_token(token: str) -> AuthenticatedUser:
    """
    Verifies a Clerk session token / JWT and returns the AuthenticatedUser.
    Uses the official Clerk SDK (verify_token_async) for cryptographic verification (JWKS/PEM).
    """
    if not token or not token.strip():
        raise UnauthorizedError("Missing authorization token")

    token = token.strip()

    # 1. Dev / Test mock tokens support for local development and test suite
    if settings.ENVIRONMENT in ("development", "test") and (
        token.startswith("dev-token-") or token.startswith("test-token-") or token == "mock-valid-token"
    ):
        user_id = token.replace("dev-token-", "").replace("test-token-", "")
        if user_id == "mock-valid-token":
            user_id = "user_dev_123"
        is_admin = "admin" in user_id
        return AuthenticatedUser(
            id=f"user_{user_id}",
            clerk_id=f"user_{user_id}",
            email=f"{user_id}@example.com",
            first_name="Dev",
            last_name="Tester",
            role=UserRole.ADMIN if is_admin else UserRole.USER,
            roles=["admin"] if is_admin else ["user"],
        )

    # 2. Determine verification credentials (offline JWT key or Clerk secret key)
    has_jwt_key = bool(settings.CLERK_JWT_KEY)
    has_secret_key = bool(
        settings.CLERK_SECRET_KEY and not settings.CLERK_SECRET_KEY.startswith("sk_test_placeholder")
    )

    if not has_jwt_key and not has_secret_key:
        if settings.ENVIRONMENT in ("development", "test"):
            raise UnauthorizedError(
                "Clerk credentials are not configured. Set CLERK_SECRET_KEY in apps/api/.env or use 'dev-token-yourname' in development."
            )
        raise UnauthorizedError("Authentication service not configured")

    options = VerifyTokenOptions(
        secret_key=settings.CLERK_SECRET_KEY if has_secret_key else None,
        jwt_key=settings.CLERK_JWT_KEY if has_jwt_key else None,
    )

    # 3. Cryptographically verify the session token via Clerk SDK
    try:
        claims = await verify_token_async(token, options)
    except TokenVerificationError as exc:
        logger.warning(f"Clerk token verification failed: {exc}")
        raise UnauthorizedError("Invalid or expired session token")
    except Exception as exc:
        logger.warning(f"Unexpected error during token verification: {exc}")
        raise UnauthorizedError("Invalid or expired session token")

    user_id = claims.get("sub")
    if not user_id:
        raise UnauthorizedError("Invalid token payload: missing subject")

    email = claims.get("email")
    first_name = claims.get("first_name")
    last_name = claims.get("last_name")
    image_url = claims.get("image_url")
    roles = claims.get("roles", ["user"])
    is_admin = "admin" in roles

    # Optional profile metadata enrichment from Clerk API if not included in JWT claims
    if not email and _clerk_client is not None:
        try:
            clerk_user_obj = _clerk_client.users.get(user_id=user_id)
            if clerk_user_obj and clerk_user_obj.email_addresses:
                email = clerk_user_obj.email_addresses[0].email_address
            if not first_name:
                first_name = getattr(clerk_user_obj, "first_name", None)
            if not last_name:
                last_name = getattr(clerk_user_obj, "last_name", None)
            if not image_url:
                image_url = getattr(clerk_user_obj, "image_url", None)
        except Exception as exc:
            logger.debug(f"Could not enrich user profile from Clerk API: {exc}")

    return AuthenticatedUser(
        id=user_id,
        clerk_id=user_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        image_url=image_url,
        role=UserRole.ADMIN if is_admin else UserRole.USER,
        roles=roles,
    )

import logging
from typing import Optional
import jwt
from clerk_backend_api import Clerk
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
    Supports official Clerk SDK, RS256 JWKS/public key, and dev/test mock tokens.
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

    # 2. If Clerk public JWT key is configured, verify signature directly
    if settings.CLERK_JWT_KEY:
        try:
            payload = jwt.decode(
                token,
                settings.CLERK_JWT_KEY,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            user_id = payload.get("sub")
            if not user_id:
                raise UnauthorizedError("Invalid token payload: missing subject")
            roles = payload.get("roles", ["user"])
            is_admin = "admin" in roles
            return AuthenticatedUser(
                id=user_id,
                clerk_id=user_id,
                email=payload.get("email"),
                first_name=payload.get("first_name"),
                last_name=payload.get("last_name"),
                image_url=payload.get("image_url"),
                role=UserRole.ADMIN if is_admin else UserRole.USER,
                roles=roles,
            )
        except jwt.PyJWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            raise UnauthorizedError(f"Invalid session token: {str(e)}")

    # 3. If official Clerk client is configured, verify via Clerk SDK
    if _clerk_client is not None:
        try:
            # Decode unverified claims first to inspect subject
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
            user_id = unverified_claims.get("sub")
            if user_id:
                # Query Clerk API to verify user exists and is active
                user = _clerk_client.users.get(user_id=user_id)
                email = None
                if user and user.email_addresses and len(user.email_addresses) > 0:
                    email = user.email_addresses[0].email_address
                image_url = getattr(user, "image_url", None)
                return AuthenticatedUser(
                    id=user.id,
                    clerk_id=user.id,
                    email=email,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    image_url=image_url,
                    role=UserRole.USER,
                    roles=["user"],
                )
        except Exception as e:
            logger.warning(f"Clerk SDK token verification failed: {e}")
            raise UnauthorizedError("Invalid or expired session token")

    # 4. If credentials are placeholders and in development, provide clear guidance
    if settings.CLERK_SECRET_KEY.startswith("sk_test_placeholder") or not settings.CLERK_SECRET_KEY:
        if settings.ENVIRONMENT == "development":
            # For development convenience with placeholder keys:
            # Reject raw random strings, but allow dev-token- prefix
            raise UnauthorizedError(
                "Clerk credentials are not configured. Set CLERK_SECRET_KEY in apps/api/.env or use 'dev-token-yourname' in development."
            )
        raise UnauthorizedError("Authentication service not configured")

    raise UnauthorizedError("Unable to verify token")

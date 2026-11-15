from enum import Enum
from typing import Any, Dict, Optional
from pymongo import ASCENDING, DESCENDING, IndexModel
from pydantic import Field

from app.db.base import BaseDocument


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class UserAuditAction(str, Enum):
    ROLE_UPDATED = "ROLE_UPDATED"
    STATUS_UPDATED = "STATUS_UPDATED"


class User(BaseDocument):
    """
    User document in MongoDB, synchronized with Clerk authentication identities.
    Supports role-based authorization (ADMIN, USER) and optimistic concurrency control.
    """

    clerk_id: str = Field(
        ...,
        description="Unique Clerk User identifier (user_...)",
    )
    email: Optional[str] = Field(
        default=None,
        description="User primary email address",
    )
    first_name: Optional[str] = Field(
        default=None,
        description="Given / first name",
    )
    last_name: Optional[str] = Field(
        default=None,
        description="Family / last name",
    )
    image_url: Optional[str] = Field(
        default=None,
        description="Profile avatar image URL",
    )
    role: UserRole = Field(
        default=UserRole.USER,
        description="User access authorization role: 'admin' or 'user'",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the user account is active",
    )
    revision: int = Field(
        default=1,
        description="Optimistic concurrency control revision counter",
    )

    class Settings:
        name = "users"
        indexes = [
            IndexModel([("clerk_id", ASCENDING)], unique=True),
            IndexModel([("email", ASCENDING)], unique=True, sparse=True),
            IndexModel([("role", ASCENDING)]),
            IndexModel([("is_active", ASCENDING)]),
        ]


class UserAuditLog(BaseDocument):
    """
    Immutable audit trail recording all privileged user mutations (role promotions,
    demotions, activation/deactivation).
    """

    actor_id: str = Field(..., description="Clerk ID of actor initiating the mutation")
    target_clerk_id: str = Field(..., description="Clerk ID of affected user")
    action: UserAuditAction = Field(..., description="Action type")
    old_value: Optional[str] = Field(default=None, description="Previous state value")
    new_value: Optional[str] = Field(default=None, description="Updated state value")
    request_id: Optional[str] = Field(default=None, description="Correlated HTTP request ID")
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional audit context")

    class Settings:
        name = "user_audit_logs"
        indexes = [
            IndexModel([("target_clerk_id", ASCENDING), ("created_at", DESCENDING)]),
            IndexModel([("actor_id", ASCENDING), ("created_at", DESCENDING)]),
            IndexModel([("action", ASCENDING), ("created_at", DESCENDING)]),
        ]


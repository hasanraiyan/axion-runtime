from enum import Enum
from typing import Optional
from pymongo import ASCENDING, IndexModel
from pydantic import Field

from app.db.base import BaseDocument


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class User(BaseDocument):
    """
    User document in MongoDB, synchronized with Clerk authentication identities.
    Supports role-based authorization (ADMIN, USER).
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

    class Settings:
        name = "users"
        indexes = [
            IndexModel([("clerk_id", ASCENDING)], unique=True),
            IndexModel([("email", ASCENDING)], unique=True, sparse=True),
            IndexModel([("role", ASCENDING)]),
        ]

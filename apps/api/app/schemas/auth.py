from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, Field, model_validator
from app.models.user import UserRole


class AuthenticatedActor(BaseModel):
    """
    Unified security actor context injected into request.state.actor.
    Unifies human Clerk sessions and machine API credentials.
    """
    actor_type: Literal["user", "credential"]
    identity_id: str                      # Clerk user ID or Credential Document ID
    project_id: Optional[str] = None      # Bound project ID (mandatory for machine credentials)
    scopes: List[str] = []                # Granted capability scopes
    email: Optional[str] = None           # Present only for human users
    is_authenticated: bool = True


class AuthenticatedUser(BaseModel):
    id: str = Field(..., description="Unique Database ID (MongoDB ObjectId)")
    clerk_id: str = Field(..., description="Unique Clerk User identifier (user_...)")
    email: Optional[str] = Field(default=None, description="Primary email address")
    first_name: Optional[str] = Field(default=None, description="First name")
    last_name: Optional[str] = Field(default=None, description="Last name")
    image_url: Optional[str] = Field(default=None, description="Profile avatar image URL")
    role: UserRole = Field(default=UserRole.USER, description="Assigned role: 'admin' or 'user'")
    roles: List[str] = Field(default_factory=list, description="Assigned authorization roles derived from DB role")
    is_active: bool = Field(default=True, description="Account active state")
    is_authenticated: bool = Field(default=True, description="Authentication state")
    created_at: Optional[datetime] = Field(default=None, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Account last update timestamp")

    @model_validator(mode="after")
    def sync_roles_from_role(self) -> "AuthenticatedUser":
        """Ensure DB role is the sole authority; roles list is always derived consistently."""
        self.roles = [self.role.value]
        return self


class UpdateUserRoleRequest(BaseModel):
    role: UserRole = Field(..., description="New role to assign: 'admin' or 'user'")


class UpdateUserStatusRequest(BaseModel):
    is_active: bool = Field(..., description="New active state for user account")


class AuthMeResponse(BaseModel):
    user: AuthenticatedUser

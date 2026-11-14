from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.user import UserRole


class AuthenticatedUser(BaseModel):
    id: str = Field(..., description="Unique Database ID (MongoDB ObjectId)")
    clerk_id: str = Field(..., description="Unique Clerk User identifier (user_...)")
    email: Optional[str] = Field(default=None, description="Primary email address")
    first_name: Optional[str] = Field(default=None, description="First name")
    last_name: Optional[str] = Field(default=None, description="Last name")
    image_url: Optional[str] = Field(default=None, description="Profile avatar image URL")
    role: UserRole = Field(default=UserRole.USER, description="Assigned role: 'admin' or 'user'")
    roles: List[str] = Field(default_factory=list, description="Assigned authorization roles")
    is_active: bool = Field(default=True, description="Account active state")
    is_authenticated: bool = Field(default=True, description="Authentication state")
    created_at: Optional[datetime] = Field(default=None, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Account last update timestamp")


class UpdateUserRoleRequest(BaseModel):
    role: UserRole = Field(..., description="New role to assign: 'admin' or 'user'")


class AuthMeResponse(BaseModel):
    user: AuthenticatedUser

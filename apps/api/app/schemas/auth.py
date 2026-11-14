from typing import List, Optional
from pydantic import BaseModel, Field


class AuthenticatedUser(BaseModel):
    id: str = Field(..., description="Unique Clerk User ID (e.g. user_...)")
    email: Optional[str] = Field(default=None, description="Primary email address")
    first_name: Optional[str] = Field(default=None, description="First name")
    last_name: Optional[str] = Field(default=None, description="Last name")
    roles: List[str] = Field(default_factory=list, description="Assigned authorization roles")
    is_authenticated: bool = Field(default=True, description="Authentication state")


class AuthMeResponse(BaseModel):
    user: AuthenticatedUser

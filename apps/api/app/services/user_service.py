from typing import Optional
from fastapi import Depends

from app.core.logging import logger
from app.models.user import User, UserRole
from app.repositories.user_repository import UserRepository, get_user_repository


class UserService:
    """
    Domain service orchestrating user profile synchronization, roles, and identity.
    Decoupled from HTTP transports and directly injected with UserRepository.
    """

    def __init__(self, user_repo: Optional[UserRepository] = None) -> None:
        self.user_repo = user_repo if user_repo is not None else get_user_repository()

    def is_db_ready(self) -> bool:
        """Check whether user repository and database connection are ready."""
        return self.user_repo.is_db_ready()

    async def sync_clerk_user(
        self,
        clerk_id: str,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        image_url: Optional[str] = None,
    ) -> Optional[User]:
        """
        Synchronize Clerk authentication profile into the local MongoDB User document.
        - If database is uninitialized/offline, returns None.
        - If user already exists: updates any changed profile fields.
        - If user is new: creates a User document. The first user in an empty DB
          automatically receives ADMIN role, otherwise USER role.
        """
        if not self.is_db_ready():
            return None

        existing_user = await self.user_repo.get_by_clerk_id(clerk_id)

        if existing_user is not None:
            # Check for profile updates
            has_changes = False
            if email and existing_user.email != email:
                existing_user.email = email
                has_changes = True
            if first_name != existing_user.first_name:
                existing_user.first_name = first_name
                has_changes = True
            if last_name != existing_user.last_name:
                existing_user.last_name = last_name
                has_changes = True
            if image_url and image_url != existing_user.image_url:
                existing_user.image_url = image_url
                has_changes = True

            if has_changes:
                await self.user_repo.update(existing_user)
                logger.info(f"Updated profile for user '{clerk_id}' in MongoDB.")

            return existing_user

        # First user bootstrap: automatically make the first registered user an ADMIN
        user_count = await self.user_repo.count_all()
        role = UserRole.ADMIN if user_count == 0 else UserRole.USER

        new_user = User(
            clerk_id=clerk_id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            image_url=image_url,
            role=role,
            is_active=True,
        )
        created_user = await self.user_repo.create(new_user)
        logger.info(f"Created new synced user '{clerk_id}' with role '{role.value}' in MongoDB.")
        return created_user

    async def get_by_clerk_id(self, clerk_id: str) -> Optional[User]:
        """Fetch user by Clerk ID."""
        return await self.user_repo.get_by_clerk_id(clerk_id)

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Fetch user by MongoDB ID."""
        return await self.user_repo.get_by_id(user_id)

    async def update_role(self, clerk_id: str, new_role: UserRole) -> Optional[User]:
        """Update user role for a given Clerk user."""
        user = await self.user_repo.get_by_clerk_id(clerk_id)
        if user is not None:
            user.role = new_role
            await self.user_repo.update(user)
            logger.info(f"Updated role for user '{clerk_id}' to '{new_role.value}'.")
        return user


def get_user_service(
    user_repo: UserRepository = Depends(get_user_repository),
) -> UserService:
    """FastAPI dependency provider for UserService."""
    return UserService(user_repo=user_repo)

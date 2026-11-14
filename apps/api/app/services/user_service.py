from typing import Optional
from app.core.logging import logger
from app.models.user import User, UserRole


class UserService:
    @classmethod
    def is_db_ready(cls) -> bool:
        try:
            return User.get_settings().pymongo_collection is not None
        except Exception:
            return False

    @classmethod
    async def sync_clerk_user(
        cls,
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
        if not cls.is_db_ready():
            return None

        existing_user = await User.find_one({"clerk_id": clerk_id})

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
                await existing_user.save()
                logger.info(f"Updated profile for user '{clerk_id}' in MongoDB.")

            return existing_user

        # First user bootstrap: automatically make the first registered user an ADMIN
        user_count = await User.count()
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
        await new_user.insert()
        logger.info(f"Created new synced user '{clerk_id}' with role '{role.value}' in MongoDB.")
        return new_user

    @classmethod
    async def get_by_clerk_id(cls, clerk_id: str) -> Optional[User]:
        if not cls.is_db_ready():
            return None
        return await User.find_one({"clerk_id": clerk_id})

    @classmethod
    async def get_by_id(cls, user_id: str) -> Optional[User]:
        if not cls.is_db_ready():
            return None
        from bson import ObjectId

        try:
            return await User.get(ObjectId(user_id))
        except Exception:
            return None

    @classmethod
    async def update_role(cls, clerk_id: str, new_role: UserRole) -> Optional[User]:
        if not cls.is_db_ready():
            return None
        user = await User.find_one({"clerk_id": clerk_id})
        if user:
            user.role = new_role
            await user.save()
            logger.info(f"Updated role for user '{clerk_id}' to '{new_role.value}'.")
        return user

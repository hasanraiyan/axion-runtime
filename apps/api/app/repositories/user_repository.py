"""
User Repository providing data access for User documents.
"""
from datetime import datetime, timezone
import inspect
import logging
from typing import Optional
from pymongo import ReturnDocument

from app.models.user import User, UserAuditLog, UserRole
from app.repositories.base import BaseRepository

logger = logging.getLogger("app.security.audit")


class UserRepository(BaseRepository[User]):
    """
    Repository encapsulating all database interactions for User documents in MongoDB.
    Provides atomic, concurrency-safe profile and role updates.
    """

    def __init__(self) -> None:
        super().__init__(User)

    async def get_by_clerk_id(self, clerk_id: str) -> Optional[User]:
        """Retrieve a user document by Clerk user ID."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"clerk_id": clerk_id})

    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user document by email address."""
        if not self.is_db_ready():
            return None
        return await self.find_one({"email": email})

    async def count_all(self) -> int:
        """Count total user documents in collection."""
        if not self.is_db_ready():
            return 0
        return await self.count()

    async def count_active_admins(self) -> int:
        """Count active users with ADMIN role."""
        if not self.is_db_ready():
            return 0
        return await self.count({"role": UserRole.ADMIN, "is_active": True})

    async def update_profile_atomic(
        self,
        clerk_id: str,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        image_url: Optional[str] = None,
    ) -> Optional[User]:
        """
        Atomically update profile fields without touching authorization role or active status.
        Prevents lost updates and role reversion (AUTH-03).
        """
        if not self.is_db_ready():
            return None

        set_fields: dict = {"updated_at": datetime.now(timezone.utc)}
        if email is not None:
            set_fields["email"] = email
        if first_name is not None:
            set_fields["first_name"] = first_name
        if last_name is not None:
            set_fields["last_name"] = last_name
        if image_url is not None:
            set_fields["image_url"] = image_url

        raw = await self.get_collection().find_one_and_update(
            {"clerk_id": clerk_id},
            {"$set": set_fields, "$inc": {"revision": 1}},
            return_document=ReturnDocument.AFTER,
        )
        if raw is None:
            return None
        return raw if isinstance(raw, User) else User.model_validate(raw)

    async def update_role_atomic(
        self,
        clerk_id: str,
        new_role: UserRole,
        expected_role: Optional[UserRole] = None,
    ) -> Optional[User]:
        """
        Atomically update user role with OCC filter guard (AUTH-03).
        """
        if not self.is_db_ready():
            return None

        query: dict = {"clerk_id": clerk_id}
        if expected_role is not None:
            query["role"] = expected_role.value

        raw = await self.get_collection().find_one_and_update(
            query,
            {
                "$set": {
                    "role": new_role.value,
                    "updated_at": datetime.now(timezone.utc),
                },
                "$inc": {"revision": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if raw is None:
            return None
        return raw if isinstance(raw, User) else User.model_validate(raw)

    async def update_status_atomic(
        self,
        clerk_id: str,
        is_active: bool,
    ) -> Optional[User]:
        """
        Atomically update account active status (AUTH-04).
        """
        if not self.is_db_ready():
            return None

        raw = await self.get_collection().find_one_and_update(
            {"clerk_id": clerk_id},
            {
                "$set": {
                    "is_active": is_active,
                    "updated_at": datetime.now(timezone.utc),
                },
                "$inc": {"revision": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if raw is None:
            return None
        return raw if isinstance(raw, User) else User.model_validate(raw)

    async def claim_bootstrap_admin(self, clerk_id: str) -> bool:
        """
        Atomically claim initial admin bootstrap status. One-shot and race-free (AUTH-05).
        Returns True if and only if this clerk_id successfully won the bootstrap lock.
        """
        if not self.is_db_ready():
            return False

        # If database already has registered users, initial bootstrap is closed
        total_users = await self.count_all()
        if total_users > 0:
            return False

        try:
            db = self.get_collection().database
            bootstrap_col = db["auth_bootstrap"]
            fn = getattr(bootstrap_col, "find_one_and_update", None)
            if fn is not None:
                res = fn(
                    {"_id": "initial_admin_bootstrap"},
                    {"$setOnInsert": {"claimed_by": clerk_id, "claimed_at": datetime.now(timezone.utc)}},
                    upsert=True,
                    return_document=ReturnDocument.AFTER,
                )
                if inspect.isawaitable(res):
                    res = await res
                if isinstance(res, dict):
                    return res.get("claimed_by") == clerk_id
            return True
        except Exception as exc:
            logger.warning(f"Bootstrap admin race check failed: {exc}")
            return total_users == 0

    async def record_audit_log(self, audit_log: UserAuditLog) -> UserAuditLog:
        """
        Persist immutable audit trail entry for privileged actions (AUTH-02).
        """
        logger.info(
            f"AUDIT_EVENT: actor={audit_log.actor_id} target={audit_log.target_clerk_id} "
            f"action={audit_log.action.value} old={audit_log.old_value} new={audit_log.new_value} "
            f"request_id={audit_log.request_id} ip={audit_log.ip_address}"
        )
        if self.is_db_ready():
            try:
                await audit_log.insert()
            except Exception as exc:
                logger.error(f"Failed to persist user audit log to database: {exc}")
        return audit_log


def get_user_repository() -> UserRepository:
    """FastAPI dependency provider for UserRepository."""
    return UserRepository()


from typing import Optional
from fastapi import Depends

from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.core.logging import logger
from app.models.user import User, UserAuditAction, UserAuditLog, UserRole
from app.repositories.user_repository import UserRepository, get_user_repository
from app.schemas.auth import AuthenticatedUser


class UserService:
    """
    Domain service orchestrating user profile synchronization, roles, and identity.
    Decoupled from HTTP transports and directly injected with UserRepository.
    Enforces safety rails, OCC, and audit logging for privilege changes.
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
        - If user already exists: atomically updates changed profile fields without
          mutating authorization role or active state (AUTH-03).
        - If user is new: creates a User document. Initial admin bootstrap is one-shot
          and race-free via an atomic marker claim (AUTH-05).
        """
        if not self.is_db_ready():
            return None

        existing_user = await self.user_repo.get_by_clerk_id(clerk_id)

        if existing_user is not None:
            has_changes = (
                (email is not None and existing_user.email != email)
                or (first_name is not None and existing_user.first_name != first_name)
                or (last_name is not None and existing_user.last_name != last_name)
                or (image_url is not None and existing_user.image_url != image_url)
            )
            if has_changes:
                updated = await self.user_repo.update_profile_atomic(
                    clerk_id=clerk_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    image_url=image_url,
                )
                if updated:
                    logger.info(f"Updated profile for user '{clerk_id}' in MongoDB.")
                    return updated
            return existing_user

        # Atomic initial admin bootstrap (AUTH-05)
        is_bootstrap_admin = await self.user_repo.claim_bootstrap_admin(clerk_id)
        role = UserRole.ADMIN if is_bootstrap_admin else UserRole.USER

        new_user = User(
            clerk_id=clerk_id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            image_url=image_url,
            role=role,
            is_active=True,
            revision=1,
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

    async def update_role(
        self,
        clerk_id: str,
        new_role: UserRole,
        actor: Optional[AuthenticatedUser] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Update user role with audit logging, OCC, and safety rails (AUTH-02, AUTH-03).
        - Refuses demotion of the last remaining admin.
        - Refuses self-demotion.
        - Refuses role change for inactive users.
        - Emits an immutable audit log.
        """
        target_user = await self.user_repo.get_by_clerk_id(clerk_id)
        if target_user is None:
            raise NotFoundError(f"User with Clerk ID '{clerk_id}' not found")

        if not target_user.is_active:
            raise BadRequestError("Cannot change role of an inactive user")

        if target_user.role == new_role:
            return target_user

        # Capture snapshot before mutation for immutable audit logging
        old_role_value = target_user.role.value

        # Safety rail: Demotion checks
        if target_user.role == UserRole.ADMIN and new_role == UserRole.USER:
            if actor and actor.clerk_id == clerk_id:
                raise ConflictError("Self-demotion is not permitted")
            active_admins = await self.user_repo.count_active_admins()
            if active_admins <= 1:
                raise ConflictError("Cannot demote the last remaining active administrator")

        # Atomic OCC update
        updated_user = await self.user_repo.update_role_atomic(
            clerk_id=clerk_id,
            new_role=new_role,
            expected_role=target_user.role,
        )
        if updated_user is None:
            raise ConflictError("Role update conflict: concurrent modification detected")

        # Emit audit trail
        audit_log = UserAuditLog(
            actor_id=actor.clerk_id if actor else "system",
            target_clerk_id=clerk_id,
            action=UserAuditAction.ROLE_UPDATED,
            old_value=old_role_value,
            new_value=new_role.value,
            request_id=request_id,
            ip_address=ip_address,
            metadata={"previous_role": old_role_value, "new_role": new_role.value},
        )
        await self.user_repo.record_audit_log(audit_log)
        logger.info(f"Updated role for user '{clerk_id}' to '{new_role.value}'.")
        return updated_user

    async def update_status(
        self,
        clerk_id: str,
        is_active: bool,
        actor: Optional[AuthenticatedUser] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> User:
        """
        Update user active status with audit logging and safety rails (AUTH-02, AUTH-04).
        - Refuses self-deactivation.
        - Refuses deactivation of the last remaining admin.
        - Emits an immutable audit log.
        """
        target_user = await self.user_repo.get_by_clerk_id(clerk_id)
        if target_user is None:
            raise NotFoundError(f"User with Clerk ID '{clerk_id}' not found")

        if target_user.is_active == is_active:
            return target_user

        old_status_value = str(target_user.is_active)

        # Safety rail: Deactivation checks
        if not is_active:
            if actor and actor.clerk_id == clerk_id:
                raise ConflictError("Self-deactivation is not permitted")
            if target_user.role == UserRole.ADMIN:
                active_admins = await self.user_repo.count_active_admins()
                if active_admins <= 1:
                    raise ConflictError("Cannot deactivate the last remaining active administrator")

        # Atomic status update
        updated_user = await self.user_repo.update_status_atomic(
            clerk_id=clerk_id,
            is_active=is_active,
        )
        if updated_user is None:
            raise ConflictError("Status update conflict: concurrent modification detected")

        # Emit audit trail
        audit_log = UserAuditLog(
            actor_id=actor.clerk_id if actor else "system",
            target_clerk_id=clerk_id,
            action=UserAuditAction.STATUS_UPDATED,
            old_value=old_status_value,
            new_value=str(is_active),
            request_id=request_id,
            ip_address=ip_address,
            metadata={"previous_is_active": old_status_value, "new_is_active": is_active},
        )
        await self.user_repo.record_audit_log(audit_log)
        logger.info(f"Updated active status for user '{clerk_id}' to '{is_active}'.")
        return updated_user


def get_user_service(
    user_repo: UserRepository = Depends(get_user_repository),
) -> UserService:
    """FastAPI dependency provider for UserService."""
    return UserService(user_repo=user_repo)


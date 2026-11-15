"""
Shared optimistic-concurrency helper (AGENTS invariant 4): filter on the expected
revision, ``ReturnDocument.AFTER``, and only on ``None`` reload to tell
404 / 409 / invalid state apart.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Type, TypeVar

from pymongo import ReturnDocument

from app.core.exceptions import ConflictError, NotFoundError, RevisionConflictError
from app.repositories.base import serialize_for_mongo

T = TypeVar("T")


async def occ_update(
    model_class: Type[T],
    collection: Any,
    base_query: Dict[str, Any],
    expected_revision: int,
    update_dict: Dict[str, Any],
    label: str,
    deleted_flag_field: Optional[str] = "is_deleted",
    allow_deleted: bool = False,
    session: Optional[Any] = None,
) -> T:
    """
    Atomically apply ``update_dict`` if the stored revision equals ``expected_revision``.

    ``base_query`` identifies the document (id/tenant/etc). Raises ``NotFoundError``,
    a deleted-state ``ConflictError``, or ``RevisionConflictError``.
    """
    set_fields = serialize_for_mongo(
        {**update_dict, "revision": expected_revision + 1, "updated_at": datetime.now(timezone.utc)}
    )
    query = {**base_query, "revision": expected_revision}
    if deleted_flag_field and not allow_deleted:
        query[deleted_flag_field] = False

    result = await collection.find_one_and_update(
        query, {"$set": set_fields}, return_document=ReturnDocument.AFTER, session=session
    )
    if result is not None:
        return result if isinstance(result, model_class) else model_class.model_validate(result)  # type: ignore[attr-defined]

    existing = await collection.find_one(base_query)
    if existing is None:
        raise NotFoundError(f"{label} not found")
    existing_revision = existing.get("revision") if isinstance(existing, dict) else getattr(existing, "revision", None)
    is_deleted = (
        bool(existing.get(deleted_flag_field)) if isinstance(existing, dict) and deleted_flag_field else False
    )
    if is_deleted and not allow_deleted:
        raise ConflictError(f"{label} has been deleted")
    if existing_revision != expected_revision:
        raise RevisionConflictError(
            f"{label} revision conflict (expected {expected_revision}, current {existing_revision})"
        )
    raise RevisionConflictError(f"{label} update conflict: concurrent modification detected")

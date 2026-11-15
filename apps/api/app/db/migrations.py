"""
One-off schema migrations that Beanie's ``init_beanie`` cannot do (it only creates indexes, never drops them).

``idx_tool_invocations_ttl`` was a fixed 30-day TTL index on ``started_at``. Invocation retention now lives in the
per-record ``expire_at`` field (``idx_tool_invocations_expire``). While the old index exists, MongoDB still deletes every
record 30 days after it started, which silently cuts short a project's longer ``invocation_content_retention_days``.

Startup only *reports* the old index; dropping it is an explicit, operator-run step (``scripts/drop_legacy_indexes.py``).
"""
from __future__ import annotations

from typing import Any, List

LEGACY_TOOL_INVOCATION_TTL_INDEX = "idx_tool_invocations_ttl"
TOOL_INVOCATIONS_COLLECTION = "tool_invocations"


async def legacy_indexes_present(database: Any) -> List[str]:
    """Names of obsolete indexes still present (empty when the collection does not exist yet)."""
    collection = database[TOOL_INVOCATIONS_COLLECTION]
    try:
        existing = {index["name"] async for index in await collection.list_indexes()}
    except Exception:  # a missing collection or an unreachable server must not break startup
        return []
    return [LEGACY_TOOL_INVOCATION_TTL_INDEX] if LEGACY_TOOL_INVOCATION_TTL_INDEX in existing else []


async def drop_legacy_indexes(database: Any) -> List[str]:
    """Drop the obsolete indexes; returns the names dropped. Idempotent."""
    dropped: List[str] = []
    for name in await legacy_indexes_present(database):
        await database[TOOL_INVOCATIONS_COLLECTION].drop_index(name)
        dropped.append(name)
    return dropped


def legacy_index_warning(names: List[str]) -> str:
    return (
        f"Obsolete MongoDB index(es) {names} on '{TOOL_INVOCATIONS_COLLECTION}' still exist; they delete invocation "
        "records after 30 days regardless of the project's retention setting. Drop them with "
        "`python scripts/drop_legacy_indexes.py --apply` (see docs/learnings.md)."
    )

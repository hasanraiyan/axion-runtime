from typing import Any, Callable, Dict, List, Optional, Sequence, TypeVar
from app.schemas.common import FilterParams

T = TypeVar("T")


def apply_search(
    items: Sequence[T],
    search_query: Optional[str],
    search_fields: List[str],
) -> List[T]:
    """Filter items where any of search_fields contains the search query."""
    if not search_query:
        return list(items)

    query = search_query.strip().lower()
    filtered: List[T] = []

    for item in items:
        matched = False
        for field in search_fields:
            val = getattr(item, field, None)
            if val is None and isinstance(item, dict):
                val = item.get(field)
            if val is not None and query in str(val).lower():
                matched = True
                break
        if matched:
            filtered.append(item)

    return filtered


def apply_sorting(
    items: List[T],
    sort_by: Optional[str],
    sort_order: str = "asc",
    allowed_sort_fields: Optional[List[str]] = None,
) -> List[T]:
    """Sort a list of items by a designated attribute or key."""
    if not sort_by:
        return items

    if allowed_sort_fields and sort_by not in allowed_sort_fields:
        return items

    reverse = sort_order.lower() == "desc"

    def sort_key(item: Any) -> Any:
        val = getattr(item, sort_by, None)
        if val is None and isinstance(item, dict):
            val = item.get(sort_by)
        return (val is None, str(val).lower() if isinstance(val, str) else val)

    try:
        return sorted(items, key=sort_key, reverse=reverse)
    except Exception:
        return items


def apply_filters(
    items: Sequence[T],
    filters: Dict[str, Any],
) -> List[T]:
    """Filter items by exact match on provided criteria."""
    filtered: List[T] = []
    for item in items:
        match = True
        for key, expected in filters.items():
            if expected is None:
                continue
            val = getattr(item, key, None)
            if val is None and isinstance(item, dict):
                val = item.get(key)
            if val != expected:
                match = False
                break
        if match:
            filtered.append(item)
    return filtered

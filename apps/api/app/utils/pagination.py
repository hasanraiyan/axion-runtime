import math
from typing import List, Sequence, Tuple, TypeVar
from app.schemas.common import PaginationMeta, PaginationParams

T = TypeVar("T")


def resolve_pagination(params: PaginationParams) -> Tuple[int, int]:
    """
    Resolve effective (page, page_size) from either page/page_size or limit/offset.
    """
    if params.limit is not None:
        page_size = params.limit
        offset = params.offset if params.offset is not None else 0
        page = (offset // page_size) + 1
        return page, page_size

    return params.page, params.page_size


def build_pagination_meta(total_records: int, page: int, page_size: int) -> PaginationMeta:
    """
    Construct pagination metadata with total_records, total_pages, and next/prev indicators.
    """
    total_pages = max(1, math.ceil(total_records / page_size)) if total_records > 0 else 1
    has_next_page = page < total_pages
    has_previous_page = page > 1 and page <= total_pages + 1

    return PaginationMeta(
        page=page,
        page_size=page_size,
        total_records=total_records,
        totalPages=total_pages,
        hasNextPage=has_next_page,
        hasPreviousPage=has_previous_page,
    )


def paginate_sequence(items: Sequence[T], params: PaginationParams) -> Tuple[List[T], PaginationMeta]:
    """
    Slice an in-memory sequence of items according to pagination parameters.
    Keeps database-ready decoupled design.
    """
    page, page_size = resolve_pagination(params)
    total_records = len(items)

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size

    sliced_items = list(items[start_idx:end_idx]) if start_idx < total_records else []
    meta = build_pagination_meta(total_records=total_records, page=page, page_size=page_size)

    return sliced_items, meta

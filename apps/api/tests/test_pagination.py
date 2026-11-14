from app.schemas.common import PaginationParams
from app.utils.pagination import build_pagination_meta, paginate_sequence, resolve_pagination


def test_resolve_pagination_with_page_and_page_size():
    params = PaginationParams(page=2, page_size=20)
    page, size = resolve_pagination(params)
    assert page == 2
    assert size == 20


def test_resolve_pagination_with_limit_and_offset():
    params = PaginationParams(limit=25, offset=50)
    page, size = resolve_pagination(params)
    assert page == 3
    assert size == 25


def test_build_pagination_meta_indicators():
    meta = build_pagination_meta(total_records=95, page=1, page_size=10)
    assert meta.totalPages == 10
    assert meta.hasNextPage is True
    assert meta.hasPreviousPage is False

    last_meta = build_pagination_meta(total_records=95, page=10, page_size=10)
    assert last_meta.totalPages == 10
    assert last_meta.hasNextPage is False
    assert last_meta.hasPreviousPage is True


def test_paginate_sequence():
    items = list(range(1, 101))
    params = PaginationParams(page=3, page_size=10)
    sliced, meta = paginate_sequence(items, params)

    assert len(sliced) == 10
    assert sliced[0] == 21
    assert sliced[-1] == 30
    assert meta.page == 3
    assert meta.total_records == 100
    assert meta.totalPages == 10
    assert meta.hasNextPage is True
    assert meta.hasPreviousPage is True

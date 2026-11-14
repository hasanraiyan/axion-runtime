import pytest
from pydantic import ValidationError
from app.schemas.common import PaginationParams, FilterParams


def test_pagination_params_validation_errors():
    # Page must be >= 1
    with pytest.raises(ValidationError) as exc_info:
        PaginationParams(page=0)
    errors = exc_info.value.errors()
    assert any(err["loc"] == ("page",) for err in errors)

    # Page size must be <= 100
    with pytest.raises(ValidationError) as exc_info:
        PaginationParams(page_size=101)
    errors = exc_info.value.errors()
    assert any(err["loc"] == ("page_size",) for err in errors)


def test_filter_params_validation():
    # Invalid sort_order must fail
    with pytest.raises(ValidationError) as exc_info:
        FilterParams(sort_order="invalid_order")  # type: ignore
    errors = exc_info.value.errors()
    assert any(err["loc"] == ("sort_order",) for err in errors)

from typing import Any, Generic, List, Literal, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    field: Optional[str] = Field(default=None, description="Field path causing the error")
    message: str = Field(..., description="Error message description")
    code: Optional[str] = Field(default=None, description="Specific error code")


class ApiErrorPayload(BaseModel):
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error summary")
    details: List[ErrorDetail] = Field(default_factory=list, description="Detailed validation or sub-errors")


class ApiErrorResponse(BaseModel):
    success: Literal[False] = Field(default=False, description="Always false for error responses")
    error: ApiErrorPayload = Field(..., description="Error details payload")


class ApiResponse(BaseModel, Generic[T]):
    success: Literal[True] = Field(default=True, description="Always true for successful responses")
    data: T = Field(..., description="Response payload")
    message: str = Field(default="Operation completed successfully", description="Status message")


class PaginationMeta(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    page: int = Field(..., description="Current page number (1-based)")
    page_size: int = Field(..., description="Number of items per page")
    total_records: int = Field(..., description="Total count of matching records")
    totalPages: int = Field(..., description="Total number of pages", alias="totalPages")
    hasNextPage: bool = Field(..., description="True if a next page is available", alias="hasNextPage")
    hasPreviousPage: bool = Field(..., description="True if a previous page is available", alias="hasPreviousPage")


class PaginatedData(BaseModel, Generic[T]):
    items: List[T] = Field(..., description="List of items for current page")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class PaginatedResponse(ApiResponse[PaginatedData[T]], Generic[T]):
    pass


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number starting from 1")
    page_size: int = Field(default=10, ge=1, le=100, description="Items per page (max 100)")
    limit: Optional[int] = Field(default=None, ge=1, le=100, description="Alternative: limit")
    offset: Optional[int] = Field(default=None, ge=0, description="Alternative: offset")


class FilterParams(BaseModel):
    search: Optional[str] = Field(default=None, description="Search query string")
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    sort_order: Literal["asc", "desc"] = Field(default="asc", description="Sort order direction")

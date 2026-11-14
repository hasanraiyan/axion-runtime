from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status


class AppException(HTTPException):
    """
    Base application exception inheriting from FastAPI's native HTTPException.
    Ensures seamless interoperability with FastAPI handlers and OpenAPI error specs.
    """

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(status_code=status_code, detail=message)
        self.message = message
        self.code = code
        self.details = details or []


class BadRequestError(AppException):
    def __init__(self, message: str = "Bad Request", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class UnauthorizedError(AppException):
    def __init__(self, message: str = "Authentication required", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenError(AppException):
    def __init__(self, message: str = "Permission denied", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class NotFoundError(AppException):
    def __init__(self, message: str = "Resource not found", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class ConflictError(AppException):
    def __init__(self, message: str = "Resource conflict", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


class ValidationError(AppException):
    def __init__(self, message: str = "Validation failed", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class RateLimitExceededError(AppException):
    def __init__(self, message: str = "Rate limit exceeded. Please try again later.", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details,
        )


class ServiceUnavailableError(AppException):
    def __init__(self, message: str = "Service unavailable", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="SERVICE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
        )


# ==============================================================================
# Project FSM & Lifecycle Domain Exceptions (SRS-01 Section 4.5)
# ==============================================================================


class ProjectFSMError(ConflictError):
    """Base exception for FSM domain rule violations."""

    def __init__(self, message: str = "Project state machine violation", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message=message, details=details)


class InvalidStateTransitionError(ProjectFSMError):
    """Raised when an illegal transition is requested."""

    def __init__(self, from_state: str, to_state: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Illegal project state transition from '{from_state}' to '{to_state}'",
            details=details,
        )


class ProjectNotActiveError(ProjectFSMError):
    """Raised when a mutation is attempted on a non-active project."""

    def __init__(self, message: str = "Project is not in active state", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message=message, details=details)


class ProjectArchivedError(ProjectNotActiveError):
    def __init__(self, project_id: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Project '{project_id}' is ARCHIVED. Mutation operations are prohibited.",
            details=details,
        )


class ProjectDeletedError(ProjectNotActiveError):
    def __init__(self, project_id: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Project '{project_id}' is SOFT_DELETED. Restore project before modifying resources.",
            details=details,
        )


class ProjectPurgedError(NotFoundError):
    def __init__(self, project_id: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Project '{project_id}' has been permanently purged.",
            details=details,
        )


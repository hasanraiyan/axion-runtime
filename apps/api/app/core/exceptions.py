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


class ConfigurationError(AppException):
    """Raised when environment or startup configuration is invalid or missing."""

    def __init__(self, message: str = "Configuration error", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


class CryptographicIntegrityError(AppException):
    """Raised when cryptographic decryption, authentication tag, or AAD validation fails."""

    def __init__(
        self,
        message: str = "Cryptographic integrity check failed",
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(
            message=message,
            code="CRYPTOGRAPHIC_INTEGRITY_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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


# ==============================================================================
# Credential Domain Exceptions (SRS-03 Section 8)
# ==============================================================================


class InvalidCredentialError(UnauthorizedError):
    def __init__(self, message: str = "Invalid API key", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message=message, details=details)
        self.code = "INVALID_CREDENTIAL"


class CredentialRevokedError(UnauthorizedError):
    def __init__(self, message: str = "API key has been revoked", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message=message, details=details)
        self.code = "CREDENTIAL_REVOKED"


class CredentialExpiredError(UnauthorizedError):
    def __init__(self, message: str = "API key has expired", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message=message, details=details)
        self.code = "CREDENTIAL_EXPIRED"


class ProjectAccessDeniedError(ForbiddenError):
    def __init__(
        self,
        message: str = "Access denied: API key is not authorized for this project",
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message=message, details=details)
        self.code = "PROJECT_ACCESS_DENIED"


class InsufficientScopeError(ForbiddenError):
    def __init__(self, required_scope: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"API key lacks required capability scope: '{required_scope}'",
            details=details,
        )
        self.code = "INSUFFICIENT_SCOPE"


class DuplicateCredentialNameError(ConflictError):
    def __init__(self, name: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Credential with name '{name}' already exists in this project",
            details=details,
        )
        self.code = "CREDENTIAL_NAME_EXISTS"


class CredentialRevisionConflictError(ConflictError):
    def __init__(
        self,
        message: str = "Credential update conflict: concurrent modification detected",
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message=message, details=details)
        self.code = "CREDENTIAL_REVISION_CONFLICT"


# ==============================================================================
# Provider & Model Domain Exceptions (SRS-06)
# ==============================================================================


class DuplicateProviderSlugError(ConflictError):
    def __init__(self, slug: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Provider with slug '{slug}' already exists in this project",
            details=details,
        )
        self.code = "PROVIDER_SLUG_EXISTS"


class DuplicateProviderNameError(ConflictError):
    def __init__(self, name: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Provider with name '{name}' already exists in this project",
            details=details,
        )
        self.code = "PROVIDER_NAME_EXISTS"


class DuplicateModelError(ConflictError):
    def __init__(self, model_id: str, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Model with identifier '{model_id}' already exists for this provider",
            details=details,
        )
        self.code = "MODEL_EXISTS"


class ProviderRevisionConflictError(ConflictError):
    def __init__(
        self,
        message: str = "Provider update conflict: concurrent modification detected",
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message=message, details=details)
        self.code = "REVISION_CONFLICT"


class ModelRevisionConflictError(ConflictError):
    def __init__(
        self,
        message: str = "Model update conflict: concurrent modification detected",
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message=message, details=details)
        self.code = "REVISION_CONFLICT"


class SecretInUseError(ConflictError):
    def __init__(self, secret_id: str, count: int = 1, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=f"Cannot delete secret '{secret_id}': referenced by {count} active provider(s)",
            details=details,
        )
        self.code = "SECRET_IN_USE"




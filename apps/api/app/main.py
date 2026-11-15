from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.exceptions import AppException
from app.core.logging import logger, setup_logging
from app.db.client import close_db, init_db
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.rate_limit import InMemoryRateLimiterMiddleware
from app.middleware.request_id import RequestIdMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.schemas.common import ApiResponse
from app.schemas.health import HealthData
from app.services.health_service import HealthService

TAGS_METADATA = [
    {
        "name": "Health",
        "description": "System operational status, uptime, and liveness monitoring.",
    },
    {
        "name": "Authentication",
        "description": "User profile verification and session identity management powered by Clerk.",
    },
    {
        "name": "Projects",
        "description": "Project workspace lifecycle, RBAC membership governance, OCC, and audit logging.",
    },
    {
        "name": "Secrets",
        "description": "Project secrets management, envelope encryption, OCC revision control, privileged reveal, and runtime resolution.",
    },
    {
        "name": "Providers",
        "description": "Model provider configuration, connectivity healthchecks, dynamic model discovery, and OCC lifecycle management.",
    },
    {
        "name": "Models",
        "description": "Project model catalog, capability inspection, manual model definition, and OCC governance.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for application startup and graceful shutdown.
    """
    setup_logging(debug=settings.DEBUG)
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    await init_db(app)
    yield
    logger.info(f"Shutting down {settings.PROJECT_NAME} gracefully...")
    await close_db(app)


def create_application() -> FastAPI:
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description="Core API for the AI Platform. Provides health verification, auth verification, and OpenAPI contracts.",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
    )

    # 1. CORS Middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time-Ms", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    # 2. Custom Middlewares
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(InMemoryRateLimiterMiddleware, requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)
    application.add_middleware(RequestLoggingMiddleware)
    application.add_middleware(RequestIdMiddleware)

    # 3. Centralized Exception Handlers
    @application.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                },
            },
        )

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        details = []
        for err in exc.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            details.append({
                "field": loc,
                "message": err.get("msg", "Invalid value"),
                "code": err.get("type", "value_error"),
            })

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Input validation failed. Please check the request parameters.",
                    "details": details,
                },
            },
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            429: "RATE_LIMIT_EXCEEDED",
            500: "INTERNAL_SERVER_ERROR",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": {
                    "code": code_map.get(exc.status_code, f"HTTP_{exc.status_code}"),
                    "message": str(exc.detail),
                    "details": [],
                },
            },
        )

    @application.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled server error: {exc}")
        message = str(exc) if settings.DEBUG else "An unexpected internal server error occurred."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": message,
                    "details": [],
                },
            },
        )

    # 4. Root Health Check Endpoint
    @application.get(
        "/health",
        response_model=ApiResponse[HealthData],
        status_code=status.HTTP_200_OK,
        tags=["Health"],
        summary="Root Service Health",
        description="Top-level health endpoint verifying service liveness.",
        operation_id="get_root_health",
    )
    async def root_health() -> ApiResponse[HealthData]:
        data = await HealthService.get_health()
        return ApiResponse(data=data, message="Service is healthy")

    # 5. Include API v1 Router
    application.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    return application


app = create_application()

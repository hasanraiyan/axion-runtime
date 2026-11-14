# AI Platform - Backend API

FastAPI backend service powering the AI Platform foundation.

## Features
- **API Versioning**: `/api/v1` routes.
- **Authentication**: Official Clerk SDK and JWT verification.
- **Standardized Response Formats**: Unified success and error envelope.
- **Pagination & Filtering**: Reusable query utilities.
- **OpenAPI 3.1 Contract**: Automated Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI spec (`/openapi.json`).
- **Centralized Error Handling**: Production-safe exceptions with proper HTTP status codes.

## Running Locally

```bash
# Sync dependencies
uv sync

# Run development server
uv run uvicorn app.main:app --reload --port 8000

# Run test suite
uv run pytest
```

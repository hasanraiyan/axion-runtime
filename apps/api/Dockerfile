# Multi-stage build for FastAPI backend using uv
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Copy dependency specifications first to leverage Docker layer caching
COPY apps/api/pyproject.toml apps/api/uv.lock apps/api/README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code and install project
COPY apps/api/app ./app
RUN uv sync --frozen --no-dev

# Final minimal production image
FROM python:3.13-slim AS runner

WORKDIR /app

# Install curl for healthchecks and setup non-root user
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 1001 appuser

# Copy virtual environment and code from builder stage
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --from=builder --chown=appuser:appuser /app/app /app/app

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8000

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

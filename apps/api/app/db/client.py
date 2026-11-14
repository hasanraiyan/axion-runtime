import time
from typing import Any, Dict, Optional
from beanie import init_beanie
from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings
from app.core.logging import logger

# Module-level client reference
_client: Optional[AsyncIOMotorClient] = None
_database: Optional[AsyncIOMotorDatabase] = None


def get_global_client() -> Optional[AsyncIOMotorClient]:
    return _client


def get_global_database() -> Optional[AsyncIOMotorDatabase]:
    return _database


async def init_db(app: Optional[FastAPI] = None) -> None:
    """
    Initialize MongoDB client with connection pooling and configure Beanie ODM.
    """
    global _client, _database

    try:
        logger.info(f"Connecting to MongoDB database '{settings.MONGODB_DB_NAME}'...")
        _client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            minPoolSize=settings.MONGODB_MIN_POOL_SIZE,
            maxPoolSize=settings.MONGODB_MAX_POOL_SIZE,
            serverSelectionTimeoutMS=settings.MONGODB_SERVER_SELECTION_TIMEOUT_MS,
        )
        _database = _client[settings.MONGODB_DB_NAME]

        # Verify connectivity
        await _client.admin.command("ping")
        logger.info("MongoDB connection successfully established.")

        # Initialize Beanie ODM if models are registered
        from app.models import DOCUMENT_MODELS

        if DOCUMENT_MODELS:
            await init_beanie(
                database=_database,
                document_models=DOCUMENT_MODELS,
            )
            logger.info(f"Beanie initialized with {len(DOCUMENT_MODELS)} document models.")

        if app is not None:
            app.state.mongo_client = _client
            app.state.mongo_db = _database

    except Exception as exc:
        logger.warning(
            f"MongoDB connection could not be established: {exc}. "
            "Continuing startup (endpoints requiring DB will fail until connection is ready)."
        )
        if app is not None:
            app.state.mongo_client = _client
            app.state.mongo_db = _database


async def close_db(app: Optional[FastAPI] = None) -> None:
    """
    Gracefully close MongoDB client connections.
    """
    global _client, _database
    if _client is not None:
        logger.info("Closing MongoDB client connections...")
        _client.close()
        _client = None
        _database = None
        if app is not None and hasattr(app.state, "mongo_client"):
            app.state.mongo_client = None
            app.state.mongo_db = None
        logger.info("MongoDB connections closed.")


async def check_db_health(client: Optional[AsyncIOMotorClient] = None) -> Dict[str, Any]:
    """
    Ping MongoDB to verify active connectivity and measure round-trip latency.
    """
    active_client = client or _client
    if active_client is None:
        return {"status": "disconnected", "error": "Client not initialized"}

    try:
        start_time = time.perf_counter()
        await active_client.admin.command("ping")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "connected",
            "latency_ms": latency_ms,
            "database": settings.MONGODB_DB_NAME,
        }
    except Exception as exc:
        return {
            "status": "disconnected",
            "error": str(exc),
            "database": settings.MONGODB_DB_NAME,
        }

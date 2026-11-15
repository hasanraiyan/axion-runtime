import base64
import json
from pathlib import Path
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.exceptions import ConfigurationError

_ENV_PATHS = (
    str(Path(__file__).resolve().parents[2] / ".env"),
    ".env",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_PATHS,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment
    ENVIRONMENT: str = Field(default="development", description="Runtime environment")
    DEBUG: bool = Field(default=False, description="Debug mode")
    PROJECT_NAME: str = Field(default="AI Platform API", description="Project Name")
    VERSION: str = Field(default="0.1.0", description="API Version")

    # Server
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    API_V1_PREFIX: str = Field(default="/api/v1", description="API v1 prefix")

    # CORS
    CORS_ORIGINS: Union[List[str], str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origins",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    # Clerk Authentication
    CLERK_SECRET_KEY: str = Field(default="", description="Clerk secret key")
    CLERK_PUBLISHABLE_KEY: str = Field(default="", description="Clerk publishable key")
    CLERK_JWT_KEY: Optional[str] = Field(default=None, description="Optional offline JWT public key")
    CLERK_FRONTEND_API: Optional[str] = Field(default=None, description="Optional Clerk frontend API domain")

    # MongoDB Database
    MONGODB_URL: str = Field(
        default="mongodb://root:example@localhost:27017/axion?authSource=admin",
        description="MongoDB connection URI",
    )
    MONGODB_DB_NAME: str = Field(default="axion", description="Database name")
    MONGODB_MIN_POOL_SIZE: int = Field(default=10, description="Minimum connection pool size")
    MONGODB_MAX_POOL_SIZE: int = Field(default=50, description="Maximum connection pool size")
    MONGODB_SERVER_SELECTION_TIMEOUT_MS: int = Field(
        default=5000, description="MongoDB server selection timeout in milliseconds"
    )

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=100, description="Max requests per minute per IP")

    # Outbound integration traffic (MOD-07 Outbound URL Guard)
    OUTBOUND_ALLOW_PRIVATE_NETWORKS: bool = Field(
        default=False,
        description="Allow integrations to target private networks (explicit on-premises deployments only)",
    )
    OUTBOUND_ALLOW_INSECURE_HTTP: bool = Field(
        default=False, description="Allow plain http integration targets (development only)"
    )

    # MCP session pool (MOD-07). Idle sessions are closed after the TTL; per-user sessions use the shorter one.
    MCP_POOL_ENABLED: bool = Field(default=True, description="Reuse MCP sessions across tool calls")
    MCP_POOL_IDLE_SECONDS: float = Field(default=300.0, ge=1.0, description="Idle TTL for shared-credential sessions")
    MCP_POOL_PER_USER_IDLE_SECONDS: float = Field(default=120.0, ge=1.0, description="Idle TTL for per-user sessions")
    MCP_POOL_MAX_PER_INTEGRATION: int = Field(default=8, ge=1, description="Pooled sessions per integration (LRU eviction)")
    MCP_POOL_MAX_TOTAL: int = Field(default=256, ge=1, description="Pooled sessions per process")
    TOOL_MAX_CONCURRENT_CALLS: int = Field(default=16, ge=1, le=256, description="In-flight tool calls per integration per process (override per integration with config.max_concurrent_calls)")
    TOOL_CONCURRENCY_WAIT_SECONDS: float = Field(default=2.0, ge=0, le=30, description="How long a call waits for a free concurrency slot before a retryable rate_limited")
    MCP_LIST_CHANGED_DEBOUNCE_SECONDS: float = Field(default=5.0, ge=0.0, description="Coalescing window before re-discovery")

    # Public base URL of this API, used to build OAuth redirect URIs and hosted connect links (MOD-07)
    PUBLIC_API_BASE_URL: str = Field(
        default="http://localhost:8000", description="Externally reachable base URL of the API (no trailing slash)"
    )

    # Cryptographic Envelope Encryption (MOD-02)
    AXION_MASTER_ENCRYPTION_KEY: str = Field(
        default="",
        description="Base64-encoded 32-byte master encryption key (KEK) for envelope encryption",
    )

    @field_validator("AXION_MASTER_ENCRYPTION_KEY", mode="before")
    @classmethod
    def validate_master_encryption_key(cls, v: Optional[str]) -> str:
        if not v or not isinstance(v, str) or not v.strip():
            raise ConfigurationError(
                "AXION_MASTER_ENCRYPTION_KEY is required and cannot be empty. "
                "A 256-bit (32-byte) base64-encoded key is required."
            )
        clean_key = v.strip()
        try:
            decoded = base64.b64decode(clean_key, validate=True)
        except Exception as exc:
            raise ConfigurationError(
                f"AXION_MASTER_ENCRYPTION_KEY is not a valid base64-encoded string: {exc}"
            ) from exc

        if len(decoded) != 32:
            raise ConfigurationError(
                f"AXION_MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits), got {len(decoded)} bytes"
            )
        return clean_key


settings = Settings()

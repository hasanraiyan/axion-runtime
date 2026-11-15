"""
OAuth value objects and PKCE helpers (SRS-07 FR-25). Pure, no I/O.

PKCE is mandatory (S256 only). ``state`` and link secrets are high-entropy random values; only their
SHA-256 digests are ever persisted.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class DiscoveredOAuth:
    issuer: str
    resource: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    scopes_supported: List[str] = field(default_factory=list)
    token_endpoint_auth_methods: List[str] = field(default_factory=list)
    iss_response_supported: bool = False


@dataclass(frozen=True)
class RegisteredClient:
    client_id: str
    client_secret: Optional[str] = None
    token_endpoint_auth_method: str = "none"


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    scopes: List[str] = field(default_factory=list)
    token_type: str = "Bearer"


def new_code_verifier() -> str:
    """RFC 7636 verifier: 43-128 unreserved characters (here 64)."""
    return secrets.token_urlsafe(48)


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_secret_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validated_iss(iss: Optional[str], issuer: str, required: bool) -> None:
    """RFC 9207: reject a mismatching ``iss``; require it when the server advertised support."""
    from app.core.tools.errors import OAuthFlowFailed

    if iss is not None and iss != issuer:
        raise OAuthFlowFailed("Authorization response came from an unexpected issuer")
    if iss is None and required:
        raise OAuthFlowFailed("Authorization response is missing the required issuer parameter")

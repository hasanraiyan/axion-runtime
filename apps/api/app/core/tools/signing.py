"""
Purpose-bound signed tokens (SRS-07 FR-37, FR-71): end-user session tokens and approval tokens.

Compact ``payload.signature`` tokens using HMAC-SHA-256 with a key derived from the
platform master key (so no new secret must be provisioned). Every token carries a
``purpose`` and an expiry; verification requires the expected purpose, so a token minted
for one use can never be replayed for another.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Callable, Dict, Optional

from app.core.exceptions import UnauthorizedError


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenSigner:
    def __init__(self, master_key_b64: str, clock: Callable[[], float] = time.time) -> None:
        master = base64.b64decode(master_key_b64)
        self._key = hashlib.sha256(b"axion:tools:token-signing:v1:" + master).digest()
        self._clock = clock

    def sign(self, purpose: str, claims: Dict[str, Any], ttl_seconds: int) -> str:
        payload = {**claims, "pur": purpose, "exp": int(self._clock()) + ttl_seconds}
        body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signature = _b64e(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def verify(self, token: str, purpose: str) -> Dict[str, Any]:
        try:
            body, signature = token.split(".", 1)
            expected = _b64e(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
            if not hmac.compare_digest(signature, expected):
                raise ValueError("bad signature")
            payload: Optional[Dict[str, Any]] = json.loads(_b64d(body))
        except (ValueError, TypeError, json.JSONDecodeError):
            raise UnauthorizedError("Invalid token") from None
        if not isinstance(payload, dict) or payload.get("pur") != purpose:
            raise UnauthorizedError("Invalid token")
        if int(payload.get("exp", 0)) < int(self._clock()):
            raise UnauthorizedError("Token expired")
        return payload


def arguments_hash(arguments: Dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

"""
Axion Runtime Cryptographic Boundary (MOD-02 Project Secrets Management).
Implements Two-Tier Envelope Encryption (AES-256-GCM + RFC 3394 AES Key Wrap)
with Canonical Additional Authenticated Data (AAD) tamper-proofing.
"""

from app.core.crypto.crypto_service import (
    AwaitableStr,
    CryptoService,
    get_crypto_service,
)
from app.core.crypto.envelope import EncryptedEnvelope
from app.core.crypto.provider import (
    AwaitableBytes,
    AwaitableTuple,
    KeyProvider,
    LocalMasterKeyProvider,
)

__all__ = [
    "KeyProvider",
    "LocalMasterKeyProvider",
    "EncryptedEnvelope",
    "CryptoService",
    "get_crypto_service",
    "AwaitableStr",
    "AwaitableTuple",
    "AwaitableBytes",
]

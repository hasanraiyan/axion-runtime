import base64
from abc import ABC, abstractmethod
from typing import Any, Generator, Optional, Tuple

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

from app.core.config import settings
from app.core.exceptions import ConfigurationError, CryptographicIntegrityError


class AwaitableTuple(tuple):
    """A tuple that can be evaluated synchronously or awaited asynchronously."""

    def __await__(self) -> Generator[Any, None, Tuple[Any, ...]]:
        async def _coro() -> Tuple[Any, ...]:
            return tuple(self)

        return _coro().__await__()


class AwaitableBytes(bytes):
    """Bytes that can be evaluated synchronously or awaited asynchronously."""

    def __await__(self) -> Generator[Any, None, bytes]:
        async def _coro() -> bytes:
            return bytes(self)

        return _coro().__await__()


class KeyProvider(ABC):
    """
    Abstract Base Class for Key Encryption Key (KEK) providers.
    Pluggable architecture allowing future extensions for Cloud KMS
    (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) per SRS-02 Section 5.4.
    """

    @abstractmethod
    async def wrap_key(self, dek: bytes, key_id: Optional[str] = None) -> Tuple[bytes, str]:
        """
        Wraps a plaintext DEK using the specified or default KEK.
        Returns (wrapped_dek_bytes, kek_id).
        """
        pass

    @abstractmethod
    async def unwrap_key(self, wrapped_dek: bytes, key_id: str) -> bytes:
        """
        Unwraps a wrapped DEK using the specified KEK ID.
        Returns the plaintext DEK bytes.
        """
        pass


class LocalMasterKeyProvider(KeyProvider):
    """
    Local Master Key Provider implementing RFC 3394 AES Key Wrap.
    Loads a 256-bit KEK from settings.AXION_MASTER_ENCRYPTION_KEY or explicit input.
    """

    def __init__(
        self,
        master_key: Optional[str] = None,
        kek_id: str = "local-v1",
    ) -> None:
        self.kek_id = kek_id
        raw_key = master_key if master_key is not None else settings.AXION_MASTER_ENCRYPTION_KEY

        if not raw_key or not isinstance(raw_key, str) or not raw_key.strip():
            raise ConfigurationError(
                "AXION_MASTER_ENCRYPTION_KEY is required and cannot be empty. "
                "A 256-bit (32-byte) base64-encoded key is required."
            )

        try:
            decoded = base64.b64decode(raw_key.strip(), validate=True)
        except Exception as exc:
            raise ConfigurationError(
                f"AXION_MASTER_ENCRYPTION_KEY is not a valid base64-encoded string: {exc}"
            ) from exc

        if len(decoded) != 32:
            raise ConfigurationError(
                f"AXION_MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits), got {len(decoded)} bytes"
            )

        self._kek_bytes = decoded

    def wrap_key(self, dek: bytes, key_id: Optional[str] = None) -> AwaitableTuple:
        """
        Wraps a 256-bit DEK using RFC 3394 AES Key Wrap.
        Returns AwaitableTuple of (wrapped_dek_bytes, kek_id).
        """
        target_kek_id = key_id or self.kek_id
        if target_kek_id != self.kek_id:
            raise CryptographicIntegrityError(
                f"Unknown KEK identifier '{target_kek_id}'. Expected '{self.kek_id}'."
            )

        if not isinstance(dek, (bytes, bytearray)):
            raise CryptographicIntegrityError("DEK must be bytes.")

        if len(dek) % 8 != 0 or len(dek) < 16:
            raise CryptographicIntegrityError(
                f"Invalid DEK length ({len(dek)} bytes). DEK must be a multiple of 8 bytes (minimum 16 bytes)."
            )

        try:
            wrapped = aes_key_wrap(self._kek_bytes, bytes(dek))
        except Exception as exc:
            raise CryptographicIntegrityError(f"Failed to wrap DEK: {exc}") from exc

        return AwaitableTuple((wrapped, self.kek_id))

    def unwrap_key(self, wrapped_dek: bytes, key_id: str) -> AwaitableBytes:
        """
        Unwraps a wrapped DEK using RFC 3394 AES Key Wrap.
        Returns AwaitableBytes of the plaintext DEK.
        """
        if key_id != self.kek_id:
            raise CryptographicIntegrityError(
                f"Unsupported or unknown KEK identifier '{key_id}'. Current KEK is '{self.kek_id}'."
            )

        if not isinstance(wrapped_dek, (bytes, bytearray)):
            raise CryptographicIntegrityError("Wrapped DEK must be bytes.")

        try:
            unwrapped = aes_key_unwrap(self._kek_bytes, bytes(wrapped_dek))
        except InvalidUnwrap as exc:
            raise CryptographicIntegrityError(
                "Failed to unwrap DEK: RFC 3394 key wrap integrity verification failed."
            ) from exc
        except Exception as exc:
            raise CryptographicIntegrityError(f"Failed to unwrap DEK: {exc}") from exc

        return AwaitableBytes(unwrapped)

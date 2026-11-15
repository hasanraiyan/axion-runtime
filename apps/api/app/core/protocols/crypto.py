from typing import Optional, Protocol, Tuple, runtime_checkable


@runtime_checkable
class KeyProviderProtocol(Protocol):
    """Protocol defining the Key Encryption Key (KEK) provider interface."""

    async def wrap_key(self, dek: bytes, key_id: Optional[str] = None) -> Tuple[bytes, str]:
        """
        Wraps a plaintext DEK using the specified or default KEK.
        Returns (wrapped_dek_bytes, kek_id).
        """
        ...

    async def unwrap_key(self, wrapped_dek: bytes, key_id: str) -> bytes:
        """
        Unwraps a wrapped DEK using the specified KEK ID.
        Returns the plaintext DEK bytes.
        """
        ...


@runtime_checkable
class EnvironmentPrefixStrategy(Protocol):
    """Protocol defining environment-to-credential prefix resolution and validation."""

    def get_prefix(self, environment: str) -> str:
        """Resolve the credential prefix (e.g. 'axion_live_' or 'axion_test_') for the environment."""
        ...

    def validate_prefix(self, raw_key: str) -> bool:
        """Verify whether an incoming raw key matches an accepted environment prefix."""
        ...


class DefaultEnvironmentPrefixStrategy:
    """Default strategy resolving 'production' to 'axion_live_' and other tiers to 'axion_test_'."""

    def get_prefix(self, environment: str) -> str:
        return "axion_live_" if environment.lower() == "production" else "axion_test_"

    def validate_prefix(self, raw_key: str) -> bool:
        return raw_key.startswith("axion_live_") or raw_key.startswith("axion_test_")

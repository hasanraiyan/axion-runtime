import base64
import os
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

from app.core.crypto.envelope import EncryptedEnvelope
from app.core.crypto.provider import KeyProvider, LocalMasterKeyProvider
from app.core.exceptions import CryptographicIntegrityError


class CryptoService:
    """
    Dedicated Cryptographic Service Boundary per SRS-02 Section 3.2, 5.1-5.4.
    Encapsulates:
    - 2-tier Envelope Encryption (Master KEK / Ephemeral 256-bit DEK).
    - AES-256-GCM AEAD encryption with 12-byte nonce and 16-byte auth tag.
    - Canonical AAD binding: 'axion:v1:proj:{project_id}:env:{environment}:name:{name}'.
    - RFC 3394 AES Key Wrap delegation to KeyProvider.
    """

    def __init__(self, key_provider: Optional[KeyProvider] = None) -> None:
        self.key_provider: KeyProvider = key_provider or LocalMasterKeyProvider()

    @staticmethod
    def build_aad(project_id: str, environment: str, name: str) -> bytes:
        """
        Constructs canonical Additional Authenticated Data (AAD) string per SRS-02 Section 5.3:
        axion:v1:proj:{project_id}:env:{environment}:name:{name}
        """
        if not project_id or not environment or not name:
            raise CryptographicIntegrityError(
                "Cannot construct AAD: project_id, environment, and name must all be non-empty."
            )
        return f"axion:v1:proj:{str(project_id).strip()}:env:{str(environment).strip()}:name:{str(name).strip()}".encode(
            "utf-8"
        )

    async def encrypt_secret(
        self,
        plaintext: Union[str, SecretStr],
        project_id: str,
        environment: str,
        name: str,
    ) -> EncryptedEnvelope:
        """
        Encrypts a plaintext secret value using AES-256-GCM and wraps a fresh 256-bit DEK
        using the active KEK provider.
        Binds mathematically to (project_id, environment, name) via canonical AAD.

        Returns EncryptedEnvelope.
        """
        # Extract string value if wrapped in SecretStr
        if isinstance(plaintext, SecretStr):
            raw_plaintext = plaintext.get_secret_value()
        elif hasattr(plaintext, "get_secret_value"):
            raw_plaintext = plaintext.get_secret_value()
        else:
            raw_plaintext = str(plaintext)

        if raw_plaintext is None:
            raise CryptographicIntegrityError("Plaintext secret value cannot be None.")

        # 1. Generate fresh 256-bit DEK (os.urandom(32)) and 96-bit nonce (os.urandom(12))
        dek = os.urandom(32)
        nonce = os.urandom(12)

        # 2. Construct canonical AAD binding
        aad = self.build_aad(project_id=project_id, environment=environment, name=name)

        # 3. Encrypt plaintext via AES-256-GCM
        try:
            aesgcm = AESGCM(dek)
            encrypted_payload = aesgcm.encrypt(nonce, raw_plaintext.encode("utf-8"), aad)
            # AESGCM in cryptography appends the 16-byte auth tag at the end of ciphertext
            ciphertext = encrypted_payload[:-16]
            auth_tag = encrypted_payload[-16:]
        except Exception as exc:
            raise CryptographicIntegrityError(f"AES-256-GCM encryption failed: {exc}") from exc

        # 4. Wrap DEK with KEK via KeyProvider (RFC 3394)
        wrapped_dek, kek_id = await self.key_provider.wrap_key(dek)

        # 5. Return EncryptedEnvelope with base64 encoded fields
        return EncryptedEnvelope(
            algorithm="AES-256-GCM",
            encrypted_dek=base64.b64encode(wrapped_dek).decode("utf-8"),
            ciphertext=base64.b64encode(ciphertext).decode("utf-8"),
            nonce=base64.b64encode(nonce).decode("utf-8"),
            auth_tag=base64.b64encode(auth_tag).decode("utf-8"),
            kek_id=kek_id,
        )

    async def decrypt_secret(
        self,
        envelope: Union[EncryptedEnvelope, dict],
        project_id: str,
        environment: str,
        name: str,
    ) -> str:
        """
        Decrypts an encrypted envelope using AES-256-GCM after unwrapping the DEK
        and verifying canonical AAD binding.
        Raises CryptographicIntegrityError if AAD or tag verification fails.

        Returns plaintext string.
        """
        # Parse into EncryptedEnvelope if a dictionary is provided
        if isinstance(envelope, dict):
            try:
                envelope_obj = EncryptedEnvelope(**envelope)
            except Exception as exc:
                raise CryptographicIntegrityError(f"Invalid encrypted envelope structure: {exc}") from exc
        elif isinstance(envelope, EncryptedEnvelope):
            envelope_obj = envelope
        else:
            raise CryptographicIntegrityError(
                f"Expected EncryptedEnvelope or dict, got {type(envelope).__name__}"
            )

        # 1. Validate algorithm
        if envelope_obj.algorithm != "AES-256-GCM":
            raise CryptographicIntegrityError(
                f"Unsupported encryption algorithm '{envelope_obj.algorithm}'. Only 'AES-256-GCM' is supported."
            )

        # 2. Base64 decode cryptographic components
        try:
            wrapped_dek = base64.b64decode(envelope_obj.encrypted_dek, validate=True)
            ciphertext = base64.b64decode(envelope_obj.ciphertext, validate=True)
            nonce = base64.b64decode(envelope_obj.nonce, validate=True)
            auth_tag = base64.b64decode(envelope_obj.auth_tag, validate=True)
        except Exception as exc:
            raise CryptographicIntegrityError(
                f"Failed to decode base64 cryptographic envelope components: {exc}"
            ) from exc

        if len(nonce) != 12:
            raise CryptographicIntegrityError(
                f"Invalid nonce length ({len(nonce)} bytes). AES-256-GCM requires a 12-byte (96-bit) nonce."
            )

        if len(auth_tag) != 16:
            raise CryptographicIntegrityError(
                f"Invalid auth_tag length ({len(auth_tag)} bytes). AES-256-GCM requires a 16-byte (128-bit) authentication tag."
            )

        # 3. Unwrap DEK using KEK provider
        dek = await self.key_provider.unwrap_key(wrapped_dek, envelope_obj.kek_id)

        if len(dek) != 32:
            raise CryptographicIntegrityError(
                f"Unwrapped DEK has invalid length ({len(dek)} bytes). Expected 32 bytes (256 bits)."
            )

        # 4. Construct canonical AAD binding
        aad = self.build_aad(project_id=project_id, environment=environment, name=name)

        # 5. Decrypt ciphertext and verify authentication tag + AAD
        try:
            aesgcm = AESGCM(dek)
            combined_payload = ciphertext + auth_tag
            plaintext_bytes = aesgcm.decrypt(nonce, combined_payload, aad)
        except InvalidTag as exc:
            raise CryptographicIntegrityError(
                "Cryptographic integrity verification failed: Authentication tag or AAD mismatch. "
                "Ciphertext may have been tampered with or translocated across projects/environments/names."
            ) from exc
        except Exception as exc:
            raise CryptographicIntegrityError(f"Decryption failed: {exc}") from exc

        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CryptographicIntegrityError(
                f"Decrypted plaintext is not valid UTF-8: {exc}"
            ) from exc

        return plaintext


_default_crypto_service: Optional[CryptoService] = None


def get_crypto_service() -> CryptoService:
    """Dependency provider / singleton accessor for CryptoService."""
    global _default_crypto_service
    if _default_crypto_service is None:
        _default_crypto_service = CryptoService()
    return _default_crypto_service

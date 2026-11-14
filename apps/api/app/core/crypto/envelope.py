from typing import Any, Generator
from pydantic import BaseModel, Field


class EncryptedEnvelope(BaseModel):
    """
    Cryptographic payload stored in database - ZERO PLAINTEXT.
    Conforms to SRS-02 Section 6.1.
    """

    algorithm: str = Field(default="AES-256-GCM", description="Cipher algorithm")
    encrypted_dek: str = Field(..., description="Base64-encoded wrapped Data Encryption Key")
    ciphertext: str = Field(..., description="Base64-encoded ciphertext")
    nonce: str = Field(..., description="Base64-encoded 12-byte initialization vector")
    auth_tag: str = Field(..., description="Base64-encoded 16-byte authentication tag")
    kek_id: str = Field(default="local-v1", description="Identifier of KEK used to wrap DEK")

    def __await__(self) -> Generator[Any, None, "EncryptedEnvelope"]:
        """
        Allows EncryptedEnvelope to be optionally awaited seamlessly
        by asynchronous service callers while remaining a standard Pydantic model.
        """
        async def _coro() -> "EncryptedEnvelope":
            return self

        return _coro().__await__()

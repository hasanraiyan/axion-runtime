import base64
import os
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.crypto import (
    CryptoService,
    EncryptedEnvelope,
    LocalMasterKeyProvider,
    get_crypto_service,
)
from app.core.exceptions import ConfigurationError, CryptographicIntegrityError


def test_master_key_fail_fast_validation():
    """Verify LocalMasterKeyProvider enforces 256-bit base64 key validation on startup."""
    # Empty key
    with pytest.raises(ConfigurationError):
        LocalMasterKeyProvider(master_key="")

    # Whitespace key
    with pytest.raises(ConfigurationError):
        LocalMasterKeyProvider(master_key="   ")

    # Invalid base64
    with pytest.raises(ConfigurationError):
        LocalMasterKeyProvider(master_key="not-valid-base64!!!")

    # Improper length: 16 bytes (128-bit)
    short_key = base64.b64encode(os.urandom(16)).decode()
    with pytest.raises(ConfigurationError):
        LocalMasterKeyProvider(master_key=short_key)

    # Improper length: 64 bytes (512-bit)
    long_key = base64.b64encode(os.urandom(64)).decode()
    with pytest.raises(ConfigurationError):
        LocalMasterKeyProvider(master_key=long_key)

    # Exactly 32 bytes (256-bit)
    valid_key = base64.b64encode(os.urandom(32)).decode()
    provider = LocalMasterKeyProvider(master_key=valid_key)
    assert provider.kek_id == "local-v1"


def test_rfc3394_key_wrap_and_unwrap():
    """Verify RFC 3394 AES Key Wrap and Unwrap operations."""
    valid_key = base64.b64encode(os.urandom(32)).decode()
    provider = LocalMasterKeyProvider(master_key=valid_key, kek_id="test-kek")

    dek = os.urandom(32)
    wrapped, kek_id = provider.wrap_key(dek)
    assert kek_id == "test-kek"
    assert len(wrapped) == 40  # 32 bytes wrapped with RFC 3394 becomes 40 bytes (32 + 8 IV)

    unwrapped = provider.unwrap_key(wrapped, "test-kek")
    assert unwrapped == dek

    # Tampered wrapped DEK raises CryptographicIntegrityError
    tampered_wrapped = bytearray(wrapped)
    tampered_wrapped[0] ^= 0xFF
    with pytest.raises(CryptographicIntegrityError):
        provider.unwrap_key(bytes(tampered_wrapped), "test-kek")

    # Mismatched KEK ID raises CryptographicIntegrityError
    with pytest.raises(CryptographicIntegrityError):
        provider.unwrap_key(wrapped, "unknown-kek")


def test_crypto_service_envelope_encryption():
    """Verify CryptoService envelope encryption produces valid EncryptedEnvelope."""
    service = get_crypto_service()

    plaintext = "super_sensitive_api_key_12345"
    project_id = "6735e0e0e0e0e0e0e0e0e001"
    environment = "production"
    name = "STRIPE_SECRET_KEY"

    envelope = service.encrypt_secret(
        plaintext=plaintext,
        project_id=project_id,
        environment=environment,
        name=name,
    )

    assert isinstance(envelope, EncryptedEnvelope)
    assert envelope.algorithm == "AES-256-GCM"
    assert envelope.kek_id == "local-v1"
    assert envelope.ciphertext != plaintext

    # Verify base64 decodability and lengths
    nonce = base64.b64decode(envelope.nonce)
    assert len(nonce) == 12  # 96-bit nonce
    tag = base64.b64decode(envelope.auth_tag)
    assert len(tag) == 16  # 128-bit auth tag
    wrapped_dek = base64.b64decode(envelope.encrypted_dek)
    assert len(wrapped_dek) == 40  # 32 bytes + 8 bytes RFC 3394 header

    # Decrypt and verify value
    decrypted = service.decrypt_secret(
        envelope=envelope,
        project_id=project_id,
        environment=environment,
        name=name,
    )
    assert decrypted == plaintext


def test_in_place_fresh_dek_and_nonce():
    """Verify each encryption operation generates fresh DEK and nonce (zero DEK/nonce reuse)."""
    service = get_crypto_service()
    plaintext = "identical_plaintext_value"

    env1 = service.encrypt_secret(plaintext, "proj1", "prod", "KEY1")
    env2 = service.encrypt_secret(plaintext, "proj1", "prod", "KEY1")

    assert env1.nonce != env2.nonce
    assert env1.ciphertext != env2.ciphertext
    assert env1.encrypted_dek != env2.encrypted_dek


def test_secretstr_support():
    """Verify pydantic.SecretStr is properly extracted and encrypted without leaking in repr."""
    service = get_crypto_service()
    secret_str = SecretStr("secret_payload_value")

    envelope = service.encrypt_secret(secret_str, "proj1", "prod", "API_TOKEN")
    decrypted = service.decrypt_secret(envelope, "proj1", "prod", "API_TOKEN")
    assert decrypted == "secret_payload_value"


def test_aad_translocation_tampering_project():
    """Verify changing project_id causes cryptographic tag verification failure (translocation protection)."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("val", "proj_legit", "production", "KEY")

    with pytest.raises(CryptographicIntegrityError) as exc_info:
        service.decrypt_secret(envelope, "proj_attacker", "production", "KEY")
    assert "Cryptographic integrity verification failed" in str(exc_info.value.message)


def test_aad_translocation_tampering_environment():
    """Verify changing environment causes cryptographic tag verification failure."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("val", "proj1", "production", "KEY")

    with pytest.raises(CryptographicIntegrityError):
        service.decrypt_secret(envelope, "proj1", "staging", "KEY")


def test_aad_translocation_tampering_name():
    """Verify changing secret name causes cryptographic tag verification failure."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("val", "proj1", "production", "KEY_A")

    with pytest.raises(CryptographicIntegrityError):
        service.decrypt_secret(envelope, "proj1", "production", "KEY_B")


def test_ciphertext_tampering():
    """Verify tampering with ciphertext bits fails tag verification."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("secret", "proj1", "prod", "KEY")

    corrupted_env = envelope.model_copy()
    raw_ct = bytearray(base64.b64decode(corrupted_env.ciphertext))
    raw_ct[0] ^= 0x01  # Flip 1 bit
    corrupted_env.ciphertext = base64.b64encode(raw_ct).decode()

    with pytest.raises(CryptographicIntegrityError):
        service.decrypt_secret(corrupted_env, "proj1", "prod", "KEY")


def test_auth_tag_tampering():
    """Verify tampering with authentication tag fails verification."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("secret", "proj1", "prod", "KEY")

    corrupted_env = envelope.model_copy()
    raw_tag = bytearray(base64.b64decode(corrupted_env.auth_tag))
    raw_tag[0] ^= 0x01
    corrupted_env.auth_tag = base64.b64encode(raw_tag).decode()

    with pytest.raises(CryptographicIntegrityError):
        service.decrypt_secret(corrupted_env, "proj1", "prod", "KEY")


def test_dict_input_to_decrypt():
    """Verify decrypt_secret accepts dictionary format (as fetched from MongoDB)."""
    service = get_crypto_service()
    envelope = service.encrypt_secret("payload", "proj1", "prod", "KEY")

    envelope_dict = envelope.model_dump()
    decrypted = service.decrypt_secret(envelope_dict, "proj1", "prod", "KEY")
    assert decrypted == "payload"


@pytest.mark.asyncio
async def test_async_awaitable_interoperability():
    """Verify encrypt_secret and decrypt_secret can be seamlessly awaited."""
    service = get_crypto_service()
    envelope = await service.encrypt_secret("async_val", "proj1", "prod", "ASYNC_KEY")
    assert isinstance(envelope, EncryptedEnvelope)

    decrypted = await service.decrypt_secret(envelope, "proj1", "prod", "ASYNC_KEY")
    assert decrypted == "async_val"

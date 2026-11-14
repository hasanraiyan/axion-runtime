from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from typing import Any, Dict

import pytest
from beanie import PydanticObjectId, init_beanie
from bson import ObjectId

from app.core.crypto.envelope import EncryptedEnvelope
from app.models.secret import ProjectSecret
from app.repositories.base import serialize_for_mongo
from app.repositories.secret_repository import ProjectSecretRepository


@pytest.fixture
async def initialized_secret_document():
    """Initialize Beanie for ProjectSecret without touching a real MongoDB."""
    db = MagicMock()
    db.name = "axion_test"
    db.command = AsyncMock(return_value={"version": "7.0.0", "versionArray": [7, 0, 0]})
    db.list_collection_names = AsyncMock(return_value=[])

    collection = MagicMock()
    collection.name = "project_secrets"
    collection.create_index = AsyncMock()
    collection.create_indexes = AsyncMock(return_value=[])
    collection.index_information = AsyncMock(return_value={})
    db.__getitem__.return_value = collection

    await init_beanie(database=db, document_models=[ProjectSecret])
    return collection


def _envelope(value: str) -> EncryptedEnvelope:
    return EncryptedEnvelope(
        encrypted_dek="ZGVr",
        ciphertext=value,
        nonce="bm9uY2U=",
        auth_tag="dGFn",
    )


def test_serialize_for_mongo_converts_nested_models():
    """Raw PyMongo update payloads must not contain Pydantic models."""
    payload = {
        "envelope": _envelope("cipher"),
        "settings": {"allowed": [{"key": "A", "ttl": 5}]},
        "tags": ("a", "b"),
    }

    result = serialize_for_mongo(payload)

    assert result["envelope"] == _envelope("cipher").model_dump()
    assert isinstance(result["envelope"], dict)
    assert result["settings"] == {"allowed": [{"key": "A", "ttl": 5}]}
    assert result["tags"] == ["a", "b"]


async def test_update_with_revision_persists_envelope_as_document(initialized_secret_document):
    """
    Regression test: secret rotation previously crashed with
    `bson.errors.InvalidDocument` because the EncryptedEnvelope model was passed
    straight to `find_one_and_update`.
    """
    repo = ProjectSecretRepository()
    project_id = ObjectId()
    secret_id = ObjectId()
    now = datetime.now(timezone.utc)

    stored_doc: Dict[str, Any] = ProjectSecret(
        id=PydanticObjectId(secret_id),
        project_id=project_id,
        name="OPENAI_API_KEY",
        environment="production",
        envelope=_envelope("bmV3"),
        revision=2,
        created_by="user_test",
        updated_by="user_test",
        last_rotated_at=now,
    ).model_dump(by_alias=True)

    collection = MagicMock()
    collection.find_one_and_update = AsyncMock(return_value=stored_doc)
    repo.get_collection = MagicMock(return_value=collection)  # type: ignore[method-assign]

    updated = await repo.update_with_revision(
        secret_id=secret_id,
        project_id=project_id,
        expected_revision=1,
        update_dict={"envelope": _envelope("bmV3"), "last_rotated_at": now},
    )

    applied_set = collection.find_one_and_update.await_args.args[1]["$set"]
    assert isinstance(applied_set["envelope"], dict)
    assert applied_set["envelope"]["ciphertext"] == "bmV3"
    assert applied_set["revision"] == 2
    assert isinstance(updated, ProjectSecret)
    assert updated.envelope.ciphertext == "bmV3"

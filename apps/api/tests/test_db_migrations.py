"""Legacy index detection/removal and the configurable toolset cache TTL."""
from typing import Any, List

from app.db.migrations import (
    LEGACY_TOOL_INVOCATION_TTL_INDEX,
    drop_legacy_indexes,
    legacy_index_warning,
    legacy_indexes_present,
)
from app.services.tools.toolset_cache import ToolsetCache


class FakeCollection:
    def __init__(self, names: List[str], fail: bool = False) -> None:
        self.names = list(names)
        self.fail = fail
        self.dropped: List[str] = []

    async def list_indexes(self) -> Any:
        if self.fail:
            raise RuntimeError("ns does not exist")

        async def gen():
            for name in self.names:
                yield {"name": name}

        return gen()

    async def drop_index(self, name: str) -> None:
        self.names.remove(name)
        self.dropped.append(name)


class FakeDb:
    def __init__(self, collection: FakeCollection) -> None:
        self.collection = collection

    def __getitem__(self, name: str) -> FakeCollection:
        assert name == "tool_invocations"
        return self.collection


async def test_the_legacy_ttl_index_is_detected_and_other_indexes_are_not():
    db = FakeDb(FakeCollection(["_id_", LEGACY_TOOL_INVOCATION_TTL_INDEX, "idx_tool_invocations_expire"]))
    assert await legacy_indexes_present(db) == [LEGACY_TOOL_INVOCATION_TTL_INDEX]
    assert await legacy_indexes_present(FakeDb(FakeCollection(["_id_", "idx_tool_invocations_expire"]))) == []


async def test_a_missing_collection_or_server_error_never_breaks_startup():
    assert await legacy_indexes_present(FakeDb(FakeCollection([], fail=True))) == []


async def test_dropping_removes_only_the_legacy_index_and_is_idempotent():
    collection = FakeCollection(["_id_", LEGACY_TOOL_INVOCATION_TTL_INDEX, "idx_tool_invocations_expire"])
    db = FakeDb(collection)
    assert await drop_legacy_indexes(db) == [LEGACY_TOOL_INVOCATION_TTL_INDEX]
    assert collection.names == ["_id_", "idx_tool_invocations_expire"]
    assert await drop_legacy_indexes(db) == []


def test_the_warning_names_the_index_and_the_fix():
    text = legacy_index_warning([LEGACY_TOOL_INVOCATION_TTL_INDEX])
    assert LEGACY_TOOL_INVOCATION_TTL_INDEX in text and "drop_legacy_indexes.py --apply" in text


def test_a_zero_ttl_disables_the_toolset_cache():
    cache = ToolsetCache(ttl=0)
    key = cache.key("p", "member:m", None)
    cache.put(key, "v", cache.generation("p"))
    assert len(cache) == 0 and cache.get(key) is None  # nothing is even stored

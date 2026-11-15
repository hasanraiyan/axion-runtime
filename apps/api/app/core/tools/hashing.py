"""Deterministic tool identity and definition hashing (SRS-07 FR-11, FR-14)."""
import hashlib
import json
import re
from typing import Any, Dict, Optional

from app.core.tools.types import DiscoveredTool

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_tool_name(name: str) -> str:
    """Lowercase, non-alphanumerics to ``_``, trimmed. Deterministic and stable."""
    cleaned = _NON_ALNUM.sub("_", name.strip().lower()).strip("_")
    return cleaned or "tool"


def make_tool_key(integration_slug: str, upstream_name: str) -> str:
    return f"{integration_slug}.{normalize_tool_name(upstream_name)}"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def definition_hash(tool: DiscoveredTool) -> str:
    """Hash of everything a model or admin could be misled by if it silently changed."""
    payload: Dict[str, Optional[Any]] = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "annotations": {k: v for k, v in sorted(tool.annotations.items())},
        "ui": tool.ui,
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def catalog_hash(hashes: list[str]) -> str:
    return hashlib.sha256(_canonical(sorted(hashes)).encode("utf-8")).hexdigest()

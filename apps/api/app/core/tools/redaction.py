"""Argument redaction for invocation records and audit payloads (SRS-07 NFR-S1, FR-61)."""
import re
from typing import Any, Dict, Iterable

_SENSITIVE_KEY = re.compile(r"(secret|token|password|passwd|authorization|api[_-]?key|credential|private[_-]?key)", re.I)
MAX_STRING = 500
MAX_ITEMS = 50
MAX_DEPTH = 5
REDACTED = "[REDACTED]"


def _redact(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for i, (key, item) in enumerate(value.items()):
            if i >= MAX_ITEMS:
                out["..."] = f"{len(value) - MAX_ITEMS} more"
                break
            out[str(key)] = REDACTED if _SENSITIVE_KEY.search(str(key)) else _redact(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [_redact(v, depth + 1) for v in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"... {len(value) - MAX_ITEMS} more")
        return items
    if isinstance(value, str) and len(value) > MAX_STRING:
        return value[:MAX_STRING] + "...[truncated]"
    return value


def redact_arguments(arguments: Dict[str, Any], hide_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """Mask sensitive-looking keys, drop hidden (context-bound/locked) ones, and bound size."""
    hidden = set(hide_keys)
    visible = {k: v for k, v in arguments.items() if k not in hidden}
    return _redact(visible, 0)

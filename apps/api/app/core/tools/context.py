"""Context-bound argument keys (SRS-07 FR-76): the server-verified values a tool parameter may be bound to."""

ALLOWED_CONTEXT_KEYS = frozenset(
    {
        "project.id",
        "member.id",
        "end_user.id",
        "end_user.external_id",
        "agent.id",
        "run.id",
    }
)


def is_valid_context_key(key: str) -> bool:
    """Fixed keys, or ``end_user.<attribute>`` for allow-listed end-user attributes."""
    if key in ALLOWED_CONTEXT_KEYS:
        return True
    prefix = "end_user."
    if key.startswith(prefix):
        attribute = key[len(prefix):]
        return bool(attribute) and attribute.replace("_", "").isalnum() and attribute not in ("id", "external_id")
    return False

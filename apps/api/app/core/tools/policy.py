"""Approval-policy derivation and ordering (SRS-07 FR-37)."""
from typing import Mapping, Optional

from app.models.tool import ApprovalPolicy

_STRICTNESS = {ApprovalPolicy.AUTO: 0, ApprovalPolicy.REQUIRE_APPROVAL: 1, ApprovalPolicy.DENY: 2}


def default_approval_policy(annotations: Mapping[str, Optional[bool]]) -> ApprovalPolicy:
    """
    Safe default from tool annotations: only provably read-only tools run unattended.
    Unknown annotations, destructive, and open-world non-read-only tools need approval.
    """
    if annotations.get("read_only") is True and annotations.get("destructive") is not True:
        return ApprovalPolicy.AUTO
    return ApprovalPolicy.REQUIRE_APPROVAL


def stricter(a: ApprovalPolicy, b: Optional[ApprovalPolicy]) -> ApprovalPolicy:
    """Return the stricter of two policies (a binding may only tighten a tool's policy)."""
    if b is None:
        return a
    return a if _STRICTNESS[a] >= _STRICTNESS[b] else b

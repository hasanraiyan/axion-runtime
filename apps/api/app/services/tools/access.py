"""
ToolAccessService (SRS-07 FR-30): Gate 1 (availability, audience, subject) as pure logic.

No I/O and no protocol or credential knowledge. Given already-loaded records it answers
"is this tool available to this principal, and if not, why?". Both the ``ToolsetResolver`` and
the Gateway use it, so listing and invoking can never disagree.

Binding precedence (most specific wins, deny wins within a level):
  1. named end-user deny rules (block list)  -> denied
  2. agent-level rules for this agent        -> deny wins, else allow
  3. project-default rules                   -> deny wins, else allow
  4. no matching rule                        -> not bound (default-deny)
Rules at levels 2 and 3 apply only when their ``audience`` contains the subject's kind.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from app.core.tools.policy import stricter
from app.core.tools.types import PrincipalContext, SubjectType
from app.models.integration import CredentialMode, EndUserAccess, Integration, IntegrationStatus
from app.models.tool import (
    ApprovalPolicy,
    BindingEffect,
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
    ToolDefinition,
    ToolSetting,
    ToolSyncState,
)


@dataclass(frozen=True)
class Availability:
    available: bool
    reason: Optional[str] = None
    auth_required: bool = False
    approval_policy: ApprovalPolicy = ApprovalPolicy.REQUIRE_APPROVAL


def _matches(binding: ToolBinding, integration: Integration, tool_key: str) -> bool:
    if binding.target_type == BindingTargetType.TOOL:
        return binding.target_id == tool_key
    return binding.target_id == str(integration.id)


class ToolAccessService:
    def evaluate(
        self,
        integration: Integration,
        definition: ToolDefinition,
        setting: Optional[ToolSetting],
        bindings: List[ToolBinding],
        principal: PrincipalContext,
    ) -> Availability:
        subject = principal.subject

        # Integration state
        if integration.is_deleted:
            return Availability(False, "integration_deleted")
        if not integration.is_enabled or integration.status == IntegrationStatus.DISABLED:
            return Availability(False, "disabled")
        per_user = integration.auth_profile.credential_mode == CredentialMode.PER_USER
        if integration.status == IntegrationStatus.DRAFT:
            return Availability(False, "integration_not_ready")
        if integration.status == IntegrationStatus.ERROR:
            return Availability(False, "integration_error")
        if integration.status == IntegrationStatus.NEEDS_AUTH and not per_user:
            return Availability(False, "integration_error")

        # Tool state
        if definition.sync_state == ToolSyncState.CHANGED:
            return Availability(False, "drift")
        if definition.sync_state == ToolSyncState.REMOVED_UPSTREAM:
            return Availability(False, "removed_upstream")
        if setting is None or not setting.is_enabled:
            return Availability(False, "disabled")
        if setting.approved_hash != definition.definition_hash and definition.sync_state != ToolSyncState.MANUAL:
            return Availability(False, "drift")
        if setting.approval_policy == ApprovalPolicy.DENY:
            return Availability(False, "denied")

        # Subject
        if subject.type == SubjectType.END_USER and integration.end_user_access != EndUserAccess.OPEN:
            return Availability(False, "end_user_access_closed")

        # Bindings (Gate 1)
        decision = self._decide_bindings(integration, definition.tool_key, bindings, principal)
        if decision[0] is not True:
            return Availability(False, decision[1])

        policy = stricter(setting.approval_policy, decision[2])

        # Gate 2 (credential): without a stored per-user connection, the subject must connect first.
        if per_user:
            return Availability(False, "auth_required", auth_required=True, approval_policy=policy)
        return Availability(True, approval_policy=policy)

    @staticmethod
    def _decide_bindings(
        integration: Integration, tool_key: str, bindings: List[ToolBinding], principal: PrincipalContext
    ) -> tuple[bool, Optional[str], Optional[ApprovalPolicy]]:
        subject = principal.subject
        audience = subject.audience
        matching = [b for b in bindings if _matches(b, integration, tool_key)]

        # 1. Named end-user block list.
        if subject.type == SubjectType.END_USER and subject.external_id:
            for b in matching:
                if (
                    b.subject_type == BindingSubjectType.END_USER
                    and b.subject_id == subject.external_id
                    and b.effect == BindingEffect.DENY
                ):
                    return False, "denied", None

        excluded_by_audience = False
        for level, level_ok in (
            (BindingSubjectType.AGENT, principal.agent_id is not None),
            (BindingSubjectType.PROJECT_DEFAULT, True),
        ):
            if not level_ok:
                continue
            rules = [
                b
                for b in matching
                if b.subject_type == level
                and (level == BindingSubjectType.PROJECT_DEFAULT or b.subject_id == principal.agent_id)
            ]
            applicable = [b for b in rules if audience in b.audience]
            if rules and not applicable:
                excluded_by_audience = True
            if not applicable:
                continue
            if any(b.effect == BindingEffect.DENY for b in applicable):
                return False, "denied", None
            override: Optional[ApprovalPolicy] = None
            for b in applicable:
                override = stricter(override, b.approval_policy_override) if override else b.approval_policy_override
            return True, None, override

        return False, ("audience_not_allowed" if excluded_by_audience else "not_bound"), None

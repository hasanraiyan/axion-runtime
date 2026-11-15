"""
Pure unit tests for Module 07 building blocks: access rules, credential gate, auth strategies,
policy, hashing, redaction, resilience, signing. No I/O. Several tests exist specifically because a
mutation run showed a rule was only protected indirectly by an earlier, overlapping check.
"""
import pytest
from beanie import PydanticObjectId

from app.core.exceptions import BadRequestError, UnauthorizedError
from app.core.tools.hashing import catalog_hash, definition_hash, make_tool_key, normalize_tool_name
from app.core.tools.policy import default_approval_policy, stricter
from app.core.tools.redaction import redact_arguments
from app.core.tools.resilience import CircuitBreaker, IdempotencyStore, SlidingWindowRateLimiter
from app.core.tools.signing import TokenSigner, arguments_hash
from app.core.tools.types import Actor, ActorType, DiscoveredTool, PrincipalContext, Subject, SubjectType
from app.core.config import settings
from app.core.secret_templates import SecretTemplateParser
from app.integrations.auth import (
    ApiKeyStrategy,
    BasicStrategy,
    BearerStrategy,
    CustomHeadersStrategy,
    NoAuthStrategy,
    build_default_auth_registry,
)
from app.models.integration import AuthProfile, AuthType, CredentialMode, Integration, IntegrationStatus, IntegrationType
from app.models.tool import (
    ApprovalPolicy,
    Audience,
    BindingEffect,
    BindingSubjectType,
    BindingTargetType,
    ToolBinding,
    ToolDefinition,
    ToolSetting,
    ToolSyncState,
)
from app.services.tools.access import ToolAccessService
from app.services.tools.credentials import AuthRequired, CredentialBuilder
from tests.tools_harness import StaticResolver  # noqa: F401  (ensures harness imports cleanly)

pytestmark = pytest.mark.usefixtures("tool_models")
PID = PydanticObjectId()


def integration(**kw) -> Integration:
    return Integration(project_id=PID, type=IntegrationType.MCP, slug="svc", name="Svc", status=IntegrationStatus.ACTIVE, created_by="u", updated_by="u", **kw)


def definition(integration_id, state=ToolSyncState.IN_SYNC, digest="h1") -> ToolDefinition:
    return ToolDefinition(project_id=PID, integration_id=integration_id, tool_key="svc.t", upstream_name="t", definition_hash=digest, sync_state=state)


def setting(**kw) -> ToolSetting:
    base = dict(project_id=PID, tool_key="svc.t", is_enabled=True, approved_hash="h1", approval_policy=ApprovalPolicy.AUTO)
    base.update(kw)
    return ToolSetting(**base)


def binding(effect=BindingEffect.ALLOW, subject=BindingSubjectType.PROJECT_DEFAULT, subject_id=None, audience=(Audience.MEMBERS,), target=None, override=None) -> ToolBinding:
    return ToolBinding(project_id=PID, subject_type=subject, subject_id=subject_id, audience=list(audience), target_type=BindingTargetType.TOOL, target_id=target or "svc.t", effect=effect, approval_policy_override=override)


def principal(subject=Subject(SubjectType.MEMBER, id="m1"), agent_id=None) -> PrincipalContext:
    return PrincipalContext(project_id=str(PID), actor=Actor(ActorType.USER, "m1"), subject=subject, agent_id=agent_id)


# ------------------------------------------------------------------ access service: each rule alone
class TestToolAccessService:
    access = ToolAccessService()

    def check(self, *, integ=None, defn=None, sett="default", bindings=None, who=None):
        integ = integ or integration()
        integ.id = integ.id or PydanticObjectId()
        defn = defn or definition(integ.id)
        sett = setting() if sett == "default" else sett
        return self.access.evaluate(integ, defn, sett, bindings if bindings is not None else [binding()], who or principal())

    def test_baseline_is_available(self):
        assert self.check().available

    def test_changed_definition_is_suspended_even_when_the_hash_still_matches(self):
        # The state flag and the hash check overlap; each must hold on its own.
        integ = integration()
        integ.id = PydanticObjectId()
        result = self.access.evaluate(integ, definition(integ.id, ToolSyncState.CHANGED), setting(), [binding()], principal())
        assert not result.available and result.reason == "drift"

    def test_unapproved_hash_is_suspended_even_when_the_state_says_in_sync(self):
        result = self.check(sett=setting(approved_hash="older"))
        assert not result.available and result.reason == "drift"

    def test_removed_upstream_disabled_and_denied_policy(self):
        integ = integration()
        integ.id = PydanticObjectId()
        assert self.access.evaluate(integ, definition(integ.id, ToolSyncState.REMOVED_UPSTREAM), setting(), [binding()], principal()).reason == "removed_upstream"
        assert self.check(sett=setting(is_enabled=False)).reason == "disabled"
        assert self.check(sett=None).reason == "disabled"
        assert self.check(sett=setting(approval_policy=ApprovalPolicy.DENY)).reason == "denied"

    @pytest.mark.parametrize(
        "status,reason",
        [(IntegrationStatus.DRAFT, "integration_not_ready"), (IntegrationStatus.ERROR, "integration_error"), (IntegrationStatus.NEEDS_AUTH, "integration_error"), (IntegrationStatus.DISABLED, "disabled")],
    )
    def test_integration_state_gates(self, status, reason):
        integ = integration()
        integ.status = status
        assert self.check(integ=integ).reason == reason

    def test_degraded_integrations_still_serve(self):
        integ = integration()
        integ.status = IntegrationStatus.DEGRADED
        assert self.check(integ=integ).available

    def test_precedence_end_user_block_beats_agent_allow_beats_default_deny(self):
        user = Subject(SubjectType.END_USER, id="u1", external_id="cust")
        integ = integration()
        integ.end_user_access = "open"
        everyone = [Audience.MEMBERS, Audience.END_USERS]
        allow_agent = binding(subject=BindingSubjectType.AGENT, subject_id="a1", audience=everyone)
        deny_default = binding(effect=BindingEffect.DENY, audience=everyone)
        who = principal(user, agent_id="a1")
        assert self.check(integ=integ, bindings=[deny_default, allow_agent], who=who).available  # agent overrides default

        block = binding(effect=BindingEffect.DENY, subject=BindingSubjectType.END_USER, subject_id="cust")
        assert self.check(integ=integ, bindings=[allow_agent, block], who=who).reason == "denied"
        other_user = principal(Subject(SubjectType.END_USER, id="u2", external_id="someone_else"), agent_id="a1")
        assert self.check(integ=integ, bindings=[allow_agent, block], who=other_user).available

    def test_audience_exclusion_is_reported_distinctly_from_not_bound(self):
        assert self.check(bindings=[binding(audience=[Audience.MACHINE])]).reason == "audience_not_allowed"
        assert self.check(bindings=[]).reason == "not_bound"

    def test_agent_rules_for_other_agents_do_not_apply(self):
        mine = binding(subject=BindingSubjectType.AGENT, subject_id="a1")
        assert self.check(bindings=[mine], who=principal(agent_id="a2")).reason == "not_bound"

    def test_per_user_integration_asks_the_subject_to_connect(self):
        integ = integration()
        integ.auth_profile.credential_mode = CredentialMode.PER_USER
        result = self.check(integ=integ)
        assert result.auth_required and not result.available

    def test_integration_level_rule_matches_every_tool_of_that_integration(self):
        integ = integration()
        integ.id = PydanticObjectId()
        rule = ToolBinding(project_id=PID, subject_type=BindingSubjectType.PROJECT_DEFAULT, target_type=BindingTargetType.INTEGRATION, target_id=str(integ.id))
        assert self.check(integ=integ, bindings=[rule]).available


# ------------------------------------------------------------------ credential gate (defence in depth)
async def test_credential_builder_never_falls_back_for_per_user_integrations():
    class Secrets:
        async def read(self, *a):  # pragma: no cover - must never be called
            raise AssertionError("a shared secret was read for a per-user integration")

        async def read_by_name(self, *a):  # pragma: no cover
            raise AssertionError("a shared secret was read for a per-user integration")

    integ = integration()
    integ.auth_profile = AuthProfile(auth_type=AuthType.BEARER, credential_mode=CredentialMode.PER_USER, secret_id=PydanticObjectId())
    builder = CredentialBuilder(build_default_auth_registry(), Secrets())
    with pytest.raises(AuthRequired):
        await builder.resolve(integ, Subject(SubjectType.END_USER, id="u1"))
    with pytest.raises(AuthRequired):
        await builder.resolve(integ, Subject(SubjectType.PROJECT))


# ------------------------------------------------------------------ auth strategies
class FakeSecrets:
    async def read(self, project_id, secret_id):
        return f"secret-{secret_id[-4:]}"

    async def read_by_name(self, project_id, name):
        return {"TOKEN": "tok-123"}.get(name)


async def test_auth_strategies_build_credentials_in_memory():
    sid = PydanticObjectId()
    tail = str(sid)[-4:]
    p = "p"
    assert (await NoAuthStrategy().build(p, AuthProfile(), FakeSecrets())).headers == {}
    assert (await BearerStrategy().build(p, AuthProfile(auth_type=AuthType.BEARER, secret_id=sid), FakeSecrets())).headers == {"Authorization": f"Bearer secret-{tail}"}
    api_header = await ApiKeyStrategy().build(p, AuthProfile(auth_type=AuthType.API_KEY, secret_id=sid, name="X-K", prefix="Key "), FakeSecrets())
    assert api_header.headers == {"X-K": f"Key secret-{tail}"}
    api_query = await ApiKeyStrategy().build(p, AuthProfile(auth_type=AuthType.API_KEY, secret_id=sid, placement="query", name="key"), FakeSecrets())
    assert api_query.query == {"key": f"secret-{tail}"} and not api_query.headers
    basic = await BasicStrategy().build(p, AuthProfile(auth_type=AuthType.BASIC, secret_id=sid, username="ann"), FakeSecrets())
    import base64

    assert base64.b64decode(basic.headers["Authorization"].split()[1]).decode() == f"ann:secret-{tail}"
    custom = await CustomHeadersStrategy().build(p, AuthProfile(auth_type=AuthType.CUSTOM_HEADERS, headers={"X-A": "Bearer {{secrets.TOKEN}}"}), FakeSecrets())
    assert custom.headers == {"X-A": "Bearer tok-123"}


async def test_credentials_repr_never_exposes_values():
    creds = await BearerStrategy().build("p", AuthProfile(auth_type=AuthType.BEARER, secret_id=PydanticObjectId()), FakeSecrets())
    assert "secret-" not in repr(creds) and "secret-" not in str(creds) and "Authorization" in repr(creds)


@pytest.mark.parametrize(
    "strategy,profile",
    [
        (ApiKeyStrategy(), AuthProfile(auth_type=AuthType.API_KEY)),  # no secret
        (ApiKeyStrategy(), AuthProfile(auth_type=AuthType.API_KEY, secret_id=PydanticObjectId(), placement="query")),  # query needs a name
        (ApiKeyStrategy(), AuthProfile(auth_type=AuthType.API_KEY, secret_id=PydanticObjectId(), name="Bad\r\nHeader")),
        (ApiKeyStrategy(), AuthProfile(auth_type=AuthType.API_KEY, secret_id=PydanticObjectId(), name="Host")),
        (BearerStrategy(), AuthProfile(auth_type=AuthType.BEARER)),
        (BasicStrategy(), AuthProfile(auth_type=AuthType.BASIC, secret_id=PydanticObjectId())),  # no username
        (BasicStrategy(), AuthProfile(auth_type=AuthType.BASIC, secret_id=PydanticObjectId(), username="a:b")),
        (CustomHeadersStrategy(), AuthProfile(auth_type=AuthType.CUSTOM_HEADERS)),
        (CustomHeadersStrategy(), AuthProfile(auth_type=AuthType.CUSTOM_HEADERS, headers={"Transfer-Encoding": "x"})),
        (CustomHeadersStrategy(), AuthProfile(auth_type=AuthType.CUSTOM_HEADERS, headers={"X-A": "line\nbreak"})),
        (NoAuthStrategy(), AuthProfile(credential_mode=CredentialMode.PER_USER)),
    ],
)
def test_malformed_auth_profiles_are_rejected(strategy, profile):
    with pytest.raises(BadRequestError):
        strategy.validate(profile)


async def test_custom_header_resolution_fails_on_a_missing_secret_and_on_injected_newlines():
    class Evil(FakeSecrets):
        async def read_by_name(self, project_id, name):
            return "ok\r\nX-Injected: 1" if name == "EVIL" else None

    strategy = CustomHeadersStrategy()
    with pytest.raises(BadRequestError):
        await strategy.build("p", AuthProfile(auth_type=AuthType.CUSTOM_HEADERS, headers={"X-A": "{{secrets.MISSING}}"}), FakeSecrets())
    with pytest.raises(BadRequestError):
        await strategy.build("p", AuthProfile(auth_type=AuthType.CUSTOM_HEADERS, headers={"X-A": "{{secrets.EVIL}}"}), Evil())


def test_secret_template_parser_and_registry_contents():
    assert SecretTemplateParser.extract_placeholders("a {{secrets.A}} {{ secrets.B }} {{secrets.A}}") == ["A", "B"]
    assert SecretTemplateParser.interpolate("x {{secrets.A}} {{secrets.B}}", {"A": "1"}) == "x 1 {{secrets.B}}"
    registry = build_default_auth_registry()
    assert {t.value for t in registry.types()} == {"none", "api_key", "bearer", "basic", "custom_headers", "oauth_authorization_code"}
    assert registry.get(AuthType.OAUTH_AUTHORIZATION_CODE).uses_connection
    assert not registry.get(AuthType.BEARER).uses_connection
    with pytest.raises(BadRequestError):
        registry.get(AuthType.OAUTH_CLIENT_CREDENTIALS)  # machine-to-machine OAuth is a later phase


# ------------------------------------------------------------------ policy, hashing
def test_default_approval_policy_is_conservative():
    assert default_approval_policy({"read_only": True}) == ApprovalPolicy.AUTO
    assert default_approval_policy({"read_only": True, "destructive": True}) == ApprovalPolicy.REQUIRE_APPROVAL
    assert default_approval_policy({"read_only": False}) == ApprovalPolicy.REQUIRE_APPROVAL
    assert default_approval_policy({}) == ApprovalPolicy.REQUIRE_APPROVAL
    assert stricter(ApprovalPolicy.AUTO, ApprovalPolicy.DENY) == ApprovalPolicy.DENY
    assert stricter(ApprovalPolicy.REQUIRE_APPROVAL, ApprovalPolicy.AUTO) == ApprovalPolicy.REQUIRE_APPROVAL
    assert stricter(ApprovalPolicy.AUTO, None) == ApprovalPolicy.AUTO


def test_tool_names_and_keys_are_deterministic():
    assert normalize_tool_name("  Get-Item.v2! ") == "get_item_v2"
    assert normalize_tool_name("!!!") == "tool"
    assert make_tool_key("svc", "Create Issue") == "svc.create_issue"


def test_definition_hash_changes_with_anything_a_model_could_be_misled_by():
    base = DiscoveredTool(name="t", description="d", input_schema={"type": "object"}, annotations={"read_only": True})
    same = DiscoveredTool(name="t", description="d", input_schema={"type": "object"}, annotations={"read_only": True})
    assert definition_hash(base) == definition_hash(same)
    for changed in (
        DiscoveredTool(name="t", description="d2", input_schema={"type": "object"}, annotations={"read_only": True}),
        DiscoveredTool(name="t", description="d", input_schema={"type": "object", "properties": {"x": {}}}, annotations={"read_only": True}),
        DiscoveredTool(name="t", description="d", input_schema={"type": "object"}, annotations={"read_only": False}),
        DiscoveredTool(name="t", description="d", input_schema={"type": "object"}, annotations={"read_only": True}, ui={"resource_uri": "ui://x"}),
    ):
        assert definition_hash(changed) != definition_hash(base)
    assert definition_hash(DiscoveredTool(name="t", description="d", input_schema={"type": "object"}, annotations={"read_only": True}, default_enabled=True)) == definition_hash(base)
    assert catalog_hash(["a", "b"]) == catalog_hash(["b", "a"])


# ------------------------------------------------------------------ redaction
def test_redaction_masks_sensitive_keys_hides_bound_params_and_bounds_size():
    out = redact_arguments(
        {"q": "ok", "Authorization": "Bearer x", "nested": {"apiKey": "k", "fine": 1}, "password": "p", "uid": "user_1", "big": "z" * 600, "items": list(range(80))},
        hide_keys=["uid"],
    )
    assert out["Authorization"] == "[REDACTED]" and out["password"] == "[REDACTED]" and out["nested"]["apiKey"] == "[REDACTED]"
    assert "uid" not in out and out["q"] == "ok" and out["nested"]["fine"] == 1
    assert out["big"].endswith("...[truncated]") and len(out["items"]) == 51


# ------------------------------------------------------------------ resilience
def test_circuit_breaker_window_half_open_and_reset():
    now = [0.0]
    b = CircuitBreaker(threshold=3, window=60, cooldown=30, clock=lambda: now[0])
    assert [b.record_failure("k"), b.record_failure("k")] == [False, False] and b.allow("k")
    now[0] = 61  # old failures age out of the window
    assert b.record_failure("k") is False and b.consecutive_failures("k") == 1
    assert [b.record_failure("k"), b.record_failure("k")] == [False, True] and b.is_open("k")
    now[0] += 31  # cooldown elapsed: half-open lets a probe through
    assert b.allow("k")
    assert b.record_failure("k") is True and b.is_open("k")  # failed probe re-opens
    now[0] += 31
    b.record_success("k")
    assert b.allow("k") and b.consecutive_failures("k") == 0


def test_rate_limiter_sliding_window_and_isolation_between_keys():
    now = [0.0]
    limiter = SlidingWindowRateLimiter(window=60, clock=lambda: now[0])
    assert [limiter.check_and_hit("a", 2) for _ in range(3)] == [True, True, False]
    assert limiter.check_and_hit("b", 2) is True and limiter.check_and_hit("a", None) is True
    now[0] = 61
    assert limiter.check_and_hit("a", 2) is True


def test_idempotency_store_ttl_and_capacity():
    now = [0.0]
    store = IdempotencyStore(ttl=10, max_entries=2, clock=lambda: now[0])
    store.put("a", 1)
    store.put("b", 2)
    store.put("c", 3)
    assert store.get("a") is None and store.get("b") == 2 and store.get("c") == 3
    now[0] = 11
    assert store.get("b") is None


# ------------------------------------------------------------------ signing
def test_tokens_are_purpose_bound_tamper_proof_and_expire():
    now = [1000.0]
    signer = TokenSigner(settings.AXION_MASTER_ENCRYPTION_KEY, clock=lambda: now[0])
    token = signer.sign("p1", {"a": 1}, 60)
    assert signer.verify(token, "p1")["a"] == 1
    with pytest.raises(UnauthorizedError):
        signer.verify(token, "p2")
    body, sig = token.split(".")
    forged_body = body[:-2] + ("AA" if not body.endswith("AA") else "BB")
    for bad in (f"{forged_body}.{sig}", "garbage", "", "a.b.c", f"{body}."):
        with pytest.raises(UnauthorizedError):
            signer.verify(bad, "p1")
    other = TokenSigner("A" * 43 + "=", clock=lambda: now[0])
    with pytest.raises(UnauthorizedError):
        other.verify(token, "p1")  # a different key cannot validate it
    now[0] += 61
    with pytest.raises(UnauthorizedError):
        signer.verify(token, "p1")


def test_arguments_hash_is_order_independent():
    assert arguments_hash({"a": 1, "b": [1, 2]}) == arguments_hash({"b": [1, 2], "a": 1})
    assert arguments_hash({"a": 1}) != arguments_hash({"a": 2})


# ------------------------------------------------------------------ subject
def test_subject_keys_and_context_values():
    member = Subject(SubjectType.MEMBER, id="m1")
    user = Subject(SubjectType.END_USER, id="eu1", external_id="cust", attributes={"plan": "pro"})
    assert Subject(SubjectType.PROJECT).key == "project" and member.key == "member:m1" and user.key == "end_user:eu1"
    assert [member.audience, user.audience, Subject(SubjectType.PROJECT).audience] == [Audience.MEMBERS, Audience.END_USERS, Audience.MACHINE]
    ctx = principal(user, agent_id="a1").context_values()
    assert ctx["end_user.id"] == "eu1" and ctx["end_user.external_id"] == "cust" and ctx["end_user.plan"] == "pro" and ctx["member.id"] is None
    assert principal(member).context_values()["member.id"] == "m1"

"""
Architecture tests: the SOLID rules of SRS-07 Section 10.8 enforced mechanically, so they cannot
erode silently. They scan source files; they need no database and no network.
"""
import ast
import re
from pathlib import Path
from typing import Iterable, List, Set

import pytest

APP = Path(__file__).resolve().parents[1] / "app"


def py_files(*parts: str, exclude: Iterable[str] = ()) -> List[Path]:
    root = APP.joinpath(*parts)
    skip = set(exclude)
    return sorted(p for p in root.rglob("*.py") if p.name not in skip and "__pycache__" not in p.parts)


def imports(path: Path) -> Set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def violations(files: Iterable[Path], forbidden: Iterable[str]) -> List[str]:
    forbidden = tuple(forbidden)
    out = []
    for path in files:
        for module in imports(path):
            if any(module == f or module.startswith(f + ".") for f in forbidden):
                out.append(f"{path.relative_to(APP)} imports {module}")
    return out


# ---------------------------------------------------------------- dependency inversion & layering
def test_services_depend_on_ports_not_on_concretes():
    """Services may not import HTTP, the DB driver, concrete repositories, adapters, or the MCP SDK."""
    files = py_files("services", "tools", exclude=["providers.py"])
    assert files, "no service files found"
    bad = violations(files, ["fastapi", "starlette", "pymongo", "httpx", "httpx2", "mcp", "app.repositories", "app.integrations", "app.api"])
    assert bad == []


def test_only_the_composition_root_wires_concrete_classes():
    providers = (APP / "services" / "tools" / "providers.py").read_text(encoding="utf-8")
    assert "app.repositories" in providers and "app.integrations" in providers  # it is the one place allowed to


def test_core_tools_is_independent_of_services_infrastructure_and_http():
    files = py_files("core", "tools") + py_files("core", "outbound")
    bad = violations(files, ["fastapi", "starlette", "app.services", "app.repositories", "app.integrations", "app.api", "mcp", "httpx", "httpx2"])
    assert bad == []


def test_integrations_do_not_depend_on_services_or_the_api_layer():
    assert violations(py_files("integrations"), ["app.services", "app.api", "fastapi", "app.repositories"]) == []


def test_only_the_mcp_connector_touches_the_mcp_sdk_and_only_the_guard_touches_raw_transports():
    # The SDK is used by exactly two integration modules: the MCP session client and the OAuth flow client.
    sdk_users = sorted(p.name for p in py_files("integrations") if violations([p], ["mcp"]))
    assert sdk_users == ["mcp_client.py", "oauth.py"]
    httpx2_users = sorted(p.name for p in py_files("integrations") if violations([p], ["httpx2"]))
    assert httpx2_users == ["guarded_transport.py", "mcp_client.py", "oauth.py"]


def test_repositories_do_not_import_services_or_the_api_layer():
    tool_repos =[APP / "repositories" / n for n in ("integration_repository.py", "tool_repository.py", "end_user_repository.py", "occ.py")]
    assert violations(tool_repos, ["app.services", "app.api", "fastapi"]) == []


def test_endpoints_never_touch_the_database_or_repositories():
    files = [p for p in py_files("api", "v1", "endpoints") if p.name in {"integrations.py", "tools.py", "tool_runtime.py", "end_users.py"}]
    assert len(files) == 4
    assert violations(files, ["app.repositories", "beanie", "pymongo", "app.integrations"]) == []


def test_no_http_types_leak_into_services():
    # providers.py is the composition root and legitimately declares FastAPI dependencies.
    text = "\n".join(p.read_text(encoding="utf-8") for p in py_files("services", "tools", exclude=["providers.py"]))
    assert "HTTPException" not in text and "fastapi" not in text


# ---------------------------------------------------------------- open/closed
TYPE_BRANCH = re.compile(r"(\.type\s*(==|!=)\s*IntegrationType\b|auth_type\s*(==|!=)\s*AuthType\b|\bif\s+\w+\.type\s+in\s+\(?IntegrationType)")


def test_no_branching_on_integration_type_or_auth_type_outside_registries():
    offenders = []
    for path in py_files("services", "tools", exclude=["providers.py"]) + py_files("core", "tools", exclude=["registry.py"]):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if TYPE_BRANCH.search(line):
                offenders.append(f"{path.relative_to(APP)}:{lineno}: {line.strip()}")
    assert offenders == []


@pytest.mark.usefixtures("tool_models")
def test_adding_a_new_integration_type_needs_no_change_to_services():
    """The scripted adapter used across the suite is registered at runtime: proof the extension point works."""
    from tests.tools_harness import make_harness

    harness = make_harness()
    assert "custom:scripted" in harness.container.adapters.keys()


# ---------------------------------------------------------------- interface segregation
def test_role_interfaces_are_small_and_adapters_implement_only_what_they_support():
    from app.core.tools import ports

    for role in (ports.ToolExecutor, ports.ToolDiscoverer, ports.HealthProber):
        public = [n for n in vars(role) if not n.startswith("_") and callable(getattr(role, n, None))]
        assert len(public) == 1, f"{role.__name__} should expose exactly one operation, found {public}"

    for role, size in ((ports.PromptProvider, 1), (ports.ResourceReader, 3)):
        public = [n for n in vars(role) if not n.startswith("_") and callable(getattr(role, n, None))]
        assert len(public) == size, f"{role.__name__} should expose {size} operation(s), found {public}"

    from app.integrations.adapters import McpAdapter, NativeAdapter

    # The native adapter has no resources, prompts, or apps, and declares no stub operations for them (ISP/LSP):
    # capability lookup, not a method that raises or returns fake data, is how absence is expressed.
    assert not any(n in vars(NativeAdapter) for n in ("list_resources", "read_resource", "list_prompts", "close"))
    assert not ports.supports(NativeAdapter(None), ports.ResourceReader)  # type: ignore[arg-type]
    assert not ports.supports(NativeAdapter(None), ports.PromptProvider)  # type: ignore[arg-type]
    # The MCP adapter genuinely implements both roles.
    mcp = McpAdapter(None)  # type: ignore[arg-type]
    assert ports.supports(mcp, ports.ResourceReader) and ports.supports(mcp, ports.PromptProvider)


def test_repository_protocols_are_one_per_aggregate():
    from app.core.protocols import tool_repositories as protocols

    names = [n for n in vars(protocols) if n.startswith("I") and n.endswith("Repository")]
    assert sorted(names) == [
        "IAppResourceRepository",
        "IConnectSessionRepository",
        "IConnectionRepository",
        "IEndUserRepository",
        "IIntegrationRepository",
        "IOAuthClientRepository",
        "IToolBindingRepository",
        "IToolDefinitionRepository",
        "IToolInvocationRepository",
        "IToolPolicyRepository",
        "IToolSettingRepository",
    ]


# ---------------------------------------------------------------- single responsibility
def test_gateway_only_composes_stages_it_contains_no_stage_logic():
    source = (APP / "services" / "tools" / "gateway.py").read_text(encoding="utf-8")
    for concern in ("jsonschema", "approval_token", "rate_limit", "CircuitBreaker", "AuthRequired", "asyncio.timeout"):
        assert concern not in source, f"gateway.py should not implement '{concern}'; that belongs in a stage"


def test_each_stage_is_a_small_single_purpose_class():
    tree = ast.parse((APP / "services" / "tools" / "gateway_stages.py").read_text(encoding="utf-8"))
    stage_classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.endswith("Stage")]
    assert len(stage_classes) == 12
    for cls in stage_classes:
        methods = [n.name for n in cls.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("__")]
        assert "run" in methods, f"{cls.name} must implement run"
        assert set(methods) <= {"run", "after", "_failure"}, f"{cls.name} has extra responsibilities: {methods}"


def test_integration_service_does_not_run_discovery_oauth_or_execution():
    source = (APP / "services" / "tools" / "integration_service.py").read_text(encoding="utf-8")
    for forbidden in ("discover(", "ToolExecutor", "execute(", "oauth", "probe("):
        assert forbidden not in source


def test_discovery_is_the_only_writer_of_tool_definitions():
    writers = [
        p.name
        for p in py_files("services", "tools")
        if re.search(r"_tools\.(create_many|update_definition|set_sync_state)|self\._tools\.create_many", p.read_text(encoding="utf-8"))
    ]
    assert sorted(writers) == ["discovery_service.py", "tool_service.py"]  # tool_service only flips drift state on approval
    approval_only = (APP / "services" / "tools" / "tool_service.py").read_text(encoding="utf-8")
    assert "create_many" not in approval_only and "set_sync_state" not in approval_only


@pytest.mark.parametrize("name", ["discovery_service.py", "gateway_stages.py", "tool_service.py"])
def test_no_module_level_mutable_state_in_services(name):
    tree = ast.parse((APP / "services" / "tools" / name).read_text(encoding="utf-8"))
    mutable = [
        t.id
        for n in tree.body
        if isinstance(n, ast.Assign)
        for t in n.targets
        if isinstance(t, ast.Name) and isinstance(n.value, (ast.Dict, ast.List, ast.Set, ast.Call)) and not t.id.isupper() and t.id != "logger"
    ]
    assert mutable == []

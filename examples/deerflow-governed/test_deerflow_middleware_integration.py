"""Optional integration tests for the AGT provider through DeerFlow middleware.

These tests do not start a DeerFlow agent or execute tools. They validate the
real GuardrailMiddleware request-building path when DeerFlow dependencies are
available in the current Python environment.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import warnings
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest


warnings.filterwarnings("ignore", message=r"agent-os-kernel is deprecated", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=r"agentmesh-primitives is deprecated", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=r"agentmesh-platform is deprecated", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=r"agent-hypervisor is deprecated", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=r"`json_encoders` is deprecated", category=Warning)
warnings.filterwarnings("ignore", message=r".*allowed_objects.*", category=PendingDeprecationWarning)

pytestmark = [
    pytest.mark.filterwarnings("ignore:agent-os-kernel is deprecated:DeprecationWarning"),
    pytest.mark.filterwarnings("ignore:agentmesh-primitives is deprecated:DeprecationWarning"),
    pytest.mark.filterwarnings("ignore:agentmesh-platform is deprecated:DeprecationWarning"),
    pytest.mark.filterwarnings("ignore:agent-hypervisor is deprecated:DeprecationWarning"),
    pytest.mark.filterwarnings("ignore:`json_encoders` is deprecated:Warning"),
    pytest.mark.filterwarnings("ignore:.*allowed_objects.*:PendingDeprecationWarning"),
    pytest.mark.filterwarnings("ignore::langchain_core._api.deprecation.LangChainPendingDeprecationWarning"),
]


ROOT = Path(__file__).resolve().parent
PROVIDER_DIR = ROOT / "provider"
POLICY_PATH = ROOT / "policies" / "deerflow-policy.yaml"

deerflow_repo = os.environ.get("DEERFLOW_REPO")
if deerflow_repo:
    harness_dir = Path(deerflow_repo).expanduser() / "backend" / "packages" / "harness"
    if harness_dir.exists():
        sys.path.insert(0, str(harness_dir))


def _make_tool_call_request(name: str, args: dict, call_id: str) -> SimpleNamespace:
    return SimpleNamespace(tool_call={"name": name, "args": args, "id": call_id})


def _import_required_module(name: str, purpose: str) -> ModuleType:
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
            return importlib.import_module(name)
    except Exception as exc:
        pytest.skip(f"{purpose} is required for this optional integration test: {exc}")


@pytest.fixture
def integration_modules() -> SimpleNamespace:
    _import_required_module("agent_os.policies", "AGT policy package")
    _import_required_module("agentmesh.governance", "AGT audit package")
    _import_required_module("langgraph.prebuilt.tool_node", "DeerFlow middleware dependency")
    _import_required_module("langchain_core.messages", "DeerFlow middleware dependency")
    deerflow_middleware = _import_required_module("deerflow.guardrails.middleware", "deerflow-harness")
    deerflow_provider_types = _import_required_module("deerflow.guardrails.provider", "deerflow-harness")

    if str(PROVIDER_DIR) not in sys.path:
        sys.path.insert(0, str(PROVIDER_DIR))
    provider_module = _import_required_module("deerflow_agt_guardrail", "AGT DeerFlow provider example")

    return SimpleNamespace(
        AGTGuardrailProvider=provider_module.AGTGuardrailProvider,
        GuardrailDecision=provider_module.GuardrailDecision,
        GuardrailMiddleware=deerflow_middleware.GuardrailMiddleware,
        NativeGuardrailDecision=deerflow_provider_types.GuardrailDecision,
    )


def _make_provider(modules: SimpleNamespace, audit_path: Path):
    return modules.AGTGuardrailProvider(policy_path=POLICY_PATH, audit_path=audit_path, framework="deerflow")


def _audit_entries(audit_path: Path) -> list[dict]:
    return [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_provider_uses_deerflow_native_decision_type(integration_modules: SimpleNamespace) -> None:
    assert integration_modules.GuardrailDecision is integration_modules.NativeGuardrailDecision


def test_deerflow_middleware_allows_safe_tool_call_and_writes_audit(tmp_path: Path, integration_modules: SimpleNamespace) -> None:
    audit_path = tmp_path / "audit.jsonl"
    provider = _make_provider(integration_modules, audit_path)
    try:
        middleware = integration_modules.GuardrailMiddleware(provider, passport="deerflow-demo-agent")
        request = _make_tool_call_request(
            "web_search",
            {"query": "DeerFlow open source agent framework", "max_results": 3},
            "call_allow",
        )
        expected = object()
        handler = MagicMock(return_value=expected)

        result = middleware.wrap_tool_call(request, handler)

        handler.assert_called_once_with(request)
        assert result is expected
        entries = _audit_entries(audit_path)
        assert len(entries) == 1
        assert entries[0]["outcome"] == "allowed"
        assert entries[0]["data"]["tool_name"] == "web_search"
        assert entries[0]["data"]["agent_id"] == "deerflow-demo-agent"
    finally:
        provider.close()


def test_deerflow_middleware_denies_risky_tool_call_and_writes_audit(tmp_path: Path, integration_modules: SimpleNamespace) -> None:
    audit_path = tmp_path / "audit.jsonl"
    provider = _make_provider(integration_modules, audit_path)
    try:
        middleware = integration_modules.GuardrailMiddleware(provider, passport="deerflow-demo-agent")
        request = _make_tool_call_request(
            "bash",
            {"description": "Remove temporary demo files", "command": "rm -rf /tmp/deerflow-demo"},
            "call_deny",
        )
        handler = MagicMock()

        result = middleware.wrap_tool_call(request, handler)

        handler.assert_not_called()
        assert result.status == "error"
        assert result.name == "bash"
        assert "Guardrail denied" in result.content
        assert "agt.denied" in result.content
        assert "deny-dangerous-bash-rm-rf" in result.content

        entries = _audit_entries(audit_path)
        assert len(entries) == 1
        assert entries[0]["outcome"] == "denied"
        assert entries[0]["data"]["policy_id"] == "deny-dangerous-bash-rm-rf"
    finally:
        provider.close()


def test_deerflow_middleware_audit_omits_raw_tool_input_and_sensitive_values(tmp_path: Path, integration_modules: SimpleNamespace) -> None:
    audit_path = tmp_path / "audit.jsonl"
    provider = _make_provider(integration_modules, audit_path)
    try:
        middleware = integration_modules.GuardrailMiddleware(provider, passport="deerflow-demo-agent")

        allow_request = _make_tool_call_request(
            "web_search",
            {"query": "public DeerFlow documentation", "max_results": 3},
            "call_allow_audit",
        )
        deny_request = _make_tool_call_request(
            "write_file",
            {
                "description": "Save customer contact details",
                "path": "/mnt/user-data/outputs/customer.txt",
                "content": "Contact alice@example.com, SSN 123-45-6789, phone 415-555-1212",
                "append": False,
            },
            "call_deny_audit",
        )

        middleware.wrap_tool_call(allow_request, MagicMock(return_value=object()))
        middleware.wrap_tool_call(deny_request, MagicMock())

        raw_audit = audit_path.read_text(encoding="utf-8")
        assert '"tool_input"' not in raw_audit
        assert "tool_input_json" not in raw_audit
        assert "alice@example.com" not in raw_audit
        assert "123-45-6789" not in raw_audit
        assert "415-555-1212" not in raw_audit
        assert "[EMAIL]" in raw_audit
        assert "[SSN]" in raw_audit
        assert "[PHONE]" in raw_audit

        entries = _audit_entries(audit_path)
        assert {entry["outcome"] for entry in entries} == {"allowed", "denied"}
    finally:
        provider.close()


def test_deerflow_middleware_async_paths_match_sync_behavior(tmp_path: Path, integration_modules: SimpleNamespace) -> None:
    audit_path = tmp_path / "audit.jsonl"
    provider = _make_provider(integration_modules, audit_path)
    try:
        middleware = integration_modules.GuardrailMiddleware(provider, passport="deerflow-demo-agent")
        allow_request = _make_tool_call_request(
            "web_fetch",
            {"url": "https://example.com/public-report"},
            "call_async_allow",
        )
        deny_request = _make_tool_call_request(
            "bash",
            {"description": "Run a database cleanup", "command": "psql -c 'DROP TABLE users'"},
            "call_async_deny",
        )

        async def run() -> tuple[object, object]:
            expected = object()

            async def allow_handler(request):
                return expected

            deny_handler = MagicMock()
            allowed = await middleware.awrap_tool_call(allow_request, allow_handler)
            denied = await middleware.awrap_tool_call(deny_request, deny_handler)
            deny_handler.assert_not_called()
            assert allowed is expected
            return allowed, denied

        _, denied_result = asyncio.run(run())

        assert denied_result.status == "error"
        assert "deny-destructive-sql" in denied_result.content
        entries = _audit_entries(audit_path)
        assert [entry["outcome"] for entry in entries] == ["allowed", "denied"]
    finally:
        provider.close()

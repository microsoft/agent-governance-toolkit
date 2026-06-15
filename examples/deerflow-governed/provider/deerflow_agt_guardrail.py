"""DeerFlow guardrail provider example backed by AGT policy and audit APIs."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent_os.policies import PolicyEvaluator
from agentmesh.governance import AuditLog, FileAuditSink

try:
    from deerflow.guardrails.provider import GuardrailDecision, GuardrailReason
except Exception:  # pragma: no cover - exercised when DeerFlow is not installed

    @dataclass
    class GuardrailReason:
        code: str
        message: str = ""

    @dataclass
    class GuardrailDecision:
        allow: bool
        reasons: list[GuardrailReason] = field(default_factory=list)
        policy_id: str | None = None
        metadata: dict[str, Any] = field(default_factory=dict)


class AGTGuardrailProvider:
    """Map DeerFlow tool-call guardrail requests into AGT policy decisions."""

    name = "agt-deerflow-guardrail-example"

    def __init__(
        self,
        *,
        policy_path: str | os.PathLike[str] | None = None,
        audit_path: str | os.PathLike[str] | None = None,
        fail_closed: bool = True,
        framework: str = "deerflow",
        **_: Any,
    ) -> None:
        self.framework = framework
        self.fail_closed = fail_closed

        base_dir = Path(__file__).resolve().parents[1]
        self.policy_path = Path(policy_path or base_dir / "policies" / "deerflow-policy.yaml").expanduser()
        self.audit_path = Path(audit_path or base_dir / "audit" / "deerflow-agt-audit.jsonl").expanduser()

        self._evaluator = PolicyEvaluator()
        self._load_policy(self.policy_path)

        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        secret = _audit_secret()
        self._audit_sink = FileAuditSink(self.audit_path, secret)
        self._audit = AuditLog(sink=self._audit_sink)

    def evaluate(self, request: Any) -> GuardrailDecision:
        """Evaluate a DeerFlow GuardrailRequest or compatible object."""

        context = self._normalize_request(request)
        try:
            result = self._evaluator.evaluate(context)
            decision = self._decision_from_result(result)
        except Exception as exc:
            decision = self._error_decision(exc)

        self._write_audit(context, decision)
        return decision

    async def aevaluate(self, request: Any) -> GuardrailDecision:
        """Async DeerFlow provider entry point."""

        return self.evaluate(request)

    def close(self) -> None:
        if hasattr(self._audit_sink, "close"):
            self._audit_sink.close()

    def _load_policy(self, policy_path: Path) -> None:
        resolved = policy_path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"AGT policy path does not exist: {resolved}")
        load_path = resolved.parent if resolved.is_file() else resolved
        self._evaluator.load_policies(load_path)

    def _normalize_request(self, request: Any) -> dict[str, Any]:
        tool_name = _read(request, "tool_name") or ""
        tool_input = _read(request, "tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {"value": tool_input}

        input_json = json.dumps(tool_input, sort_keys=True, ensure_ascii=False, default=str)
        context: dict[str, Any] = {
            "framework": self.framework,
            "tool_name": tool_name,
            "agent_id": _read(request, "agent_id"),
            "timestamp": _read(request, "timestamp") or "",
            "tool_input_sha256": hashlib.sha256(input_json.encode("utf-8")).hexdigest(),
            "tool_input_size": len(input_json.encode("utf-8")),
            # Prefer typed fields below for policies; keep this only as a broad fallback.
            "tool_input_json": input_json,
        }

        command = _first_present(tool_input, "command", "cmd", "script", "query")
        path = _first_present(tool_input, "path", "file_path", "filename", "target_file")
        url = _first_present(tool_input, "url", "uri", "link")
        task_description = _first_present(tool_input, "description", "task", "prompt", "instructions")
        content_preview = _content_preview(tool_input)

        if command is not None:
            context["command"] = str(command)
        if path is not None:
            context["path"] = str(path)
        if url is not None:
            parsed = urlparse(str(url))
            context["url"] = str(url)
            context["host"] = parsed.hostname or ""
        if task_description is not None:
            context["task_description"] = str(task_description)
        if content_preview is not None:
            context["content_preview"] = content_preview

        context["is_mcp_tool"] = tool_name.startswith("mcp__")
        if context["is_mcp_tool"]:
            context["mcp_tool_name"] = tool_name.removeprefix("mcp__")

        content_size = _content_size(tool_input)
        if content_size:
            context["content_size"] = content_size
        context["message"] = _build_message(context, tool_input)

        return context

    def _decision_from_result(self, result: Any) -> GuardrailDecision:
        allowed = bool(_read(result, "allowed"))
        matched_rule = _read(result, "matched_rule")
        reason = _read(result, "reason") or _read(result, "message")
        action = _read(result, "action")

        code = "agt.allowed" if allowed else "agt.denied"
        message = reason or ("allowed by AGT policy" if allowed else "denied by AGT policy")
        if matched_rule:
            message = f"{message} (rule: {matched_rule})"

        return GuardrailDecision(
            allow=allowed,
            reasons=[GuardrailReason(code=code, message=message)],
            policy_id=str(matched_rule) if matched_rule else None,
            metadata={
                "framework": self.framework,
                "agt_action": action,
                "matched_rule": matched_rule,
            },
        )

    def _error_decision(self, exc: Exception) -> GuardrailDecision:
        allow = not self.fail_closed
        code = "agt.evaluator_error_allow" if allow else "agt.evaluator_error_deny"
        message = f"AGT policy evaluation failed: {exc}"
        return GuardrailDecision(
            allow=allow,
            reasons=[GuardrailReason(code=code, message=message)],
            policy_id=None,
            metadata={"framework": self.framework, "error": str(exc), "fail_closed": self.fail_closed},
        )

    def _write_audit(self, context: dict[str, Any], decision: GuardrailDecision) -> None:
        reason = decision.reasons[0].message if decision.reasons else ""
        data = {
            "framework": context.get("framework"),
            "tool_name": context.get("tool_name"),
            "agent_id": context.get("agent_id"),
            "decision": "allow" if decision.allow else "deny",
            "policy_id": decision.policy_id,
            "reason": reason,
            "tool_input_sha256": context.get("tool_input_sha256"),
            "tool_input_size": context.get("tool_input_size"),
            "command_preview": _redacted_preview(context.get("command")),
            "content_preview": _redacted_preview(context.get("content_preview"), limit=200),
            "message_preview": _redacted_preview(context.get("message")),
            "path": context.get("path"),
            "url": context.get("url"),
            "host": context.get("host"),
            "task_preview": _redacted_preview(context.get("task_description")),
            "is_mcp_tool": context.get("is_mcp_tool"),
            "mcp_tool_name": context.get("mcp_tool_name"),
        }
        self._audit.log(
            event_type="tool_invocation",
            agent_did=str(context.get("agent_id") or "deerflow-agent"),
            action=str(context.get("tool_name") or "unknown_tool"),
            resource=str(context.get("path") or context.get("url") or context.get("tool_name") or "unknown"),
            data={key: value for key, value in data.items() if value not in (None, "")},
            outcome="allowed" if decision.allow else "denied",
            policy_decision="allow" if decision.allow else "deny",
        )


def _read(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _first_present(values: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in values and values[key] not in (None, ""):
            return values[key]
    return None


def _content_size(values: dict[str, Any]) -> int:
    total = 0
    for key in ("content", "text", "replacement", "new_str", "old_str"):
        value = values.get(key)
        if isinstance(value, str):
            total += len(value.encode("utf-8"))
    return total


def _content_preview(values: dict[str, Any], limit: int = 200) -> str | None:
    parts: list[str] = []
    for key in ("content", "text", "replacement", "new_str", "old_str", "value"):
        value = values.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    if not parts:
        return None
    return _preview(" ".join(parts), limit=limit)


def _simple_scalar_values(values: dict[str, Any]) -> list[str]:
    ignored = {
        "content",
        "text",
        "replacement",
        "new_str",
        "old_str",
        "command",
        "cmd",
        "script",
        "query",
        "path",
        "file_path",
        "filename",
        "target_file",
        "url",
        "uri",
        "link",
        "description",
        "task",
        "prompt",
        "instructions",
    }
    result: list[str] = []
    for key, value in sorted(values.items()):
        if key in ignored or value in (None, ""):
            continue
        if isinstance(value, (str, int, float, bool)):
            result.append(f"{key}={value}")
    return result


def _build_message(context: dict[str, Any], tool_input: dict[str, Any], limit: int = 500) -> str:
    parts: list[str] = []
    for key in ("command", "path", "url", "host", "task_description", "content_preview"):
        value = context.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    parts.extend(_simple_scalar_values(tool_input))
    return _preview(" ".join(parts), limit=limit) or ""


def _preview(value: Any, limit: int = 120) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _redacted_preview(value: Any, limit: int = 120) -> str | None:
    text = _preview(value, limit=limit)
    if text is None:
        return None
    redactions = (
        (r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL]"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
        (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", "[PHONE]"),
    )
    for pattern, replacement in redactions:
        text = re.sub(pattern, replacement, text)
    return text


def _audit_secret() -> bytes:
    configured = os.environ.get("AGT_DEERFLOW_AUDIT_SECRET", "agt-deerflow-governed-example")
    return hashlib.sha256(configured.encode("utf-8")).digest()


__all__ = ["AGTGuardrailProvider"]

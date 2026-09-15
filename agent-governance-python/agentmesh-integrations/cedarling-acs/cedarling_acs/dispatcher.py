# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cedarling policy dispatcher for the ACS v5 runtime.

Implements the ``agent_control_specification.PolicyDispatcher`` protocol
(``evaluate(invocation) -> Mapping``) so Cedarling authorization decisions run
through the native runtime. Bind it to a ``type: custom`` policy in the manifest
and pass the dispatcher as ``policy_dispatcher=`` to ``AgentControl.from_path``.

The dispatcher receives the ACS final policy input under ``invocation["input"]``
(spec section 7): the five members ``intervention_point``, ``policy_target``,
``snapshot``, ``annotations``, ``tool``. It builds a Cedar request from that
input, calls ``cedarling-python`` in process, and returns a verdict mapping
(spec section 13).

Fail-closed contract: any error, a missing policy input, or a missing
``cedarling-python`` install maps to a ``deny`` verdict. Reasons never use the
reserved ``runtime_error:`` prefix; that prefix belongs to the runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal, Mapping, Optional

if TYPE_CHECKING:
    import cedarling_python

    # A Cedarling authorization result from either auth path. Both expose
    # is_allowed(), request_id(), and response.diagnostics.
    AuthorizeResult = (
        cedarling_python.AuthorizeResult | cedarling_python.MultiIssuerAuthorizeResult
    )

logger = logging.getLogger(__name__)

AuthType = Literal["unsigned", "multi-issuer"]

# Reason codes returned on the fail-closed paths. Low cardinality on purpose so a
# host can alert on them without parsing free text.
_REASON_MALFORMED = "cedarling_invocation_malformed"
_REASON_AUTHZ_ERROR = "cedarling_authorization_error"
_REASON_ENGINE_ERROR = "cedarling_engine_error"
_REASON_DENY = "cedarling_deny"
_REASON_ALLOW = "cedarling_allow"


@dataclass
class CedarlingConfig:
    """Shape of the Cedar request built from the ACS policy input.

    The defaults mirror the bundled ``cedar`` dispatcher mapping in spec section
    12.4 so existing Cedar schemas keep working:

    - principal ``Agent::"<envelope.agent.id>"``
    - action ``Action::"<intervention_point>"``
    - resource ``Tool::"<tool name>"`` at tool points, else
      ``PolicyTarget::"<policy_target.kind>"``
    - context: the snapshot minus ``envelope``, plus each annotation keyed as
      ``annotations.<name>``
    """

    auth_type: AuthType = "unsigned"
    namespace: Optional[str] = None
    principal_attributes_path: tuple[str, ...] = ("envelope", "agent", "attributes")
    principal_entity_type: str = "Agent"
    resource_entity_type: str = "PolicyTarget"
    tool_entity_type: str = "Tool"
    action_namespace: str = "Action"
    # Snapshot path (sequence of keys) to the per-request token map for
    # multi-issuer auth. First hit wins.
    token_paths: tuple[tuple[str, ...], ...] = (
        ("tokens",),
        ("envelope", "agent", "tokens"),
    )
    # Emit a verification pointer to the policy store in the verdict evidence.
    policy_store_pointer: Optional[str] = None


class CedarlingPolicyDispatcher:
    """ACS v5 ``PolicyDispatcher`` backed by ``cedarling-python``.

    Construct with a ready :class:`cedarling_python.Cedarling` engine, or use
    :meth:`from_bootstrap` to build one from a bootstrap config.
    """

    def __init__(
        self,
        engine: cedarling_python.Cedarling,
        *,
        config: Optional[CedarlingConfig] = None,
    ) -> None:
        if engine is None:
            raise ValueError(
                "engine is required; use CedarlingPolicyDispatcher.from_bootstrap "
                "to build one"
            )
        self._engine = engine
        self._config = config or CedarlingConfig()

    @classmethod
    def from_bootstrap(
        cls,
        bootstrap_config: Optional[dict[str, Any]] = None,
        *,
        application_name: str = "agent-governance-toolkit",
        config: Optional[CedarlingConfig] = None,
    ) -> "CedarlingPolicyDispatcher":
        cedarling = _import_cedarling()
        cfg = dict(bootstrap_config) if bootstrap_config else {}
        cfg.setdefault("CEDARLING_APPLICATION_NAME", application_name)
        engine = cedarling.Cedarling(cedarling.BootstrapConfig(cfg))
        return cls(engine, config=config)

    def evaluate(self, invocation: Mapping[str, Any]) -> Mapping[str, Any]:
        import cedarling_python

        policy_input = _policy_input(invocation)
        if policy_input is None:
            return _deny(_REASON_MALFORMED, "ACS policy input was missing or malformed")

        try:
            return self._authorize(policy_input)
        except cedarling_python.authorize_errors.AuthorizeError as exc:
            return _deny(_REASON_AUTHZ_ERROR, str(exc))
        except Exception as exc:  # fail closed on anything else
            logger.error("Cedarling evaluation failed", exc_info=True)
            return _deny(_REASON_ENGINE_ERROR, str(exc))

    def _authorize(self, pi: Mapping[str, Any]) -> Mapping[str, Any]:
        import cedarling_python

        cfg = self._config

        snapshot = _as_dict(pi.get("snapshot"))
        annotations = _as_dict(pi.get("annotations"))
        policy_target = _as_dict(pi.get("policy_target"))
        tool = pi.get("tool")
        intervention_point = str(pi.get("intervention_point", "unknown"))

        action = self._action_ref(intervention_point)
        resource_type, resource_id = self._resource_ref(tool, policy_target)
        context = self._context(snapshot, annotations)

        resource = cedarling_python.EntityData.from_dict(
            {
                "cedar_entity_mapping": {
                    "entity_type": resource_type,
                    "id": resource_id,
                }
            }
        )

        result: AuthorizeResult
        if cfg.auth_type == "multi-issuer":
            tokens = self._tokens(snapshot)
            token_inputs = [
                cedarling_python.TokenInput(mapping=k, payload=v)
                for k, v in tokens.items()
            ]
            request = cedarling_python.AuthorizeMultiIssuerRequest(
                tokens=token_inputs,
                action=action,
                resource=resource,
                context=context,
            )
            result = self._engine.authorize_multi_issuer(request)
        else:
            principal_id = str(_dig(snapshot, ("envelope", "agent", "id")) or "anonymous")
            principal_attrs = _as_dict(_dig(snapshot, cfg.principal_attributes_path))
            principal = cedarling_python.EntityData.from_dict(
                {
                    "cedar_entity_mapping": {
                        "entity_type": self._ns(cfg.principal_entity_type),
                        "id": principal_id,
                    },
                    **principal_attrs,
                }
            )
            request = cedarling_python.RequestUnsigned(
                principal=principal,
                action=action,
                resource=resource,
                context=context,
            )
            result = self._engine.authorize_unsigned(request)

        return self._verdict(result)

    def _verdict(self, result: AuthorizeResult) -> Mapping[str, Any]:
        allowed = bool(result.is_allowed())
        fallback = _REASON_ALLOW if allowed else _REASON_DENY
        verdict: dict[str, Any] = {
            "decision": "allow" if allowed else "deny",
            "reason": self._policy_reason(result, fallback),
        }
        message = _diagnostic_message(result)
        if message:
            verdict["message"] = message

        evidence = self._evidence()
        if evidence:
            verdict["evidence"] = evidence
        return verdict

    def _policy_reason(self, result: AuthorizeResult, fallback: str) -> str:
        """First contributing Cedar policy id (spec 12.4 diagnostics), else a code.

        The fallback is used only when no policy contributed, which is a
        default deny.``diagnostics.reason`` is an unordered ``set[str]``, so
        sort before picking to keep the verdict deterministic across runs.
        """
        try:
            for code in sorted(_response(result).diagnostics.reason):
                if code and not code.startswith("runtime_error:"):
                    return str(code)
        except Exception:
            logger.debug("no Cedarling diagnostics available", exc_info=True)
        return fallback

    def _evidence(self) -> Optional[dict[str, Any]]:
        pointers: dict[str, str] = {}
        if self._config.policy_store_pointer:
            pointers["policy_store"] = self._config.policy_store_pointer
        if not pointers:
            return None
        return {"verification_pointers": pointers}

    def _action_ref(self, intervention_point: str) -> str:
        return f'{self._ns(self._config.action_namespace)}::"{intervention_point}"'

    def _resource_ref(
        self, tool: Any, policy_target: Mapping[str, Any]
    ) -> tuple[str, str]:
        cfg = self._config
        if isinstance(tool, Mapping) and tool.get("name"):
            return self._ns(cfg.tool_entity_type), str(tool["name"])
        kind = policy_target.get("kind") or "policy_target"
        return self._ns(cfg.resource_entity_type), str(kind)

    def _context(
        self, snapshot: Mapping[str, Any], annotations: Mapping[str, Any]
    ) -> dict[str, Any]:
        ctx = {k: v for k, v in snapshot.items() if k != "envelope"}
        for name, value in annotations.items():
            ctx[f"annotations.{name}"] = value
        return ctx

    def _tokens(self, snapshot: Mapping[str, Any]) -> dict[str, str]:
        for path in self._config.token_paths:
            found = _dig(snapshot, path)
            if isinstance(found, Mapping) and found:
                return _validate_tokens(found)
        raise ValueError(
            "multi-issuer auth requires a token map in the snapshot; "
            f"looked at {['/'.join(p) for p in self._config.token_paths]}"
        )

    def _ns(self, entity_type: str) -> str:
        prefix = f"{self._config.namespace}::" if self._config.namespace else ""
        return f"{prefix}{entity_type}"


def _import_cedarling() -> ModuleType:
    try:
        import cedarling_python

        return cedarling_python
    except ImportError as exc:
        raise ImportError(
            "cedarling-python is not installed. Install the extra: "
            "pip install 'agent-governance-toolkit-integrations[cedarling]'"
        ) from exc


def _policy_input(invocation: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    if not isinstance(invocation, Mapping):
        return None
    candidate = invocation.get("input")
    if isinstance(candidate, Mapping):
        return candidate
    if "intervention_point" in invocation:
        return invocation
    return None


def _validate_tokens(tokens: Mapping[str, Any]) -> dict[str, str]:
    bad = {k: type(v).__name__ for k, v in tokens.items() if not isinstance(v, str)}
    if bad:
        raise TypeError(
            f"all token values must be JWT strings; non-string values: {bad}"
        )
    return dict(tokens)


def _deny(reason: str, message: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason, "message": message}


def _response(result: AuthorizeResult) -> Any:
    """Normalize the response accessor across the two result types.

    ``AuthorizeResult.response`` is an attribute; ``MultiIssuerAuthorizeResult.response``
    is a method. Calling the method form here keeps the diagnostics path working
    for both auth types.
    """
    response = result.response
    return response() if callable(response) else response


def _diagnostic_message(result: AuthorizeResult) -> Optional[str]:
    """Human-facing diagnostic built from Cedarling's contributing reasons.

    Distinct from the low-cardinality verdict ``reason`` code: this carries the
    full list for a caller, sorted for determinism.
    """
    try:
        reasons = sorted(_response(result).diagnostics.reason)
    except Exception:
        return None
    if not reasons:
        return None
    return "cedar policies: " + ", ".join(str(r) for r in reasons)


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dig(obj: Any, path: tuple[str, ...]) -> Any:
    cur = obj
    for key in path:
        if not isinstance(cur, Mapping) or key not in cur:
            return None
        cur = cur[key]
    return cur

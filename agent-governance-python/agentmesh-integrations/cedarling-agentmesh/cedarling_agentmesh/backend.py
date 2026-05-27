# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CedarlingBackend — Cedarling policy adapter for AGT.

Implements the ExternalPolicyBackend protocol (name + evaluate) so that
Cedarling authorization decisions flow seamlessly into AGT's PolicyEvaluator
pipeline without modifying AGT core.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from agent_os.policies import BackendDecision
import cedarling_python

logger = logging.getLogger(__name__)


def _tool_to_cedar_action(tool_name: str) -> str:
    return "".join(part.capitalize() for part in tool_name.split("_"))


class CedarlingBackend:
    """Cedarling policy backend for Agent Governance Toolkit.

    Implements the ``ExternalPolicyBackend`` protocol — exposes ``name`` and
    ``evaluate(request) -> BackendDecision`` — so it can be registered with
    ``PolicyEvaluator.add_backend()`` without any changes to AGT core.

    ``cedarling_python`` must be installed. The backend creates a ``Cedarling``
    instance from *bootstrap_config* unless *cedarling_instance* is provided.

    Auth types:
        ``"unsigned"``     - authorize without JWT tokens. A principal entity
                             is built from ``agent_id`` and optional
                             ``principal_attributes`` in the request dict.
        ``"multi-issuer"`` - authorize with JWT tokens from one or more
                             issuers. Include a ``tokens`` key in the
                             request dict (``{"AGENT::TokenType": "jwt", ...}``).
    """

    def __init__(
        self,
        bootstrap_config: Optional[dict[str, Any]] = None,
        application_name: str = "agent-governance-toolkit",
        namespace: Optional[str] = None,
        auth_type: Literal["unsigned", "multi-issuer"] = "unsigned",
        principal_entity_type: str = "Agent",
        resource_entity_type: str = "Resource",
        action_namespace: str = "Action",
        cedarling_instance: Optional[cedarling_python.Cedarling] = None,
    ) -> None:
        cfg: dict[str, Any] = dict(bootstrap_config) if bootstrap_config else {}
        cfg.setdefault("CEDARLING_APPLICATION_NAME", application_name)
        self._bootstrap_config = cfg
        self._namespace = namespace
        self._auth_type = auth_type
        self._principal_entity_type = principal_entity_type
        self._resource_entity_type = resource_entity_type
        self._action_namespace = action_namespace
        self._cedarling_instance = cedarling_instance

        if self._cedarling_instance is None:
            bootstrap = cedarling_python.BootstrapConfig(self._bootstrap_config)
            self._cedarling_instance = cedarling_python.Cedarling(bootstrap)

    @property
    def name(self) -> str:
        return "cedarling"

    def evaluate(self, request: dict[str, Any]) -> BackendDecision:
        if self._auth_type == "multi-issuer" and "tokens" not in request:
            raise ValueError(
                "multi-issuer auth requires a 'tokens' key in the request dict"
            )
        start = datetime.now(timezone.utc)
        try:
            result = self._evaluate(request)
            result.evaluation_ms = (
                datetime.now(timezone.utc) - start
            ).total_seconds() * 1000
            return result
        except Exception as exc:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            logger.error("Cedarling evaluation failed: %s", exc)
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"Cedarling evaluation error: {exc}",
                backend="cedarling",
                evaluation_ms=elapsed,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_diagnostics(self, result: Any) -> Optional[dict[str, Any]]:
        try:
            raw = getattr(result, "response", None)
            if raw is None:
                return None
            diag = getattr(raw, "diagnostics", None)
            if diag is None:
                return None
            return {
                "decision": str(raw.decision),
                "reasons": list(diag.reason),
            }
        except Exception:
            logger.debug(
                "Failed to extract Cedarling diagnostics from result type %s",
                type(result).__name__,
                exc_info=True,
            )
            return None

    def _build_request(self, context: dict[str, Any]) -> dict[str, Any]:
        """Build a Cedar authorization request from the AGT context dict.

        Converts AGT's ``tool_name`` (snake_case) → Cedar ``action``
        (PascalCase), and normalises ``agent_id`` / ``resource`` into
        namespaced entity references.
        """
        agent_id = str(context.get("agent_id", "anonymous"))
        tool_name = str(context.get("tool_name", "unknown"))
        resource_id = str(context.get("resource", ""))
        action = _tool_to_cedar_action(tool_name)

        ns_prefix = f"{self._namespace}::" if self._namespace else ""
        principal_type = f"{ns_prefix}{self._principal_entity_type}"
        resource_type = f"{ns_prefix}{self._resource_entity_type}"
        action_full = f'{ns_prefix}{self._action_namespace}::"{action}"'

        extra = {
            k: v
            for k, v in context.items()
            if k not in ("agent_id", "tool_name", "resource", "tokens")
        }
        return {
            "principal": {"type": principal_type, "id": agent_id},
            "action": action_full,
            "resource": {"type": resource_type, "id": resource_id},
            "context": extra,
        }

    def _evaluate(self, request: dict[str, Any]) -> BackendDecision:
        tokens = request.get("tokens")
        req = self._build_request(request)
        engine = self._cedarling_instance

        context_dict = dict(req["context"])
        principal_attrs: dict[str, Any] = {}

        if self._auth_type == "unsigned":
            principal_attrs = context_dict.pop("principal_attributes", {})

        resource = cedarling_python.EntityData.from_dict({
            "cedar_entity_mapping": {
                "entity_type": req["resource"]["type"],
                "id": req["resource"]["id"],
            },
            **context_dict,
        })

        try:
            if self._auth_type == "multi-issuer":
                token_inputs = [
                    cedarling_python.TokenInput(mapping=k, payload=v)
                    for k, v in (tokens or {}).items()
                ]
                request = cedarling_python.AuthorizeMultiIssuerRequest(
                    tokens=token_inputs,
                    action=req["action"],
                    resource=resource,
                    context=context_dict,
                )
                result = engine.authorize_multi_issuer(request)
            else:
                principal = cedarling_python.EntityData.from_dict({
                    "cedar_entity_mapping": {
                        "entity_type": req["principal"]["type"],
                        "id": req["principal"]["id"],
                    },
                    **principal_attrs,
                })
                request = cedarling_python.RequestUnsigned(
                    principal=principal,
                    action=req["action"],
                    resource=resource,
                    context=context_dict,
                )
                result = engine.authorize_unsigned(request)
        except cedarling_python.authorize_errors.AuthorizeError as exc:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason=f"Cedarling authorization error: {exc}",
                backend="cedarling",
                error=str(exc),
                raw_result={"request_id": getattr(exc, "request_id", None)},
            )

        allowed = result.is_allowed()
        diagnostics = self._extract_diagnostics(result)

        return BackendDecision(
            allowed=allowed,
            action="allow" if allowed else "deny",
            reason=f"Cedarling: {'allowed' if allowed else 'denied'} ({self._auth_type})",
            backend="cedarling",
            raw_result={
                "request_id": result.request_id(),
                "diagnostics": diagnostics,
            },
        )

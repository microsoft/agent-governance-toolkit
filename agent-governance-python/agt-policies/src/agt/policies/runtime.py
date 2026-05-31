# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT Python runtime wrapper over the ACS Python SDK.

:class:`AgtRuntime` is the public host-facing entry point. It wraps the
underlying :class:`agent_control_specification.AgentControl` async
orchestrator with a small synchronous API tailored to AGT host code:

- Accepts a manifest by path. When ``resolution_root`` is provided the
  AGT manifest-resolution layer (:mod:`agt.manifest_resolution`) walks
  the workspace, merges the governance chain, and writes a flat ACS
  manifest first. Otherwise the manifest is fed to
  :meth:`AgentControl.from_path` as-is.
- Translates an AGT snapshot (the dict shape from
  ``policy-engine/spec/agt/AGT-SNAPSHOT-1.0.md`` 1) into the ACS
  ``snapshot`` argument and calls
  :meth:`AgentControl.evaluate_intervention_point`.
- Maps the returned :class:`InterventionPointResult` to an AGT
  :class:`agt.policies.result.EvaluationResult`, propagating the
  five-state ``verdict`` per AGT-DELTA D1, the transform body per D1.1,
  the evidence per D2, and the bisected identities per D1.4.
- Registers a host-supplied approval resolver. When the engine returns
  ``escalate`` the resolver is invoked through the ACS approval path,
  which binds the approved action identity to the canonical policy
  input per AGT-DELTA D1.4 and ACS 17.1; an identity mismatch raises
  ``runtime_error:approval_action_mismatch``.

When the ACS native binding is not built importing this module raises
``ImportError`` with installation guidance; tests that exercise the
wrapper should ``pytest.importorskip("agent_control_specification")``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional, Union

from agt.policies.result import EvaluationResult

try:
    from agent_control_specification import (
        AgentControl,
        AgentControlBlocked,
        AgentControlInterruption,
        AgentControlSuspended,
        ApprovalOutcome,
        ApprovalResolution,
        EnforcementMode,
        InterventionPoint,
        InterventionPointResult,
        Verdict,
    )
except ImportError as exc:  # pragma: no cover - exercised only without the SDK
    raise ImportError(
        "agt.policies.runtime requires the agent_control_specification Python SDK. "
        "Install it from policy-engine/sdk/python (or `pip install "
        "agent_control_specification`) and ensure the native binding is built "
        "(needs a C toolchain like gcc and maturin to build the Rust core)."
    ) from exc


ApprovalCallback = Callable[
    [str, EvaluationResult],
    Union[
        "ApprovalDecision",
        Awaitable["ApprovalDecision"],
    ],
]
"""Host-supplied callback for ``escalate`` verdicts.

The callback receives the intervention-point name and the
:class:`EvaluationResult` and returns an :class:`ApprovalDecision`
(allow/deny/suspend) carrying the approved ``enforced_identity`` per
AGT-DELTA D1.4. It may be sync or async.
"""


class ApprovalDecision:
    """Result returned by an :data:`ApprovalCallback`.

    Wraps the ACS :class:`ApprovalResolution` so AGT host code does not
    need to import from :mod:`agent_control_specification` directly. The
    ``enforced_identity`` MUST match the
    :attr:`EvaluationResult.enforced_identity` the resolver was handed,
    per AGT-DELTA D1.4. The runtime raises
    ``runtime_error:approval_action_mismatch`` when the identities do
    not match.
    """

    __slots__ = ("outcome", "enforced_identity", "handle")

    def __init__(
        self,
        outcome: str,
        *,
        enforced_identity: str | None = None,
        handle: Any | None = None,
    ) -> None:
        if outcome not in ("allow", "deny", "suspend"):
            raise ValueError(
                f"outcome must be one of allow|deny|suspend, got {outcome!r}"
            )
        self.outcome = outcome
        self.enforced_identity = enforced_identity
        self.handle = handle

    @classmethod
    def allow(cls, enforced_identity: str) -> "ApprovalDecision":
        return cls("allow", enforced_identity=enforced_identity)

    @classmethod
    def deny(cls) -> "ApprovalDecision":
        return cls("deny")

    @classmethod
    def suspend(
        cls, *, enforced_identity: str | None = None, handle: Any | None = None
    ) -> "ApprovalDecision":
        return cls("suspend", enforced_identity=enforced_identity, handle=handle)


def _result_from_intervention(
    ip_result: InterventionPointResult,
    snapshot: Mapping[str, Any],
) -> EvaluationResult:
    """Map an ACS :class:`InterventionPointResult` to an AGT :class:`EvaluationResult`."""
    verdict: Verdict = ip_result.verdict
    decision = verdict.decision.value
    transform: dict[str, Any] | None = None
    if verdict.transform is not None:
        transform = {"path": verdict.transform.path, "value": verdict.transform.value}
        if ip_result.transformed_policy_target is not None:
            transform["applied_value"] = ip_result.transformed_policy_target
    evidence: dict[str, Any] | None = None
    if verdict.evidence is not None:
        evidence = {
            "artefact": verdict.evidence.artefact,
            "verification_pointers": dict(verdict.evidence.verification_pointers),
        }
    reason = verdict.reason or ""
    message = verdict.message or ""
    audit: dict[str, Any] = {
        "verdict": decision,
        "intervention_point": snapshot.get("envelope", {}).get(
            "intervention_point", ""
        ),
    }
    if verdict.result_labels:
        audit["result_labels"] = list(verdict.result_labels)
    if ip_result.input_identity is not None:
        audit["input_identity"] = ip_result.input_identity
    if ip_result.enforced_identity is not None:
        audit["enforced_identity"] = ip_result.enforced_identity
    return EvaluationResult(
        allowed=decision in ("allow", "warn", "transform"),
        category=None,
        matched_rule=None,
        public_message=message,
        detail=message,
        reason=reason,
        audit_entry=audit,
        verdict=decision,  # type: ignore[arg-type]
        transform=transform,
        evidence=evidence,
        input_identity=ip_result.input_identity,
        enforced_identity=ip_result.enforced_identity,
        message=message,
    )


def _snapshot_to_acs(
    intervention_point: str, snapshot: Mapping[str, Any]
) -> dict[str, Any]:
    """Translate an AGT snapshot dict to the ACS evaluate_intervention_point input.

    ACS expects the snapshot at the top level. AGT snapshots already
    match the per-IP shape from AGT-SNAPSHOT 2; this function is the
    documented translation seam so future divergence stays here.
    """
    return dict(snapshot)


class AgtRuntime:
    """Public host wrapper over :class:`agent_control_specification.AgentControl`.

    Construct with the path to an AGT manifest. When ``resolution_root``
    is supplied the AGT manifest-resolution layer pre-resolves the
    governance chain (folder discovery, scope filter, merge, Rego bundle
    materialisation) and feeds the engine the resolved manifest. With
    no ``resolution_root`` the manifest at ``manifest_path`` is loaded
    verbatim.

    Pass ``approval_resolver`` to wire the host approval path. The
    callback is invoked synchronously by :meth:`evaluate_intervention_point`
    when the engine returns ``escalate``; it MUST return an
    :class:`ApprovalDecision` whose ``enforced_identity`` matches the
    one carried on the :class:`EvaluationResult`. An identity mismatch
    raises ``runtime_error:approval_action_mismatch`` per AGT-DELTA
    D1.4.
    """

    def __init__(
        self,
        manifest_path: Path | str,
        *,
        resolution_root: Path | None = None,
        approval_resolver: ApprovalCallback | None = None,
        policy_dispatcher: Any | None = None,
        annotator_dispatcher: Any | None = None,
    ) -> None:
        self._manifest_path = Path(manifest_path)
        self._resolution_root = resolution_root
        self._approval_resolver = approval_resolver

        if resolution_root is not None:
            from agt.manifest_resolution import resolve_manifest

            resolved = resolve_manifest(Path(resolution_root), self._manifest_path)
            self._control = AgentControl.from_native(
                resolved,
                annotator_dispatcher=annotator_dispatcher,
                policy_dispatcher=policy_dispatcher,
            )
        elif policy_dispatcher is not None or annotator_dispatcher is not None:
            manifest_text = self._manifest_path.read_text(encoding="utf-8")
            self._control = AgentControl.from_native(
                manifest_text,
                annotator_dispatcher=annotator_dispatcher,
                policy_dispatcher=policy_dispatcher,
            )
        else:
            self._control = AgentControl.from_path(str(self._manifest_path))

    @property
    def control(self) -> AgentControl:
        """Underlying ACS orchestrator. Exposed for advanced hosts."""
        return self._control

    def evaluate_intervention_point(
        self,
        ip: str,
        snapshot: Mapping[str, Any],
        mode: str = "enforce",
    ) -> EvaluationResult:
        """Evaluate one intervention point.

        Translates the AGT snapshot to ACS shape, calls the engine, and
        maps the verdict back to :class:`EvaluationResult`. In
        ``enforce`` mode an ``escalate`` verdict is routed through the
        host-supplied approval resolver and the result's verdict is
        rewritten to reflect the resolution outcome (``allow``,
        ``deny``, or unchanged ``escalate`` when the resolver suspends).
        ``evaluate_only`` mode never invokes the resolver and surfaces
        the raw verdict.
        """
        intervention_point = InterventionPoint(ip)
        enforcement_mode = EnforcementMode(mode)
        acs_snapshot = _snapshot_to_acs(ip, snapshot)

        async def _run() -> tuple[InterventionPointResult, Optional[BaseException]]:
            raw = await self._control.evaluate_intervention_point(
                intervention_point, acs_snapshot, enforcement_mode
            )
            if enforcement_mode != EnforcementMode.ENFORCE:
                return raw, None
            if raw.verdict.decision.value != "escalate":
                return raw, None
            try:
                await self._control.enforce(
                    intervention_point,
                    raw,
                    enforcement_mode,
                    approval_resolver=_make_acs_resolver(
                        self._approval_resolver, snapshot
                    ),
                )
                return raw, None
            except AgentControlInterruption as exc:
                return raw, exc

        raw_result, exc = _run_sync(_run())
        result = _result_from_intervention(raw_result, snapshot)

        if exc is None:
            if (
                enforcement_mode == EnforcementMode.ENFORCE
                and result.verdict == "escalate"
                and self._approval_resolver is not None
            ):
                # An ``escalate`` that returned cleanly means the resolver
                # approved the action; reflect that in the EvaluationResult
                # so callers see ``allow`` like the ACS ``run`` helper does.
                result = result.model_copy(
                    update={"verdict": "allow", "allowed": True}
                )
            return result

        if isinstance(exc, AgentControlSuspended):
            return result.model_copy(
                update={
                    "verdict": "escalate",
                    "allowed": False,
                    "audit_entry": {**result.audit_entry, "suspend_handle": exc.handle},
                }
            )

        if isinstance(exc, AgentControlBlocked):
            blocked_result = exc.result
            mapped = _result_from_intervention(blocked_result, snapshot)
            # An escalate that resolves into a block (no resolver, resolver
            # returned deny, identity mismatch, etc.) MUST surface as a
            # deny verdict to the host so it is not mistaken for an
            # in-flight approval request. Preserve the engine reason
            # (``runtime_error:approval_*`` or the original escalate
            # reason) and the bisected identities.
            update: dict[str, Any] = {
                "audit_entry": {
                    **result.audit_entry,
                    **mapped.audit_entry,
                    "approval_outcome": "deny",
                },
            }
            if mapped.verdict == "escalate":
                update["verdict"] = "deny"
                update["allowed"] = False
            return mapped.model_copy(update=update)

        raise exc  # pragma: no cover - exhaustive control flow

    # ── lifecycle helpers ─────────────────────────────────────────

    def close(self) -> None:
        """Release the underlying ACS runtime (best effort)."""
        self._control = None  # type: ignore[assignment]


def _make_acs_resolver(
    callback: ApprovalCallback | None,
    snapshot: Mapping[str, Any],
) -> Optional[Callable[..., Awaitable[ApprovalResolution]]]:
    """Adapt an AGT :class:`ApprovalCallback` to the ACS approval resolver shape.

    Returns ``None`` when ``callback`` is ``None`` so the underlying
    ACS layer fails closed on escalate per its documented contract.
    """
    if callback is None:
        return None

    async def _resolve(
        intervention_point: InterventionPoint,
        ip_result: InterventionPointResult,
    ) -> ApprovalResolution:
        agt_result = _result_from_intervention(ip_result, snapshot)
        outcome = callback(intervention_point.value, agt_result)
        if asyncio.iscoroutine(outcome):
            outcome = await outcome  # type: ignore[assignment]
        if not isinstance(outcome, ApprovalDecision):
            raise TypeError(
                "approval_resolver must return an ApprovalDecision, "
                f"got {type(outcome).__name__}"
            )
        if outcome.outcome == "allow":
            if outcome.enforced_identity is None:
                raise ValueError(
                    "ApprovalDecision.allow requires enforced_identity per AGT-DELTA D1.4"
                )
            return ApprovalResolution.allow(outcome.enforced_identity)
        if outcome.outcome == "deny":
            return ApprovalResolution.deny()
        return ApprovalResolution(
            ApprovalOutcome.SUSPEND,
            handle=outcome.handle,
            action_identity=outcome.enforced_identity,
        )

    return _resolve


def _run_sync(coro: Awaitable[Any]) -> Any:
    """Run an awaitable to completion from a sync context."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]
    # An event loop is already running. Use a private loop on a new
    # thread to keep the sync surface available even from async tests.
    import threading

    holder: dict[str, Any] = {}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            holder["value"] = loop.run_until_complete(coro)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 - propagate to caller
            holder["error"] = exc
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in holder:
        raise holder["error"]
    return holder["value"]


__all__ = ["AgtRuntime", "ApprovalDecision", "ApprovalCallback"]

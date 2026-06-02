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
import copy
import math
from pathlib import Path
import tempfile
import threading
from typing import Any, Awaitable, Callable, Mapping, Optional, Union

import yaml

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


_DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300.0
_IMMEDIATE_APPROVAL_TIMEOUT_SECONDS = 0.0
_TIMED_RUN_SYNC_MAX_WORKERS = 16
_TIMED_RUN_SYNC_CANCEL_GRACE_SECONDS = 0.05
_TIMED_RUN_SYNC_SLOTS = threading.BoundedSemaphore(_TIMED_RUN_SYNC_MAX_WORKERS)


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
        self._resolution_bundle_dir: Any | None = None

        if resolution_root is not None:
            from agt.manifest_resolution import resolve_manifest

            bundle_dir = tempfile.TemporaryDirectory(prefix="agt_runtime_bundle_")
            self._resolution_bundle_dir = bundle_dir
            try:
                resolved = resolve_manifest(
                    Path(resolution_root),
                    self._manifest_path,
                    bundle_dir=Path(bundle_dir.name),
                )
                (
                    self._approval_timeout_seconds,
                    self._approval_on_timeout,
                ) = _approval_settings_from_manifest(resolved)
                engine_manifest, _ = _sanitize_manifest_for_acs(resolved)
                self._control = AgentControl.from_native(
                    engine_manifest,
                    annotator_dispatcher=annotator_dispatcher,
                    policy_dispatcher=policy_dispatcher,
                )
            except Exception:
                bundle_dir.cleanup()
                self._resolution_bundle_dir = None
                raise
        elif policy_dispatcher is not None or annotator_dispatcher is not None:
            manifest_text = self._manifest_path.read_text(encoding="utf-8")
            parsed, engine_manifest = _parse_and_sanitize_manifest_text(manifest_text)
            (
                self._approval_timeout_seconds,
                self._approval_on_timeout,
            ) = _approval_settings_from_manifest(parsed)
            self._control = AgentControl.from_native(
                engine_manifest,
                annotator_dispatcher=annotator_dispatcher,
                policy_dispatcher=policy_dispatcher,
            )
        else:
            manifest_text = self._manifest_path.read_text(encoding="utf-8")
            parsed, engine_manifest = _parse_and_sanitize_manifest_text(manifest_text)
            (
                self._approval_timeout_seconds,
                self._approval_on_timeout,
            ) = _approval_settings_from_manifest(parsed)
            if engine_manifest == manifest_text:
                self._control = AgentControl.from_path(str(self._manifest_path))
            else:
                self._control = AgentControl.from_native(engine_manifest)

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

        async def _evaluate() -> InterventionPointResult:
            return await self._control.evaluate_intervention_point(
                intervention_point, acs_snapshot, enforcement_mode
            )

        raw_result = _run_sync(_evaluate())
        exc: Optional[BaseException] = None
        if (
            enforcement_mode == EnforcementMode.ENFORCE
            and raw_result.verdict.decision.value == "escalate"
        ):

            async def _enforce() -> None:
                await self._control.enforce(
                    intervention_point,
                    raw_result,
                    enforcement_mode,
                    approval_resolver=_make_acs_resolver(
                        self._approval_resolver, snapshot
                    ),
                )

            try:
                _run_sync(_enforce(), timeout=self._approval_timeout_seconds)
            except TimeoutError:
                return _approval_timeout_result(
                    raw_result,
                    snapshot,
                    self._approval_on_timeout,
                )
            except AgentControlInterruption as caught:
                exc = caught
            except RuntimeError as caught:
                if _is_event_loop_binding_error(caught):
                    return _approval_timeout_result(raw_result, snapshot, "deny")
                return _approval_error_result(raw_result, snapshot, caught)
            except Exception as caught:  # noqa: BLE001 - resolver errors fail closed
                return _approval_error_result(raw_result, snapshot, caught)

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
        if self._resolution_bundle_dir is not None:
            self._resolution_bundle_dir.cleanup()
            self._resolution_bundle_dir = None


def _parse_and_sanitize_manifest_text(manifest_text: str) -> tuple[Mapping[str, Any], str]:
    parsed = yaml.safe_load(manifest_text) or {}
    if not isinstance(parsed, Mapping):
        return {}, manifest_text
    sanitized, changed = _sanitize_manifest_for_acs(parsed)
    if not changed:
        return parsed, manifest_text
    return parsed, yaml.safe_dump(sanitized, sort_keys=False)


def _approval_settings_from_manifest_text(manifest_text: str) -> tuple[float, str]:
    parsed = yaml.safe_load(manifest_text) or {}
    if not isinstance(parsed, Mapping):
        return _DEFAULT_APPROVAL_TIMEOUT_SECONDS, "deny"
    return _approval_settings_from_manifest(parsed)


def _valid_approval_timeout(raw_timeout: Any) -> bool:
    return (
        not isinstance(raw_timeout, bool)
        and isinstance(raw_timeout, (int, float))
        and math.isfinite(float(raw_timeout))
        and raw_timeout > 0
    )


def _sanitize_manifest_for_acs(manifest: Mapping[str, Any]) -> tuple[Mapping[str, Any], bool]:
    sanitized = copy.deepcopy(dict(manifest))
    approval = sanitized.get("approval")
    if not isinstance(approval, Mapping):
        return sanitized, False

    changed = False
    sanitized_approval = dict(approval)
    timeout_valid = True
    if "timeout_seconds" in approval:
        raw_timeout = approval.get("timeout_seconds")
        timeout_valid = _valid_approval_timeout(raw_timeout)
        acs_timeout = max(1, int(math.ceil(float(raw_timeout)))) if timeout_valid else 1
        if raw_timeout != acs_timeout:
            changed = True
        sanitized_approval["timeout_seconds"] = acs_timeout

    if "on_timeout" in approval:
        raw_on_timeout = approval.get("on_timeout")
        acs_on_timeout = (
            "allow"
            if timeout_valid and str(raw_on_timeout or "deny").lower() == "allow"
            else "deny"
        )
        if raw_on_timeout != acs_on_timeout:
            changed = True
        sanitized_approval["on_timeout"] = acs_on_timeout

    sanitized["approval"] = sanitized_approval
    return sanitized, changed


def _approval_settings_from_manifest(manifest: Mapping[str, Any]) -> tuple[float, str]:
    """Return approval timeout settings with invalid values failing closed.

    Missing ``timeout_seconds`` preserves the 300s default. Explicit zero,
    negative, non-finite, boolean, or non-numeric values are treated as an
    immediate fail-closed timeout and cannot opt into ``on_timeout: allow``.
    """
    approval = manifest.get("approval")
    if not isinstance(approval, Mapping):
        return _DEFAULT_APPROVAL_TIMEOUT_SECONDS, "deny"

    raw_timeout = approval.get("timeout_seconds")
    timeout = _DEFAULT_APPROVAL_TIMEOUT_SECONDS
    timeout_valid = True
    if "timeout_seconds" in approval:
        timeout_valid = _valid_approval_timeout(raw_timeout)
        timeout = (
            float(raw_timeout)
            if timeout_valid
            else _IMMEDIATE_APPROVAL_TIMEOUT_SECONDS
        )

    on_timeout = str(approval.get("on_timeout") or "deny").lower()
    if on_timeout != "allow" or not timeout_valid:
        on_timeout = "deny"
    return timeout, on_timeout


def _approval_timeout_result(
    raw_result: InterventionPointResult,
    snapshot: Mapping[str, Any],
    on_timeout: str,
) -> EvaluationResult:
    result = _result_from_intervention(raw_result, snapshot)
    if on_timeout == "allow":
        return result.model_copy(
            update={
                "verdict": "allow",
                "allowed": True,
                "audit_entry": {
                    **result.audit_entry,
                    "approval_outcome": "allow",
                    "approval_timeout": True,
                },
            }
        )
    return result.model_copy(
        update={
            "verdict": "deny",
            "allowed": False,
            "reason": "runtime_error:approval_timeout",
            "message": "Approval resolver timed out and failed closed.",
            "audit_entry": {
                **result.audit_entry,
                "approval_outcome": "deny",
                "approval_timeout": True,
            },
        }
    )


def _approval_error_result(
    raw_result: InterventionPointResult,
    snapshot: Mapping[str, Any],
    exc: Exception,
) -> EvaluationResult:
    result = _result_from_intervention(raw_result, snapshot)
    return result.model_copy(
        update={
            "verdict": "deny",
            "allowed": False,
            "reason": "runtime_error:approval_resolver_error",
            "message": f"Approval resolver failed closed: {type(exc).__name__}",
            "audit_entry": {
                **result.audit_entry,
                "approval_outcome": "deny",
                "approval_error": type(exc).__name__,
            },
        }
    )


def _is_event_loop_binding_error(exc: RuntimeError) -> bool:
    message = str(exc)
    return (
        "attached to a different loop" in message
        or "bound to a different event loop" in message
    )


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
        try:
            outcome = callback(intervention_point.value, agt_result)
            if asyncio.iscoroutine(outcome):
                outcome = await outcome  # type: ignore[assignment]
        except RuntimeError as exc:
            if _is_event_loop_binding_error(exc):
                await asyncio.Event().wait()
            raise
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


def _close_unstarted_awaitable(awaitable: Awaitable[Any]) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()


def _cancel_pending_tasks(loop: asyncio.AbstractEventLoop) -> None:
    pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
    if pending:
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.run_until_complete(loop.shutdown_asyncgens())


def _run_sync(coro: Awaitable[Any], *, timeout: float | None = None) -> Any:
    """Run an awaitable to completion from a sync context.

    Timed calls use daemon worker threads capped by
    ``_TIMED_RUN_SYNC_MAX_WORKERS``. CPython cannot kill a resolver that is
    stuck in synchronous code, so a timed-out worker may remain alive; keeping
    its semaphore slot prevents unbounded accumulation and future approvals
    fail closed once the cap is reached.
    """
    if timeout is None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)  # type: ignore[arg-type]

    slot_acquired = False
    if timeout is not None:
        if timeout <= 0:
            _close_unstarted_awaitable(coro)
            raise TimeoutError("approval resolver timed out")
        if not _TIMED_RUN_SYNC_SLOTS.acquire(blocking=False):
            _close_unstarted_awaitable(coro)
            raise TimeoutError("approval resolver timed out")
        slot_acquired = True

    holder: dict[str, Any] = {}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            task = loop.create_task(coro)  # type: ignore[arg-type]
            holder["loop"] = loop
            holder["task"] = task
            try:
                holder["value"] = loop.run_until_complete(task)
            except BaseException as exc:  # noqa: BLE001 - propagate to caller
                holder["error"] = exc
            finally:
                _cancel_pending_tasks(loop)
        except BaseException as exc:  # noqa: BLE001 - propagate to caller
            holder.setdefault("error", exc)
        finally:
            loop.close()
            if slot_acquired:
                _TIMED_RUN_SYNC_SLOTS.release()

    thread = threading.Thread(
        target=_runner,
        name="agt-approval-resolver",
        daemon=True,
    )
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        loop = holder.get("loop")
        task = holder.get("task")
        if loop is not None and task is not None:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
        thread.join(_TIMED_RUN_SYNC_CANCEL_GRACE_SECONDS)
        raise TimeoutError("approval resolver timed out")
    if "error" in holder:
        raise holder["error"]
    return holder["value"]


__all__ = ["AgtRuntime", "ApprovalDecision", "ApprovalCallback"]

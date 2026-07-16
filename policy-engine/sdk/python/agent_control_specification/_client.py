from __future__ import annotations

import asyncio
import json
from typing import Callable, Mapping, Protocol, runtime_checkable

from ._types import JsonValue, InterventionPoint, InterventionPointRequest, InterventionPointResult, Verdict


@runtime_checkable
class AnnotatorDispatcher(Protocol):
    """Host-owned annotator hook invoked synchronously by the native runtime."""

    def dispatch(
        self,
        annotator_name: str,
        annotator_config: Mapping[str, JsonValue],
        preliminary_policy_input: Mapping[str, JsonValue],
    ) -> JsonValue: ...


@runtime_checkable
class PolicyDispatcher(Protocol):
    """Host-owned policy-engine hook invoked synchronously by the native runtime."""

    def evaluate(self, invocation: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]: ...


@runtime_checkable
class RuntimeClient(Protocol):
    """Minimal async boundary that Python adapters depend on."""

    async def evaluate_intervention_point(self, request: InterventionPointRequest) -> InterventionPointResult: ...


def parse_manifest(manifest: str | bytes) -> JsonValue:
    """Parse manifest text with the same serde_yaml implementation as the Rust runtime."""

    try:
        from agent_control_specification import _native
    except ImportError as exc:
        raise ImportError(
            "The agent_control_specification._native extension is not built. "
            "Install this package with maturin or build the wheel before parsing manifests."
        ) from exc
    manifest_str = manifest.decode("utf-8") if isinstance(manifest, bytes) else manifest
    if not isinstance(manifest_str, str):
        raise TypeError("manifest must be a string or bytes")
    return _native.parse_manifest(manifest_str)


def validate_manifest(manifest: str | bytes) -> None:
    """Validate manifest text with the Rust runtime's typed manifest contract."""

    try:
        from agent_control_specification import _native
    except ImportError as exc:
        raise ImportError(
            "The agent_control_specification._native extension is not built. "
            "Install this package with maturin or build the wheel before validating manifests."
        ) from exc
    manifest_str = manifest.decode("utf-8") if isinstance(manifest, bytes) else manifest
    if not isinstance(manifest_str, str):
        raise TypeError("manifest must be a string or bytes")
    _native.validate_manifest(manifest_str)


def validate_manifest_overlay(manifest: str | bytes) -> None:
    """Validate resolution-independent fields on a partial manifest."""

    try:
        from agent_control_specification import _native
    except ImportError as exc:
        raise ImportError(
            "The agent_control_specification._native extension is not built. "
            "Install this package with maturin or build the wheel before validating manifests."
        ) from exc
    manifest_str = manifest.decode("utf-8") if isinstance(manifest, bytes) else manifest
    if not isinstance(manifest_str, str):
        raise TypeError("manifest must be a string or bytes")
    _native.validate_manifest_overlay(manifest_str)


class NativeRuntimeClient:
    """Thin async facade over the deterministic Rust core PyO3 binding."""

    @classmethod
    def from_path(
        cls,
        path: str,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        perf_telemetry: int = 0,
    ) -> "NativeRuntimeClient":
        return cls(
            path,
            annotator_dispatcher,
            policy_dispatcher,
            perf_telemetry,
            loader=lambda native, a, p: native.NativeRuntime.from_path(path, a, p, perf_telemetry),
        )

    @classmethod
    def from_url(
        cls,
        url: str,
        sha256: str | None = None,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        perf_telemetry: int = 0,
        *,
        max_url_bytes: int | None = None,
        url_timeout_ms: int | None = None,
        max_url_redirects: int | None = None,
    ) -> "NativeRuntimeClient":
        return cls(
            url,
            annotator_dispatcher,
            policy_dispatcher,
            perf_telemetry,
            loader=lambda native, a, p: native.NativeRuntime.from_url(
                url,
                sha256,
                a,
                p,
                perf_telemetry,
                max_url_bytes,
                url_timeout_ms,
                max_url_redirects,
            ),
        )

    @classmethod
    def from_manifest_chain(
        cls,
        manifests: list[str],
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        perf_telemetry: int = 0,
    ) -> "NativeRuntimeClient":
        return cls(
            "",
            annotator_dispatcher,
            policy_dispatcher,
            perf_telemetry,
            loader=lambda native, a, p: native.NativeRuntime.from_manifest_chain(manifests, a, p, perf_telemetry),
        )

    def __init__(
        self,
        manifest: Mapping[str, JsonValue] | str | bytes,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        perf_telemetry: int = 0,
        loader: Callable[[object, object, object], object] | None = None,
    ) -> None:
        self._annotator_dispatcher = annotator_dispatcher
        self._policy_dispatcher = policy_dispatcher
        # A provided dispatcher that lacks its hook method is a pure-Python test
        # stub; fall back to the not-implemented async path. A `None` dispatcher
        # opts into the bundled native default supplied by the Rust core.
        annotator_unusable = annotator_dispatcher is not None and not hasattr(
            annotator_dispatcher, "dispatch"
        )
        policy_unusable = policy_dispatcher is not None and not hasattr(
            policy_dispatcher, "evaluate"
        )
        if annotator_unusable or policy_unusable:
            self._native = None
            return

        try:
            from agent_control_specification import _native
        except ImportError as exc:
            raise ImportError(
                "The agent_control_specification._native extension is not built. "
                "Install this package with maturin or build the wheel before using NativeRuntimeClient."
            ) from exc

        if isinstance(manifest, Mapping):
            manifest_str = json.dumps(manifest)
        elif isinstance(manifest, bytes):
            manifest_str = manifest.decode("utf-8")
        else:
            manifest_str = manifest

        annotator_cb = annotator_dispatcher.dispatch if annotator_dispatcher is not None else None
        policy_cb = policy_dispatcher.evaluate if policy_dispatcher is not None else None

        self._native = (
            loader(_native, annotator_cb, policy_cb)
            if loader is not None
            else _native.NativeRuntime(
                manifest_str,
                annotator_cb,
                policy_cb,
                perf_telemetry,
            )
        )

    async def evaluate_intervention_point(self, request: InterventionPointRequest) -> InterventionPointResult:
        if self._native is None:
            raise NotImplementedError(
                "Native Agent Control Specification Python bindings are not implemented yet; "
                "provide a RuntimeClient implementation or wire the Rust core FFI."
            )
        request_dict = {
            "intervention_point": (
                request.intervention_point.value
                if isinstance(request.intervention_point, InterventionPoint)
                else request.intervention_point
            ),
            "snapshot": dict(request.snapshot),
            "mode": request.mode.value,
        }
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(None, self._native.evaluate, request_dict)
        # AGT D1.4: prefer the new bisected identity fields when the native
        # core exposes them. Older builds only emitted ``action_identity``;
        # fall back to that single value for both slots so the SDK stays
        # tolerant of older binaries during a rollout.
        legacy_identity = raw.get("action_identity")
        input_identity = raw.get("input_identity", legacy_identity)
        enforced_identity = raw.get("enforced_identity", legacy_identity)
        return InterventionPointResult(
            verdict=Verdict.from_mapping(raw["verdict"]),
            transformed_policy_target=raw.get("transformed_policy_target"),
            transformed_policy_target_applied=bool(
                raw.get("transformed_policy_target_applied", raw.get("transformed_policy_target") is not None)
            ),
            policy_input=raw.get("policy_input"),
            input_identity=input_identity,
            enforced_identity=enforced_identity,
        )

    def policy_labels(self) -> dict[str, dict[str, object]]:
        """Resolved ``policy_id`` and configured annotator names per intervention
        point, from the native runtime's merged manifest.

        The host telemetry layer reads this once at construction so events are
        labelled on every constructor, including ``from_url`` and
        ``from_manifest_chain`` where the SDK never holds the manifest text.
        Returns an empty mapping when the native extension is unavailable (a
        pure-Python test client), and never raises, since telemetry labels are
        best effort. The shape is
        ``{"<intervention_point>": {"policy_id": str | None, "annotators": [str]}}``.
        """

        native = self._native
        if native is None or not hasattr(native, "policy_labels"):
            return {}
        try:
            labels = native.policy_labels()
        except Exception:  # noqa: BLE001 - label lookup must never break construction
            return {}
        return labels if isinstance(labels, dict) else {}

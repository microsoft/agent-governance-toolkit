# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Agent Threat Rules (ATR) annotator + custom policy for the ACS runtime.

This wires the open-source ATR detection engine (``pyatr``) into the Agent
Control Specification (ACS) runtime as a host-provided annotator, paired with a
thin ``custom`` policy that denies when ATR matches.

Design (kept deliberately thin, per the contribution guidance):

* ``ATRAnnotator.dispatch`` runs ``pyatr`` over the policy target text and
  returns a free-form *annotation* (the match summary). It makes no decision.
* ``ATRPolicy.evaluate`` reads that annotation and returns an ACS *verdict*
  dict -- ``deny`` on a match, ``allow`` otherwise. The adapter only translates
  shapes; it does not re-implement detection.

Notes:
* ``pyatr`` is an optional dependency (pre-1.0). It is imported lazily so the
  module can be inspected without it; calling the annotator without it raises a
  clear ImportError.
* A dispatcher exception fails closed in the ACS runtime
  (``runtime_error:annotation_failed``), so an engine error blocks rather than
  silently allows.
* Verdicts intentionally use only ``decision``/``reason``/``evidence``. The
  ``effects[]`` surface was removed by AGT D1; mutation would require a
  ``transform`` verdict, which this example does not need.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

try:  # optional dependency: the ATR detection engine
    from pyatr import scan as _atr_scan
except ImportError as exc:  # pragma: no cover - exercised when pyatr is absent
    _atr_scan = None
    _ATR_IMPORT_ERROR: ImportError | None = exc
else:
    _ATR_IMPORT_ERROR = None

MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.yaml"
RULE_URL = "https://agentthreatrule.org/rules/{rule_id}"
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _require_scan():
    if _atr_scan is None:
        raise ImportError(
            "The Agent Threat Rules engine 'pyatr' is not installed. "
            "Install it with: pip install pyatr"
        ) from _ATR_IMPORT_ERROR
    return _atr_scan


def _text_from_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _policy_target_value(policy_input: dict[str, Any]) -> Any:
    target = policy_input.get("policy_target")
    if isinstance(target, dict) and "value" in target:
        return target.get("value")
    return target


class ATRAnnotator:
    """Annotator dispatcher that scans the policy target with Agent Threat Rules."""

    def __init__(self, *, rules_dir: str | None = None, min_severity: str = "high") -> None:
        self.rules_dir = rules_dir or None
        self.min_severity = min_severity

    def dispatch(
        self,
        annotator_name: str,
        annotator_config: dict[str, Any],
        preliminary_policy_input: dict[str, Any],
    ) -> dict[str, Any]:
        _ = annotator_name, annotator_config
        scan = _require_scan()
        text = _text_from_value(_policy_target_value(preliminary_policy_input))
        threshold = _SEVERITY_RANK.get(self.min_severity, 2)
        matches = scan(text, rules_dir=self.rules_dir)
        hits = [m for m in matches if _SEVERITY_RANK.get(m.severity, 0) >= threshold]
        max_sev = max(
            (m.severity for m in hits),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
            default=None,
        )
        return {
            "matched": bool(hits),
            "count": len(hits),
            "max_severity": max_sev,
            "rule_ids": [m.rule_id for m in hits],
            "matches": [
                {"rule_id": m.rule_id, "title": m.title, "severity": m.severity}
                for m in hits[:10]
            ],
        }


class ATRPolicy:
    """Custom policy: deny when the ATR annotator reports a match, else allow."""

    ANNOTATOR_NAME = "atr_scanner"

    def evaluate(self, invocation: dict[str, Any]) -> dict[str, Any]:
        policy_input = invocation.get("input", {})
        annotation = (policy_input.get("annotations") or {}).get(self.ANNOTATOR_NAME, {})
        if annotation.get("matched"):
            rule_ids = annotation.get("rule_ids", [])
            reason = (
                f"Agent Threat Rules matched {annotation.get('count', 0)} rule(s) "
                f"(max severity {annotation.get('max_severity')}): "
                f"{', '.join(rule_ids[:5])}"
            )
            verdict: dict[str, Any] = {"decision": "deny", "reason": reason}
            evidence = _evidence(rule_ids)
            if evidence is not None:
                verdict["evidence"] = evidence
            return verdict
        return {"decision": "allow", "reason": "No Agent Threat Rules matched the policy target"}


def _evidence(rule_ids: list[str]) -> dict[str, Any] | None:
    if not rule_ids:
        return None
    pointers = {rid: RULE_URL.format(rule_id=rid) for rid in rule_ids[:8]}
    artefact = "sha256:" + hashlib.sha256(",".join(sorted(rule_ids)).encode()).hexdigest()
    return {"artefact": artefact, "verification_pointers": pointers}


def _manifest_adapter_config() -> tuple[str | None, str]:
    """Read rules_dir / min_severity from the custom policy's adapter_config."""
    rules_dir: str | None = None
    min_severity = "high"
    try:
        import yaml

        doc = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
        for policy in (doc.get("policies") or {}).values():
            if policy.get("type") == "custom" and policy.get("adapter") == "atr_annotator":
                rules_dir = policy.get("rules_dir") or None
                min_severity = policy.get("min_severity", "high")
                break
    except Exception:
        pass
    return rules_dir, min_severity


def make_control(*, rules_dir: str | None = None, min_severity: str | None = None) -> Any:
    """Construct an AgentControl wired to the ATR annotator + deny-on-match policy.

    The rule-set path and severity threshold default to the custom policy's
    ``adapter_config`` in ``manifest.yaml`` and can be overridden by the host.
    """
    from agent_control_specification import AgentControl

    cfg_dir, cfg_sev = _manifest_adapter_config()
    annotator = ATRAnnotator(
        rules_dir=rules_dir if rules_dir is not None else cfg_dir,
        min_severity=min_severity or cfg_sev,
    )
    return AgentControl.from_path(
        str(MANIFEST_PATH),
        annotator_dispatcher=annotator,
        policy_dispatcher=ATRPolicy(),
    )

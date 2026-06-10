from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .llm import LanguageModel
from .manifest_builder import build_manifest, referenced_tool_names
from .plan import PlanError, PolicyPlan, parse_policy_plan
from .rego_builder import build_rego
from .report import build_report
from .validation import ValidationError, dump_manifest_yaml, validate_artifacts
from .vocabulary import INTERVENTION_POINT_NAMES, MAX_REPAIR_ATTEMPTS

SYSTEM_PROMPT = """You author only a constrained JSON policy plan for ACS artifacts.
Return JSON only. Do not emit YAML. Do not emit complete Rego modules.
Schema: {name, guarded_points, annotators, annotations, tools, rules, warnings}.
Valid intervention points: %s.
Annotator types: classifier, llm, endpoint. Decisions: allow, warn, deny, escalate.
Effects must use append, replace, or redact and paths beginning with $policy_target.
Rule conditions are Rego body lines that may read only input.intervention_point, input.annotations.<annotator>, input.policy_target.value, input.tool.name, input.tool.id, and constants.
Every rule must set "point" to one of the valid intervention points and include at least one condition that selects when it fires, unless its decision is "allow" with no effects. Never emit a rule with an empty point or empty conditions.
""" % ", ".join(INTERVENTION_POINT_NAMES)


@dataclass(frozen=True)
class GenerationResult:
    slug: str
    manifest: dict[str, Any]
    manifest_yaml: str
    rego: str
    report: str
    warnings: tuple[str, ...]


class GenerationError(RuntimeError):
    pass


class GenerationEngine:
    def __init__(self, language_model: LanguageModel) -> None:
        self.language_model = language_model

    def generate(
        self,
        *,
        prompt: str,
        out_dir: Path,
        tool_inventory: dict[str, dict[str, Any]] | None = None,
        strict: bool = False,
        write: bool = True,
    ) -> GenerationResult:
        inventory = tool_inventory or {}
        repair_context = ""
        diagnostics: list[str] = []
        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            raw_plan = self.language_model.complete(SYSTEM_PROMPT, self._user_prompt(prompt, inventory, repair_context))
            try:
                plan = parse_policy_plan(raw_plan)
                warnings = self._plan_warnings(plan, inventory)
                manifest, slug = build_manifest(plan, inventory)
                rego = build_rego(plan, slug)
                manifest_yaml = dump_manifest_yaml(manifest)
                result = validate_artifacts(manifest, manifest_yaml, rego, slug, out_dir, strict=strict)
                all_warnings = [*warnings, *result.warnings]
                report = build_report(plan, slug, manifest, all_warnings)
                generation = GenerationResult(slug, manifest, manifest_yaml, rego, report, tuple(all_warnings))
                if write:
                    self._write(out_dir, generation)
                return generation
            except (PlanError, ValidationError) as exc:
                diagnostics.append(f"attempt {attempt}: {exc}")
                repair_context = self._repair_prompt(diagnostics)
        raise GenerationError("generation failed after repair attempts:\n" + "\n".join(diagnostics))

    def _user_prompt(self, prompt: str, inventory: dict[str, dict[str, Any]], repair_context: str) -> str:
        tool_lines = "\n".join(f"- {name}: {config}" for name, config in inventory.items()) or "No tool inventory was provided."
        return f"Natural-language guardrails:\n{prompt}\n\nTool inventory:\n{tool_lines}\n\n{repair_context}".strip()

    def _repair_prompt(self, diagnostics: list[str]) -> str:
        return (
            "Previous generated plan failed validation. Repair only the failing section while preserving validated intent. "
            "Concrete diagnostics:\n" + "\n".join(diagnostics[-3:])
        )

    def _plan_warnings(self, plan: PolicyPlan, inventory: dict[str, dict[str, Any]]) -> list[str]:
        warnings: list[str] = []
        undocumented = [name for name in referenced_tool_names(plan) if name not in inventory]
        if undocumented:
            warnings.append(
                "Tools declared with minimal metadata (no inventory provided): " + ", ".join(undocumented)
            )
        return warnings

    def _write(self, out_dir: Path, result: GenerationResult) -> None:
        policy_dir = out_dir / "policy"
        policy_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "manifest.yaml").write_text(result.manifest_yaml, encoding="utf-8")
        (policy_dir / f"{result.slug}.rego").write_text(result.rego, encoding="utf-8")
        (out_dir / "report.md").write_text(result.report, encoding="utf-8")

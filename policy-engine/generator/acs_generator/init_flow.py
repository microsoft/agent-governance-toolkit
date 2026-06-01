from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import yaml

from .manifest_builder import build_manifest
from .plan import PolicyPlan, RulePlan
from .rego_builder import build_rego
from .report import build_report
from .validation import ValidationError, ValidationResult, dump_manifest_yaml, validate_artifacts
from .vocabulary import INTERVENTION_POINT_NAMES, TOOL_POINTS

_GENERATED_PATHS = ("manifest.yaml", "report.md", "policy", "snapshots", "test_policy.py")
_DEFAULT_POINTS = ("input", "pre_tool_call", "output")
_DRY_RUN_VALIDATION_ROOT = ".acs_generator_dry_run_validation"
_SINGLETON_FLAGS = frozenset({"--out", "--answers-file", "--name", "--points"})
_SUPPORTED_ANSWER_KEYS = frozenset(
    {
        "name",
        "points",
        "tools",
        "deny_keywords",
        "deny_keyword",
        "escalate_tools",
        "escalate_tool",
        "redact_output_patterns",
        "redact_output_pattern",
    }
)


@dataclass(frozen=True)
class InitResult:
    slug: str
    manifest: dict[str, Any]
    manifest_yaml: str
    rego: str
    report: str
    warnings: tuple[str, ...]
    snapshots: dict[str, dict[str, Any]]
    test_file: str | None


class InitError(RuntimeError):
    pass


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None) -> int:
    parser = _parser()
    try:
        _reject_repeated_singleton_flags(sys.argv[1:] if argv is None else argv)
    except InitError as exc:
        print(f"acs init failed: {exc}")
        return 1
    args = parser.parse_args(argv)
    try:
        result = run_init(args, stdin=stdin or sys.stdin)
    except (OSError, ValueError, ValidationError, InitError) as exc:
        print(f"acs init failed: {exc}")
        return 1
    if not args.quiet:
        print(f"Designed ACS artifacts for `{result.slug}`")
        if not args.dry_run:
            print(f"Output directory: {Path(args.out)}")
        if result.warnings:
            print("Warnings: " + "; ".join(result.warnings))
    return 0


def run_init(args: argparse.Namespace, *, stdin: TextIO) -> InitResult:
    answers = _answers(args, stdin)
    if not answers and not args.non_interactive:
        answers = _prompt_for_answers(args, stdin)
    answers = _merge_flag_answers(args, answers)
    plan, inventory = _plan_from_answers(answers)
    manifest, slug = build_manifest(plan, inventory)
    rego = build_rego(plan, slug)
    manifest_yaml = dump_manifest_yaml(manifest)
    out_dir = Path(args.out)
    validation = _validate_init_artifacts(manifest, manifest_yaml, rego, slug, out_dir, strict=args.strict, dry_run=args.dry_run)
    warnings = tuple([*plan.warnings, *validation.warnings])
    report = build_report(plan, slug, manifest, list(warnings))
    snapshots = _sample_snapshots(manifest) if args.sample_snapshot or args.sample_test else {}
    test_file = _sample_test(slug, sorted(snapshots)) if args.sample_test else None
    result = InitResult(slug, manifest, manifest_yaml, rego, report, warnings, snapshots, test_file)
    if args.dry_run:
        _print_preview(result, full=True)
        return result
    _prepare_output_dir(out_dir, force=args.force)
    _write(out_dir, result)
    if not args.quiet:
        _print_preview(result, full=False)
    return result


def _validate_init_artifacts(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
    out_dir: Path,
    *,
    strict: bool,
    dry_run: bool,
) -> ValidationResult:
    if not dry_run:
        return validate_artifacts(manifest, manifest_yaml, rego, slug, out_dir, strict=strict)
    validation_dir = Path.cwd() / _DRY_RUN_VALIDATION_ROOT / slug
    try:
        return validate_artifacts(manifest, manifest_yaml, rego, slug, validation_dir, strict=strict)
    finally:
        root = Path.cwd() / _DRY_RUN_VALIDATION_ROOT
        if root.exists():
            shutil.rmtree(root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acs-generate init",
        description="Guided ACS manifest and Rego policy designer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Generated layout:\n"
            "  manifest.yaml\n"
            "  policy/<slug>.rego\n"
            "  report.md\n"
            "  snapshots/<intervention_point>.json when --sample-snapshot or --sample-test is set\n"
            "  test_policy.py when --sample-test is set\n\n"
            "Strict validation:\n"
            "  --strict requires an opa binary on PATH. In an artifact-only kit, install or extract the\n"
            "  local agent-control-specification-opa package and prepend its bin directory to PATH before\n"
            "  running acs-generate init --strict."
        ),
    )
    parser.add_argument("--out", default="acs-policy", help="Output directory. It must be empty unless --force is used")
    parser.add_argument("--force", action="store_true", help="Replace generated files in the output directory")
    parser.add_argument("--dry-run", action="store_true", help="Print generated artifacts instead of writing files")
    parser.add_argument("--strict", action="store_true", help="Fail if optional validators such as opa are unavailable")
    parser.add_argument("--quiet", action="store_true", help="Suppress policy preview and summary output")
    parser.add_argument("--non-interactive", action="store_true", help="Do not prompt. Flags or --answers-file provide all answers")
    parser.add_argument("--answers-file", help="JSON or YAML answers file. Use - to read answers from stdin")
    parser.add_argument("--name", help="Agent or policy name")
    parser.add_argument("--points", help="Comma-separated intervention points to guard")
    parser.add_argument("--tool", action="append", default=[], help="Tool entry as name:clearance1,clearance2. Repeatable")
    parser.add_argument("--deny-keyword", action="append", default=[], help="Keyword that should deny matching policy targets")
    parser.add_argument("--escalate-tool", action="append", default=[], help="Tool name that should return an escalate verdict")
    parser.add_argument("--redact-output-pattern", action="append", default=[], help="Regex pattern to redact from output policy targets")
    parser.add_argument("--sample-snapshot", action="store_true", help="Write one sample snapshot per intervention point")
    parser.add_argument("--sample-test", action="store_true", help="Write sample snapshots and a pytest smoke test")
    return parser


def _answers(args: argparse.Namespace, stdin: TextIO) -> dict[str, Any]:
    if not args.answers_file:
        return {}
    raw = stdin.read() if args.answers_file == "-" else Path(args.answers_file).read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    loaded = json.loads(raw) if args.answers_file.endswith(".json") else yaml.safe_load(raw)
    if not isinstance(loaded, dict):
        raise InitError("answers must be a JSON or YAML object")
    unsupported = sorted(set(loaded) - _SUPPORTED_ANSWER_KEYS)
    if unsupported:
        raise InitError(
            "unsupported answers-file keys: "
            + ", ".join(unsupported)
            + ". Supported keys: "
            + ", ".join(sorted(_SUPPORTED_ANSWER_KEYS))
        )
    return dict(loaded)


def _prompt_for_answers(args: argparse.Namespace, stdin: TextIO) -> dict[str, Any]:
    if not stdin.isatty():
        return {}
    print("ACS guided init. Press Enter to accept defaults.")
    name = input("Agent or policy name [acs policy]: ").strip() or "acs policy"
    points = input("Intervention points [input,pre_tool_call,output]: ").strip() or ",".join(_DEFAULT_POINTS)
    keywords = input("Deny keywords, comma-separated [secret]: ").strip() or "secret"
    tools = input("Tool inventory entries, semicolon-separated name:clearance [send_email:internal]: ").strip() or "send_email:internal"
    escalations = input("Escalate tool names, comma-separated [send_email]: ").strip() or "send_email"
    redact = input("Output regex patterns to redact, comma-separated []: ").strip()
    return {
        "name": name,
        "points": points,
        "deny_keywords": keywords,
        "tools": tools,
        "escalate_tools": escalations,
        "redact_output_patterns": redact,
    }


def _merge_flag_answers(args: argparse.Namespace, answers: dict[str, Any]) -> dict[str, Any]:
    merged = dict(answers)
    if args.name is not None:
        merged["name"] = args.name
    if args.points is not None:
        merged["points"] = args.points
    if args.tool:
        merged["tools"] = args.tool
    if args.deny_keyword:
        merged["deny_keywords"] = args.deny_keyword
    if args.escalate_tool:
        merged["escalate_tools"] = args.escalate_tool
    if args.redact_output_pattern:
        merged["redact_output_patterns"] = args.redact_output_pattern
    return merged


def _plan_from_answers(answers: dict[str, Any]) -> tuple[PolicyPlan, dict[str, dict[str, Any]]]:
    if "name" in answers:
        name = str(answers["name"]).strip()
        if not name:
            raise InitError("name must be non-empty")
    else:
        name = "acs policy"
    if "points" in answers:
        points = tuple(_list(answers.get("points")))
        if not points:
            raise InitError("points must include at least one intervention point")
    else:
        points = _DEFAULT_POINTS
    unsupported = [point for point in points if point not in INTERVENTION_POINT_NAMES]
    if unsupported:
        raise InitError("unsupported intervention point: " + ", ".join(unsupported))
    inventory = _inventory(_tool_entries(answers.get("tools")))
    rules: list[RulePlan] = []
    for keyword in _list(answers.get("deny_keywords") or answers.get("deny_keyword") or "secret"):
        escaped = json.dumps(keyword.lower())
        for point in points:
            rules.append(
                RulePlan(
                    point=point,
                    decision="deny",
                    reason="blocked_keyword",
                    message=f"The {point} policy target matched a blocked keyword.",
                    conditions=(f"contains(lower(json.marshal(input.policy_target.value)), {escaped})",),
                )
            )
    for tool in _list(answers.get("escalate_tools") or answers.get("escalate_tool")):
        if "pre_tool_call" not in points:
            continue
        rules.append(
            RulePlan(
                point="pre_tool_call",
                decision="escalate",
                reason="tool_requires_approval",
                message=f"The {tool} tool requires host approval.",
                conditions=(f"object.get(input.tool, \"id\", object.get(input.tool, \"name\", \"\")) == {json.dumps(tool)}",),
            )
        )
        inventory.setdefault(tool, {"type": "Tool", "id": tool})
    for pattern in _list(answers.get("redact_output_patterns") or answers.get("redact_output_pattern")):
        if "output" not in points:
            continue
        rules.append(
            RulePlan(
                point="output",
                decision="warn",
                reason="output_redacted",
                message="The output policy target was redacted.",
                conditions=(f"is_string(input.policy_target.value)", f"regex.match({json.dumps(pattern)}, input.policy_target.value)"),
                effects=({"type": "redact", "path": "$policy_target", "pattern": pattern},),
            )
        )
    if any(point in TOOL_POINTS for point in points) and not inventory:
        inventory["sample_tool"] = {"type": "Tool", "id": "sample_tool"}
    warnings = [] if rules else ["No deny, warn, or escalate rule was selected. The generated policy defaults to allow."]
    plan = PolicyPlan(name=name, guarded_points=points, tools=tuple(sorted(inventory)), rules=tuple(rules), warnings=tuple(warnings))
    return plan, inventory


def _reject_repeated_singleton_flags(argv: list[str]) -> None:
    seen: set[str] = set()
    for arg in argv:
        flag = arg.split("=", 1)[0]
        if flag not in _SINGLETON_FLAGS:
            continue
        if flag in seen:
            raise InitError(f"{flag} may be supplied only once")
        seen.add(flag)


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list | tuple):
        items: list[str] = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("name") or item.get("id") or item.get("tool")
                if name:
                    items.append(str(name))
            else:
                items.append(str(item))
        return items
    return [str(value)]


def _tool_entries(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(";") if part.strip()]
    if isinstance(value, list | tuple):
        return list(value)
    return [value]


def _inventory(entries: list[Any]) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if isinstance(entry, dict):
            name = str(entry.get("id") or entry.get("name") or "").strip()
            if not name:
                continue
            config = dict(entry)
            config.setdefault("type", "Tool")
            config.setdefault("id", name)
            inventory[name] = config
            continue
        name, _, clearance_text = str(entry).partition(":")
        name = name.strip()
        if not name:
            continue
        labels = [part.strip() for part in clearance_text.split(",") if part.strip()]
        config: dict[str, Any] = {"type": "Tool", "id": name}
        if labels:
            config["clearance"] = labels
            config["security_labels"] = labels
        inventory[name] = config
    return inventory


def _prepare_output_dir(out_dir: Path, *, force: bool) -> None:
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise InitError(f"output directory {out_dir} is not empty. Use --force to replace generated files")
    out_dir.mkdir(parents=True, exist_ok=True)
    if force:
        for relative in _GENERATED_PATHS:
            target = out_dir / relative
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()


def _write(out_dir: Path, result: InitResult) -> None:
    policy_dir = out_dir / "policy"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.yaml").write_text(result.manifest_yaml, encoding="utf-8")
    (policy_dir / f"{result.slug}.rego").write_text(result.rego, encoding="utf-8")
    (out_dir / "report.md").write_text(result.report, encoding="utf-8")
    if result.snapshots:
        snapshot_dir = out_dir / "snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        for point, snapshot in result.snapshots.items():
            (snapshot_dir / f"{point}.json").write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    if result.test_file:
        (out_dir / "test_policy.py").write_text(result.test_file, encoding="utf-8")


def _print_preview(result: InitResult, *, full: bool) -> None:
    print("\nManifest preview:\n" + result.manifest_yaml.rstrip())
    rego_lines = result.rego.rstrip().splitlines()
    if full or len(rego_lines) <= 80:
        print("\nPolicy preview:\n" + result.rego.rstrip())
    else:
        print("\nPolicy preview:\n" + "\n".join(rego_lines[:80]) + "\n...")


def _sample_snapshots(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {point: _snapshot_for_point(point, manifest) for point in manifest["intervention_points"]}


def _snapshot_for_point(point: str, manifest: dict[str, Any]) -> dict[str, Any]:
    if point == "agent_startup":
        return {"agent": {"name": manifest.get("metadata", {}).get("name", "agent")}, "metadata": {}}
    if point == "input":
        return {"input": {"text": "hello"}}
    if point == "pre_model_call":
        return {"model_request": {"messages": [{"role": "user", "content": "hello"}]}}
    if point == "post_model_call":
        return {"model_response": {"message": {"role": "assistant", "content": "hello"}}}
    if point == "pre_tool_call":
        tool = next(iter(manifest.get("tools", {"sample_tool": {}})))
        return {"tool_call": {"id": "sample-call", "name": tool, "args": {"text": "hello"}}}
    if point == "post_tool_call":
        tool = next(iter(manifest.get("tools", {"sample_tool": {}})))
        return {"tool_call": {"id": "sample-call", "name": tool}, "tool_result": {"text": "hello"}}
    if point == "output":
        return {"output": "hello"}
    if point == "agent_shutdown":
        return {"summary": {"status": "complete"}, "agent": {"name": "agent"}}
    raise InitError(f"cannot build sample snapshot for {point}")


def _sample_test(slug: str, points: list[str]) -> str:
    point_list = json.dumps(points)
    return f'''from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

try:
    from agent_control_specification import AgentControl, InterventionPoint
except Exception as exc:  # noqa: BLE001
    pytest.skip(f"ACS Python SDK unavailable: {{exc}}", allow_module_level=True)


@pytest.mark.parametrize("point", {point_list})
def test_generated_policy_accepts_sample_snapshot(point: str) -> None:
    root = Path(__file__).parent
    control = AgentControl.from_path(str(root / "manifest.yaml"))
    snapshot = json.loads((root / "snapshots" / f"{{point}}.json").read_text(encoding="utf-8"))
    result = asyncio.run(control.evaluate_intervention_point(InterventionPoint(point), snapshot))
    assert result.verdict.decision.value in {{"allow", "warn", "deny", "escalate"}}
'''

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Standalone example: compile Agent Threat Rules (ATR) YAML into per-category
Agent OS PolicyDocument YAML files.

This example lives under ``examples/atr-import/`` and is not part of agent-os
core. It does not register a CLI subcommand on ``agentos``; run it directly:

    python examples/atr-import/import_atr.py path/to/atr/rules/ --out ./atr-policies

ATR (https://github.com/Agent-Threat-Rule/agent-threat-rules) is an external
MIT-licensed community project. Keeping the integration in ``examples/`` means
agent-os core takes no runtime dependency on it.

This example builds on ``examples/atr-community-rules/sync_atr_rules.py`` from
PR #908. PR #908 emits a single bundled PolicyDocument with all rules merged;
this script produces one PolicyDocument per ATR category, which lets operators:

  * Drop the output directory into AGT's folder-merge policy layout where
    each ``governance.yaml`` corresponds to one threat class.
  * Use AGT's ``scope`` glob to gate a category's rules to a path subtree.
  * Filter at compile time by category, severity, or ATR ID prefix.

A ``--watch`` mode polls the source tree for changes and re-emits on
mtime drift, with no third-party dependency.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable

import yaml

# ---------------------------------------------------------------------------
# Conversion logic reuse
#
# We deliberately avoid duplicating the ATR -> AGT rule mapping. PR #908
# already implements the rule-by-rule conversion in
# ``examples/atr-community-rules/sync_atr_rules.py``. We import it here so
# that any future schema drift in ATR is fixed in exactly one place.
# ---------------------------------------------------------------------------


def _import_pr908_module():
    """Import the PR #908 sync utility by file path.

    The script lives under ``examples/`` and is not packaged as a normal
    module, so we use importlib to load it at runtime. We walk up the
    parent chain from this file rather than hard-coding a depth, which
    keeps the lookup robust if the source layout shifts.

    Honours the ``AGT_ATR_SYNC_PATH`` environment variable for installed
    deployments where the ``examples/`` directory is not co-located with
    the package.
    """
    import importlib.util

    override = os.environ.get("AGT_ATR_SYNC_PATH")
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override))

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent / "examples" / "atr-community-rules" / "sync_atr_rules.py")
        if (parent / ".git").exists():
            break

    for candidate in candidates:
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location(
                "agt_pr908_sync_atr_rules", candidate
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

    raise FileNotFoundError(
        "Cannot locate examples/atr-community-rules/sync_atr_rules.py "
        "(PR #908). Set AGT_ATR_SYNC_PATH or run from a full repo checkout."
    )


# ---------------------------------------------------------------------------
# Per-category emission
# ---------------------------------------------------------------------------


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def _category_of(atr_rule: dict[str, Any]) -> str:
    """Return the ATR category for a single rule dict."""
    tags = atr_rule.get("tags") or {}
    return str(tags.get("category") or "uncategorised")


def _severity_of(atr_rule: dict[str, Any]) -> str:
    return str(atr_rule.get("severity", "medium")).lower()


def _atr_id_of(atr_rule: dict[str, Any]) -> str:
    return str(atr_rule.get("id", ""))


def _walk_atr(atr_dir: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Yield ``(path, parsed_yaml)`` for every ATR rule file."""
    for path in sorted(atr_dir.rglob("*.yaml")):
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            print(f"WARNING: skipping {path}: {exc}", file=sys.stderr)
            continue
        if isinstance(data, dict) and "detection" in data:
            yield path, data


def _passes_filter(
    atr_rule: dict[str, Any],
    *,
    categories: set[str] | None,
    min_severity: str | None,
    id_prefix: str | None,
) -> bool:
    if categories is not None and _category_of(atr_rule) not in categories:
        return False
    if min_severity is not None:
        threshold = SEVERITY_RANK.get(min_severity, 0)
        if SEVERITY_RANK.get(_severity_of(atr_rule), 0) < threshold:
            return False
    if id_prefix is not None and not _atr_id_of(atr_rule).startswith(id_prefix):
        return False
    return True


def compile_per_category(
    atr_dir: Path,
    out_dir: Path,
    *,
    categories: set[str] | None = None,
    min_severity: str | None = None,
    id_prefix: str | None = None,
    strict_regex: bool = False,
    sync_module: Any | None = None,
) -> dict[str, Any]:
    """Compile ATR rules into one PolicyDocument YAML per category.

    Returns a manifest dict summarising what was written.

    Reuses the PR #908 conversion helpers ``_atr_to_agt_rule`` and
    ``_extract_regex_patterns`` / ``_validate_regex`` rather than
    re-implementing them. If those helpers move, this command moves with
    them — single source of truth for the mapping.
    """
    if sync_module is None:
        sync_module = _import_pr908_module()

    if not atr_dir.is_dir():
        raise NotADirectoryError(f"ATR rules directory not found: {atr_dir}")

    by_category: dict[str, list[dict[str, Any]]] = {}
    skipped_filter = 0
    skipped_maturity = 0
    dropped_regex = 0
    total_input = 0

    for path, atr_rule in _walk_atr(atr_dir):
        total_input += 1

        # Maturity gate matches PR #908 behaviour
        if atr_rule.get("status") == "draft" or atr_rule.get("maturity") == "test":
            skipped_maturity += 1
            continue

        if not _passes_filter(
            atr_rule,
            categories=categories,
            min_severity=min_severity,
            id_prefix=id_prefix,
        ):
            skipped_filter += 1
            continue

        patterns = sync_module._extract_regex_patterns(atr_rule["detection"])
        for index, pattern in enumerate(patterns):
            if not sync_module._validate_regex(pattern, str(path), strict=strict_regex):
                dropped_regex += 1
                continue
            rule = sync_module._atr_to_agt_rule(atr_rule, pattern, index)
            by_category.setdefault(_category_of(atr_rule), []).append(rule)

    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[dict[str, Any]] = []
    for category, rules in sorted(by_category.items()):
        document = {
            "version": "1.0",
            "name": f"atr-{category}",
            "description": (
                f"Auto-generated from Agent Threat Rules (ATR) — category "
                f"'{category}'. {len(rules)} detection patterns. "
                "Source: https://github.com/Agent-Threat-Rule/agent-threat-rules"
            ),
            "rules": rules,
            "defaults": {"action": "allow"},
        }
        target = out_dir / f"{category}.yaml"
        with open(target, "w", encoding="utf-8") as fh:
            yaml.dump(
                document,
                fh,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        written.append(
            {"category": category, "path": str(target), "rule_count": len(rules)}
        )

    manifest = {
        "atr_source": str(atr_dir),
        "out_dir": str(out_dir),
        "input_files": total_input,
        "skipped_filter": skipped_filter,
        "skipped_maturity": skipped_maturity,
        "dropped_invalid_regex": dropped_regex,
        "categories": written,
        "total_compiled_rules": sum(item["rule_count"] for item in written),
    }
    return manifest


# ---------------------------------------------------------------------------
# Watch loop (stdlib only)
# ---------------------------------------------------------------------------


def _tree_signature(root: Path) -> tuple[tuple[str, float], ...]:
    """Return a deterministic mtime signature for the ATR source tree."""
    items: list[tuple[str, float]] = []
    for path in sorted(root.rglob("*.yaml")):
        try:
            items.append((str(path), path.stat().st_mtime))
        except FileNotFoundError:
            continue
    return tuple(items)


def watch_and_recompile(
    atr_dir: Path,
    out_dir: Path,
    *,
    interval_seconds: float = 2.0,
    iterations: int | None = None,
    on_change: Callable[[dict[str, Any]], None] | None = None,
    **compile_kwargs: Any,
) -> int:
    """Poll the ATR source tree and recompile on any mtime change.

    Stdlib-only polling avoids adding a watchdog dependency. ``iterations``
    bounds the loop for tests; production callers leave it as ``None``.
    Returns the number of recompile cycles that actually ran.
    """
    last_sig: tuple[tuple[str, float], ...] = ()
    cycles = 0
    count = 0

    while iterations is None or count < iterations:
        count += 1
        sig = _tree_signature(atr_dir)
        if sig != last_sig:
            manifest = compile_per_category(atr_dir, out_dir, **compile_kwargs)
            cycles += 1
            last_sig = sig
            if on_change is not None:
                on_change(manifest)
            else:
                print(
                    f"[atr-import] recompiled — {manifest['total_compiled_rules']} "
                    f"rules across {len(manifest['categories'])} categories",
                    file=sys.stderr,
                )
        if iterations is None:  # pragma: no cover — covered via iterations
            time.sleep(interval_seconds)
        else:
            time.sleep(min(interval_seconds, 0.01))

    return cycles


# ---------------------------------------------------------------------------
# Argparse wiring (standalone script — not registered on agentos)
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the standalone argparse parser for this example."""
    parser = argparse.ArgumentParser(
        prog="import_atr.py",
        description="Compile Agent Threat Rules (ATR) YAML into per-category Agent OS PolicyDocument YAML files.",
    )
    parser.add_argument(
        "atr_dir",
        type=Path,
        help="Path to the ATR rules/ directory (e.g. node_modules/agent-threat-rules/rules/).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("./atr-policies"),
        help="Output directory for per-category PolicyDocument YAML files (default: ./atr-policies).",
    )
    parser.add_argument(
        "--category",
        action="append",
        default=None,
        help="Restrict output to a category (repeatable). Default: all categories.",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_RANK.keys()),
        default=None,
        help="Drop rules below this ATR severity tier.",
    )
    parser.add_argument(
        "--id-prefix",
        default=None,
        help="Restrict output to ATR rule IDs with this prefix (e.g. 'ATR-2026-').",
    )
    parser.add_argument(
        "--strict-regex",
        action="store_true",
        help="Fail fast on invalid or oversized regex (matches PR #908 semantics).",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="If set, write a JSON manifest of compiled output to this path.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Poll the ATR source tree and recompile on changes (Ctrl+C to exit).",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=2.0,
        help="Watch poll interval in seconds (default: 2.0).",
    )
    return parser


def _validate_cli_paths(
    atr_dir: Path, out_dir: Path
) -> str | None:
    """Pre-flight validation for CLI path arguments.

    Returns ``None`` on success, or a single-line error message that the
    caller should print to stderr before returning a non-zero exit code.

    Validates:
      * ``atr_dir`` exists as a directory (fail fast before doing any work).
      * ``out_dir.parent`` is creatable / writable (fail before the first
        rule is parsed, instead of mid-compile after manifest generation).
    """
    if not atr_dir.exists():
        return f"ATR rules directory does not exist: {atr_dir}"
    if not atr_dir.is_dir():
        return f"ATR rules path is not a directory: {atr_dir}"
    try:
        out_dir.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as exc:
        return f"Output directory parent is not writable: {out_dir.parent} ({exc})"
    return None


def cmd_atr_import(args: argparse.Namespace) -> int:
    """Entry point for ``agentos atr-import``."""
    validation_error = _validate_cli_paths(args.atr_dir, args.out)
    if validation_error is not None:
        print(f"ERROR: {validation_error}", file=sys.stderr)
        return 1

    categories: set[str] | None = (
        set(args.category) if getattr(args, "category", None) else None
    )

    compile_kwargs = {
        "categories": categories,
        "min_severity": getattr(args, "min_severity", None),
        "id_prefix": getattr(args, "id_prefix", None),
        "strict_regex": bool(getattr(args, "strict_regex", False)),
    }

    try:
        manifest = compile_per_category(args.atr_dir, args.out, **compile_kwargs)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"[atr-import] {manifest['total_compiled_rules']} rules compiled across "
        f"{len(manifest['categories'])} categories -> {args.out}",
        file=sys.stderr,
    )

    if args.manifest is not None:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

    if args.watch:
        try:
            watch_and_recompile(
                args.atr_dir,
                args.out,
                interval_seconds=args.watch_interval,
                **compile_kwargs,
            )
        except KeyboardInterrupt:
            return 0

    return 0


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return cmd_atr_import(args)


if __name__ == "__main__":
    raise SystemExit(main())

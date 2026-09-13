#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Compile Agent Threat Rules into one native ACS policy per category."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def _import_sync_module() -> Any:
    """Load the sibling ATR compiler from a checkout or explicit override."""

    candidates: list[Path] = []
    if override := os.environ.get("AGT_ATR_SYNC_PATH"):
        candidates.append(Path(override))
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(
            parent / "examples" / "atr-community-rules" / "sync_atr_rules.py"
        )
        if (parent / ".git").exists():
            break
    for candidate in candidates:
        if not candidate.is_file():
            continue
        spec = importlib.util.spec_from_file_location("agt_atr_sync", candidate)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise FileNotFoundError(
        "Cannot locate examples/atr-community-rules/sync_atr_rules.py"
    )


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
    """Write one native ACS manifest and Rego bundle per ATR category."""

    module = sync_module or _import_sync_module()
    if not atr_dir.is_dir():
        raise NotADirectoryError(f"ATR rules directory not found: {atr_dir}")
    threshold = (
        SEVERITY_RANK.get(min_severity, 0)
        if min_severity is not None
        else None
    )
    grouped: dict[str, list[Any]] = {}
    for pattern in module.iter_atr_patterns(
        atr_dir,
        strict_regex=strict_regex,
    ):
        if categories is not None and pattern.category not in categories:
            continue
        if (
            threshold is not None
            and SEVERITY_RANK.get(pattern.severity, 0) < threshold
        ):
            continue
        if id_prefix is not None and not pattern.atr_id.startswith(id_prefix):
            continue
        grouped.setdefault(pattern.category, []).append(pattern)

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    for category, patterns in sorted(grouped.items()):
        safe = re.sub(r"[^a-z0-9_]", "_", category.lower())
        compiled = module.compile_patterns(
            patterns,
            name=f"atr-{category}",
            bundle=f"{safe}-bundle",
            package=f"agt.examples.atr.{safe}",
        )
        target = out_dir / f"{category}.yaml"
        module.write_compiled(target, compiled)
        written.append(
            {
                "category": category,
                "path": str(target),
                "pattern_count": compiled.pattern_count,
            }
        )
    return {
        "atr_source": str(atr_dir),
        "out_dir": str(out_dir),
        "categories": written,
        "total_compiled_rules": sum(
            item["pattern_count"] for item in written
        ),
    }


def _tree_signature(root: Path) -> tuple[tuple[str, float], ...]:
    entries: list[tuple[str, float]] = []
    for path in sorted(root.rglob("*.yaml")):
        try:
            entries.append((str(path), path.stat().st_mtime))
        except FileNotFoundError:
            continue
    return tuple(entries)


def watch_and_recompile(
    atr_dir: Path,
    out_dir: Path,
    *,
    interval_seconds: float = 2.0,
    iterations: int | None = None,
    on_change: Callable[[dict[str, Any]], None] | None = None,
    **compile_kwargs: Any,
) -> int:
    """Poll for ATR changes and recompile changed trees."""

    last_signature: tuple[tuple[str, float], ...] = ()
    cycles = 0
    count = 0
    while iterations is None or count < iterations:
        count += 1
        signature = _tree_signature(atr_dir)
        if signature != last_signature:
            result = compile_per_category(
                atr_dir,
                out_dir,
                **compile_kwargs,
            )
            cycles += 1
            last_signature = signature
            if on_change is not None:
                on_change(result)
        if iterations is None:
            time.sleep(interval_seconds)
        else:
            time.sleep(min(interval_seconds, 0.01))
    return cycles


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile ATR YAML into native ACS manifests"
    )
    parser.add_argument("atr_dir", type=Path)
    parser.add_argument("--out", type=Path, default=Path("./atr-policies"))
    parser.add_argument("--category", action="append", default=None)
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_RANK),
        default=None,
    )
    parser.add_argument("--id-prefix", default=None)
    parser.add_argument("--strict-regex", action="store_true")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--watch-interval", type=float, default=2.0)
    return parser


def _validate_cli_paths(atr_dir: Path, out_dir: Path) -> str | None:
    if not atr_dir.exists():
        return f"ATR rules directory does not exist: {atr_dir}"
    if not atr_dir.is_dir():
        return f"ATR rules path is not a directory: {atr_dir}"
    try:
        out_dir.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"Output directory parent is not writable: {exc}"
    return None


def cmd_atr_import(args: argparse.Namespace) -> int:
    error = _validate_cli_paths(args.atr_dir, args.out)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    kwargs = {
        "categories": set(args.category) if args.category else None,
        "min_severity": args.min_severity,
        "id_prefix": args.id_prefix,
        "strict_regex": args.strict_regex,
    }
    try:
        result = compile_per_category(args.atr_dir, args.out, **kwargs)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.manifest is not None:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            json.dumps(result, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    print(
        f"[atr-import] {result['total_compiled_rules']} patterns across "
        f"{len(result['categories'])} categories",
        file=sys.stderr,
    )
    if args.watch:
        try:
            watch_and_recompile(
                args.atr_dir,
                args.out,
                interval_seconds=args.watch_interval,
                **kwargs,
            )
        except KeyboardInterrupt:
            return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    return cmd_atr_import(_build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())

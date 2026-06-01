from __future__ import annotations

import argparse
import sys
import json
import os
from pathlib import Path
from typing import Any

import yaml

from .engine import GenerationEngine, GenerationError
from .init_flow import main as init_main
from .llm import OpenAICompatibleLanguageModel


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "init":
        return init_main(argv[1:])
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        prompt = _prompt(args)
        inventory = _tool_inventory(args)
        model = OpenAICompatibleLanguageModel(
            api_base=args.api_base, api_key=args.api_key, model=args.model, api_version=args.api_version
        )
        result = GenerationEngine(model).generate(
            prompt=prompt,
            out_dir=Path(args.out),
            tool_inventory=inventory,
            strict=args.strict,
        )
    except (OSError, ValueError, GenerationError, RuntimeError) as exc:
        print(f"acs-generate failed: {exc}")
        return 1
    print(f"Generated ACS artifacts for `{result.slug}` in {args.out}")
    if result.warnings:
        print("Warnings: " + "; ".join(result.warnings))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate ACS manifest and Rego policy artifacts from guardrail prose. Use `acs-generate init` for guided setup.")
    prompt = parser.add_mutually_exclusive_group(required=True)
    prompt.add_argument("--prompt", help="Natural-language guardrail prompt")
    prompt.add_argument("--prompt-file", help="File containing the natural-language guardrail prompt")
    parser.add_argument("--tool", action="append", default=[], help="Tool inventory entry as name:clearance1,clearance2")
    parser.add_argument("--tools-file", help="JSON or YAML object mapping tool names to tool configs")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--strict", action="store_true", help="Fail if optional validators such as opa are unavailable")
    parser.add_argument("--api-base", default=os.getenv("ACS_GENERATOR_API_BASE"), help="OpenAI-compatible API base URL")
    parser.add_argument("--api-key", default=os.getenv("ACS_GENERATOR_API_KEY"), help="OpenAI-compatible API key")
    parser.add_argument("--model", default=os.getenv("ACS_GENERATOR_MODEL"), help="Provider model name")
    parser.add_argument(
        "--api-version",
        default=os.getenv("ACS_GENERATOR_API_VERSION"),
        help="API version for Azure OpenAI endpoints (enables api-key auth)",
    )
    return parser


def _prompt(args: argparse.Namespace) -> str:
    if args.prompt_file:
        return Path(args.prompt_file).read_text(encoding="utf-8")
    return args.prompt


def _tool_inventory(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    if args.tools_file:
        with Path(args.tools_file).open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) if not args.tools_file.endswith(".json") else json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError("--tools-file must contain a mapping")
        inventory.update({str(name): dict(config or {}) for name, config in loaded.items()})
    for entry in args.tool:
        name, sep, clearances = entry.partition(":")
        if not sep or not name:
            raise ValueError("--tool must use name:clearance1,clearance2")
        labels = [item for item in (part.strip() for part in clearances.split(",")) if item]
        inventory[name] = {"type": "Tool", "id": name, "clearance": labels, "security_labels": labels}
    return inventory


if __name__ == "__main__":
    raise SystemExit(main())

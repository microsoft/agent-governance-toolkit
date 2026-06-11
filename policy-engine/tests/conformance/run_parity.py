#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONF = REPO / "tests" / "conformance"
SDKS = ("rust", "python", "node", "dotnet")


def load_cases() -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((CONF / "cases").glob("*.json"))]


def command_for(sdk: str, output: Path) -> list[str] | None:
    if sdk == "rust":
        return [str(CONF / "run_rust.sh")]
    if sdk == "python":
        return [sys.executable, str(CONF / "run_python.py"), "--output", str(output)]
    if sdk == "node":
        return ["node", str(CONF / "run_node.mjs"), "--output", str(output)] if shutil.which("node") else None
    if sdk == "dotnet":
        return [str(CONF / "run_dotnet.sh")] if shutil.which("dotnet") else None
    raise ValueError(sdk)


def run_sdk(sdk: str, output: Path) -> None:
    command = command_for(sdk, output)
    if command is None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"sdk": sdk, "results": []}, indent=2) + "\n", encoding="utf-8")
        print(f"{sdk} skip runtime unavailable")
        return
    env = None
    if sdk in {"rust", "dotnet"}:
        env = {**dict(), **__import__("os").environ, "ACS_CONFORMANCE_RESULTS": str(output)}
    subprocess.run(command, cwd=REPO, check=True, env=env)


def load_report(path: Path, sdk: str) -> dict[str, dict]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("sdk") != sdk:
        raise SystemExit(f"{path} reports sdk {payload.get('sdk')!r}")
    return {item["case"]: item for item in payload.get("results", [])}


def classify(case: dict, sdk: str, result: dict | None) -> tuple[bool, str]:
    support = case.get("sdk_support", {}).get(sdk, "required")
    status = "missing" if result is None else result.get("status", "missing")
    if support == "skip":
        return True, "skip"
    if status == "pass":
        return True, "pass"
    if support == "optional" and status in {"skip", "missing"}:
        return True, "optional"
    return False, status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default=str(CONF / "results"))
    parser.add_argument("--sdk", action="append", choices=SDKS)
    parser.add_argument("--no-run", action="store_true")
    args = parser.parse_args()

    sdks = tuple(args.sdk) if args.sdk else SDKS
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    if not args.no_run:
        for sdk in sdks:
            run_sdk(sdk, results_dir / f"{sdk}.json")

    reports = {sdk: load_report(results_dir / f"{sdk}.json", sdk) for sdk in sdks}
    failures = []
    for case in load_cases():
        row = [case["id"]]
        for sdk in sdks:
            ok, label = classify(case, sdk, reports[sdk].get(case["id"]))
            row.append(f"{sdk}={label}")
            if not ok:
                failures.append(f"{case['id']} {sdk} {label}")
        print(" ".join(row))
    if failures:
        print("parity failures")
        for failure in failures:
            print(failure)
        return 1
    print("parity PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

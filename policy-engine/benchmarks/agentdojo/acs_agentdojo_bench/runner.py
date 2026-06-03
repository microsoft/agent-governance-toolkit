from __future__ import annotations

import argparse
import csv
import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

DEFAULT_BENCHMARK_VERSION = "v1.2.2"
DEFAULT_SUITE = "banking"
DEFAULT_USER_TASKS = ["user_task_0", "user_task_1", "user_task_2"]
DEFAULT_INJECTION_TASKS = ["injection_task_0", "injection_task_1", "injection_task_2"]
DEFAULT_ATTACK = "important_instructions"
DEFAULT_MODEL = "gpt-4o-mini"
TRUTHY = {"1", "true", "yes", "on"}
HARNESS_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = HARNESS_DIR / "results"


@dataclass(frozen=True)
class RunSummary:
    mode: str
    suite: str
    llm: str
    model: str
    attack: str
    benign_utility: float
    attacked_utility: float
    attack_success_rate: float
    benign_cases: int
    security_cases: int
    csv_path: Path | None


def skip_reason_for_environment(llm: str = "openai") -> str | None:
    if os.environ.get("ACS_AGENTDOJO_ENABLE", "").lower() not in TRUTHY:
        return "ACS_AGENTDOJO_ENABLE is not set"
    if llm == "openai" and not (
        os.environ.get("OPENAI_API_KEY")
        or (os.environ.get("AZURE_OPENAI_API_KEY") and os.environ.get("AZURE_OPENAI_ENDPOINT"))
    ):
        return "OpenAI or Azure OpenAI credentials are not set"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    reason = skip_reason_for_environment(args.llm)
    if reason:
        print(f"SKIP agentdojo benchmark. {reason}.")
        return 0
    try:
        importlib.import_module("agentdojo")
    except ImportError as exc:
        print(f"SKIP agentdojo benchmark. agentdojo is not installed. {exc}.")
        return 0
    modes = ["baseline", "acs"] if args.mode == "both" else [args.mode]
    if "acs" in modes:
        acs_reason = acs_unavailable_reason()
        if acs_reason:
            print(f"SKIP agentdojo benchmark. {acs_reason}.")
            return 0
    summaries = [run_mode(args, mode) for mode in modes]
    print_results_table(summaries)
    return 0


def acs_unavailable_reason() -> str | None:
    try:
        from .policy import make_control

        make_control()
    except ImportError as exc:
        return f"ACS Python SDK is unavailable: {exc}"
    except Exception as exc:
        return f"ACS runtime could not load the benchmark manifest: {exc}"
    return None


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ACS AgentDojo benchmark harness")
    parser.add_argument("--suite", default=DEFAULT_SUITE, choices=["banking"])
    parser.add_argument("--benchmark-version", default=DEFAULT_BENCHMARK_VERSION)
    parser.add_argument("--mode", default="both", choices=["baseline", "acs", "both"])
    parser.add_argument("--llm", default="openai", choices=["openai", "scripted"])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--attack", default=DEFAULT_ATTACK)
    parser.add_argument("--user-task", action="append", dest="user_tasks")
    parser.add_argument("--injection-task", action="append", dest="injection_tasks")
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--no-write", action="store_true")
    return parser.parse_args(argv)


def run_mode(args: argparse.Namespace, mode: str) -> RunSummary:
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite

    from .pipeline import ScriptedLLM, build_pipeline

    suite = get_suite(args.benchmark_version, args.suite)
    llm_element = build_llm_element(args.llm, suite, args.model)
    pipeline_name = f"acs-{mode}-{model_tag(args.llm, args.model)}-{args.suite}-{args.attack}-v1"
    pipeline = build_pipeline(suite, mode, llm_element, pipeline_name=pipeline_name)
    attack = load_attack(args.attack, suite, pipeline)
    logdir = None if args.no_write else _mode_dir(args.output_dir, mode)
    with OutputLogger(str(logdir) if logdir else None):
        benign = benchmark_suite_without_injections(
            pipeline,
            suite,
            logdir=logdir,
            force_rerun=True,
            user_tasks=args.user_tasks or DEFAULT_USER_TASKS,
            benchmark_version=args.benchmark_version,
        )
        attacked = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack=attack,
            logdir=logdir,
            force_rerun=True,
            user_tasks=args.user_tasks or DEFAULT_USER_TASKS,
            injection_tasks=args.injection_tasks or DEFAULT_INJECTION_TASKS,
            verbose=False,
            benchmark_version=args.benchmark_version,
        )
    benign_utility = {str(key): bool(value) for key, value in benign["utility_results"].items()}
    attacked_utility = {str(key): bool(value) for key, value in attacked["utility_results"].items()}
    attacked_security = {str(key): bool(value) for key, value in attacked["security_results"].items()}
    csv_path = None if args.no_write else write_csv(args.output_dir, mode, benign_utility, attacked_utility, attacked_security)
    return RunSummary(
        mode=mode,
        suite=args.suite,
        llm=args.llm,
        model=args.model,
        attack=args.attack,
        benign_utility=rate(benign_utility.values()),
        attacked_utility=rate(attacked_utility.values()),
        attack_success_rate=rate(attacked_security.values()),
        benign_cases=len(benign_utility),
        security_cases=len(attacked_security),
        csv_path=csv_path,
    )


def build_llm_element(llm: str, suite: Any, model: str) -> Any:
    if llm == "scripted":
        from .pipeline import ScriptedLLM

        return ScriptedLLM(suite)
    if llm == "openai":
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        openai_key = os.environ.get("OPENAI_API_KEY")
        azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        azure_key = os.environ.get("AZURE_OPENAI_API_KEY")
        if not openai_key and azure_endpoint and azure_key:
            from openai import AzureOpenAI

            deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT") or model
            client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=azure_key,
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION") or "2024-12-01-preview",
            )
            return OpenAILLM(client, deployment)
        from openai import OpenAI

        return OpenAILLM(OpenAI(), model)
    raise ValueError(f"Unsupported llm {llm}")


def model_tag(llm: str, model: str) -> str:
    if llm == "scripted":
        return "local"
    if llm == "openai" and not os.environ.get("OPENAI_API_KEY") and os.environ.get("AZURE_OPENAI_API_KEY"):
        return "gpt-4o-mini-2024-07-18"
    return model


def print_results_table(summaries: Iterable[RunSummary]) -> None:
    rows = list(summaries)
    headers = ["mode", "suite", "llm", "model", "attack", "benign", "attacked", "ASR", "n", "csv"]
    table = [headers]
    for summary in rows:
        table.append(
            [
                summary.mode,
                summary.suite,
                summary.llm,
                summary.model,
                summary.attack,
                f"{summary.benign_utility:.3f}",
                f"{summary.attacked_utility:.3f}",
                f"{summary.attack_success_rate:.3f}",
                str(summary.security_cases),
                str(summary.csv_path or ""),
            ]
        )
    widths = [max(len(row[index]) for row in table) for index in range(len(headers))]
    for index, row in enumerate(table):
        print("  ".join(value.ljust(widths[column]) for column, value in enumerate(row)))
        if index == 0:
            print("  ".join("-" * width for width in widths))


def rate(values: Iterable[bool]) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(1 for item in items if item) / float(len(items))


def _mode_dir(output_dir: Path, mode: str) -> Path:
    path = output_dir / mode
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_csv(
    output_dir: Path,
    mode: str,
    benign_utility: dict[str, bool],
    attacked_utility: dict[str, bool],
    attacked_security: dict[str, bool],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"banking-{mode}-summary.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "passed", "total", "rate"])
        write_metric(writer, "benign_utility", benign_utility.values())
        write_metric(writer, "attacked_utility", attacked_utility.values())
        write_metric(writer, "attack_success", attacked_security.values())
    return path


def write_metric(writer: Any, name: str, values: Iterable[bool]) -> None:
    items = list(values)
    passed = sum(1 for item in items if item)
    writer.writerow([name, passed, len(items), f"{rate(items):.6f}"])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

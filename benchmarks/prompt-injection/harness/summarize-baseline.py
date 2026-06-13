#!/usr/bin/env python3
"""Summarize AGT Rust prompt-injection baseline counts and rates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


Z95 = 1.959963984540054
BASE_RATE_RATIOS = (100, 1000)


def wilson(successes: int, total: int, z: float = Z95) -> dict:
    if total == 0:
        return {"estimate": None, "lower": None, "upper": None, "successes": successes, "total": total}
    phat = successes / total
    denom = 1 + (z * z) / total
    centre = phat + (z * z) / (2 * total)
    margin = z * ((phat * (1 - phat) + (z * z) / (4 * total)) / total) ** 0.5
    return {
        "estimate": phat,
        "lower": (centre - margin) / denom,
        "upper": (centre + margin) / denom,
        "successes": successes,
        "total": total,
    }


def base_rate_precision(recall: float, false_positive_rate: float, benign_per_attack: int) -> float | None:
    attack_prevalence = 1 / (benign_per_attack + 1)
    true_positive_mass = recall * attack_prevalence
    false_positive_mass = false_positive_rate * (1 - attack_prevalence)
    denom = true_positive_mass + false_positive_mass
    if denom == 0:
        return None
    return true_positive_mass / denom


def rate(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return value / total


def build_metrics(summary: dict) -> dict:
    if summary.get("raw_text_in_output") is not False:
        raise SystemExit("baseline summary must be metadata-only with raw_text_in_output=false")

    overall = summary["overall"]
    attacks = int(overall["attacks"])
    attacks_caught = int(overall["attacks_caught"])
    benign = int(overall["benign"])
    benign_flagged = int(overall["benign_flagged"])
    recall = rate(attacks_caught, attacks)
    fp_rate = rate(benign_flagged, benign)

    return {
        "source_summary": summary.get("corpus"),
        "detector": summary.get("detector"),
        "processed": summary.get("processed"),
        "raw_text_in_output": summary.get("raw_text_in_output"),
        "overall": {
            "attacks": attacks,
            "attacks_caught": attacks_caught,
            "attack_recall_wilson_95": wilson(attacks_caught, attacks),
            "benign": benign,
            "benign_flagged": benign_flagged,
            "benign_fp_rate_wilson_95": wilson(benign_flagged, benign),
            "fp_per_1k_benign": fp_rate * 1000,
            "base_rate_precision": {
                f"1_attack_per_{ratio}_benign": base_rate_precision(recall, fp_rate, ratio)
                for ratio in BASE_RATE_RATIOS
            },
        },
        "by_bypass_class": {
            key: {
                "attack_recall_wilson_95": wilson(int(value["attacks_caught"]), int(value["attacks"])),
                "benign_fp_rate_wilson_95": wilson(int(value["benign_flagged"]), int(value["benign"])),
                "fp_per_1k_benign": rate(int(value["benign_flagged"]), int(value["benign"])) * 1000
                if int(value["benign"])
                else None,
            }
            for key, value in summary.get("by_bypass_class", {}).items()
        },
        "by_benign_subclass": {
            key: {
                "benign": int(value["benign"]),
                "benign_flagged": int(value["benign_flagged"]),
                "benign_fp_rate_wilson_95": wilson(int(value["benign_flagged"]), int(value["benign"])),
                "fp_per_1k_benign": rate(int(value["benign_flagged"]), int(value["benign"])) * 1000
                if int(value["benign"])
                else None,
            }
            for key, value in summary.get("by_benign_subclass", {}).items()
            if int(value.get("benign", 0)) > 0
        },
    }


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("summary", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    metrics = build_metrics(summary)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics["overall"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

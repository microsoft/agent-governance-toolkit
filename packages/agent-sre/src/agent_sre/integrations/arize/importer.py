# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Evaluation Importer — import Arize/Phoenix evaluations as SLI data points.

When Phoenix or Arize runs evaluations (e.g. hallucination detection,
relevance scoring), this importer converts those results into Agent-SRE
SLI values that feed into SLO calculations.

No Arize/Phoenix dependency — accepts plain dicts matching their eval format.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvaluationRecord:
    """A single evaluation result from Arize/Phoenix."""

    eval_name: str
    label: str = ""  # e.g. "hallucinated", "correct", "relevant"
    score: float = 0.0  # 0.0 to 1.0
    explanation: str = ""
    trace_id: str = ""
    span_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "eval_name": self.eval_name,
            "label": self.label,
            "score": self.score,
            "explanation": self.explanation,
            "trace_id": self.trace_id,
        }


# Map Phoenix eval names to Agent-SRE SLI types
_EVAL_TO_SLI_MAP = {
    "hallucination": "hallucination_rate",
    "Hallucination": "hallucination_rate",
    "relevance": "task_success_rate",
    "Relevance": "task_success_rate",
    "correctness": "task_success_rate",
    "Correctness": "task_success_rate",
    "toxicity": "policy_compliance",
    "Toxicity": "policy_compliance",
    "qa_correctness": "task_success_rate",
    "QA Correctness": "task_success_rate",
}


class EvaluationImporter:
    """
    Import Arize/Phoenix evaluations and convert to SLI-compatible values.

    Usage:
        importer = EvaluationImporter()

        # Import a Phoenix eval
        importer.import_evaluation({
            "eval_name": "hallucination",
            "label": "hallucinated",
            "score": 0.85,
            "trace_id": "abc123",
        })

        # Get SLI-ready values
        values = importer.get_sli_values()
        # {"hallucination_rate": [0.85, ...], "task_success_rate": [...]}
    """

    def __init__(self) -> None:
        self._records: list[EvaluationRecord] = []

    def import_evaluation(self, data: dict[str, Any]) -> EvaluationRecord:
        """
        Import a single evaluation result.

        Accepts Phoenix/Arize evaluation format:
        - eval_name: Name of the evaluation (e.g. "hallucination")
        - label: Categorical label (e.g. "hallucinated", "correct")
        - score: Numeric score 0.0-1.0
        - trace_id: Associated trace ID
        """
        record = EvaluationRecord(
            eval_name=data.get("eval_name", ""),
            label=data.get("label", ""),
            score=data.get("score", 0.0),
            explanation=data.get("explanation", ""),
            trace_id=data.get("trace_id", ""),
            span_id=data.get("span_id", ""),
            metadata=data.get("metadata", {}),
        )
        self._records.append(record)
        return record

    def import_batch(self, evaluations: list[dict[str, Any]]) -> list[EvaluationRecord]:
        """Import a batch of evaluations."""
        return [self.import_evaluation(e) for e in evaluations]

    def get_sli_values(self) -> dict[str, list[float]]:
        """
        Convert imported evaluations to SLI-compatible values.

        Returns dict mapping SLI type names to lists of float values.
        """
        sli_values: dict[str, list[float]] = {}
        for record in self._records:
            sli_type = _EVAL_TO_SLI_MAP.get(record.eval_name)
            if sli_type:
                sli_values.setdefault(sli_type, []).append(record.score)
        return sli_values

    def get_records(self, eval_name: str | None = None) -> list[EvaluationRecord]:
        """Get imported records, optionally filtered by eval name."""
        if eval_name:
            return [r for r in self._records if r.eval_name == eval_name]
        return list(self._records)

    def get_stats(self) -> dict[str, Any]:
        by_eval: dict[str, int] = {}
        for r in self._records:
            by_eval[r.eval_name] = by_eval.get(r.eval_name, 0) + 1
        return {
            "total_evaluations": len(self._records),
            "by_eval_name": by_eval,
            "mapped_sli_types": list(set(
                _EVAL_TO_SLI_MAP.get(r.eval_name, "unmapped")
                for r in self._records
            )),
        }

    def clear(self) -> None:
        self._records.clear()

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Benchmark Suite

Framework for benchmarking single-model vs multi-model verification accuracy.
This creates the infrastructure for benchmarks - actual results require running
with real LLM API calls.

Usage:
    python -m cmvk.benchmarks.run --models gpt-4,claude-sonnet-4,gemini-pro
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

import numpy as np


class TaskCategory(Enum):
    """Categories of benchmark tasks."""
    FACTUAL = "factual"           # Verifiable facts
    MATHEMATICAL = "mathematical"  # Numeric calculations
    REASONING = "reasoning"        # Logic and inference
    EXTRACTION = "extraction"      # Information extraction


@dataclass
class BenchmarkTask:
    """A single benchmark task."""
    id: str
    category: TaskCategory
    prompt: str
    ground_truth: Any
    difficulty: str = "medium"  # easy, medium, hard
    metadata: dict = field(default_factory=dict)


@dataclass
class ModelResponse:
    """Response from a single model."""
    model_name: str
    response: Any
    latency_ms: float
    raw_output: str = ""


@dataclass
class VerificationResult:
    """Result of verifying a task."""
    task_id: str
    is_correct: bool
    confidence: float
    responses: list[ModelResponse]
    consensus_method: str
    drift_score: float = 0.0
    details: dict = field(default_factory=dict)


@dataclass
class BenchmarkResults:
    """Aggregate benchmark results."""
    total_tasks: int
    correct: int
    accuracy: float
    avg_latency_ms: float
    by_category: dict[str, dict]
    by_difficulty: dict[str, dict]
    timestamp: str
    config: dict


class ConsensusMethod(Enum):
    """Methods for reaching consensus across models."""
    MAJORITY_VOTE = "majority_vote"
    UNANIMOUS = "unanimous"
    WEIGHTED = "weighted"
    DRIFT_THRESHOLD = "drift_threshold"


class CMVKBenchmark:
    """
    Benchmark framework for CMVK verification.
    
    This class provides infrastructure for running benchmarks.
    Actual model calls must be provided via the `model_fn` parameter.
    """
    
    def __init__(
        self,
        models: list[str],
        model_fn: Optional[Callable[[str, str], str]] = None,
        consensus_method: ConsensusMethod = ConsensusMethod.DRIFT_THRESHOLD,
        drift_threshold: float = 0.15
    ):
        """
        Initialize benchmark.
        
        Args:
            models: List of model names to use
            model_fn: Function(model_name, prompt) -> response
                     If None, uses mock responses for testing
            consensus_method: How to combine model responses
            drift_threshold: Threshold for drift-based consensus
        """
        self.models = models
        self.model_fn = model_fn or self._mock_model_fn
        self.consensus_method = consensus_method
        self.drift_threshold = drift_threshold
        self.results: list[VerificationResult] = []
    
    def _mock_model_fn(self, model_name: str, prompt: str) -> str:
        """Mock model function for testing the framework."""
        # Return deterministic mock response based on prompt hash
        return f"Mock response from {model_name} for prompt hash {hash(prompt) % 1000}"
    
    def load_tasks(self, path: Path) -> list[BenchmarkTask]:
        """Load benchmark tasks from JSON file."""
        with open(path) as f:
            data = json.load(f)
        
        return [
            BenchmarkTask(
                id=t["id"],
                category=TaskCategory(t["category"]),
                prompt=t["prompt"],
                ground_truth=t["ground_truth"],
                difficulty=t.get("difficulty", "medium"),
                metadata=t.get("metadata", {})
            )
            for t in data["tasks"]
        ]
    
    def run_single_model(self, tasks: list[BenchmarkTask], model: str) -> list[VerificationResult]:
        """Run benchmark with a single model."""
        results = []
        
        for task in tasks:
            start = time.perf_counter()
            response = self.model_fn(model, task.prompt)
            latency = (time.perf_counter() - start) * 1000
            
            model_response = ModelResponse(
                model_name=model,
                response=response,
                latency_ms=latency,
                raw_output=response
            )
            
            is_correct = self._check_correctness(response, task.ground_truth)
            
            results.append(VerificationResult(
                task_id=task.id,
                is_correct=is_correct,
                confidence=1.0 if is_correct else 0.0,
                responses=[model_response],
                consensus_method="single_model"
            ))
        
        return results
    
    def run_multi_model(self, tasks: list[BenchmarkTask]) -> list[VerificationResult]:
        """Run benchmark with multiple models using CMVK consensus."""
        results = []
        
        for task in tasks:
            responses = []
            
            # Get response from each model
            for model in self.models:
                start = time.perf_counter()
                response = self.model_fn(model, task.prompt)
                latency = (time.perf_counter() - start) * 1000
                
                responses.append(ModelResponse(
                    model_name=model,
                    response=response,
                    latency_ms=latency,
                    raw_output=response
                ))
            
            # Apply consensus method
            consensus_result = self._apply_consensus(responses, task.ground_truth)
            
            results.append(VerificationResult(
                task_id=task.id,
                is_correct=consensus_result["is_correct"],
                confidence=consensus_result["confidence"],
                responses=responses,
                consensus_method=self.consensus_method.value,
                drift_score=consensus_result.get("drift_score", 0.0),
                details=consensus_result.get("details", {})
            ))
        
        return results
    
    def _apply_consensus(self, responses: list[ModelResponse], ground_truth: Any) -> dict:
        """
        Apply consensus method to multiple model responses.
        
        This is where the CMVK algorithm is applied.
        """
        if self.consensus_method == ConsensusMethod.MAJORITY_VOTE:
            return self._majority_vote_consensus(responses, ground_truth)
        elif self.consensus_method == ConsensusMethod.UNANIMOUS:
            return self._unanimous_consensus(responses, ground_truth)
        elif self.consensus_method == ConsensusMethod.DRIFT_THRESHOLD:
            return self._drift_consensus(responses, ground_truth)
        else:
            return self._majority_vote_consensus(responses, ground_truth)
    
    def _majority_vote_consensus(self, responses: list[ModelResponse], ground_truth: Any) -> dict:
        """Simple majority voting."""
        correct_count = sum(
            1 for r in responses 
            if self._check_correctness(r.response, ground_truth)
        )
        
        majority = correct_count > len(responses) / 2
        confidence = correct_count / len(responses)
        
        return {
            "is_correct": majority,
            "confidence": confidence,
            "details": {"correct_count": correct_count, "total": len(responses)}
        }
    
    def _unanimous_consensus(self, responses: list[ModelResponse], ground_truth: Any) -> dict:
        """Require all models to agree."""
        all_correct = all(
            self._check_correctness(r.response, ground_truth) 
            for r in responses
        )
        
        return {
            "is_correct": all_correct,
            "confidence": 1.0 if all_correct else 0.0,
            "details": {"unanimous": all_correct}
        }
    
    def _drift_consensus(self, responses: list[ModelResponse], ground_truth: Any) -> dict:
        """
        CMVK drift-based consensus.
        
        Algorithm:
        1. Convert responses to vectors (embeddings or numeric)
        2. Calculate pairwise drift between all responses
        3. If max drift > threshold, responses disagree → flag for review
        4. If responses agree, check against ground truth
        """
        # Calculate drift between responses
        drift_scores = self._calculate_pairwise_drift(responses)
        max_drift = max(drift_scores) if drift_scores else 0.0
        avg_drift = np.mean(drift_scores) if drift_scores else 0.0
        
        # High drift = disagreement = low confidence
        if max_drift > self.drift_threshold:
            # Models disagree significantly
            return {
                "is_correct": False,  # Can't trust when models disagree
                "confidence": 1.0 - max_drift,
                "drift_score": max_drift,
                "details": {
                    "disagreement_detected": True,
                    "max_drift": max_drift,
                    "avg_drift": avg_drift,
                    "threshold": self.drift_threshold
                }
            }
        
        # Models agree - check correctness
        # Use first response as representative (they all agree)
        is_correct = self._check_correctness(responses[0].response, ground_truth)
        
        return {
            "is_correct": is_correct,
            "confidence": 1.0 - avg_drift,
            "drift_score": avg_drift,
            "details": {
                "disagreement_detected": False,
                "max_drift": max_drift,
                "avg_drift": avg_drift,
                "consensus_response": responses[0].response
            }
        }
    
    def _calculate_pairwise_drift(self, responses: list[ModelResponse]) -> list[float]:
        """Calculate drift between all pairs of responses."""
        drifts = []
        
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                drift = self._response_drift(
                    responses[i].response, 
                    responses[j].response
                )
                drifts.append(drift)
        
        return drifts
    
    def _response_drift(self, response_a: Any, response_b: Any) -> float:
        """
        Calculate drift between two responses.
        
        For numeric responses: normalized absolute difference
        For string responses: Levenshtein-based similarity
        For structured: recursive comparison
        """
        # Handle numeric
        if isinstance(response_a, (int, float)) and isinstance(response_b, (int, float)):
            max_val = max(abs(response_a), abs(response_b), 1)
            return abs(response_a - response_b) / max_val
        
        # Handle string
        if isinstance(response_a, str) and isinstance(response_b, str):
            return self._string_drift(response_a, response_b)
        
        # Handle lists/arrays
        if isinstance(response_a, (list, np.ndarray)) and isinstance(response_b, (list, np.ndarray)):
            a = np.array(response_a)
            b = np.array(response_b)
            if a.shape == b.shape:
                return float(np.linalg.norm(a - b) / (np.linalg.norm(a) + np.linalg.norm(b) + 1e-10))
        
        # Fallback: exact match
        return 0.0 if response_a == response_b else 1.0
    
    def _string_drift(self, a: str, b: str) -> float:
        """Calculate drift between strings using character-level comparison."""
        if a == b:
            return 0.0
        if not a or not b:
            return 1.0
        
        # Simple normalized edit distance approximation
        # (For production, use proper Levenshtein or embedding similarity)
        common = sum(1 for c in a if c in b)
        total = len(a) + len(b)
        similarity = (2 * common) / total if total > 0 else 0
        return 1.0 - similarity
    
    def _check_correctness(self, response: Any, ground_truth: Any) -> bool:
        """Check if response matches ground truth."""
        # Exact match
        if response == ground_truth:
            return True
        
        # Numeric tolerance
        if isinstance(response, (int, float)) and isinstance(ground_truth, (int, float)):
            return abs(response - ground_truth) < 0.01 * abs(ground_truth + 1e-10)
        
        # String containment (ground truth in response)
        if isinstance(response, str) and isinstance(ground_truth, str):
            return ground_truth.lower() in response.lower()
        
        return False
    
    def aggregate_results(self, results: list[VerificationResult], config: dict = None) -> BenchmarkResults:
        """Aggregate results into summary statistics."""
        correct = sum(1 for r in results if r.is_correct)
        total = len(results)
        
        # Group by category
        by_category = {}
        for r in results:
            # Would need task info to group properly
            pass
        
        # Calculate latency
        all_latencies = []
        for r in results:
            for resp in r.responses:
                all_latencies.append(resp.latency_ms)
        
        avg_latency = np.mean(all_latencies) if all_latencies else 0.0
        
        return BenchmarkResults(
            total_tasks=total,
            correct=correct,
            accuracy=correct / total if total > 0 else 0.0,
            avg_latency_ms=avg_latency,
            by_category={},
            by_difficulty={},
            timestamp=datetime.utcnow().isoformat(),
            config=config or {}
        )
    
    def save_results(self, results: BenchmarkResults, path: Path) -> None:
        """Save results to JSON file."""
        with open(path, "w") as f:
            json.dump({
                "total_tasks": results.total_tasks,
                "correct": results.correct,
                "accuracy": results.accuracy,
                "avg_latency_ms": results.avg_latency_ms,
                "by_category": results.by_category,
                "by_difficulty": results.by_difficulty,
                "timestamp": results.timestamp,
                "config": results.config
            }, f, indent=2)


def create_sample_tasks(n: int = 100) -> list[BenchmarkTask]:
    """Create sample benchmark tasks for testing."""
    tasks = []
    
    categories = list(TaskCategory)
    difficulties = ["easy", "medium", "hard"]
    
    for i in range(n):
        cat = categories[i % len(categories)]
        diff = difficulties[i % len(difficulties)]
        
        if cat == TaskCategory.FACTUAL:
            tasks.append(BenchmarkTask(
                id=f"factual_{i}",
                category=cat,
                prompt=f"What is the capital of country {i % 50}?",
                ground_truth=f"Capital_{i % 50}",
                difficulty=diff
            ))
        elif cat == TaskCategory.MATHEMATICAL:
            a, b = i * 7, i * 3
            tasks.append(BenchmarkTask(
                id=f"math_{i}",
                category=cat,
                prompt=f"What is {a} + {b}?",
                ground_truth=a + b,
                difficulty=diff
            ))
        elif cat == TaskCategory.REASONING:
            tasks.append(BenchmarkTask(
                id=f"reasoning_{i}",
                category=cat,
                prompt=f"If A implies B, and A is true, what can we conclude about B?",
                ground_truth="B is true",
                difficulty=diff
            ))
        else:
            tasks.append(BenchmarkTask(
                id=f"extraction_{i}",
                category=cat,
                prompt=f"Extract the number from: 'There are {i * 5} items'",
                ground_truth=i * 5,
                difficulty=diff
            ))
    
    return tasks


if __name__ == "__main__":
    # Demo: Run benchmark with mock data
    benchmark = CMVKBenchmark(
        models=["model_a", "model_b", "model_c"],
        consensus_method=ConsensusMethod.DRIFT_THRESHOLD,
        drift_threshold=0.15
    )
    
    tasks = create_sample_tasks(100)
    
    print("Running single-model benchmark...")
    single_results = benchmark.run_single_model(tasks, "model_a")
    single_summary = benchmark.aggregate_results(single_results, {"mode": "single", "model": "model_a"})
    print(f"Single model accuracy: {single_summary.accuracy:.2%}")
    
    print("\nRunning multi-model (CMVK) benchmark...")
    multi_results = benchmark.run_multi_model(tasks)
    multi_summary = benchmark.aggregate_results(multi_results, {"mode": "cmvk", "models": benchmark.models})
    print(f"CMVK accuracy: {multi_summary.accuracy:.2%}")
    
    print("\nNote: These are mock results. Run with real LLM APIs for actual benchmarks.")

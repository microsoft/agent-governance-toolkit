# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Evaluation Engineering Framework

This module implements the "New TDD" - Evaluation-Driven Development.
Instead of writing implementation code, engineers write:
1. Golden Datasets: Test cases with expected outputs
2. Scoring Rubrics: Multi-dimensional evaluation criteria
3. Evaluation Suites: Automated testing against the dataset

The key insight: In a probabilistic AI world, the "Source Code" is the 
Evaluation Suite that constrains the AI's behavior.
"""

import json
import os
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class ScoreType(Enum):
    """Types of scoring dimensions."""
    CORRECTNESS = "correctness"
    TONE = "tone"
    COMPLETENESS = "completeness"
    CLARITY = "clarity"
    SAFETY = "safety"
    EFFICIENCY = "efficiency"
    CUSTOM = "custom"


@dataclass
class EvaluationCase:
    """
    A single test case in the golden dataset.
    
    This is what replaces traditional "unit tests" in Eval-DD.
    Engineers write these instead of writing the implementation.
    """
    id: str
    input: str
    expected_output: Optional[str] = None
    expected_behavior: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    difficulty: str = "medium"  # easy, medium, hard, edge_case
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class ScoringCriteria:
    """
    A single dimension of evaluation with weights and thresholds.
    
    Example: "If the answer is correct but rude, score 5/10"
    """
    dimension: str  # e.g., "correctness", "tone", "safety"
    weight: float  # How much this dimension contributes to final score (0-1)
    description: str
    evaluator: Optional[Callable[[str, str, Any], float]] = None  # Custom evaluator function
    
    def evaluate(self, input_text: str, output_text: str, context: Any = None) -> float:
        """
        Evaluate this dimension.
        
        Args:
            input_text: The input given to the AI
            output_text: The AI's response
            context: Optional context (e.g., expected output)
            
        Returns:
            Score from 0.0 to 1.0 for this dimension
        """
        if self.evaluator:
            return self.evaluator(input_text, output_text, context)
        return 0.0


class ScoringRubric:
    """
    The Scoring Rubric - The most valuable code a Senior Engineer writes.
    
    This defines HOW to evaluate AI responses across multiple dimensions.
    Example: Correctness=40%, Tone=30%, Completeness=20%, Safety=10%
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.criteria: List[ScoringCriteria] = []
        self.pass_threshold = 0.9  # Default 90% to pass
    
    def add_criteria(self, 
                    dimension: str,
                    weight: float,
                    description: str,
                    evaluator: Optional[Callable[[str, str, Any], float]] = None) -> 'ScoringRubric':
        """
        Add a scoring dimension to the rubric.
        
        Args:
            dimension: Name of the dimension (e.g., "correctness", "tone")
            weight: Weight of this dimension (0-1), all weights should sum to 1
            description: Human-readable description of what this dimension measures
            evaluator: Optional custom function to evaluate this dimension
            
        Returns:
            self for method chaining
        """
        criteria = ScoringCriteria(
            dimension=dimension,
            weight=weight,
            description=description,
            evaluator=evaluator
        )
        self.criteria.append(criteria)
        return self
    
    def set_pass_threshold(self, threshold: float) -> 'ScoringRubric':
        """Set the minimum score to pass (0-1)."""
        self.pass_threshold = threshold
        return self
    
    def evaluate(self, input_text: str, output_text: str, context: Any = None) -> Dict[str, Any]:
        """
        Evaluate a response against all criteria.
        
        Returns:
            Dictionary with overall score, dimension scores, and pass/fail status
        """
        dimension_scores = {}
        weighted_sum = 0.0
        
        for criteria in self.criteria:
            score = criteria.evaluate(input_text, output_text, context)
            dimension_scores[criteria.dimension] = {
                "score": score,
                "weight": criteria.weight,
                "weighted_score": score * criteria.weight
            }
            weighted_sum += score * criteria.weight
        
        overall_score = weighted_sum
        passed = overall_score >= self.pass_threshold
        
        return {
            "overall_score": overall_score,
            "passed": passed,
            "threshold": self.pass_threshold,
            "dimension_scores": dimension_scores,
            "rubric_name": self.name
        }
    
    def validate_weights(self) -> bool:
        """Validate that weights sum to approximately 1.0."""
        total_weight = sum(c.weight for c in self.criteria)
        return abs(total_weight - 1.0) < 0.01


class EvaluationDataset:
    """
    The Golden Dataset - The "Source Code" of the AI system.
    
    This is what engineers write instead of implementation code.
    The dataset defines what "good" looks like through examples.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.cases: List[EvaluationCase] = []
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "author": "evaluation_engineer"
        }
    
    def add_case(self, 
                id: str,
                input: str,
                expected_output: Optional[str] = None,
                expected_behavior: Optional[str] = None,
                context: Optional[Dict[str, Any]] = None,
                tags: Optional[List[str]] = None,
                difficulty: str = "medium") -> 'EvaluationDataset':
        """
        Add a test case to the golden dataset.
        
        This is the primary way engineers "write code" in Eval-DD.
        """
        case = EvaluationCase(
            id=id,
            input=input,
            expected_output=expected_output,
            expected_behavior=expected_behavior,
            context=context,
            tags=tags or [],
            difficulty=difficulty
        )
        self.cases.append(case)
        return self
    
    def get_cases_by_tag(self, tag: str) -> List[EvaluationCase]:
        """Filter cases by tag."""
        return [case for case in self.cases if tag in case.tags]
    
    def get_cases_by_difficulty(self, difficulty: str) -> List[EvaluationCase]:
        """Filter cases by difficulty level."""
        return [case for case in self.cases if case.difficulty == difficulty]
    
    def save(self, filepath: str) -> None:
        """Save the dataset to a JSON file."""
        data = {
            "name": self.name,
            "description": self.description,
            "metadata": self.metadata,
            "cases": [case.to_dict() for case in self.cases]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def load(cls, filepath: str) -> 'EvaluationDataset':
        """Load a dataset from a JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        dataset = cls(data["name"], data["description"])
        dataset.metadata = data.get("metadata", dataset.metadata)
        
        for case_data in data.get("cases", []):
            dataset.cases.append(EvaluationCase(**case_data))
        
        return dataset
    
    def __len__(self) -> int:
        """Return number of cases in the dataset."""
        return len(self.cases)


@dataclass
class EvaluationResult:
    """Result of running a single evaluation case."""
    case_id: str
    input: str
    expected_output: Optional[str]
    actual_output: str
    scores: Dict[str, Any]
    passed: bool
    timestamp: str
    execution_time_ms: Optional[float] = None


class EvaluationRunner:
    """
    The Evaluation Runner - Executes the golden dataset against the AI.
    
    This replaces traditional "test runners" but for probabilistic systems.
    It runs the AI against the golden dataset and scores using the rubric.
    """
    
    def __init__(self, 
                dataset: EvaluationDataset,
                rubric: ScoringRubric,
                ai_function: Callable[[str], str]):
        """
        Initialize the evaluation runner.
        
        Args:
            dataset: The golden dataset to evaluate against
            rubric: The scoring rubric to use
            ai_function: The AI function to test (takes input string, returns output string)
        """
        self.dataset = dataset
        self.rubric = rubric
        self.ai_function = ai_function
        self.results: List[EvaluationResult] = []
    
    def run(self, verbose: bool = True) -> Dict[str, Any]:
        """
        Run the evaluation suite.
        
        This is like running "pytest" but for AI systems.
        Returns aggregate metrics and pass/fail status.
        """
        if verbose:
            print(f"\n{'='*70}")
            print(f"EVALUATION ENGINEERING: {self.dataset.name}")
            print(f"{'='*70}")
            print(f"Dataset: {len(self.dataset.cases)} cases")
            print(f"Rubric: {self.rubric.name}")
            print(f"Pass Threshold: {self.rubric.pass_threshold * 100}%")
            print(f"{'='*70}\n")
        
        self.results = []
        passed_count = 0
        failed_count = 0
        total_score = 0.0
        
        for i, case in enumerate(self.dataset.cases, 1):
            if verbose:
                print(f"[{i}/{len(self.dataset.cases)}] Testing: {case.id}")
                print(f"  Input: {case.input[:100]}...")
            
            # Execute AI function
            start_time = datetime.now()
            try:
                actual_output = self.ai_function(case.input)
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
            except Exception as e:
                actual_output = f"ERROR: {str(e)}"
                execution_time = 0
            
            # Score the output
            context = {
                "expected_output": case.expected_output,
                "expected_behavior": case.expected_behavior,
                "case_context": case.context
            }
            scores = self.rubric.evaluate(case.input, actual_output, context)
            
            # Record result
            result = EvaluationResult(
                case_id=case.id,
                input=case.input,
                expected_output=case.expected_output,
                actual_output=actual_output,
                scores=scores,
                passed=scores["passed"],
                timestamp=datetime.now().isoformat(),
                execution_time_ms=execution_time
            )
            self.results.append(result)
            
            if scores["passed"]:
                passed_count += 1
                status = "✓ PASS"
            else:
                failed_count += 1
                status = "✗ FAIL"
            
            total_score += scores["overall_score"]
            
            if verbose:
                print(f"  Output: {actual_output[:100]}...")
                print(f"  Score: {scores['overall_score']:.2f} - {status}")
                print()
        
        # Compute aggregate metrics
        total_cases = len(self.dataset.cases)
        pass_rate = passed_count / total_cases if total_cases > 0 else 0
        avg_score = total_score / total_cases if total_cases > 0 else 0
        
        summary = {
            "dataset_name": self.dataset.name,
            "total_cases": total_cases,
            "passed": passed_count,
            "failed": failed_count,
            "pass_rate": pass_rate,
            "average_score": avg_score,
            "threshold": self.rubric.pass_threshold,
            "overall_passed": pass_rate >= self.rubric.pass_threshold,
            "timestamp": datetime.now().isoformat()
        }
        
        if verbose:
            print(f"\n{'='*70}")
            print(f"EVALUATION SUMMARY")
            print(f"{'='*70}")
            print(f"Total Cases: {total_cases}")
            print(f"Passed: {passed_count} ({pass_rate*100:.1f}%)")
            print(f"Failed: {failed_count}")
            print(f"Average Score: {avg_score:.2f}")
            print(f"Required Threshold: {self.rubric.pass_threshold:.2f}")
            
            if summary["overall_passed"]:
                print(f"\n🎉 EVALUATION PASSED - AI meets requirements!")
            else:
                print(f"\n❌ EVALUATION FAILED - AI needs improvement")
            
            print(f"{'='*70}\n")
        
        return summary
    
    def get_failed_cases(self) -> List[EvaluationResult]:
        """Get all failed test cases for debugging."""
        return [r for r in self.results if not r.passed]
    
    def get_detailed_report(self) -> Dict[str, Any]:
        """Generate a detailed report of all results."""
        return {
            "summary": {
                "total": len(self.results),
                "passed": len([r for r in self.results if r.passed]),
                "failed": len([r for r in self.results if not r.passed])
            },
            "results": [
                {
                    "case_id": r.case_id,
                    "passed": r.passed,
                    "score": r.scores["overall_score"],
                    "input": r.input,
                    "actual_output": r.actual_output,
                    "expected_output": r.expected_output
                }
                for r in self.results
            ]
        }
    
    def save_results(self, filepath: str) -> None:
        """Save evaluation results to a JSON file."""
        report = self.get_detailed_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)


# Common evaluator functions that can be reused across rubrics

def exact_match_evaluator(input_text: str, output_text: str, context: Any) -> float:
    """Simple exact match evaluator."""
    expected = context.get("expected_output", "") if isinstance(context, dict) else ""
    if not expected:
        return 0.5  # No expected output to compare
    return 1.0 if output_text.strip() == expected.strip() else 0.0


def contains_keywords_evaluator(keywords: List[str]) -> Callable:
    """Create an evaluator that checks if output contains required keywords."""
    def evaluator(input_text: str, output_text: str, context: Any) -> float:
        output_lower = output_text.lower()
        matches = sum(1 for kw in keywords if kw.lower() in output_lower)
        return matches / len(keywords) if keywords else 0.0
    return evaluator


def length_check_evaluator(min_length: int, max_length: int) -> Callable:
    """Create an evaluator that checks if output length is within range."""
    def evaluator(input_text: str, output_text: str, context: Any) -> float:
        length = len(output_text)
        if length < min_length:
            return length / min_length
        elif length > max_length:
            return max_length / length
        return 1.0
    return evaluator


def no_harmful_content_evaluator(harmful_keywords: List[str]) -> Callable:
    """Create an evaluator that penalizes harmful content."""
    def evaluator(input_text: str, output_text: str, context: Any) -> float:
        output_lower = output_text.lower()
        for keyword in harmful_keywords:
            if keyword.lower() in output_lower:
                return 0.0  # Immediate fail if harmful content detected
        return 1.0
    return evaluator

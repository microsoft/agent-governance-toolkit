# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the Evaluation Engineering framework.

Tests the core components without requiring API calls.
"""

import os
import json
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation_engineering import (
    EvaluationDataset,
    EvaluationCase,
    ScoringRubric,
    ScoringCriteria,
    EvaluationRunner,
    EvaluationResult,
    exact_match_evaluator,
    contains_keywords_evaluator,
    length_check_evaluator,
    no_harmful_content_evaluator
)


def test_evaluation_case():
    """Test EvaluationCase dataclass."""
    print("Testing EvaluationCase...")
    
    case = EvaluationCase(
        id="test_001",
        input="What is 2+2?",
        expected_output="4",
        tags=["math", "basic"],
        difficulty="easy"
    )
    
    assert case.id == "test_001"
    assert case.input == "What is 2+2?"
    assert case.expected_output == "4"
    assert "math" in case.tags
    assert case.difficulty == "easy"
    
    # Test to_dict
    case_dict = case.to_dict()
    assert isinstance(case_dict, dict)
    assert case_dict["id"] == "test_001"
    
    print("✓ EvaluationCase works correctly")


def test_evaluation_dataset():
    """Test EvaluationDataset class."""
    print("\nTesting EvaluationDataset...")
    
    # Create dataset
    dataset = EvaluationDataset(
        name="Test Dataset",
        description="A test dataset"
    )
    
    assert dataset.name == "Test Dataset"
    assert len(dataset) == 0
    
    # Add cases
    dataset.add_case(
        id="case_001",
        input="Test input 1",
        expected_output="Test output 1",
        tags=["test", "basic"]
    )
    
    dataset.add_case(
        id="case_002",
        input="Test input 2",
        expected_output="Test output 2",
        tags=["test", "advanced"],
        difficulty="hard"
    )
    
    assert len(dataset) == 2
    
    # Test filtering by tag
    basic_cases = dataset.get_cases_by_tag("basic")
    assert len(basic_cases) == 1
    assert basic_cases[0].id == "case_001"
    
    # Test filtering by difficulty
    hard_cases = dataset.get_cases_by_difficulty("hard")
    assert len(hard_cases) == 1
    assert hard_cases[0].id == "case_002"
    
    print("✓ EvaluationDataset works correctly")


def test_dataset_persistence():
    """Test saving and loading datasets."""
    print("\nTesting dataset persistence...")
    
    # Create a temporary file
    temp_file = os.path.join(tempfile.gettempdir(), 'test_dataset.json')
    
    try:
        # Create and save dataset
        dataset = EvaluationDataset("Test", "Test dataset")
        dataset.add_case(
            id="case_001",
            input="Input 1",
            expected_output="Output 1",
            tags=["test"]
        )
        
        dataset.save(temp_file)
        assert os.path.exists(temp_file)
        
        # Load dataset
        loaded_dataset = EvaluationDataset.load(temp_file)
        assert loaded_dataset.name == "Test"
        assert len(loaded_dataset) == 1
        assert loaded_dataset.cases[0].id == "case_001"
        
        print("✓ Dataset persistence works correctly")
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_scoring_rubric():
    """Test ScoringRubric class."""
    print("\nTesting ScoringRubric...")
    
    # Create rubric
    rubric = ScoringRubric(
        name="Test Rubric",
        description="A test rubric"
    )
    
    # Add criteria
    rubric.add_criteria(
        dimension="correctness",
        weight=0.7,
        description="Is it correct?",
        evaluator=exact_match_evaluator
    )
    
    rubric.add_criteria(
        dimension="clarity",
        weight=0.3,
        description="Is it clear?",
        evaluator=lambda i, o, c: 1.0 if len(o) < 100 else 0.5
    )
    
    assert len(rubric.criteria) == 2
    assert rubric.validate_weights()
    
    # Test evaluation
    result = rubric.evaluate(
        "test input",
        "test output",
        {"expected_output": "test output"}
    )
    
    assert "overall_score" in result
    assert "passed" in result
    assert "dimension_scores" in result
    assert "correctness" in result["dimension_scores"]
    assert "clarity" in result["dimension_scores"]
    
    print("✓ ScoringRubric works correctly")


def test_exact_match_evaluator():
    """Test exact match evaluator."""
    print("\nTesting exact_match_evaluator...")
    
    # Exact match
    score = exact_match_evaluator(
        "input",
        "expected output",
        {"expected_output": "expected output"}
    )
    assert score == 1.0
    
    # No match
    score = exact_match_evaluator(
        "input",
        "different output",
        {"expected_output": "expected output"}
    )
    assert score == 0.0
    
    # No expected output
    score = exact_match_evaluator(
        "input",
        "any output",
        {}
    )
    assert score == 0.5
    
    print("✓ exact_match_evaluator works correctly")


def test_contains_keywords_evaluator():
    """Test contains keywords evaluator."""
    print("\nTesting contains_keywords_evaluator...")
    
    evaluator = contains_keywords_evaluator(["hello", "world"])
    
    # All keywords present
    score = evaluator("input", "hello world", None)
    assert score == 1.0
    
    # One keyword present
    score = evaluator("input", "hello there", None)
    assert score == 0.5
    
    # No keywords present
    score = evaluator("input", "goodbye", None)
    assert score == 0.0
    
    print("✓ contains_keywords_evaluator works correctly")


def test_length_check_evaluator():
    """Test length check evaluator."""
    print("\nTesting length_check_evaluator...")
    
    evaluator = length_check_evaluator(min_length=10, max_length=50)
    
    # Perfect length
    score = evaluator("input", "This is a good length response", None)
    assert score == 1.0
    
    # Too short
    score = evaluator("input", "Short", None)
    assert score < 1.0
    
    # Too long
    score = evaluator("input", "x" * 100, None)
    assert score < 1.0
    
    print("✓ length_check_evaluator works correctly")


def test_no_harmful_content_evaluator():
    """Test harmful content evaluator."""
    print("\nTesting no_harmful_content_evaluator...")
    
    evaluator = no_harmful_content_evaluator(["badword", "harmful"])
    
    # Safe content
    score = evaluator("input", "This is safe content", None)
    assert score == 1.0
    
    # Harmful content
    score = evaluator("input", "This contains badword", None)
    assert score == 0.0
    
    print("✓ no_harmful_content_evaluator works correctly")


def test_evaluation_runner():
    """Test EvaluationRunner class."""
    print("\nTesting EvaluationRunner...")
    
    # Create a simple dataset
    dataset = EvaluationDataset("Test", "Test dataset")
    dataset.add_case(
        id="case_001",
        input="2+2",
        expected_output="4",
        tags=["math"]
    )
    dataset.add_case(
        id="case_002",
        input="3+3",
        expected_output="6",
        tags=["math"]
    )
    
    # Create a simple rubric
    rubric = ScoringRubric("Test Rubric", "Test")
    rubric.add_criteria(
        dimension="correctness",
        weight=1.0,
        description="Correctness",
        evaluator=exact_match_evaluator
    )
    rubric.set_pass_threshold(0.9)
    
    # Create a simple AI function that always returns "4"
    def simple_ai(input_text: str) -> str:
        if "2+2" in input_text:
            return "4"
        return "wrong"
    
    # Run evaluation
    runner = EvaluationRunner(dataset, rubric, simple_ai)
    summary = runner.run(verbose=False)
    
    assert summary["total_cases"] == 2
    assert summary["passed"] == 1  # Only 2+2 should pass
    assert summary["failed"] == 1  # 3+3 should fail
    assert summary["pass_rate"] == 0.5
    
    # Test get_failed_cases
    failed = runner.get_failed_cases()
    assert len(failed) == 1
    assert failed[0].case_id == "case_002"
    
    # Test get_detailed_report
    report = runner.get_detailed_report()
    assert "summary" in report
    assert "results" in report
    assert len(report["results"]) == 2
    
    print("✓ EvaluationRunner works correctly")


def test_evaluation_runner_with_perfect_score():
    """Test evaluation runner with AI that passes all tests."""
    print("\nTesting EvaluationRunner with perfect AI...")
    
    # Create dataset
    dataset = EvaluationDataset("Math", "Math tests")
    dataset.add_case(id="c1", input="2+2", expected_output="4")
    dataset.add_case(id="c2", input="3+3", expected_output="6")
    
    # Create rubric
    rubric = ScoringRubric("Math Rubric", "Test")
    rubric.add_criteria(
        dimension="correctness",
        weight=1.0,
        description="Correct",
        evaluator=exact_match_evaluator
    )
    rubric.set_pass_threshold(0.9)
    
    # Perfect AI
    def perfect_ai(input_text: str) -> str:
        if "2+2" in input_text:
            return "4"
        if "3+3" in input_text:
            return "6"
        return "0"
    
    runner = EvaluationRunner(dataset, rubric, perfect_ai)
    summary = runner.run(verbose=False)
    
    assert summary["passed"] == 2
    assert summary["failed"] == 0
    assert summary["pass_rate"] == 1.0
    assert summary["overall_passed"] == True
    
    print("✓ Perfect AI passes all tests")


def test_multi_dimensional_scoring():
    """Test multi-dimensional scoring rubric."""
    print("\nTesting multi-dimensional scoring...")
    
    # Create dataset
    dataset = EvaluationDataset("Customer Service", "CS tests")
    dataset.add_case(
        id="cs_001",
        input="Help me",
        expected_output="I'm happy to help you!",
        context={"requires_polite": True}
    )
    
    # Create rubric with multiple dimensions
    rubric = ScoringRubric("CS Rubric", "Multi-dimensional")
    
    # Correctness dimension
    def correctness_eval(i, o, c):
        expected = c.get("expected_output", "")
        return 1.0 if expected.lower() in o.lower() else 0.0
    
    # Tone dimension
    def tone_eval(i, o, c):
        polite_words = ["please", "thank", "happy", "help"]
        return 1.0 if any(word in o.lower() for word in polite_words) else 0.0
    
    rubric.add_criteria("correctness", 0.6, "Correct response", correctness_eval)
    rubric.add_criteria("tone", 0.4, "Polite tone", tone_eval)
    rubric.set_pass_threshold(0.8)
    
    # Test with response that is correct and polite
    def good_ai(input_text: str) -> str:
        return "I'm happy to help you!"
    
    runner = EvaluationRunner(dataset, rubric, good_ai)
    summary = runner.run(verbose=False)
    
    assert summary["passed"] == 1
    assert summary["average_score"] >= 0.8
    
    # Test with response that is correct but rude
    def rude_ai(input_text: str) -> str:
        return "I'm to help you!"  # Missing polite word
    
    runner2 = EvaluationRunner(dataset, rubric, rude_ai)
    summary2 = runner2.run(verbose=False)
    
    # Should score lower due to missing tone
    assert summary2["average_score"] < summary["average_score"]
    
    print("✓ Multi-dimensional scoring works correctly")


def test_save_results():
    """Test saving evaluation results."""
    print("\nTesting save_results...")
    
    # Create dataset and rubric
    dataset = EvaluationDataset("Test", "Test")
    dataset.add_case(id="c1", input="test", expected_output="result")
    
    rubric = ScoringRubric("Test", "Test")
    rubric.add_criteria("correctness", 1.0, "Test", exact_match_evaluator)
    
    # Run evaluation
    runner = EvaluationRunner(dataset, rubric, lambda x: "result")
    runner.run(verbose=False)
    
    # Save results
    temp_file = os.path.join(tempfile.gettempdir(), 'test_results.json')
    
    try:
        runner.save_results(temp_file)
        assert os.path.exists(temp_file)
        
        # Load and verify
        with open(temp_file, 'r') as f:
            results = json.load(f)
        
        assert "summary" in results
        assert "results" in results
        assert len(results["results"]) == 1
        
        print("✓ save_results works correctly")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def run_all_tests():
    """Run all tests."""
    print("="*70)
    print("TESTING EVALUATION ENGINEERING FRAMEWORK")
    print("="*70)
    
    test_evaluation_case()
    test_evaluation_dataset()
    test_dataset_persistence()
    test_scoring_rubric()
    test_exact_match_evaluator()
    test_contains_keywords_evaluator()
    test_length_check_evaluator()
    test_no_harmful_content_evaluator()
    test_evaluation_runner()
    test_evaluation_runner_with_perfect_score()
    test_multi_dimensional_scoring()
    test_save_results()
    
    print("\n" + "="*70)
    print("ALL TESTS PASSED ✓")
    print("="*70)


if __name__ == "__main__":
    run_all_tests()

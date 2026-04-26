# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Evaluation Engineering (The New TDD)

This demonstrates the shift from writing implementation to writing evaluations.

The Old World: "I write the code, then I write a unit test to prove it works."
The New World: "I write the evaluation suite, then let the AI iterate until it passes."

This is Eval-DD: Evaluation-Driven Development
"""

import os
import time
from typing import Dict, Any
from openai import OpenAI
from dotenv import load_dotenv

import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.evaluation_engineering import (
    EvaluationDataset,
    ScoringRubric,
    EvaluationRunner,
    exact_match_evaluator,
    contains_keywords_evaluator,
    no_harmful_content_evaluator,
    length_check_evaluator
)

# Load environment variables
load_dotenv()


def create_date_parsing_dataset() -> EvaluationDataset:
    """
    Create the golden dataset for date parsing.
    
    This is what a Senior Engineer writes instead of parseDate() implementation.
    25 tricky, malformed date strings with expected outputs.
    
    Note: The problem statement mentions "50 tricky date strings" as the concept.
    This demo includes 25 representative cases for practical demonstration.
    In production, you would enumerate 50+ edge cases.
    """
    dataset = EvaluationDataset(
        name="Date Parsing Golden Dataset",
        description="Tricky, malformed date strings that the AI must parse correctly"
    )
    
    # Add diverse, edge-case date formats
    test_cases = [
        ("parse_date_001", "2024-01-15", "2024-01-15", ["basic", "iso"]),
        ("parse_date_002", "01/15/2024", "2024-01-15", ["basic", "us_format"]),
        ("parse_date_003", "15/01/2024", "2024-01-15", ["basic", "eu_format"]),
        ("parse_date_004", "Jan 15, 2024", "2024-01-15", ["readable"]),
        ("parse_date_005", "January 15th, 2024", "2024-01-15", ["readable"]),
        ("parse_date_006", "15 Jan 2024", "2024-01-15", ["readable"]),
        ("parse_date_007", "2024/01/15", "2024-01-15", ["slash_format"]),
        ("parse_date_008", "20240115", "2024-01-15", ["compact"]),
        ("parse_date_009", "01-15-24", "2024-01-15", ["short_year"]),
        ("parse_date_010", "1/5/24", "2024-01-05", ["short_format", "edge_case"]),
        
        # Malformed and tricky cases
        ("parse_date_011", "2024.01.15", "2024-01-15", ["dot_separator", "edge_case"]),
        ("parse_date_012", "15-JAN-2024", "2024-01-15", ["uppercase", "edge_case"]),
        ("parse_date_013", "january 15 2024", "2024-01-15", ["lowercase", "edge_case"]),
        ("parse_date_014", "1st January 2024", "2024-01-01", ["ordinal"]),
        ("parse_date_015", "Dec 31, 23", "2023-12-31", ["short_year", "edge_case"]),
        
        # Ambiguous formats
        ("parse_date_016", "02/03/2024", "2024-02-03", ["ambiguous", "us_assumed"]),
        ("parse_date_017", "2024-1-5", "2024-01-05", ["no_padding"]),
        ("parse_date_018", "5-1-2024", "2024-01-05", ["short_format"]),
        
        # With extra text
        ("parse_date_019", "Date: 2024-01-15", "2024-01-15", ["with_prefix"]),
        ("parse_date_020", "Born on Jan 15, 2024", "2024-01-15", ["with_context"]),
        
        # Invalid/error cases
        ("parse_date_021", "2024-13-01", "ERROR", ["invalid", "bad_month"]),
        ("parse_date_022", "2024-02-30", "ERROR", ["invalid", "bad_day"]),
        ("parse_date_023", "not a date", "ERROR", ["invalid", "no_date"]),
        ("parse_date_024", "32/01/2024", "ERROR", ["invalid", "bad_day"]),
        ("parse_date_025", "", "ERROR", ["invalid", "empty"]),
    ]
    
    for case_id, input_str, expected, tags in test_cases:
        difficulty = "edge_case" if "edge_case" in tags or "invalid" in tags else "medium"
        dataset.add_case(
            id=case_id,
            input=f"Parse this date string into ISO format (YYYY-MM-DD): {input_str}",
            expected_output=expected,
            tags=tags,
            difficulty=difficulty
        )
    
    return dataset


def create_customer_service_dataset() -> EvaluationDataset:
    """
    Create a customer service response dataset.
    
    This tests not just correctness, but tone, empathy, and helpfulness.
    """
    dataset = EvaluationDataset(
        name="Customer Service Response Dataset",
        description="Evaluates AI responses for correctness, tone, and helpfulness"
    )
    
    test_cases = [
        {
            "id": "cs_001",
            "input": "My order hasn't arrived and it's been 2 weeks!",
            "expected_behavior": "Apologize, show empathy, offer to investigate",
            "tags": ["complaint", "empathy_required"]
        },
        {
            "id": "cs_002",
            "input": "How do I reset my password?",
            "expected_output": "Click 'Forgot Password' on the login page, then check your email for a reset link.",
            "tags": ["technical_support", "clear_instructions"]
        },
        {
            "id": "cs_003",
            "input": "Your product is garbage!",
            "expected_behavior": "Stay professional, acknowledge concern, offer solution",
            "tags": ["hostile", "professionalism_required"]
        },
        {
            "id": "cs_004",
            "input": "Can I get a refund?",
            "expected_behavior": "Explain refund policy clearly and offer to process if eligible",
            "tags": ["refund", "policy_knowledge"]
        },
        {
            "id": "cs_005",
            "input": "I love your service! How do I upgrade?",
            "expected_behavior": "Thank customer, provide clear upgrade steps",
            "tags": ["positive", "upsell_opportunity"]
        },
    ]
    
    for case in test_cases:
        dataset.add_case(**case)
    
    return dataset


def create_date_parsing_rubric() -> ScoringRubric:
    """
    Create a scoring rubric for date parsing.
    
    This is THE KEY INSIGHT: "If the answer is correct but rude, score 5/10"
    We evaluate on multiple dimensions, not just correctness.
    """
    
    def correctness_evaluator(input_text: str, output_text: str, context: Any) -> float:
        """Evaluate if the parsed date is correct."""
        expected = context.get("expected_output", "") if isinstance(context, dict) else ""
        if not expected:
            return 0.5
        
        # Extract the actual date from the output (might have extra text)
        output_clean = output_text.strip()
        
        # Check if expected date is in the output
        if expected in output_clean or expected.replace("-", "/") in output_clean:
            return 1.0
        
        # Check for ERROR cases
        if expected == "ERROR" and ("error" in output_clean.lower() or "invalid" in output_clean.lower()):
            return 1.0
        
        return 0.0
    
    def clarity_evaluator(input_text: str, output_text: str, context: Any) -> float:
        """Evaluate if the response is clear and concise."""
        length = len(output_text)
        
        # Too short (< 10 chars) or too long (> 200 chars) loses points
        if length < 10:
            return 0.3
        elif length > 200:
            return 0.7
        
        # Just right
        return 1.0
    
    rubric = ScoringRubric(
        name="Date Parsing Rubric",
        description="Evaluates date parsing on correctness and clarity"
    )
    
    rubric.add_criteria(
        dimension="correctness",
        weight=0.7,  # 70% of score is correctness
        description="Is the parsed date correct?",
        evaluator=correctness_evaluator
    )
    
    rubric.add_criteria(
        dimension="clarity",
        weight=0.3,  # 30% is clarity
        description="Is the response clear and concise?",
        evaluator=clarity_evaluator
    )
    
    rubric.set_pass_threshold(0.9)  # 90% to pass
    
    return rubric


def create_customer_service_rubric() -> ScoringRubric:
    """
    Create a nuanced rubric for customer service.
    
    Example: "If the answer is correct but rude, score 5/10. If incorrect but polite, score 0/10."
    """
    
    def correctness_evaluator(input_text: str, output_text: str, context: Any) -> float:
        """Check if the response addresses the customer's issue."""
        expected_output = context.get("expected_output") if isinstance(context, dict) else None
        expected_behavior = context.get("expected_behavior") if isinstance(context, dict) else None
        
        output_lower = output_text.lower()
        
        # Check for expected output
        if expected_output and expected_output.lower() in output_lower:
            return 1.0
        
        # Check for expected behaviors
        if expected_behavior:
            behavior_keywords = expected_behavior.lower().split()
            matches = sum(1 for kw in behavior_keywords if kw in output_lower)
            if matches >= len(behavior_keywords) * 0.5:  # At least 50% of keywords
                return 0.8
        
        # Basic relevance check
        if any(keyword in output_lower for keyword in ["help", "assist", "sorry", "understand"]):
            return 0.5
        
        return 0.0
    
    def tone_evaluator(input_text: str, output_text: str, context: Any) -> float:
        """
        THE KEY INSIGHT: Tone matters as much as correctness!
        
        Rude but correct = LOW score
        Polite but wrong = MEDIUM score (at least they tried)
        Polite and correct = HIGH score
        """
        output_lower = output_text.lower()
        
        # Negative tone indicators (rude, dismissive)
        negative_phrases = [
            "that's stupid", "obviously", "just", "simply", "read the manual",
            "not my problem", "deal with it", "too bad", "whatever"
        ]
        
        # Positive tone indicators (polite, empathetic)
        positive_phrases = [
            "sorry", "apologize", "understand", "help", "appreciate",
            "thank", "happy to", "glad to", "certainly", "absolutely"
        ]
        
        negative_count = sum(1 for phrase in negative_phrases if phrase in output_lower)
        positive_count = sum(1 for phrase in positive_phrases if phrase in output_lower)
        
        if negative_count > 0:
            return 0.0  # Any rudeness = zero tone score
        elif positive_count >= 2:
            return 1.0  # Multiple positive phrases = perfect tone
        elif positive_count == 1:
            return 0.7  # Some politeness
        else:
            return 0.5  # Neutral tone
    
    rubric = ScoringRubric(
        name="Customer Service Rubric",
        description="Correctness AND tone both matter"
    )
    
    # THE KEY INSIGHT: Weighted evaluation across dimensions
    rubric.add_criteria(
        dimension="correctness",
        weight=0.5,  # 50% correctness
        description="Does the response address the customer's issue?",
        evaluator=correctness_evaluator
    )
    
    rubric.add_criteria(
        dimension="tone",
        weight=0.4,  # 40% tone - ALMOST as important as correctness!
        description="Is the response polite and empathetic?",
        evaluator=tone_evaluator
    )
    
    rubric.add_criteria(
        dimension="safety",
        weight=0.1,  # 10% safety
        description="No harmful or inappropriate content",
        evaluator=no_harmful_content_evaluator(["idiot", "stupid customer", "moron"])
    )
    
    rubric.set_pass_threshold(0.85)  # 85% to pass
    
    return rubric


def simple_date_parser_v1(query: str) -> str:
    """
    Version 1: A naive implementation that will fail many cases.
    
    This demonstrates that even with "code", it's hard to handle all edge cases.
    """
    query = query.replace("Parse this date string into ISO format (YYYY-MM-DD): ", "").strip()
    
    # Very naive - only handles ISO format
    if len(query) == 10 and query[4] == '-' and query[7] == '-':
        return query
    
    return "ERROR: Unsupported format"


def ai_date_parser(client: OpenAI, model: str = "gpt-4o-mini") -> callable:
    """
    Create an AI-based date parser.
    
    This is the "New World" - we don't write parseDate() anymore.
    We let the AI handle it and constrain it with evaluations.
    """
    def parser(query: str) -> str:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a date parsing assistant. Parse date strings into ISO format (YYYY-MM-DD). If the date is invalid or cannot be parsed, respond with 'ERROR'. Be concise - respond with just the date or ERROR."
                    },
                    {"role": "user", "content": query}
                ],
                temperature=0.1  # Low temperature for consistent parsing
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    return parser


def ai_customer_service(client: OpenAI, model: str = "gpt-4o-mini") -> callable:
    """Create an AI-based customer service agent."""
    def responder(query: str) -> str:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a professional customer service representative. Be helpful, empathetic, and polite. Provide clear solutions to customer issues."
                    },
                    {"role": "user", "content": query}
                ],
                temperature=0.7
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error: {str(e)}"
    
    return responder


def demonstrate_eval_dd():
    """
    Demonstrate the Eval-DD workflow.
    
    The Old World: Write implementation → Write tests
    The New World: Write golden dataset → Write rubric → Let AI iterate
    """
    print("\n" + "="*80)
    print("EVALUATION ENGINEERING: THE NEW TDD")
    print("="*80)
    print("\nThe Paradigm Shift:")
    print("  OLD: 'I write the code, then I write a unit test to prove it works.'")
    print("  NEW: 'I write the evaluation suite, then let the AI iterate until it passes.'")
    print("\n" + "="*80)
    
    # Check for API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("\n⚠️  Warning: OPENAI_API_KEY not found.")
        print("The AI-based parsers will be skipped.")
        print("You can still see the evaluation framework in action with the naive parser.\n")
    
    # Demo 1: Date Parsing
    print("\n\n" + "#"*80)
    print("DEMO 1: Date Parsing - 25 Tricky Date Strings")
    print("#"*80)
    print("\nThe Engineer's Job: Write the Golden Dataset (not the code!)")
    print("  ✓ Created 25 test cases with edge cases")
    print("  ✓ Created scoring rubric: 70% correctness + 30% clarity")
    print("  ✓ Set pass threshold: 90%")
    
    dataset_dates = create_date_parsing_dataset()
    rubric_dates = create_date_parsing_rubric()
    
    # Test naive implementation
    print("\n\n--- Testing: Naive Implementation (simple_date_parser_v1) ---")
    runner1 = EvaluationRunner(dataset_dates, rubric_dates, simple_date_parser_v1)
    results1 = runner1.run(verbose=True)
    
    print("\n💡 Key Insight: The naive implementation fails many edge cases.")
    print("   In the Old World, we'd keep adding if/else statements.")
    print("   In the New World, we let the AI handle it!\n")
    
    # Test AI implementation if API key available
    if api_key:
        client = OpenAI(api_key=api_key)
        
        print("\n\n--- Testing: AI-Based Parser (gpt-4o-mini) ---")
        ai_parser = ai_date_parser(client)
        runner2 = EvaluationRunner(dataset_dates, rubric_dates, ai_parser)
        results2 = runner2.run(verbose=True)
        
        print("\n✨ The AI handles edge cases better without explicit code!")
    
    # Demo 2: Customer Service
    print("\n\n" + "#"*80)
    print("DEMO 2: Customer Service - Correctness + Tone Evaluation")
    print("#"*80)
    print("\nTHE KEY INSIGHT: Multi-Dimensional Scoring")
    print("  'If the answer is correct but rude, score 5/10'")
    print("  'If incorrect but polite, score 0/10'")
    print("\n  Rubric: 50% correctness + 40% tone + 10% safety")
    
    if api_key:
        dataset_cs = create_customer_service_dataset()
        rubric_cs = create_customer_service_rubric()
        
        ai_cs = ai_customer_service(client)
        runner3 = EvaluationRunner(dataset_cs, rubric_cs, ai_cs)
        results3 = runner3.run(verbose=True)
        
        print("\n🎯 The Lesson:")
        print("   The 'Source Code' of the future isn't the application logic;")
        print("   it's the Evaluation Suite that constrains it.")
    else:
        print("\n⚠️  Skipping Demo 2 (requires OPENAI_API_KEY)")
    
    print("\n\n" + "="*80)
    print("EVAL-DD COMPLETE")
    print("="*80)
    print("\nYou've just witnessed:")
    print("  ✓ Golden Datasets replacing implementation code")
    print("  ✓ Scoring Rubrics with multi-dimensional evaluation")
    print("  ✓ Automated testing against probabilistic AI systems")
    print("  ✓ The evolution of TDD → Eval-DD")
    print("\nThis is Evaluation Engineering - the most valuable code a Senior Engineer writes today.")
    print("="*80 + "\n")


if __name__ == "__main__":
    demonstrate_eval_dd()

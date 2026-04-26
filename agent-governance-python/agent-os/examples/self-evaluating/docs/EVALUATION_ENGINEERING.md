# Evaluation Engineering: The New TDD

## The Paradigm Shift

### The Old World
> "I write the code, then I write a unit test to prove it works."

In traditional software engineering, developers write implementation code (functions, classes, algorithms) and then write unit tests to verify the implementation works correctly. This approach works well for deterministic systems.

### The Engineering Reality
> "In a probabilistic world, you can't write a unit test that covers every creative variation of an AI's answer."

When working with AI systems, traditional unit testing breaks down. An AI might give different (but equally valid) responses to the same input. Testing becomes about evaluating quality across multiple dimensions rather than checking for exact matches.

### The New World: Evaluation Engineering
> "If the AI is the Coder, the Human is the Examiner. We don't write the implementation anymore. We write the Exam."

**Evaluation Engineering** is the most valuable code a Senior Engineer writes today. Instead of writing `parseDate()`, you write:

1. **Golden Dataset**: 50 tricky, malformed date strings with expected outputs
2. **Scoring Rubric**: "If the answer is correct but rude, score 5/10. If incorrect but polite, score 0/10."
3. **Pass Threshold**: AI must score >90% to pass

This is the evolution of TDD (Test-Driven Development) into **Eval-DD (Evaluation-Driven Development)**: You write the "Golden Dataset" first and let the AI iterate until it scores >90% against your rubric.

## Core Concepts

### 1. Golden Dataset

The Golden Dataset is your test suite. It defines what "good" looks like through examples.

```python
from evaluation_engineering import EvaluationDataset

dataset = EvaluationDataset(
    name="Date Parsing Golden Dataset",
    description="50 tricky, malformed date strings"
)

# Instead of writing parseDate(), write examples
dataset.add_case(
    id="parse_date_001",
    input="Parse this date: 2024-01-15",
    expected_output="2024-01-15",
    tags=["basic", "iso"]
)

dataset.add_case(
    id="parse_date_002",
    input="Parse this date: Jan 15, 2024",
    expected_output="2024-01-15",
    tags=["readable"]
)

# Edge cases
dataset.add_case(
    id="parse_date_edge_001",
    input="Parse this date: 2024-13-01",
    expected_output="ERROR",
    tags=["invalid", "edge_case"],
    difficulty="hard"
)
```

### 2. Scoring Rubric

The Scoring Rubric defines HOW to evaluate responses. This is where you encode your engineering judgment.

```python
from evaluation_engineering import ScoringRubric

rubric = ScoringRubric(
    name="Customer Service Rubric",
    description="Evaluates correctness AND tone"
)

# Multi-dimensional evaluation
rubric.add_criteria(
    dimension="correctness",
    weight=0.5,  # 50% of score
    description="Does it solve the problem?",
    evaluator=correctness_evaluator
)

rubric.add_criteria(
    dimension="tone",
    weight=0.4,  # 40% of score - tone is almost as important!
    description="Is it polite and empathetic?",
    evaluator=tone_evaluator
)

rubric.add_criteria(
    dimension="safety",
    weight=0.1,  # 10% of score
    description="No harmful content",
    evaluator=safety_evaluator
)

rubric.set_pass_threshold(0.85)  # Must score 85% to pass
```

### 3. Evaluation Runner

The Evaluation Runner executes your AI against the Golden Dataset and scores it with your Rubric.

```python
from evaluation_engineering import EvaluationRunner

# Your AI function (could be GPT-4, Claude, custom model, etc.)
def my_ai_function(input_text: str) -> str:
    # AI implementation here
    return ai_response

# Run the evaluation
runner = EvaluationRunner(dataset, rubric, my_ai_function)
results = runner.run(verbose=True)

print(f"Pass Rate: {results['pass_rate']*100:.1f}%")
print(f"Average Score: {results['average_score']:.2f}")

if results['overall_passed']:
    print("🎉 AI meets requirements!")
else:
    print("❌ AI needs improvement")
    
    # Debug failed cases
    failed = runner.get_failed_cases()
    for case in failed:
        print(f"Failed: {case.case_id}")
        print(f"  Input: {case.input}")
        print(f"  Expected: {case.expected_output}")
        print(f"  Got: {case.actual_output}")
```

## Key Insights

### 1. Multi-Dimensional Scoring

The most important insight: **Correctness alone is not enough.**

```python
# Example: Customer Service Agent
# Scenario: Customer asks "How do I reset my password?"

# Response A: "Just click forgot password. Duh."
#   Correctness: 100% (answer is correct)
#   Tone: 0% (rude)
#   Overall: 50% (assuming 50/50 weight)

# Response B: "I'm happy to help! Click 'Forgot Password' on the login page."
#   Correctness: 100% (answer is correct)
#   Tone: 100% (polite and helpful)
#   Overall: 100%

# Response C: "I apologize for any confusion. Let me help you with that."
#   Correctness: 0% (doesn't answer the question)
#   Tone: 100% (very polite)
#   Overall: 50% (assuming 50/50 weight)
```

This is why the rubric matters: **"If correct but rude, score 5/10. If incorrect but polite, score 0/10."**

### 2. The Dataset is the Spec

In traditional development, you write a specification document, then write code to implement it. In Eval-DD, **the dataset IS the specification**.

```python
# Traditional Spec:
# "parseDate() should accept ISO 8601 format, US format (MM/DD/YYYY),
#  EU format (DD/MM/YYYY), and readable formats like 'Jan 15, 2024'.
#  It should return dates in ISO format (YYYY-MM-DD).
#  Invalid dates should return 'ERROR'."

# Eval-DD Spec (via dataset):
dataset.add_case(id="iso", input="2024-01-15", expected="2024-01-15")
dataset.add_case(id="us", input="01/15/2024", expected="2024-01-15")
dataset.add_case(id="eu", input="15/01/2024", expected="2024-01-15")
dataset.add_case(id="readable", input="Jan 15, 2024", expected="2024-01-15")
dataset.add_case(id="invalid", input="2024-13-01", expected="ERROR")
```

The dataset is clearer, more precise, and easier to maintain than prose.

### 3. Edge Cases First

In Eval-DD, you focus on edge cases from day one.

```python
# In traditional TDD, you might start with happy path:
def test_parse_date():
    assert parseDate("2024-01-15") == "2024-01-15"

# In Eval-DD, you enumerate edge cases immediately:
dataset.add_case(id="edge_001", input="2024.01.15", expected="2024-01-15")  # Dots
dataset.add_case(id="edge_002", input="15-JAN-2024", expected="2024-01-15")  # Uppercase
dataset.add_case(id="edge_003", input="january 15 2024", expected="2024-01-15")  # Lowercase
dataset.add_case(id="edge_004", input="1/5/24", expected="2024-01-05")  # Short format
dataset.add_case(id="edge_005", input="32/01/2024", expected="ERROR")  # Invalid day
```

## Usage Examples

### Example 1: Date Parsing

```python
from evaluation_engineering import EvaluationDataset, ScoringRubric, EvaluationRunner

# 1. Write the Golden Dataset (this is your "code")
dataset = EvaluationDataset("Date Parsing", "Test suite for date parsing")

# Add 50 test cases covering all edge cases
for i, (input_str, expected) in enumerate(test_cases):
    dataset.add_case(
        id=f"date_{i:03d}",
        input=f"Parse: {input_str}",
        expected_output=expected
    )

# 2. Write the Scoring Rubric
rubric = ScoringRubric("Date Parser Rubric", "Correctness + Clarity")
rubric.add_criteria("correctness", 0.7, "Correct parse", correctness_eval)
rubric.add_criteria("clarity", 0.3, "Clear response", clarity_eval)
rubric.set_pass_threshold(0.9)

# 3. Test your AI
runner = EvaluationRunner(dataset, rubric, my_ai_parser)
results = runner.run()

# 4. Iterate until passing
if not results['overall_passed']:
    print("Failed cases:")
    for case in runner.get_failed_cases():
        print(f"  {case.case_id}: {case.input}")
    
    # Improve AI (retrain, adjust prompt, etc.)
    # Run again
```

### Example 2: Customer Service Agent

```python
# 1. Golden Dataset with behavioral expectations
dataset = EvaluationDataset("Customer Service", "CS agent evaluation")

dataset.add_case(
    id="complaint_001",
    input="My order is late!",
    expected_behavior="Apologize, show empathy, offer solution",
    tags=["complaint", "empathy"]
)

dataset.add_case(
    id="technical_001",
    input="How do I reset password?",
    expected_output="Click 'Forgot Password', check email",
    tags=["technical"]
)

# 2. Multi-dimensional Rubric
rubric = ScoringRubric("CS Agent Rubric", "Quality + Tone + Safety")
rubric.add_criteria("correctness", 0.5, "Solves problem", solve_eval)
rubric.add_criteria("tone", 0.4, "Polite and helpful", tone_eval)
rubric.add_criteria("safety", 0.1, "No harmful content", safety_eval)
rubric.set_pass_threshold(0.85)

# 3. Run evaluation
runner = EvaluationRunner(dataset, rubric, cs_agent)
results = runner.run()
```

### Example 3: Code Generation

```python
# Evaluate code generation on multiple dimensions
dataset = EvaluationDataset("Code Generation", "Python function generation")

dataset.add_case(
    id="code_001",
    input="Write a function to calculate factorial",
    expected_behavior="Correct implementation, handles edge cases, includes docstring",
    tags=["python", "recursion"]
)

rubric = ScoringRubric("Code Quality", "Multi-dimensional code evaluation")
rubric.add_criteria("correctness", 0.4, "Code works", correctness_eval)
rubric.add_criteria("efficiency", 0.2, "Time complexity", efficiency_eval)
rubric.add_criteria("readability", 0.2, "Clear and documented", readability_eval)
rubric.add_criteria("safety", 0.2, "Handles edge cases", safety_eval)
```

## Custom Evaluators

You can write custom evaluators for any dimension:

```python
def tone_evaluator(input_text: str, output_text: str, context: Any) -> float:
    """
    Evaluate the tone of the response.
    Returns 0.0 (rude) to 1.0 (polite).
    """
    output_lower = output_text.lower()
    
    # Negative indicators
    rude_words = ["stupid", "idiot", "obviously", "duh"]
    if any(word in output_lower for word in rude_words):
        return 0.0
    
    # Positive indicators
    polite_words = ["please", "thank you", "happy to help", "sorry"]
    polite_count = sum(1 for word in polite_words if word in output_lower)
    
    if polite_count >= 2:
        return 1.0
    elif polite_count == 1:
        return 0.7
    else:
        return 0.5  # Neutral

rubric.add_criteria(
    dimension="tone",
    weight=0.4,
    description="Politeness and empathy",
    evaluator=tone_evaluator
)
```

## Best Practices

### 1. Start with the Dataset

Before writing any code, create your golden dataset. This forces you to think about:
- What inputs should the system handle?
- What outputs are expected?
- What edge cases exist?
- What quality dimensions matter?

### 2. Make Edge Cases Explicit

Don't rely on "it should handle edge cases." Enumerate them:

```python
# Bad (vague)
# "The system should handle invalid inputs"

# Good (explicit)
dataset.add_case(id="empty_input", input="", expected="ERROR")
dataset.add_case(id="null_input", input="null", expected="ERROR")
dataset.add_case(id="special_chars", input="@#$%", expected="ERROR")
dataset.add_case(id="very_long", input="x"*10000, expected="ERROR")
```

### 3. Weight Your Dimensions

Think carefully about the relative importance of each dimension:

```python
# Customer-facing system: Tone matters a lot
rubric.add_criteria("correctness", 0.5, ...)
rubric.add_criteria("tone", 0.4, ...)  # Almost as important!
rubric.add_criteria("safety", 0.1, ...)

# Internal tool: Correctness matters most
rubric.add_criteria("correctness", 0.8, ...)
rubric.add_criteria("efficiency", 0.15, ...)
rubric.add_criteria("clarity", 0.05, ...)
```

### 4. Version Your Datasets

Treat datasets like source code:

```python
dataset.metadata = {
    "version": "2.0",
    "created_at": "2024-01-15",
    "author": "engineering_team",
    "changes": "Added 20 new edge cases for emoji handling"
}
```

### 5. Iterate Based on Failures

When cases fail, use them to improve:

```python
# Run evaluation
runner = EvaluationRunner(dataset, rubric, ai_function)
results = runner.run()

# Analyze failures
for case in runner.get_failed_cases():
    print(f"\nFailed: {case.case_id}")
    print(f"Score: {case.scores['overall_score']:.2f}")
    print(f"Input: {case.input}")
    print(f"Expected: {case.expected_output}")
    print(f"Got: {case.actual_output}")
    
    # Dimension breakdown
    for dim, scores in case.scores['dimension_scores'].items():
        print(f"  {dim}: {scores['score']:.2f}")

# Use failures to:
# 1. Add more training data
# 2. Adjust prompts
# 3. Fine-tune models
# 4. Update rubric weights
```

### 6. Track Progress Over Time

Save results to track improvement:

```python
# After each iteration
runner.save_results(f"results_{version}_{timestamp}.json")

# Compare versions
v1_results = load_results("results_v1.json")
v2_results = load_results("results_v2.json")

print(f"V1 Pass Rate: {v1_results['pass_rate']:.1%}")
print(f"V2 Pass Rate: {v2_results['pass_rate']:.1%}")
print(f"Improvement: {(v2_results['pass_rate'] - v1_results['pass_rate']):.1%}")
```

## The Lesson

**The "Source Code" of the future isn't the application logic; it's the Evaluation Suite that constrains it.**

In a world where AI systems generate the implementation, the engineer's role shifts from writing code to:

1. **Defining Quality**: What does "good" look like across multiple dimensions?
2. **Enumerating Edge Cases**: What are all the tricky scenarios?
3. **Setting Standards**: What pass threshold is acceptable?
4. **Iterating Based on Data**: How do we improve based on failures?

This is **Evaluation Engineering** - and it's the most valuable work a Senior Engineer does today.

## API Reference

See the code documentation in `evaluation_engineering.py` for detailed API reference.

### Key Classes

- `EvaluationDataset`: Container for test cases
- `EvaluationCase`: Individual test case
- `ScoringRubric`: Multi-dimensional evaluation criteria
- `ScoringCriteria`: Single evaluation dimension
- `EvaluationRunner`: Executes evaluations and generates reports

### Key Functions

- `exact_match_evaluator`: Check for exact string match
- `contains_keywords_evaluator`: Check for required keywords
- `length_check_evaluator`: Validate response length
- `no_harmful_content_evaluator`: Screen for harmful content

## Running the Examples

```bash
# Run the main demonstration
python example_evaluation_engineering.py

# Run tests
python test_evaluation_engineering.py
```

## Integration with Self-Evolving Agent

The Evaluation Engineering framework integrates naturally with the self-evolving agent system:

```python
from agent import DoerAgent
from observer import ObserverAgent
from evaluation_engineering import EvaluationDataset, ScoringRubric, EvaluationRunner

# Create evaluation suite
dataset = create_my_dataset()
rubric = create_my_rubric()

# Wrap DoerAgent for evaluation
def ai_function(input_text: str) -> str:
    doer = DoerAgent()
    result = doer.run(input_text, verbose=False)
    return result['response']

# Run evaluation
runner = EvaluationRunner(dataset, rubric, ai_function)
results = runner.run()

# If not passing, trigger evolution
if not results['overall_passed']:
    observer = ObserverAgent()
    observer.process_events()  # Learn from failures
```

This creates a closed loop: Evaluation → Evolution → Re-evaluation.

## Conclusion

Evaluation Engineering represents a fundamental shift in how we build AI systems. Instead of writing `parseDate()`, we write the exam that `parseDate()` must pass. Instead of writing customer service responses, we write the rubric that defines quality.

This is the evolution of Test-Driven Development into Evaluation-Driven Development - and it's how Senior Engineers add value in the age of AI.

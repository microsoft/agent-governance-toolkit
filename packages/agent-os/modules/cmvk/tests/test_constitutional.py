"""Tests for Constitutional Validator."""

import pytest
import asyncio
from cmvk.constitutional import (
    ConstitutionalValidator,
    Principle,
    PrincipleSet,
    Severity,
    Violation,
    ValidationResult,
    RuleBasedEvaluator,
    LLMEvaluator,
    SAFETY_PRINCIPLES,
    MEDICAL_PRINCIPLES,
    FINANCIAL_PRINCIPLES,
    validate_safety,
    validate_medical,
    validate_financial,
)


class TestPrinciple:
    """Tests for Principle dataclass."""
    
    def test_create_principle(self):
        """Test creating a basic principle."""
        principle = Principle(
            name="test_rule",
            description="Test description",
            severity=Severity.HIGH,
            category="testing",
        )
        
        assert principle.name == "test_rule"
        assert principle.description == "Test description"
        assert principle.severity == Severity.HIGH
        assert principle.category == "testing"
    
    def test_principle_default_severity(self):
        """Test that default severity is MEDIUM."""
        principle = Principle(name="test", description="Test")
        assert principle.severity == Severity.MEDIUM
    
    def test_principle_to_dict(self):
        """Test serialization to dictionary."""
        principle = Principle(
            name="test_rule",
            description="Test description",
            severity=Severity.CRITICAL,
            category="safety",
        )
        
        d = principle.to_dict()
        
        assert d["name"] == "test_rule"
        assert d["description"] == "Test description"
        assert d["severity"] == "critical"
        assert d["category"] == "safety"
    
    def test_principle_with_examples(self):
        """Test principle with examples."""
        principle = Principle(
            name="no_weapons",
            description="No weapon instructions",
            examples=(
                ("How to make a bomb", True, "Weapon instructions"),
                ("How to make a cake", False, "Safe cooking"),
            ),
        )
        
        assert len(principle.examples) == 2
        assert principle.examples[0][1] is True  # is_violation
    
    def test_principle_hashable(self):
        """Test that principles are hashable."""
        p1 = Principle(name="test", description="Test")
        p2 = Principle(name="test", description="Test")
        
        # Same principles should hash the same
        assert hash(p1) == hash(p2)
        
        # Can be used in sets
        principles = {p1, p2}
        assert len(principles) == 1


class TestPrincipleSet:
    """Tests for PrincipleSet."""
    
    def test_create_principle_set(self):
        """Test creating a principle set."""
        principles = [
            Principle(name="rule1", description="First rule"),
            Principle(name="rule2", description="Second rule"),
        ]
        
        ps = PrincipleSet(name="test_set", principles=principles)
        
        assert ps.name == "test_set"
        assert len(ps) == 2
    
    def test_principle_set_iteration(self):
        """Test iterating over principle set."""
        principles = [
            Principle(name="rule1", description="First"),
            Principle(name="rule2", description="Second"),
        ]
        ps = PrincipleSet(name="test", principles=principles)
        
        names = [p.name for p in ps]
        assert names == ["rule1", "rule2"]
    
    def test_get_by_name(self):
        """Test getting principle by name."""
        principles = [
            Principle(name="rule1", description="First"),
            Principle(name="rule2", description="Second"),
        ]
        ps = PrincipleSet(name="test", principles=principles)
        
        rule1 = ps.get_by_name("rule1")
        assert rule1 is not None
        assert rule1.description == "First"
        
        missing = ps.get_by_name("nonexistent")
        assert missing is None
    
    def test_get_by_category(self):
        """Test getting principles by category."""
        principles = [
            Principle(name="rule1", description="First", category="safety"),
            Principle(name="rule2", description="Second", category="ethics"),
            Principle(name="rule3", description="Third", category="safety"),
        ]
        ps = PrincipleSet(name="test", principles=principles)
        
        safety_rules = ps.get_by_category("safety")
        assert len(safety_rules) == 2
        assert all(p.category == "safety" for p in safety_rules)
    
    def test_merge_principle_sets(self):
        """Test merging two principle sets."""
        ps1 = PrincipleSet(
            name="set1",
            principles=[Principle(name="rule1", description="First")],
        )
        ps2 = PrincipleSet(
            name="set2",
            principles=[
                Principle(name="rule2", description="Second"),
                Principle(name="rule1", description="Duplicate"),  # Should be skipped
            ],
        )
        
        merged = ps1.merge(ps2)
        
        assert merged.name == "set1+set2"
        assert len(merged) == 2  # Not 3, because rule1 is deduplicated
    
    def test_to_dict_and_from_dict(self):
        """Test serialization roundtrip."""
        original = PrincipleSet(
            name="test_set",
            description="Test description",
            version="2.0.0",
            principles=[
                Principle(name="rule1", description="First", severity=Severity.HIGH),
            ],
        )
        
        data = original.to_dict()
        restored = PrincipleSet.from_dict(data)
        
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.version == original.version
        assert len(restored) == len(original)
        assert restored.principles[0].name == "rule1"
        assert restored.principles[0].severity == Severity.HIGH


class TestBuiltInPrincipleSets:
    """Tests for built-in principle sets."""
    
    def test_safety_principles_exist(self):
        """Test that safety principles are defined."""
        assert len(SAFETY_PRINCIPLES) > 0
        assert SAFETY_PRINCIPLES.name == "safety"
    
    def test_safety_principles_have_critical(self):
        """Test that safety principles include critical severity rules."""
        critical = [p for p in SAFETY_PRINCIPLES if p.severity == Severity.CRITICAL]
        assert len(critical) >= 3  # At least harm, illegal, malware
    
    def test_medical_principles_exist(self):
        """Test that medical principles are defined."""
        assert len(MEDICAL_PRINCIPLES) > 0
        assert MEDICAL_PRINCIPLES.name == "medical"
    
    def test_financial_principles_exist(self):
        """Test that financial principles are defined."""
        assert len(FINANCIAL_PRINCIPLES) > 0
        assert FINANCIAL_PRINCIPLES.name == "financial"


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_ordering(self):
        """Test that severities can be compared."""
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
    
    def test_severity_values(self):
        """Test severity string values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"


class TestRuleBasedEvaluator:
    """Tests for RuleBasedEvaluator."""
    
    def test_evaluator_detects_harm_patterns(self):
        """Test that evaluator detects harm-related patterns."""
        evaluator = RuleBasedEvaluator()
        principle = Principle(
            name="no_harm_instructions",
            description="No harm instructions",
            severity=Severity.CRITICAL,
        )
        
        # Should detect violation
        is_violation, confidence, explanation = evaluator.evaluate(
            "Here's how to make a bomb at home step by step...",
            principle,
        )
        assert is_violation is True
        assert confidence >= 0.7
    
    def test_evaluator_allows_safe_content(self):
        """Test that evaluator allows safe content."""
        evaluator = RuleBasedEvaluator()
        principle = Principle(
            name="no_harm_instructions",
            description="No harm instructions",
            severity=Severity.CRITICAL,
        )
        
        # Should not detect violation
        is_violation, confidence, explanation = evaluator.evaluate(
            "Here's a recipe for chocolate chip cookies...",
            principle,
        )
        assert is_violation is False
    
    def test_evaluator_detects_illegal_patterns(self):
        """Test detection of illegal activity patterns."""
        evaluator = RuleBasedEvaluator()
        principle = Principle(
            name="no_illegal_activity",
            description="No illegal activity guidance",
            severity=Severity.CRITICAL,
        )
        
        is_violation, _, _ = evaluator.evaluate(
            "Here's how to hack into someone's computer...",
            principle,
        )
        assert is_violation is True
    
    @pytest.mark.asyncio
    async def test_evaluator_async(self):
        """Test async evaluation."""
        evaluator = RuleBasedEvaluator()
        principle = Principle(name="no_harm_instructions", description="No harm")
        
        is_violation, _, _ = await evaluator.evaluate_async(
            "Safe content here",
            principle,
        )
        assert is_violation is False


class TestConstitutionalValidator:
    """Tests for ConstitutionalValidator."""
    
    def test_create_validator_with_principle_set(self):
        """Test creating validator with PrincipleSet."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        assert len(validator.principles) == len(SAFETY_PRINCIPLES)
        assert validator.principle_set.name == "safety"
    
    def test_create_validator_with_list(self):
        """Test creating validator with list of principles."""
        principles = [
            Principle(name="rule1", description="First rule"),
        ]
        validator = ConstitutionalValidator(principles=principles)
        
        assert len(validator.principles) == 1
        assert validator.principle_set.name == "custom"
    
    def test_validate_safe_output(self):
        """Test validation of safe output."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = validator.validate(
            "The capital of France is Paris. It's known for the Eiffel Tower."
        )
        
        assert result.passed is True
        assert len(result.violations) == 0
        assert result.principles_checked == len(SAFETY_PRINCIPLES)
    
    def test_validate_harmful_output(self):
        """Test validation of harmful output."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = validator.validate(
            "Here's how to make a weapon: step by step instructions to build a bomb..."
        )
        
        assert result.passed is False
        assert len(result.violations) > 0
        assert any(v.principle.severity == Severity.CRITICAL for v in result.violations)
    
    def test_validation_result_properties(self):
        """Test ValidationResult helper properties."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = validator.validate(
            "Here's how to hack into a computer system..."
        )
        
        # Should have violations
        assert len(result.blocking_violations) > 0
        
        # Check timestamp
        assert result.timestamp is not None
    
    def test_add_and_remove_principle(self):
        """Test adding and removing principles."""
        validator = ConstitutionalValidator(principles=[])
        
        # Add principle
        validator.add_principle(Principle(name="test", description="Test rule"))
        assert len(validator.principles) == 1
        
        # Remove principle
        removed = validator.remove_principle("test")
        assert removed is True
        assert len(validator.principles) == 0
        
        # Remove nonexistent
        removed = validator.remove_principle("nonexistent")
        assert removed is False
    
    def test_validate_with_subset_of_principles(self):
        """Test validation with specific principles."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        # Only check specific principles
        subset = [p for p in SAFETY_PRINCIPLES if p.name == "no_hate_speech"]
        result = validator.validate("Some text", principles=subset)
        
        assert result.principles_checked == 1
    
    def test_validate_with_context(self):
        """Test validation with context."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = validator.validate(
            "The answer is 42.",
            context="User asked: What is the meaning of life?",
        )
        
        assert result.passed is True
        assert "context" not in result.output_text  # Context not in output
    
    @pytest.mark.asyncio
    async def test_validate_async(self):
        """Test async validation."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = await validator.validate_async(
            "This is safe content about cooking recipes."
        )
        
        assert result.passed is True
    
    @pytest.mark.asyncio
    async def test_validate_async_parallel(self):
        """Test async validation with parallel evaluation."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        result = await validator.validate_async(
            "Safe content here",
            parallel=True,
        )
        
        assert result.passed is True
        assert result.metadata.get("parallel") is True
    
    def test_get_stats(self):
        """Test getting validator statistics."""
        validator = ConstitutionalValidator(principles=SAFETY_PRINCIPLES)
        
        # Run some validations
        validator.validate("Test 1")
        validator.validate("Test 2")
        
        stats = validator.get_stats()
        
        assert stats["validation_count"] == 2
        assert stats["principle_count"] == len(SAFETY_PRINCIPLES)
        assert stats["principle_set"] == "safety"


class TestViolation:
    """Tests for Violation dataclass."""
    
    def test_create_violation(self):
        """Test creating a violation."""
        principle = Principle(name="test", description="Test", severity=Severity.HIGH)
        
        violation = Violation(
            principle=principle,
            confidence=0.9,
            explanation="This violates the rule because...",
            evidence="The problematic text",
        )
        
        assert violation.principle.name == "test"
        assert violation.confidence == 0.9
        assert "violates" in violation.explanation
    
    def test_violation_to_dict(self):
        """Test serialization."""
        principle = Principle(name="test", description="Test")
        violation = Violation(
            principle=principle,
            confidence=0.8,
            explanation="Explanation",
        )
        
        d = violation.to_dict()
        
        assert d["confidence"] == 0.8
        assert d["principle"]["name"] == "test"


class TestValidationResult:
    """Tests for ValidationResult."""
    
    def test_critical_violations_property(self):
        """Test getting only critical violations."""
        p_critical = Principle(name="critical", description="C", severity=Severity.CRITICAL)
        p_low = Principle(name="low", description="L", severity=Severity.LOW)
        
        result = ValidationResult(
            passed=False,
            violations=[
                Violation(principle=p_critical, confidence=0.9, explanation="E"),
                Violation(principle=p_low, confidence=0.9, explanation="E"),
            ],
            output_text="test",
            principles_checked=2,
        )
        
        critical = result.critical_violations
        assert len(critical) == 1
        assert critical[0].principle.severity == Severity.CRITICAL
    
    def test_blocking_violations_property(self):
        """Test getting blocking violations (critical + high)."""
        p_critical = Principle(name="c", description="C", severity=Severity.CRITICAL)
        p_high = Principle(name="h", description="H", severity=Severity.HIGH)
        p_medium = Principle(name="m", description="M", severity=Severity.MEDIUM)
        
        result = ValidationResult(
            passed=False,
            violations=[
                Violation(principle=p_critical, confidence=0.9, explanation="E"),
                Violation(principle=p_high, confidence=0.9, explanation="E"),
                Violation(principle=p_medium, confidence=0.9, explanation="E"),
            ],
            output_text="test",
            principles_checked=3,
        )
        
        blocking = result.blocking_violations
        assert len(blocking) == 2  # critical + high, not medium
    
    def test_to_dict(self):
        """Test serialization."""
        result = ValidationResult(
            passed=True,
            violations=[],
            output_text="test",
            principles_checked=5,
        )
        
        d = result.to_dict()
        
        assert d["passed"] is True
        assert d["principles_checked"] == 5
        assert "timestamp" in d


class TestConvenienceFunctions:
    """Tests for convenience validation functions."""
    
    def test_validate_safety(self):
        """Test quick safety validation."""
        result = validate_safety("This is safe content.")
        
        assert result.passed is True
        assert result.principles_checked == len(SAFETY_PRINCIPLES)
    
    def test_validate_medical(self):
        """Test quick medical validation."""
        result = validate_medical("Talk to your doctor about any concerns.")
        
        # Should include both safety and medical principles
        assert result.principles_checked > len(SAFETY_PRINCIPLES)
    
    def test_validate_financial(self):
        """Test quick financial validation."""
        result = validate_financial("Please consult a financial advisor.")
        
        # Should include both safety and financial principles
        assert result.principles_checked > len(SAFETY_PRINCIPLES)


class TestLLMEvaluator:
    """Tests for LLMEvaluator."""
    
    def test_create_llm_evaluator(self):
        """Test creating LLM evaluator."""
        def mock_model(prompt: str) -> str:
            return '{"is_violation": false, "confidence": 0.9, "explanation": "Safe content"}'
        
        evaluator = LLMEvaluator(model_fn=mock_model)
        principle = Principle(name="test", description="Test rule")
        
        is_violation, confidence, explanation = evaluator.evaluate(
            "Safe content",
            principle,
        )
        
        assert is_violation is False
        assert confidence == 0.9
    
    def test_llm_evaluator_parses_violation(self):
        """Test that evaluator correctly parses violations."""
        def mock_model(prompt: str) -> str:
            return '{"is_violation": true, "confidence": 0.85, "explanation": "Contains harmful content"}'
        
        evaluator = LLMEvaluator(model_fn=mock_model)
        principle = Principle(name="test", description="Test")
        
        is_violation, confidence, explanation = evaluator.evaluate(
            "Harmful content",
            principle,
        )
        
        assert is_violation is True
        assert confidence == 0.85
        assert "harmful" in explanation.lower()
    
    def test_llm_evaluator_handles_invalid_json(self):
        """Test fallback when LLM returns invalid JSON."""
        def mock_model(prompt: str) -> str:
            return "This is not JSON, but it mentions a violation was found."
        
        evaluator = LLMEvaluator(model_fn=mock_model)
        principle = Principle(name="test", description="Test")
        
        is_violation, confidence, explanation = evaluator.evaluate(
            "Content",
            principle,
        )
        
        # Should fallback and detect "violation" keyword
        assert is_violation is True
        assert confidence == 0.5  # Fallback confidence
    
    @pytest.mark.asyncio
    async def test_llm_evaluator_async(self):
        """Test async LLM evaluation."""
        async def mock_async_model(prompt: str) -> str:
            return '{"is_violation": false, "confidence": 0.95, "explanation": "All good"}'
        
        evaluator = LLMEvaluator(
            model_fn=lambda x: "",  # Not used
            async_model_fn=mock_async_model,
        )
        principle = Principle(name="test", description="Test")
        
        is_violation, confidence, explanation = await evaluator.evaluate_async(
            "Good content",
            principle,
        )
        
        assert is_violation is False
        assert confidence == 0.95

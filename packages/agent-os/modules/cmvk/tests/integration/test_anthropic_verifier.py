"""
Tests for the Anthropic Verifier agent.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cross_model_verification_kernel.agents.verifier_anthropic import AnthropicVerifier
from cross_model_verification_kernel.core.types import VerificationOutcome, VerificationResult


class TestAnthropicVerifier:
    """Tests for AnthropicVerifier agent."""

    def test_init_without_api_key(self):
        """Test initialization without API key uses environment variable."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            verifier = AnthropicVerifier(model_name="claude-3-5-sonnet-20241022")
            assert verifier.api_key == "test-key"
            assert verifier.model_name == "claude-3-5-sonnet-20241022"

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        verifier = AnthropicVerifier(model_name="claude-3-5-haiku-20241022", api_key="explicit-key")
        assert verifier.api_key == "explicit-key"

    def test_init_default_model(self):
        """Test default model is claude-3-5-sonnet."""
        verifier = AnthropicVerifier(api_key="test-key")
        assert verifier.model_name == "claude-3-5-sonnet-20241022"

    def test_init_temperature(self):
        """Test temperature setting."""
        verifier = AnthropicVerifier(api_key="test-key", temperature=0.5)
        assert verifier.temperature == 0.5

    def test_generate_raises_not_implemented(self):
        """Test that generate() raises NotImplementedError for verifiers."""
        verifier = AnthropicVerifier(api_key="test-key")
        with pytest.raises(NotImplementedError):
            verifier.generate("test task")

    def test_mock_verification_when_client_unavailable(self):
        """Test mock verification is returned when API client is not available."""
        verifier = AnthropicVerifier(api_key="test-key")
        verifier.client = None  # Simulate unavailable client

        result = verifier.verify(
            {
                "task": "Test task",
                "solution": "def test(): pass",
                "explanation": "Simple test",
                "test_cases": "assert True",
            }
        )

        assert isinstance(result, VerificationResult)
        assert result.outcome == VerificationOutcome.PASS
        assert result.confidence == 0.75
        assert "Mock verification" in result.reasoning

    def test_parse_verification_response_pass(self):
        """Test parsing a PASS verdict."""
        verifier = AnthropicVerifier(api_key="test-key")

        response = """
VERDICT: PASS
CONFIDENCE: 0.95
CRITICAL_ISSUES:
- None
LOGIC_FLAWS:
- None
MISSING_EDGE_CASES:
- None
REASONING:
The solution correctly implements the required functionality.
"""
        result = verifier._parse_verification_response(response)

        assert result.outcome == VerificationOutcome.PASS
        assert result.confidence == 0.95

    def test_parse_verification_response_fail(self):
        """Test parsing a FAIL verdict."""
        verifier = AnthropicVerifier(api_key="test-key")

        response = """
VERDICT: FAIL
CONFIDENCE: 0.85
CRITICAL_ISSUES:
- Off-by-one error in loop bounds
- Missing null check
LOGIC_FLAWS:
- Incorrect algorithm complexity
MISSING_EDGE_CASES:
- Empty input not handled
REASONING:
The solution has critical bugs that need to be fixed.
"""
        result = verifier._parse_verification_response(response)

        assert result.outcome == VerificationOutcome.FAIL
        assert result.confidence == 0.85
        assert len(result.critical_issues) == 2
        assert "Off-by-one error" in result.critical_issues[0]

    def test_parse_verification_response_uncertain(self):
        """Test parsing an UNCERTAIN verdict."""
        verifier = AnthropicVerifier(api_key="test-key")

        response = """
VERDICT: UNCERTAIN
CONFIDENCE: 0.5
CRITICAL_ISSUES:
LOGIC_FLAWS:
MISSING_EDGE_CASES:
- Some edge cases may not be covered
REASONING:
Unable to determine correctness without more context.
"""
        result = verifier._parse_verification_response(response)

        assert result.outcome == VerificationOutcome.UNCERTAIN
        assert result.confidence == 0.5

    def test_extract_section(self):
        """Test extracting bullet points from a section."""
        verifier = AnthropicVerifier(api_key="test-key")

        content = """
CRITICAL_ISSUES:
- First issue
- Second issue
• Third issue with bullet
LOGIC_FLAWS:
- A logic flaw
"""
        issues = verifier._extract_section(content, "CRITICAL_ISSUES")

        assert len(issues) == 3
        assert "First issue" in issues
        assert "Second issue" in issues
        assert "Third issue with bullet" in issues

    def test_extract_function_name(self):
        """Test extracting function name from code."""
        verifier = AnthropicVerifier(api_key="test-key")

        code = """
def longest_palindrome(s: str) -> str:
    if not s:
        return ""
    return s
"""
        name = verifier._extract_function_name(code)
        assert name == "longest_palindrome"

    def test_extract_function_name_no_function(self):
        """Test extracting function name when none exists."""
        verifier = AnthropicVerifier(api_key="test-key")

        code = "x = 5\nprint(x)"
        name = verifier._extract_function_name(code)
        assert name is None

    def test_generate_template_attack(self):
        """Test template attack generation."""
        verifier = AnthropicVerifier(api_key="test-key")

        code = "def factorial(n):\n    return 1 if n <= 1 else n * factorial(n-1)"
        attack = verifier._generate_template_attack(code)

        assert "factorial" in attack
        assert "-1" in attack  # Tests negative input

    def test_build_verification_prompt(self):
        """Test building the verification prompt."""
        verifier = AnthropicVerifier(api_key="test-key")

        context = {
            "task": "Write a sorting function",
            "solution": "def sort(arr): return sorted(arr)",
            "explanation": "Uses built-in sort",
            "test_cases": "assert sort([3,1,2]) == [1,2,3]",
        }

        prompt = verifier._build_verification_prompt(context)

        assert "sorting function" in prompt
        assert "def sort(arr)" in prompt
        assert "built-in sort" in prompt

    @patch("anthropic.Anthropic")
    def test_verify_with_mocked_api(self, mock_anthropic_class):
        """Test verification with mocked Anthropic API."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text="VERDICT: PASS\nCONFIDENCE: 0.9\nREASONING: Good code")
        ]
        mock_response.usage = MagicMock(input_tokens=100, output_tokens=50)

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_anthropic_class.return_value = mock_client

        verifier = AnthropicVerifier(api_key="test-key", enable_prosecutor_mode=False)
        verifier.client = mock_client

        result = verifier.verify(
            {
                "task": "Test task",
                "solution": "def test(): pass",
                "explanation": "Test",
                "test_cases": "assert True",
            }
        )

        assert result.outcome == VerificationOutcome.PASS
        mock_client.messages.create.assert_called_once()

    def test_prosecutor_mode_disabled(self):
        """Test that prosecutor mode can be disabled."""
        verifier = AnthropicVerifier(api_key="test-key", enable_prosecutor_mode=False)
        assert verifier.enable_prosecutor_mode is False
        assert verifier.sandbox is None

    def test_prosecutor_mode_enabled_by_default(self):
        """Test that prosecutor mode is enabled by default."""
        verifier = AnthropicVerifier(api_key="test-key")
        assert verifier.enable_prosecutor_mode is True


class TestAnthropicVerifierIntegration:
    """Integration tests requiring actual API access."""

    @pytest.mark.integration
    def test_real_verification(self):
        """Test real API verification (requires ANTHROPIC_API_KEY)."""
        import os

        if not os.getenv("ANTHROPIC_API_KEY"):
            pytest.skip("ANTHROPIC_API_KEY not set")

        verifier = AnthropicVerifier()
        result = verifier.verify(
            {
                "task": "Write a function that returns the sum of two numbers",
                "solution": "def add(a, b):\n    return a + b",
                "explanation": "Simple addition function",
                "test_cases": "assert add(2, 3) == 5",
            }
        )

        assert isinstance(result, VerificationResult)
        assert result.outcome in [
            VerificationOutcome.PASS,
            VerificationOutcome.FAIL,
            VerificationOutcome.UNCERTAIN,
        ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

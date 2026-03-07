"""
Tests for the Cross-Model Verification Kernel
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from cross_model_verification_kernel.generator import Generator, GeneratorConfig
from cross_model_verification_kernel.kernel import VerificationKernel
from cross_model_verification_kernel.models import MockModelInterface, ModelProvider
from cross_model_verification_kernel.verifier import Severity, Verifier, VerifierConfig


class TestModelProvider(unittest.TestCase):
    """Test model provider enumeration"""

    def test_model_providers_exist(self):
        """Test that all required model providers are defined"""
        self.assertIsNotNone(ModelProvider.GPT4O)
        self.assertIsNotNone(ModelProvider.GEMINI_15_PRO)
        self.assertIsNotNone(ModelProvider.CLAUDE_35_SONNET)

    def test_model_values(self):
        """Test model provider values"""
        self.assertEqual(ModelProvider.GPT4O.value, "gpt-4o")
        self.assertEqual(ModelProvider.GEMINI_15_PRO.value, "gemini-1.5-pro")


class TestMockModelInterface(unittest.TestCase):
    """Test mock model interface"""

    def test_mock_gpt_response(self):
        """Test GPT-style mock response"""
        interface = MockModelInterface(ModelProvider.GPT4O)
        response = interface.generate("generate code for fibonacci")

        self.assertIsNotNone(response.content)
        self.assertEqual(response.provider, ModelProvider.GPT4O)
        self.assertIn("fibonacci", response.content.lower())

    def test_mock_gemini_response(self):
        """Test Gemini-style mock response (hostile verification)"""
        interface = MockModelInterface(ModelProvider.GEMINI_15_PRO)
        response = interface.generate("verify this code")

        self.assertIsNotNone(response.content)
        self.assertEqual(response.provider, ModelProvider.GEMINI_15_PRO)
        # Gemini mock should find issues
        self.assertTrue(
            "CRITICAL" in response.content
            or "HIGH" in response.content
            or "issues" in response.content.lower()
        )


class TestGenerator(unittest.TestCase):
    """Test Generator component"""

    def test_generator_initialization(self):
        """Test generator initialization"""
        config = GeneratorConfig(model=ModelProvider.GPT4O)
        generator = Generator(config)

        self.assertEqual(generator.config.model, ModelProvider.GPT4O)
        self.assertEqual(generator.generation_count, 0)

    def test_code_generation(self):
        """Test code generation"""
        config = GeneratorConfig(model=ModelProvider.GPT4O)
        generator = Generator(config)

        result = generator.generate_code(
            task_description="Create a hello world function", language="python"
        )

        self.assertIsNotNone(result.code)
        self.assertEqual(result.language, "python")
        self.assertEqual(generator.generation_count, 1)

    def test_generator_stats(self):
        """Test generator statistics"""
        config = GeneratorConfig(model=ModelProvider.GPT4O)
        generator = Generator(config)
        generator.generate_code("test task")

        stats = generator.get_stats()
        self.assertEqual(stats["generation_count"], 1)
        self.assertEqual(stats["model"], "gpt-4o")


class TestVerifier(unittest.TestCase):
    """Test Verifier component"""

    def test_verifier_initialization(self):
        """Test verifier initialization"""
        config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)
        verifier = Verifier(config)

        self.assertEqual(verifier.config.model, ModelProvider.GEMINI_15_PRO)
        self.assertTrue(verifier.config.adversarial_mode)
        self.assertEqual(verifier.verification_count, 0)

    def test_code_verification(self):
        """Test code verification"""
        config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)
        verifier = Verifier(config)

        code = "def test(): pass"
        result = verifier.verify_code(code=code, description="A test function", language="python")

        self.assertIsNotNone(result.summary)
        self.assertEqual(result.code_reviewed, code)
        self.assertEqual(verifier.verification_count, 1)

    def test_adversarial_mode(self):
        """Test adversarial verification mode"""
        config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO, adversarial_mode=True)
        verifier = Verifier(config)

        # The mock Gemini should find issues in this basic code
        code = "def fibonacci(n): return fibonacci(n-1) + fibonacci(n-2)"
        result = verifier.verify_code(
            code=code, description="Calculate fibonacci", language="python"
        )

        # Should find issues
        self.assertGreater(len(result.issues), 0)

    def test_verifier_stats(self):
        """Test verifier statistics"""
        config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)
        verifier = Verifier(config)
        verifier.verify_code("def test(): pass", "test")

        stats = verifier.get_stats()
        self.assertEqual(stats["verification_count"], 1)
        self.assertEqual(stats["model"], "gemini-1.5-pro")


class TestVerificationKernel(unittest.TestCase):
    """Test the main Verification Kernel"""

    def test_kernel_enforces_model_diversity(self):
        """Test that kernel enforces different models"""
        generator_config = GeneratorConfig(model=ModelProvider.GPT4O)
        verifier_config = VerifierConfig(model=ModelProvider.GPT4O)

        # Should raise ValueError due to same model
        with self.assertRaises(ValueError) as context:
            VerificationKernel(generator_config, verifier_config)

        self.assertIn("DIFFERENT models", str(context.exception))

    def test_kernel_accepts_diverse_models(self):
        """Test that kernel accepts different models"""
        generator_config = GeneratorConfig(model=ModelProvider.GPT4O)
        verifier_config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)

        # Should work fine with different models
        kernel = VerificationKernel(generator_config, verifier_config)
        self.assertIsNotNone(kernel)

    def test_full_verification_pipeline(self):
        """Test complete verification pipeline"""
        generator_config = GeneratorConfig(model=ModelProvider.GPT4O)
        verifier_config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)

        kernel = VerificationKernel(generator_config, verifier_config)

        result = kernel.verify_task(
            task_description="Create a fibonacci function", language="python"
        )

        self.assertIsNotNone(result.generated_code)
        self.assertIsNotNone(result.verification_report)
        self.assertIsNotNone(result.blind_spot_analysis)
        self.assertNotEqual(result.generator_model, result.verifier_model)

    def test_blind_spot_calculation(self):
        """Test blind spot probability calculation"""
        generator_config = GeneratorConfig(model=ModelProvider.GPT4O)
        verifier_config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)

        kernel = VerificationKernel(generator_config, verifier_config)
        result = kernel.verify_task("test task")

        analysis = result.blind_spot_analysis

        # Combined error should be less than single model
        self.assertLess(analysis.combined_error_prob, analysis.single_model_error_prob)

        # Risk reduction should be greater than 1
        self.assertGreater(analysis.risk_reduction_factor, 1.0)

    def test_model_correlation_different_providers(self):
        """Test that different providers have low correlation"""
        # GPT (OpenAI) vs Gemini (Google) should have low correlation
        gen_config = GeneratorConfig(model=ModelProvider.GPT4O)
        ver_config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)

        kernel = VerificationKernel(gen_config, ver_config)
        result = kernel.verify_task("test")

        # Different providers should have correlation around 0.2
        self.assertLess(result.blind_spot_analysis.correlation_coefficient, 0.3)

    def test_model_correlation_same_provider(self):
        """Test that same provider models have higher correlation"""
        # GPT-4o vs GPT-4 Turbo (both OpenAI) should have higher correlation
        gen_config = GeneratorConfig(model=ModelProvider.GPT4O)
        ver_config = VerifierConfig(model=ModelProvider.GPT4_TURBO)

        kernel = VerificationKernel(gen_config, ver_config)
        result = kernel.verify_task("test")

        # Same provider should have correlation around 0.5
        self.assertGreater(result.blind_spot_analysis.correlation_coefficient, 0.4)

    def test_kernel_statistics(self):
        """Test kernel statistics"""
        gen_config = GeneratorConfig(model=ModelProvider.GPT4O)
        ver_config = VerifierConfig(model=ModelProvider.GEMINI_15_PRO)

        kernel = VerificationKernel(gen_config, ver_config)

        # Run multiple verifications
        for i in range(3):
            kernel.verify_task(f"task {i}")

        stats = kernel.get_statistics()

        self.assertEqual(stats["total_verifications"], 3)
        self.assertTrue(stats["model_diversity"]["are_different"])
        self.assertEqual(stats["generator"]["generation_count"], 3)
        self.assertEqual(stats["verifier"]["verification_count"], 3)


class TestSeverity(unittest.TestCase):
    """Test severity enumeration"""

    def test_severity_levels(self):
        """Test severity level definitions"""
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFO.value, "info")


if __name__ == "__main__":
    unittest.main()

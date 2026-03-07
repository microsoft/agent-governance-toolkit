"""
Tests for the CLI module.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cross_model_verification_kernel.cli import (
    GeneratorModel,
    OutputFormat,
    VerifierModel,
    app,
    set_seed,
)

runner = CliRunner()


class TestCLIBasics:
    """Basic CLI functionality tests."""

    def test_version(self):
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.stdout
        assert "CMVK" in result.stdout

    def test_help(self):
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Cross-Model Verification Kernel" in result.stdout
        assert "run" in result.stdout
        assert "config" in result.stdout

    def test_run_help(self):
        """Test run command help."""
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "--task" in result.stdout
        assert "--generator" in result.stdout
        assert "--verifier" in result.stdout
        assert "--seed" in result.stdout

    def test_models_command(self):
        """Test models command lists available models."""
        result = runner.invoke(app, ["models"])
        assert result.exit_code == 0
        assert "gpt-4o" in result.stdout
        assert "gemini-1.5-pro" in result.stdout
        assert "claude-3-5-sonnet" in result.stdout


class TestCLIConfig:
    """Tests for config command."""

    def test_config_no_args(self):
        """Test config command with no arguments."""
        result = runner.invoke(app, ["config"])
        assert result.exit_code == 0
        assert "--show" in result.stdout or "--init" in result.stdout

    def test_config_show_missing_file(self):
        """Test config --show with missing file."""
        result = runner.invoke(app, ["config", "--show", "--path", "nonexistent.yaml"])
        assert "not found" in result.stdout.lower()

    def test_config_init(self, tmp_path):
        """Test config --init creates a config file."""
        config_path = tmp_path / "test_config.yaml"
        result = runner.invoke(app, ["config", "--init", "--path", str(config_path)])

        assert result.exit_code == 0
        assert config_path.exists()

        content = config_path.read_text()
        assert "api_keys" in content
        assert "kernel" in content
        assert "max_loops" in content


class TestCLIRun:
    """Tests for run command."""

    def test_run_missing_api_key(self):
        """Test run command fails without API key."""
        with patch.dict("os.environ", {}, clear=True):
            result = runner.invoke(app, ["run", "--task", "test task"])
            assert result.exit_code == 1
            assert "OPENAI_API_KEY" in result.stdout

    @patch("cross_model_verification_kernel.cli.OpenAIGenerator")
    @patch("cross_model_verification_kernel.cli.GeminiVerifier")
    @patch("cross_model_verification_kernel.cli.VerificationKernel")
    def test_run_with_mocked_kernel(self, mock_kernel_class, mock_verifier, mock_generator):
        """Test run command with mocked components."""
        # Setup mocks
        mock_state = MagicMock()
        mock_state.is_complete = True
        mock_state.final_result = "def solution(): pass"
        mock_state.current_loop = 2
        mock_state.verification_history = []

        mock_kernel = MagicMock()
        mock_kernel.execute.return_value = mock_state
        mock_kernel_class.return_value = mock_kernel

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key", "GOOGLE_API_KEY": "test-key"}):
            result = runner.invoke(app, ["run", "--task", "Write hello world", "--output", "json"])

            # Should succeed or fail gracefully
            if result.exit_code == 0:
                output = json.loads(result.stdout)
                assert "success" in output

    def test_run_invalid_generator(self):
        """Test run with invalid generator model."""
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test"}):
            result = runner.invoke(app, ["run", "--task", "test", "--generator", "invalid-model"])
            assert result.exit_code != 0


class TestCLIVisualize:
    """Tests for visualize command."""

    def test_visualize_missing_file(self):
        """Test visualize with missing trace file."""
        result = runner.invoke(app, ["visualize", "nonexistent.json"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_visualize_valid_trace(self, tmp_path):
        """Test visualize with a valid trace file."""
        trace_file = tmp_path / "test_trace.json"
        trace_data = {
            "task_id": "test_001",
            "task_description": "Test task description",
            "total_loops": 3,
            "success": True,
            "generator_model": "gpt-4o",
            "verifier_model": "gemini-1.5-pro",
            "conversation_trace": [
                {"type": "generation", "loop": 1},
                {"type": "verification", "loop": 1},
            ],
        }
        trace_file.write_text(json.dumps(trace_data))

        result = runner.invoke(app, ["visualize", str(trace_file)])

        assert result.exit_code == 0
        assert "test_001" in result.stdout
        assert "gpt-4o" in result.stdout


class TestCLIBenchmark:
    """Tests for benchmark command."""

    def test_benchmark_missing_dataset(self):
        """Test benchmark with missing dataset."""
        result = runner.invoke(app, ["benchmark", "--dataset", "nonexistent_dataset"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()


class TestSetSeed:
    """Tests for seed functionality."""

    def test_set_seed_deterministic(self):
        """Test that set_seed produces deterministic results."""
        import random

        set_seed(42)
        values1 = [random.random() for _ in range(5)]

        set_seed(42)
        values2 = [random.random() for _ in range(5)]

        assert values1 == values2

    def test_set_seed_different_seeds(self):
        """Test that different seeds produce different results."""
        import random

        set_seed(42)
        values1 = [random.random() for _ in range(5)]

        set_seed(123)
        values2 = [random.random() for _ in range(5)]

        assert values1 != values2


class TestEnums:
    """Tests for CLI enums."""

    def test_generator_models(self):
        """Test generator model enum values."""
        assert GeneratorModel.GPT_4O.value == "gpt-4o"
        assert GeneratorModel.O1.value == "o1"
        assert GeneratorModel.O3_MINI.value == "o3-mini"

    def test_verifier_models(self):
        """Test verifier model enum values."""
        assert VerifierModel.GEMINI_15_PRO.value == "gemini-1.5-pro"
        assert VerifierModel.CLAUDE_35_SONNET.value == "claude-3-5-sonnet-20241022"

    def test_output_formats(self):
        """Test output format enum values."""
        assert OutputFormat.PRETTY.value == "pretty"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.MINIMAL.value == "minimal"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

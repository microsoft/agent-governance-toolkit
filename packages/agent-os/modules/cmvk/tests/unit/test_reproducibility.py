"""
Tests for reproducibility and seed functionality.
"""

import random
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cross_model_verification_kernel.core.kernel import VerificationKernel, set_reproducibility_seed


class TestReproducibilitySeed:
    """Tests for the reproducibility seed functionality."""

    def test_set_reproducibility_seed_random(self):
        """Test that seed affects Python's random module."""
        set_reproducibility_seed(42)
        values1 = [random.random() for _ in range(10)]

        set_reproducibility_seed(42)
        values2 = [random.random() for _ in range(10)]

        assert values1 == values2

    def test_set_reproducibility_seed_different_seeds(self):
        """Test that different seeds produce different results."""
        set_reproducibility_seed(42)
        values1 = [random.random() for _ in range(10)]

        set_reproducibility_seed(99)
        values2 = [random.random() for _ in range(10)]

        assert values1 != values2

    def test_set_reproducibility_seed_numpy(self):
        """Test that seed affects numpy if available."""
        try:
            import numpy as np

            set_reproducibility_seed(42)
            values1 = np.random.rand(10).tolist()

            set_reproducibility_seed(42)
            values2 = np.random.rand(10).tolist()

            assert values1 == values2
        except ImportError:
            pytest.skip("NumPy not installed")

    def test_set_reproducibility_seed_hash_env(self):
        """Test that PYTHONHASHSEED is set."""
        import os

        set_reproducibility_seed(12345)
        assert os.environ.get("PYTHONHASHSEED") == "12345"


class TestKernelWithSeed:
    """Tests for VerificationKernel seed functionality."""

    @pytest.fixture
    def mock_agents(self):
        """Create mock generator and verifier agents."""
        mock_gen = MagicMock()
        mock_gen.model_name = "test-generator"

        mock_ver = MagicMock()
        mock_ver.model_name = "test-verifier"

        return mock_gen, mock_ver

    def test_kernel_init_with_seed(self, mock_agents):
        """Test kernel initialization with seed parameter."""
        gen, ver = mock_agents

        with patch.object(VerificationKernel, "_load_config", return_value={}):
            kernel = VerificationKernel(generator=gen, verifier=ver, seed=42)

            assert kernel.seed == 42

    def test_kernel_init_without_seed(self, mock_agents):
        """Test kernel initialization without seed."""
        gen, ver = mock_agents

        with patch.object(VerificationKernel, "_load_config", return_value={}):
            kernel = VerificationKernel(generator=gen, verifier=ver)

            assert kernel.seed is None

    def test_kernel_seed_from_config(self, mock_agents):
        """Test kernel reads seed from config file."""
        gen, ver = mock_agents

        config = {"kernel": {"seed": 123, "max_loops": 5, "confidence_threshold": 0.85}}

        with patch.object(VerificationKernel, "_load_config", return_value=config):
            kernel = VerificationKernel(generator=gen, verifier=ver)

            assert kernel.seed == 123

    def test_kernel_explicit_seed_overrides_config(self, mock_agents):
        """Test that explicit seed parameter overrides config."""
        gen, ver = mock_agents

        config = {"kernel": {"seed": 123, "max_loops": 5}}

        with patch.object(VerificationKernel, "_load_config", return_value=config):
            kernel = VerificationKernel(generator=gen, verifier=ver, seed=456)

            # Explicit seed should be used
            assert kernel.seed == 456


class TestDeterministicExecution:
    """Tests to verify deterministic behavior with seeds."""

    def test_random_choices_deterministic(self):
        """Test that random.choice is deterministic with seed."""
        options = ["a", "b", "c", "d", "e"]

        set_reproducibility_seed(42)
        choices1 = [random.choice(options) for _ in range(20)]

        set_reproducibility_seed(42)
        choices2 = [random.choice(options) for _ in range(20)]

        assert choices1 == choices2

    def test_random_shuffle_deterministic(self):
        """Test that random.shuffle is deterministic with seed."""
        set_reproducibility_seed(42)
        list1 = [1, 2, 3, 4, 5]
        random.shuffle(list1)

        set_reproducibility_seed(42)
        list2 = [1, 2, 3, 4, 5]
        random.shuffle(list2)

        assert list1 == list2

    def test_random_sample_deterministic(self):
        """Test that random.sample is deterministic with seed."""
        population = list(range(100))

        set_reproducibility_seed(42)
        sample1 = random.sample(population, 10)

        set_reproducibility_seed(42)
        sample2 = random.sample(population, 10)

        assert sample1 == sample2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

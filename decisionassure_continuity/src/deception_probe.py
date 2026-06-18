from typing import List, Dict, Any, Optional
from src.models import DeceptionProbeResult
import numpy as np
from datetime import datetime

class DeceptionProbe:
    """
    Real-time internal activation monitoring for jailbreak detection.
    Inspired by representation engineering research.
    """

    def __init__(self, threshold: float = 0.7, dim: int = 768):
        self.threshold = threshold
        self.probe_weights = np.random.randn(dim) * 0.01  # Dummy probe

    def scan_activation(self, hidden_state: List[float], layer: str = "layer_12") -> DeceptionProbeResult:
        """
        Scan a hidden state for harmful intent patterns.
        """
        # Convert to numpy array
        state = np.array(hidden_state)

        # Align to probe weights
        if len(state) < len(self.probe_weights):
            padded = np.zeros(len(self.probe_weights))
            padded[:len(state)] = state
            state = padded
        else:
            state = state[:len(self.probe_weights)]

        # Compute activation score
        score = float(np.dot(state, self.probe_weights))
        # Normalize to 0-1
        score = 1.0 / (1.0 + np.exp(-score))

        harmful_detected = score >= self.threshold

        # Activation pattern summary
        pattern = {
            "mean": float(np.mean(state)),
            "std": float(np.std(state)),
            "max": float(np.max(state)),
            "min": float(np.min(state))
        }

        return DeceptionProbeResult(
            harmful_intent_detected=harmful_detected,
            confidence_score=score,
            generation_denied=harmful_detected,
            probe_layer=layer,
            activation_pattern=pattern,
            timestamp=datetime.now()
        )

    def train_probe(self, positive_samples: List[np.ndarray], negative_samples: List[np.ndarray]) -> None:
        """
        Train the probe on labelled samples (placeholder implementation).
        In production, use logistic regression or linear probing.
        """
        # Dummy training – in practice, implement proper training
        # For example, use sklearn.linear_model.LogisticRegression
        dim = positive_samples[0].shape[0] if positive_samples else 768
        self.probe_weights = np.random.randn(dim) * 0.01
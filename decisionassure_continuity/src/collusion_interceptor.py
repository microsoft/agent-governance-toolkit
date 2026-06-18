from typing import List, Dict, Any, Optional
from src.models import CollusionDetectionResult
import numpy as np
from datetime import datetime

class CollusionInterceptor:
    """
    Runtime multi-agent collusion detection using activation alignment.
    Inspired by Om Tailor's "Audit the Whisper" research.
    """

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
        self.suspicion_history: List[float] = []
        self.agents: Dict[str, Dict[str, Any]] = {}

    def register_agent(self, agent_id: str, activation_vector: List[float]) -> None:
        """Register an agent with its current activation state."""
        self.agents[agent_id] = {
            "activation": np.array(activation_vector),
            "last_seen": datetime.now()
        }

    def compute_alignment(self, agent_a: str, agent_b: str) -> float:
        """Compute cosine similarity between two agents' activations."""
        if agent_a not in self.agents or agent_b not in self.agents:
            return 0.0
        vec_a = self.agents[agent_a]["activation"]
        vec_b = self.agents[agent_b]["activation"]
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(vec_a, vec_b) / (norm_a * norm_b))

    def detect_collusion(self, agents: List[str]) -> CollusionDetectionResult:
        """
        Detect collusion by analyzing cross-agent alignment spikes.
        """
        if len(agents) < 2:
            return CollusionDetectionResult(
                suspicion_score=0.0,
                threshold=self.threshold,
                collusion_detected=False,
                agents_involved=[],
                alignment_spikes=[],
                decision="ADMIT"
            )

        alignment_scores = []
        for i in range(len(agents)):
            for j in range(i + 1, len(agents)):
                score = self.compute_alignment(agents[i], agents[j])
                alignment_scores.append({
                    "agent_a": agents[i],
                    "agent_b": agents[j],
                    "score": score
                })

        # Calculate suspicion score as average of top alignment scores
        scores = [s["score"] for s in alignment_scores]
        avg_score = np.mean(scores) if scores else 0.0
        max_score = max(scores) if scores else 0.0

        # Suspicion = weighted combination of avg and max
        suspicion_score = (avg_score * 0.4) + (max_score * 0.6)
        suspicion_score = min(suspicion_score, 1.0)

        collusion_detected = suspicion_score >= self.threshold

        # Determine decision
        decision = "DENY" if collusion_detected else "ADMIT"

        self.suspicion_history.append(suspicion_score)

        return CollusionDetectionResult(
            suspicion_score=suspicion_score,
            threshold=self.threshold,
            collusion_detected=collusion_detected,
            agents_involved=agents,
            alignment_spikes=alignment_scores,
            decision=decision,
            timestamp=datetime.now()
        )

    def get_suspicion_history(self) -> List[float]:
        """Return the suspicion score history."""
        return self.suspicion_history
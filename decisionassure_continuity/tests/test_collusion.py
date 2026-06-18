import pytest
from src.collusion_interceptor import CollusionInterceptor

def test_collusion_orthogonal():
    interceptor = CollusionInterceptor(threshold=0.7)
    interceptor.register_agent("alice", [1.0, 0.0, 0.0])
    interceptor.register_agent("bob", [0.0, 1.0, 0.0])
    result = interceptor.detect_collusion(["alice", "bob"])
    assert result.suspicion_score < 0.1
    assert result.collusion_detected is False

def test_collusion_similar():
    interceptor = CollusionInterceptor(threshold=0.9)
    interceptor.register_agent("alice", [0.9, 0.8, 0.7])
    interceptor.register_agent("bob", [0.85, 0.78, 0.68])
    result = interceptor.detect_collusion(["alice", "bob"])
    assert result.suspicion_score > 0.9
    assert result.collusion_detected is True
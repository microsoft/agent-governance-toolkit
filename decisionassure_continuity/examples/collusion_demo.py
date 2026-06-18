#!/usr/bin/env python3
"""Multi-agent collusion detection demo."""

from src.collusion_interceptor import CollusionInterceptor

def main():
    interceptor = CollusionInterceptor(threshold=0.7)

    # Simulate three agents with steganographic coordination
    # Alice and Bob have high alignment (colluding), Charlie is independent
    interceptor.register_agent("alice", [0.9, 0.8, 0.7, 0.6])
    interceptor.register_agent("bob", [0.85, 0.78, 0.68, 0.58])
    interceptor.register_agent("charlie", [0.2, 0.3, 0.1, 0.4])

    result = interceptor.detect_collusion(["alice", "bob", "charlie"])

    print("\n🚨 Collusion Detection Result")
    print(f"Suspicion Score: {result.suspicion_score:.4f}")
    print(f"Threshold: {result.threshold}")
    print(f"Collusion Detected: {result.collusion_detected}")
    print(f"Decision: {result.decision}")
    print(f"Agents Involved: {result.agents_involved}")

if __name__ == "__main__":
    main()
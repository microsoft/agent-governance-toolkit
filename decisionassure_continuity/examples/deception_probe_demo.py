#!/usr/bin/env python3
"""Deception probe demonstration."""

from src.deception_probe import DeceptionProbe

def main():
    probe = DeceptionProbe(threshold=0.6)

    # Simulate a hidden state from a model processing a benign prompt
    benign_state = [0.1] * 768
    result_benign = probe.scan_activation(benign_state)
    print("\n✅ Benign Prompt")
    print(f"Harmful Intent Detected: {result_benign.harmful_intent_detected}")
    print(f"Confidence: {result_benign.confidence_score:.4f}")

    # Simulate a hidden state from a model processing a jailbreak prompt
    # Here we artificially inject a pattern (in practice, this would come from the model)
    jailbreak_state = [0.9] * 768
    result_jailbreak = probe.scan_activation(jailbreak_state)
    print("\n🚨 Jailbreak Prompt")
    print(f"Harmful Intent Detected: {result_jailbreak.harmful_intent_detected}")
    print(f"Confidence: {result_jailbreak.confidence_score:.4f}")
    print(f"Generation Denied: {result_jailbreak.generation_denied}")

if __name__ == "__main__":
    main()
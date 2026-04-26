# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmark suite for crypto operations (#117).

Measures Ed25519 key generation, signing, verification, DID derivation,
and full trust handshake latency. Target: <10 ms for handshake on
commodity hardware.

Run benchmarks only:
    pytest tests/test_benchmarks.py -v -m benchmark
"""

import asyncio
import base64
import statistics
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from agentmesh.identity.agent_id import AgentDID, AgentIdentity, IdentityRegistry
from agentmesh.trust.handshake import TrustHandshake

# Mark every test in this module as a benchmark
pytestmark = pytest.mark.benchmark

ITERATIONS = 100
PAYLOAD_1KB = b"x" * 1024


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bench(fn, n: int = ITERATIONS) -> dict:
    """Run *fn* n times and return timing stats in milliseconds."""
    times: list[float] = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return {
        "min_ms": min(times),
        "max_ms": max(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
        "iterations": n,
    }


def _make_identity(name: str = "bench") -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=["read", "write"],
    )


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

class TestCryptoBenchmarks:
    """Crypto operation benchmarks."""

    def test_ed25519_keygen(self):
        """Benchmark Ed25519 key generation."""
        stats = _bench(ed25519.Ed25519PrivateKey.generate)
        print(f"\nEd25519 keygen: {stats['mean_ms']:.3f} ms mean ({stats['iterations']} iters)")
        # Sanity: key generation should complete
        assert stats["mean_ms"] < 100  # generous upper bound

    def test_message_signing_1kb(self):
        """Benchmark signing a 1 KB payload."""
        identity = _make_identity()

        def sign():
            identity.sign(PAYLOAD_1KB)

        stats = _bench(sign)
        print(f"\nSign 1KB: {stats['mean_ms']:.3f} ms mean ({stats['iterations']} iters)")
        assert stats["mean_ms"] < 50

    def test_signature_verification_1kb(self):
        """Benchmark verifying a signature on a 1 KB payload."""
        identity = _make_identity()
        sig = identity.sign(PAYLOAD_1KB)

        def verify():
            identity.verify_signature(PAYLOAD_1KB, sig)

        stats = _bench(verify)
        print(f"\nVerify 1KB: {stats['mean_ms']:.3f} ms mean ({stats['iterations']} iters)")
        assert stats["mean_ms"] < 50

    def test_did_derivation(self):
        """Benchmark DID derivation from public key."""

        def derive():
            AgentDID.generate("bench-agent", org="bench-org")

        stats = _bench(derive)
        print(f"\nDID derivation: {stats['mean_ms']:.3f} ms mean ({stats['iterations']} iters)")
        assert stats["mean_ms"] < 50

    @pytest.mark.asyncio
    async def test_trust_handshake_completion(self):
        """Benchmark full handshake between two agents (<10 ms target)."""
        agent_a = _make_identity("hs-a")
        agent_b = _make_identity("hs-b")
        registry = IdentityRegistry()
        registry.register(agent_a)
        registry.register(agent_b)

        times: list[float] = []
        for _ in range(ITERATIONS):
            hs = TrustHandshake(
                agent_did=str(agent_a.did), identity=agent_a, registry=registry,
            )
            start = time.perf_counter()
            result = await hs.initiate(
                peer_did=str(agent_b.did),
                required_trust_score=500,
                use_cache=False,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)
            assert result.verified, f"Handshake failed: {result.rejection_reason}"

        mean_ms = statistics.mean(times)
        median_ms = statistics.median(times)
        print(
            f"\nHandshake: mean={mean_ms:.1f} ms, median={median_ms:.1f} ms "
            f"({ITERATIONS} iters)"
        )
        # The crypto portion targets <10 ms; allow a realistic
        # upper bound of 200 ms for slow CI.
        assert mean_ms < 200

    def test_identity_creation(self):
        """Benchmark full AgentIdentity.create (keygen + DID + model)."""
        stats = _bench(lambda: _make_identity("bench-create"))
        print(
            f"\nIdentity.create: {stats['mean_ms']:.3f} ms mean "
            f"({stats['iterations']} iters)"
        )
        assert stats["mean_ms"] < 100

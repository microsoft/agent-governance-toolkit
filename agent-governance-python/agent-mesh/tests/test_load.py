# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Load test for concurrent handshakes (#120).

Simulates 100+ simultaneous trust handshakes and reports throughput,
latency percentiles, and peak memory usage.

Run:
    pytest tests/test_load.py -v -m slow -s
"""

import asyncio
import statistics
import time
import tracemalloc

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.trust.handshake import TrustHandshake

NUM_AGENTS = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=["read", "write"],
    )


async def _single_handshake(
    initiator: AgentIdentity,
    peer: AgentIdentity,
    registry=None,
) -> float:
    """Run one handshake and return elapsed time in seconds."""
    hs = TrustHandshake(
        agent_did=str(initiator.did), identity=initiator, registry=registry,
    )
    start = time.perf_counter()
    result = await hs.initiate(
        peer_did=str(peer.did),
        required_trust_score=500,
        use_cache=False,
    )
    elapsed = time.perf_counter() - start
    assert result.verified, f"Handshake failed: {result.rejection_reason}"
    return elapsed


def _percentile(data: list[float], pct: float) -> float:
    """Return the *pct*-th percentile (0-100) of *data*."""
    s = sorted(data)
    idx = int(len(s) * pct / 100)
    idx = min(idx, len(s) - 1)
    return s[idx]


# ---------------------------------------------------------------------------
# Load test
# ---------------------------------------------------------------------------

@pytest.mark.slow
class TestConcurrentHandshakes:
    """Load test: 100 concurrent trust handshakes."""

    @pytest.mark.asyncio
    async def test_concurrent_handshakes(self):
        """Create 100 agents and run 100 parallel handshakes.

        Measures total time, throughput, latency percentiles, and peak memory.
        All handshakes must succeed.
        """
        # 1. Create agent identities
        agents = [_make_identity(f"agent-{i}") for i in range(NUM_AGENTS)]

        # Use a fixed "server" agent that every agent handshakes with
        server = _make_identity("server-agent")

        # Build a shared registry containing all agents + server
        registry = IdentityRegistry()
        registry.register(server)
        for agent in agents:
            registry.register(agent)

        # 2. Run handshakes concurrently
        tracemalloc.start()
        wall_start = time.perf_counter()

        latencies = await asyncio.gather(
            *[_single_handshake(agent, server, registry=registry) for agent in agents]
        )

        wall_elapsed = time.perf_counter() - wall_start
        _, peak_mem_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # 3. Compute stats
        throughput = NUM_AGENTS / wall_elapsed
        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)
        peak_mem_mb = peak_mem_bytes / (1024 * 1024)

        # 4. Print report
        print(f"\n{'=' * 60}")
        print(f"  Concurrent Handshake Load Test — {NUM_AGENTS} agents")
        print(f"{'=' * 60}")
        print(f"  Total wall time : {wall_elapsed:.2f} s")
        print(f"  Throughput       : {throughput:.1f} handshakes/sec")
        print(f"  Latency p50      : {p50 * 1000:.1f} ms")
        print(f"  Latency p95      : {p95 * 1000:.1f} ms")
        print(f"  Latency p99      : {p99 * 1000:.1f} ms")
        print(f"  Peak memory      : {peak_mem_mb:.1f} MB")
        print(f"{'=' * 60}")

        # 5. Assertions
        assert len(latencies) == NUM_AGENTS, "Not all handshakes completed"
        # All latencies should be > 0
        assert all(lat > 0 for lat in latencies)
        # Throughput sanity (should handle at least 10 hs/sec even on slow CI)
        assert throughput > 10, f"Throughput too low: {throughput:.1f} hs/sec"

    @pytest.mark.asyncio
    async def test_all_handshakes_succeed(self):
        """Every handshake in a 100-agent burst must verify successfully."""
        agents = [_make_identity(f"v-agent-{i}") for i in range(NUM_AGENTS)]
        server = _make_identity("v-server")

        registry = IdentityRegistry()
        registry.register(server)
        for agent in agents:
            registry.register(agent)

        async def _check(agent: AgentIdentity) -> bool:
            hs = TrustHandshake(
                agent_did=str(agent.did), identity=agent, registry=registry,
            )
            result = await hs.initiate(
                peer_did=str(server.did),
                required_trust_score=500,
                use_cache=False,
            )
            return result.verified

        results = await asyncio.gather(*[_check(a) for a in agents])
        assert all(results), f"{results.count(False)} handshakes failed"

# Performance Benchmarks

> **Last updated:** March 2026 · **Toolkit version:** 2.1.0 · **Python:** 3.13 · **OS:** Windows 11 (AMD64)
>
> All benchmarks use `time.perf_counter()` with 10,000 iterations (unless noted).
> Numbers are from a development workstation — CI runs on `ubuntu-latest` GitHub-hosted runners.

## TL;DR

| What you care about | Number |
|---|---|
| **Policy evaluation (single rule)** | **0.011 ms** (p50) — 84K ops/sec |
| **Policy evaluation (100 rules)** | **0.030 ms** (p50) — 32K ops/sec |
| **Kernel enforcement (allow path)** | **0.103 ms** (p50) — 9.7K ops/sec |
| **Adapter governance overhead** | **0.005–0.007 ms** (p50) — 135K–190K ops/sec |
| **Circuit breaker check** | **0.0005 ms** (p50) — 1.83M ops/sec |
| **Concurrent throughput (50 agents)** | **46,329 ops/sec** |
| **Concurrent throughput (1,000 agents)** | **47,085 ops/sec** |

**Bottom line:** Policy enforcement adds **< 0.1 ms** per action. At 1,000 concurrent agents, the governance layer sustains **47K ops/sec** with near-linear scaling — your LLM API call is 1,000–10,000× slower.

---

## 1. Policy Evaluation

Measures `PolicyEvaluator.evaluate()` — the core enforcement path every agent action passes through.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Single rule evaluation | 84,489 | 0.011 | 0.014 | 0.037 |
| 10-rule policy | 76,406 | 0.012 | 0.017 | 0.049 |
| 100-rule policy | 32,025 | 0.030 | 0.039 | 0.108 |
| SharedPolicy cross-project eval | 116,454 | 0.008 | 0.010 | 0.028 |
| YAML policy load (cold, 10 rules) | 112 | 8.432 | 12.717 | 17.763 |

**Key takeaway:** Rule count scales linearly. Even with 100 rules, p99 is under 0.11 ms. YAML loading is a cold-start cost (once per deployment, not per action).

Source: [`packages/agent-os/benchmarks/bench_policy.py`](packages/agent-os/benchmarks/bench_policy.py)

## 2. Kernel Enforcement

Measures `StatelessKernel.execute()` — the full enforcement path including policy evaluation, audit logging, and execution context management.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Kernel execute (allow) | 9,668 | 0.103 | 0.198 | 0.347 |
| Kernel execute (deny) | 10,239 | 0.097 | 0.191 | 0.322 |
| Circuit breaker state check | 1,828,845 | 0.001 | 0.001 | 0.001 |

### Concurrent Throughput (Scaling)

| Concurrency | Total ops | Wall time (s) | ops/sec | vs. single-threaded |
|---:|---:|---:|---:|---|
| 50 agents × 200 ops | 10,000 | 0.216 | 46,329 | 4.8× |
| 100 agents × 100 ops | 10,000 | 0.209 | 47,920 | 5.0× |
| 500 agents × 100 ops | 50,000 | 1.085 | 46,089 | 4.8× |
| **1,000 agents × 100 ops** | **100,000** | **2.124** | **47,085** | **4.9×** |

**Key takeaway:** Throughput is **stable at ~47K ops/sec** from 50 to 1,000 concurrent agents — no degradation at scale. The deny path is slightly faster than allow (no downstream execution). Circuit breaker overhead is negligible (sub-microsecond).

Source: [`packages/agent-os/benchmarks/bench_kernel.py`](packages/agent-os/benchmarks/bench_kernel.py)

## 3. Audit System

Measures audit entry creation, querying, and serialization — the observability overhead.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Audit entry write | 285,202 | 0.002 | 0.006 | 0.008 |
| Audit entry serialization | 343,548 | 0.003 | 0.003 | 0.004 |
| Execution time tracking | 442,206 | 0.002 | 0.002 | 0.003 |
| Audit log query (10K entries) | 1,399 | 0.716 | 0.877 | 1.076 |

**Key takeaway:** Audit writes add ~2 µs per action. Querying 10K entries takes ~0.7 ms (in-memory scan). For production deployments, external append-only stores (e.g., OpenTelemetry export) are recommended for large-scale query workloads.

Source: [`packages/agent-os/benchmarks/bench_audit.py`](packages/agent-os/benchmarks/bench_audit.py)

## 4. Framework Adapter Overhead

Measures the governance check overhead per framework adapter — the cost added to each tool call or agent step.

| Adapter | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| GovernancePolicy init (startup) | 134,923 | 0.007 | 0.008 | 0.019 |
| Tool allowed check | 3,745,036 | 0.000 | 0.000 | 0.000 |
| Pattern match (per call) | 135,717 | 0.007 | 0.008 | 0.022 |
| **OpenAI** adapter | 166,363 | 0.005 | 0.007 | 0.017 |
| **LangChain** adapter | 156,591 | 0.006 | 0.007 | 0.019 |
| **Anthropic** adapter | 164,194 | 0.006 | 0.008 | 0.017 |
| **LlamaIndex** adapter | 156,157 | 0.006 | 0.007 | 0.016 |
| **CrewAI** adapter | 190,134 | 0.005 | 0.006 | 0.013 |
| **AutoGen** adapter | 169,358 | 0.005 | 0.007 | 0.018 |
| **Google Gemini** adapter | 180,770 | 0.006 | 0.006 | 0.011 |
| **Mistral** adapter | 182,439 | 0.005 | 0.006 | 0.015 |
| **Semantic Kernel** adapter | 170,930 | 0.005 | 0.007 | 0.014 |

**Key takeaway:** All adapters add **< 0.02 ms** (p99) per tool call. This is 3–4 orders of magnitude below a typical LLM API round-trip (200–2000 ms). The governance layer is invisible to end users.

Source: [`packages/agent-os/benchmarks/bench_adapters.py`](packages/agent-os/benchmarks/bench_adapters.py)

## 5. Agent SRE (Reliability Engineering)

Measures chaos engineering, SLO enforcement, and observability primitives.

| Benchmark | ops/sec | p50 (µs) | p99 (µs) |
|---|---:|---:|---:|
| Fault injection | 428,253 | 1.20 | 6.60 |
| Chaos template init | 98,889 | 9.10 | 18.50 |
| Chaos schedule eval | 168,380 | 5.30 | 7.60 |
| SLO evaluation | 29,475 | 30.10 | 96.60 |
| Error budget calculation | 29,851 | 31.70 | 111.70 |
| Burn rate alert | 25,543 | 37.10 | 116.20 |
| SLI recording | 284,274 | 2.40 | 11.10 |

**Key takeaway:** SRE operations are sub-120 µs at p99. SLI recording (the hot path for every action) is ~2.4 µs. These can run alongside every agent action without measurable impact.

Source: [`packages/agent-sre/benchmarks/`](packages/agent-sre/benchmarks/)

## 6. Memory Footprint

Measured with `tracemalloc` — PolicyEvaluator with 100 rules, 1,000 evaluations:

| Metric | Value |
|---|---|
| Evaluator instance (100 rules) | ~2 KB |
| Per-evaluation context overhead | ~0.5 KB |
| Peak process memory (Python runtime + evaluator + 1K evals) | ~126 MB |

> **Note:** The 126 MB peak includes the entire Python runtime, standard library, and imported modules. The evaluator itself is a small fraction. For comparison, a bare `python -c "pass"` process uses ~15 MB.

## Methodology

### Hardware

These benchmarks were run on a development workstation. CI runs on GitHub-hosted `ubuntu-latest` runners (2-core, 7 GB RAM). Expect ±20% variance between runs due to shared infrastructure.

### Measurement

- **Timer:** `time.perf_counter()` (nanosecond resolution)
- **Iterations:** 10,000 per benchmark (100,000 for circuit breaker, 1,000 for YAML load)
- **Percentiles:** Sorted latency array, index-based selection
- **Warm-up:** None (benchmarks measure cold-start-inclusive performance)

### Reproducing

```bash
# Clone and install
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit

# Policy, kernel, audit, adapter benchmarks
cd packages/agent-os
pip install -e ".[dev]"
python benchmarks/bench_policy.py
python benchmarks/bench_kernel.py
python benchmarks/bench_audit.py
python benchmarks/bench_adapters.py

# SRE benchmarks
cd ../agent-sre
pip install -e ".[dev]"
python benchmarks/bench_chaos.py
python benchmarks/bench_slo.py

# Custom concurrency levels (default: 50 agents × 200 ops)
python -c "
from benchmarks.bench_kernel import bench_concurrent_kernel
import json
result = bench_concurrent_kernel(concurrency=1000, per_task=100)
print(json.dumps(result, indent=2))
"
```

### CI Integration

Benchmarks run automatically on every release via the [`benchmarks.yml`](.github/workflows/benchmarks.yml) workflow. Results are uploaded as workflow artifacts for comparison across releases.

## Comparison Context

For context, here's where the governance overhead sits relative to typical agent operations:

| Operation | Typical latency |
|---|---|
| **Policy evaluation (this toolkit)** | **0.01–0.03 ms** |
| **Full kernel enforcement** | **0.10 ms** |
| **Adapter overhead** | **0.005–0.007 ms** |
| Python function call | 0.001 ms |
| Redis read (local) | 0.1–0.5 ms |
| Database query (simple) | 1–10 ms |
| LLM API call (GPT-4) | 200–2,000 ms |
| LLM API call (Claude Sonnet) | 300–3,000 ms |

The governance layer adds less overhead than a single Redis read and is **10,000× faster than an LLM call**.

## Version History

| Version | Date | Notable changes |
|---|---|---|
| v2.1.0 | March 2026 | Added 1K concurrent agent benchmarks, ~15% faster policy eval vs v1.1.x |
| v1.1.0 | February 2026 | Initial published benchmarks |
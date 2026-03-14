# Performance Benchmarks

> **Last updated:** March 2026 · **VADP version:** 0.3.x · **Python:** 3.13 · **OS:** Windows 11 (AMD64)
>
> All benchmarks use `time.perf_counter()` with 10,000 iterations (unless noted).
> Numbers are from a development workstation — CI runs on `ubuntu-latest` GitHub-hosted runners.

## TL;DR

| What you care about | Number |
|---|---|
| **Policy evaluation (single rule)** | **0.012 ms** (p50) — 72K ops/sec |
| **Policy evaluation (100 rules)** | **0.029 ms** (p50) — 31K ops/sec |
| **Kernel enforcement (allow path)** | **0.091 ms** (p50) — 9.3K ops/sec |
| **Adapter governance overhead** | **0.004–0.006 ms** (p50) — 130K–230K ops/sec |
| **Circuit breaker check** | **0.0005 ms** (p50) — 1.66M ops/sec |
| **Concurrent throughput (50 agents)** | **35,481 ops/sec** |

**Bottom line:** Policy enforcement adds **< 0.1 ms** per action. At 1,000 concurrent agents, the governance layer is not the bottleneck — your LLM API call is 100–1000× slower.

---

## 1. Policy Evaluation

Measures `PolicyEvaluator.evaluate()` — the core enforcement path every agent action passes through.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Single rule evaluation | 72,386 | 0.012 | 0.019 | 0.081 |
| 10-rule policy | 67,044 | 0.014 | 0.018 | 0.074 |
| 100-rule policy | 31,016 | 0.029 | 0.047 | 0.116 |
| SharedPolicy cross-project eval | 120,500 | 0.008 | 0.010 | 0.026 |
| YAML policy load (cold, 10 rules) | 111 | 8.403 | 12.571 | 21.835 |

**Key takeaway:** Rule count scales linearly. Even with 100 rules, p99 is under 0.12 ms. YAML loading is a cold-start cost (once per deployment, not per action).

Source: [`packages/agent-os/benchmarks/bench_policy.py`](packages/agent-os/benchmarks/bench_policy.py)

## 2. Kernel Enforcement

Measures `StatelessKernel.execute()` — the full enforcement path including policy evaluation, audit logging, and execution context management.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Kernel execute (allow) | 9,285 | 0.091 | 0.224 | 0.398 |
| Kernel execute (deny) | 11,731 | 0.071 | 0.199 | 0.422 |
| Circuit breaker state check | 1,662,638 | 0.001 | 0.001 | 0.001 |

### Concurrent Throughput

| Concurrency | Total ops | Wall time (s) | ops/sec |
|---:|---:|---:|---:|
| 50 agents × 200 ops each | 10,000 | 0.282 | 35,481 |

**Key takeaway:** Deny path is slightly faster than allow (no downstream execution). Circuit breaker overhead is negligible (sub-microsecond). At 50 concurrent agents, throughput exceeds 35K ops/sec.

Source: [`packages/agent-os/benchmarks/bench_kernel.py`](packages/agent-os/benchmarks/bench_kernel.py)

## 3. Audit System

Measures audit entry creation, querying, and serialization — the observability overhead.

| Benchmark | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| Audit entry write | 212,565 | 0.003 | 0.007 | 0.015 |
| Audit entry serialization | 247,175 | 0.004 | 0.006 | 0.008 |
| Execution time tracking | 510,071 | 0.002 | 0.003 | 0.003 |
| Audit log query (10K entries) | 1,119 | 0.810 | 1.537 | 1.935 |

**Key takeaway:** Audit writes add ~3 µs per action. Querying 10K entries takes ~1 ms (in-memory scan). For production deployments, external append-only stores (e.g., OpenTelemetry export) are recommended for large-scale query workloads.

Source: [`packages/agent-os/benchmarks/bench_audit.py`](packages/agent-os/benchmarks/bench_audit.py)

## 4. Framework Adapter Overhead

Measures the governance check overhead per framework adapter — the cost added to each tool call or agent step.

| Adapter | ops/sec | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|
| GovernancePolicy init (startup) | 189,403 | 0.005 | 0.007 | 0.013 |
| Tool allowed check | 7,506,344 | 0.000 | 0.000 | 0.000 |
| Pattern match (per call) | 130,817 | 0.006 | 0.013 | 0.029 |
| **OpenAI** adapter | 132,340 | 0.006 | 0.013 | 0.031 |
| **LangChain** adapter | 225,128 | 0.004 | 0.007 | 0.010 |
| **Anthropic** adapter | 213,598 | 0.004 | 0.007 | 0.011 |
| **LlamaIndex** adapter | 215,934 | 0.004 | 0.006 | 0.011 |
| **CrewAI** adapter | 230,223 | 0.004 | 0.006 | 0.010 |
| **AutoGen** adapter | 191,390 | 0.005 | 0.007 | 0.010 |
| **Google Gemini** adapter | 139,730 | 0.005 | 0.011 | 0.027 |
| **Mistral** adapter | 148,880 | 0.006 | 0.009 | 0.020 |
| **Semantic Kernel** adapter | 138,810 | 0.006 | 0.012 | 0.015 |

**Key takeaway:** All adapters add **< 0.03 ms** (p99) per tool call. This is 3–4 orders of magnitude below a typical LLM API round-trip (200–2000 ms). The governance layer is invisible to end users.

Source: [`packages/agent-os/benchmarks/bench_adapters.py`](packages/agent-os/benchmarks/bench_adapters.py)

## 5. Agent SRE (Reliability Engineering)

Measures chaos engineering, SLO enforcement, and observability primitives.

| Benchmark | ops/sec | p50 (µs) | p99 (µs) |
|---|---:|---:|---:|
| Fault injection | 1,060,108 | 0.60 | 1.90 |
| Chaos template init | 221,270 | 3.20 | 11.80 |
| Chaos schedule eval | 360,531 | 2.20 | 4.40 |
| SLO evaluation | 48,747 | 18.70 | 49.20 |
| Error budget calculation | 58,229 | 15.70 | 42.50 |
| Burn rate alert | 49,593 | 16.30 | 50.10 |
| SLI recording | 618,961 | 1.10 | 4.10 |

**Key takeaway:** SRE operations are sub-50 µs at p99. SLI recording (the hot path for every action) is ~1 µs. These can run alongside every agent action without measurable impact.

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
```

### CI Integration

Benchmarks run automatically on every release via the [`benchmarks.yml`](.github/workflows/benchmarks.yml) workflow. Results are uploaded as workflow artifacts for comparison across releases.

## Comparison Context

For context, here's where the governance overhead sits relative to typical agent operations:

| Operation | Typical latency |
|---|---|
| **Policy evaluation (this toolkit)** | **0.01–0.03 ms** |
| **Full kernel enforcement** | **0.07–0.10 ms** |
| **Adapter overhead** | **0.004–0.006 ms** |
| Python function call | 0.001 ms |
| Redis read (local) | 0.1–0.5 ms |
| Database query (simple) | 1–10 ms |
| LLM API call (GPT-4) | 200–2,000 ms |
| LLM API call (Claude Sonnet) | 300–3,000 ms |

The governance layer adds less overhead than a single Redis read and is 10,000× faster than an LLM call.

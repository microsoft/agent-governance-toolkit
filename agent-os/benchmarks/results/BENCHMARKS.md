# Agent OS Performance Benchmarks

> Benchmarked on: AMD Ryzen 9 5950X, 32GB RAM, Python 3.11

## Summary

| Operation | Throughput | Latency (p50) | Latency (p99) |
|-----------|-----------|---------------|---------------|
| Kernel Execute (allow) | 45,000 ops/sec | 0.022ms | 0.065ms |
| Kernel Execute (deny) | 52,000 ops/sec | 0.019ms | 0.058ms |
| Policy Evaluation (10 rules) | 120,000 ops/sec | 0.008ms | 0.025ms |
| Policy Evaluation (100 rules) | 18,000 ops/sec | 0.055ms | 0.15ms |
| YAML Policy Load | 2,800 ops/sec | 0.36ms | 0.95ms |
| Audit Entry Write | 145,000 ops/sec | 0.007ms | 0.021ms |
| Audit Log Query (10K entries) | 1,200 ops/sec | 0.83ms | 2.1ms |
| Circuit Breaker Check | 890,000 ops/sec | 0.001ms | 0.003ms |
| Adapter Overhead (avg) | — | 0.015ms | 0.042ms |
| **Full Governed Action** | **28,000 ops/sec** | **0.036ms** | **0.098ms** |

## Key Takeaways

- **Sub-100μs governance**: Full kernel enforcement in <0.1ms p99
- **Zero-overhead adapters**: Framework integration adds <42μs
- **1,577+ tests passing** with governance enforcement active

## Running Benchmarks

```bash
# Run all benchmarks with JSON + markdown output
python -m benchmarks.run_all

# Run individual benchmark modules
python -m benchmarks.bench_kernel
python -m benchmarks.bench_policy
python -m benchmarks.bench_audit
python -m benchmarks.bench_adapters
```

## Methodology

- Each operation is measured over thousands of iterations
- Latencies captured via `time.perf_counter()` (sub-microsecond resolution)
- p50/p95/p99 percentiles computed from sorted latency distributions
- Concurrent benchmarks use `asyncio.gather()` to simulate real-world load
- All benchmarks run against in-memory backends to isolate kernel overhead

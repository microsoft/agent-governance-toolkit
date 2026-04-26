# Agent SRE Performance Benchmarks

> Benchmarked on: AMD Ryzen 9 5950X, 32GB RAM, Python 3.11

## Summary

| Operation | Throughput | Latency (p50) | Latency (p99) |
|-----------|-----------|---------------|---------------|
| SLO Evaluation | 85,000 ops/sec | 0.012ms | 0.035ms |
| Error Budget Calc | 120,000 ops/sec | 0.008ms | 0.024ms |
| Burn Rate Alert | 95,000 ops/sec | 0.010ms | 0.029ms |
| SLI Recording | 200,000 ops/sec | 0.005ms | 0.014ms |
| Fault Injection | 15,000 ops/sec | 0.067ms | 0.18ms |
| Chaos Template Init | 8,500 ops/sec | 0.12ms | 0.31ms |
| Staged Rollout Analysis | 12,000 ops/sec | 0.083ms | 0.22ms |
| Rollback Decision | 45,000 ops/sec | 0.022ms | 0.061ms |
| **Full SRE Pipeline** | **7,200 ops/sec** | **0.14ms** | **0.38ms** |

## Key Takeaways

- **Sub-millisecond SRE**: Full SLO + chaos + delivery pipeline in <0.4ms p99
- **Real-time burn rate**: Alert detection in <30μs
- **200K SLI recordings/sec**: Handle high-frequency agent telemetry

## Running Benchmarks

```bash
# Run all benchmarks
python -m benchmarks.run_all

# Custom iteration count
python -m benchmarks.run_all --iterations 50000

# Run individual benchmark modules
python -m benchmarks.bench_slo
python -m benchmarks.bench_chaos
python -m benchmarks.bench_delivery
```

## Benchmark Details

### SLO Engine

| Benchmark | Description |
|-----------|-------------|
| SLO Evaluation | Full `SLO.evaluate()` call with indicators and budget checks |
| Error Budget Calc | `remaining_percent` + `burn_rate()` computation |
| Burn Rate Alert | Alert detection via `firing_alerts()` |
| SLI Recording | `record()` across all 7 indicator types (round-robin) |

### Chaos Engine

| Benchmark | Description |
|-----------|-------------|
| Fault Injection | `inject_fault()` event creation and recording |
| Chaos Template Init | `instantiate()` across all 9 built-in templates |
| Chaos Schedule Eval | Blackout window evaluation with progressive config |

### Progressive Delivery

| Benchmark | Description |
|-----------|-------------|
| Staged Rollout Analysis | Analysis criteria evaluation (4 metrics) |
| Rollback Decision | `check_rollback()` with 3 conditions |
| Traffic Split Calc | `current_weight` + `progress_percent` computation |

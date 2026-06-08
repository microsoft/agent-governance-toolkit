# ACS core performance harness

This directory stores the regression harness for Criterion benchmarks in `core/benches/`.

Run from the repository root.

```sh
cargo bench -p agent_control_specification_core --bench evaluation -- --warm-up-time 1 --measurement-time 3 --sample-size 20
python3 tests/perf/extract_stats.py target/criterion > tests/perf/current.json
python3 tests/perf/compare.py --baseline tests/perf/baselines.json --current tests/perf/current.json --threshold 25
```

To refresh baselines, run the benchmark on an idle machine, inspect `tests/perf/current.json`, then copy it to `tests/perf/baselines.json`. Commit the updated baseline with the code change that intentionally changed performance.

The default comparison metric is `p95_ns`, which maps to Criterion's upper confidence bound for the mean. The workflow uses a 25 percent threshold to catch material ACS core regressions while avoiding false failures from shared runner noise.

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

CORPUS="benchmarks/prompt-injection/corpus/injection-smoke.jsonl"
MANIFEST="benchmarks/prompt-injection/corpus/manifest-smoke.json"
CHECK_SUMMARY="benchmarks/prompt-injection/corpus/check-smoke-summary.json"
PER_ROW="${TMPDIR:-/tmp}/agt-prompt-injection-rules-baseline-smoke.jsonl"
CHECK_OUT="${TMPDIR:-/tmp}/agt-prompt-injection-check-smoke.out"
RULES_OUT="${TMPDIR:-/tmp}/agt-prompt-injection-rules-baseline.out"
RULES_SUMMARY="benchmarks/prompt-injection/artifacts/rules-baseline-smoke-summary.json"
RULES_METRICS="benchmarks/prompt-injection/artifacts/rules-baseline-smoke-metrics.json"
RUST_MANIFEST="benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/agt-prompt-injection-baseline-target}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-${TMPDIR:-/tmp}/agt-prompt-injection-pycache}"

echo "[prompt-injection-fixture] compile Python helpers"
python3 -m py_compile \
  benchmarks/prompt-injection/harness/generate-corpus.py \
  benchmarks/prompt-injection/harness/check-corpus.py \
  benchmarks/prompt-injection/harness/summarize-baseline.py

echo "[prompt-injection-fixture] regenerate smoke corpus + manifest"
python3 benchmarks/prompt-injection/harness/generate-corpus.py \
  --profile smoke \
  --out "$CORPUS" \
  --manifest "$MANIFEST"

echo "[prompt-injection-fixture] validate corpus hygiene"
python3 benchmarks/prompt-injection/harness/check-corpus.py \
  "$CORPUS" \
  --manifest "$MANIFEST" \
  --summary-json "$CHECK_SUMMARY" \
  >"$CHECK_OUT"
tail -n 1 "$CHECK_OUT"

echo "[prompt-injection-fixture] compile Rust AGT scorer"
cargo check --manifest-path "$RUST_MANIFEST"

echo "[prompt-injection-fixture] regenerate Rust AGT rules baseline"
cargo run --manifest-path "$RUST_MANIFEST" -- \
  "$CORPUS" \
  --per-row "$PER_ROW" \
  --summary "$RULES_SUMMARY" \
  >"$RULES_OUT"

echo "[prompt-injection-fixture] rebuild Wilson/base-rate metrics"
python3 benchmarks/prompt-injection/harness/summarize-baseline.py \
  "$RULES_SUMMARY" \
  --out "$RULES_METRICS"

echo "[prompt-injection-fixture] assert metadata-only evidence outputs"
python3 - "$PER_ROW" "$RULES_SUMMARY" "$RULES_METRICS" <<'PY'
import json
import sys
from pathlib import Path

per_row, summary, metrics = [Path(p) for p in sys.argv[1:]]

for lineno, line in enumerate(per_row.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    row = json.loads(line)
    if "text" in row:
        raise SystemExit(f"{per_row}:{lineno}: raw text field leaked into per-row evidence")

for path in (summary, metrics):
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("raw_text_in_output") is not False:
        raise SystemExit(f"{path}: raw_text_in_output must be false")

print("metadata-only evidence: PASS")
PY

echo "[prompt-injection-fixture] smoke reproduction complete"

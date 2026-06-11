#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
OUTPUT="${ACS_CONFORMANCE_RESULTS:-tests/conformance/results/rust.json}"

cargo test -p agent_control_specification_core --test conformance_corpus --quiet

python3 - <<'PY'
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path

repo = Path.cwd()
output = Path(os.environ.get("ACS_CONFORMANCE_RESULTS", "tests/conformance/results/rust.json"))
cases = sorted((repo / "tests/conformance/cases").glob("*.json"))
results = [{"case": json.loads(path.read_text(encoding="utf-8"))["id"], "status": "pass", "detail": None} for path in cases]
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"sdk": "rust", "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "results": results}, indent=2) + "\n", encoding="utf-8")
for result in results:
    print(f"rust {result['status']} {result['case']}")
PY

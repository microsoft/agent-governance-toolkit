#!/usr/bin/env bash
# Runs the shared corpus through the Java SDK (sdk/java, ConformanceTest) and writes the parity report.
# Needs JDK 25+ (JAVA_HOME, or -Pacs.jdk via ACS_JAVA_GRADLE_ARGS) and the native library
# (ACS_NATIVE_LIBRARY, or target/release/{agent_control_specification.dll,libagent_control_specification.so,.dylib}).
set -euo pipefail

cd "$(dirname "$0")/../.."
OUTPUT="${ACS_CONFORMANCE_RESULTS:-tests/conformance/results/java.json}"
case "$OUTPUT" in /*|[A-Za-z]:*) ;; *) OUTPUT="$PWD/$OUTPUT" ;; esac

LIB="${ACS_NATIVE_LIBRARY:-}"
if [ -z "$LIB" ]; then
  for candidate in target/release/agent_control_specification.dll target/release/libagent_control_specification.so target/release/libagent_control_specification.dylib; do
    if [ -f "$candidate" ]; then LIB="$PWD/$candidate"; break; fi
  done
fi

JAVA_STATUS="pass"
JAVA_DETAIL=""
if [ -z "$LIB" ] || [ ! -f "$LIB" ]; then
  JAVA_STATUS="skip"
  JAVA_DETAIL="native library not built (cargo build --release -p agent_control_specification --features opa,bundled-dispatchers)"
else
  # shellcheck disable=SC2086
  if ! (cd sdk/java && ACS_CONFORMANCE_RESULTS="$OUTPUT" ./gradlew test --tests '*ConformanceTest' --no-daemon -Pacs.native.library="$LIB" ${ACS_JAVA_GRADLE_ARGS:-}); then
    echo "java conformance run failed" >&2
    exit 1
  fi
  exit 0
fi

JAVA_STATUS="$JAVA_STATUS" JAVA_DETAIL="$JAVA_DETAIL" OUTPUT="$OUTPUT" python3 - <<'PY'
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path

output = Path(os.environ["OUTPUT"])
results = []
for path in sorted(Path("tests/conformance/cases").glob("*.json")):
    case = json.loads(path.read_text(encoding="utf-8"))
    results.append({"case": case["id"], "status": os.environ["JAVA_STATUS"], "detail": os.environ["JAVA_DETAIL"]})
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"sdk": "java", "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "results": results}, indent=2) + "\n", encoding="utf-8")
print(f"java {os.environ['JAVA_STATUS']}: {os.environ['JAVA_DETAIL']}")
PY

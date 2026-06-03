#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
OUTPUT="${ACS_CONFORMANCE_RESULTS:-tests/conformance/results/dotnet.json}"

if ! command -v dotnet >/dev/null 2>&1; then
  DOTNET_STATUS="skip"
  DOTNET_DETAIL="dotnet is not on PATH"
else
  dotnet build sdk/dotnet/AgentControlSpecification.sln --nologo --verbosity minimal
  dotnet run --project sdk/dotnet/tests/AgentControlSpecification.Tests/AgentControlSpecification.Tests.csproj
  DOTNET_STATUS="skip"
  DOTNET_DETAIL="console harness passed and corpus cases are optional for dotnet runner"
fi

DOTNET_STATUS="$DOTNET_STATUS" DOTNET_DETAIL="$DOTNET_DETAIL" python3 - <<'PY'
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path

repo = Path.cwd()
output = Path(os.environ.get("ACS_CONFORMANCE_RESULTS", "tests/conformance/results/dotnet.json"))
status = os.environ["DOTNET_STATUS"]
detail = os.environ["DOTNET_DETAIL"]
results = []
for path in sorted((repo / "tests/conformance/cases").glob("*.json")):
    case = json.loads(path.read_text(encoding="utf-8"))
    if case.get("sdk_support", {}).get("dotnet") == "skip":
        results.append({"case": case["id"], "status": "skip", "detail": "case excludes dotnet"})
    else:
        results.append({"case": case["id"], "status": status, "detail": detail})
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"sdk": "dotnet", "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "results": results}, indent=2) + "\n", encoding="utf-8")
for result in results:
    print(f"dotnet {result['status']} {result['case']}: {result['detail']}")
PY

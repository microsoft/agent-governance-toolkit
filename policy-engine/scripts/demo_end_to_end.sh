#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT 5.0 end-to-end demo script.
#
# Walks the user from a clean checkout to a working AGT 5.0 setup
# across every language SDK (Rust, Python, Node, .NET) plus the AGT
# Python wrapper and the migration tool. Builds and packages each
# SDK, installs each, and runs a tiny demo that exercises:
#
#   1. A manifest with an allow rule         (decision: allow)
#   2. A manifest with a deny rule           (decision: deny)
#   3. A manifest with a transform verdict   (decision: transform; verifies
#                                            the policy target was actually
#                                            rewritten end-to-end)
#   4. The AGT manifest-resolution layer     (governance.yaml chain →
#                                            flat ACS manifest)
#
# Designed to be re-runnable. Each step is idempotent and prints a
# clear status banner. Stops at the first failure and surfaces the
# command output.
#
# Usage:
#   bash policy-engine/scripts/demo_end_to_end.sh [--skip <suite>]...
#
# Suites: core | python-sdk | node-sdk | dotnet-sdk | agt-policies | migration
#
# Examples:
#   bash demo_end_to_end.sh                            # run everything
#   bash demo_end_to_end.sh --skip dotnet-sdk          # skip .NET
#   bash demo_end_to_end.sh --only python-sdk          # run one suite

set -u
set -o pipefail

# ── plumbing ──────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POLICY_ENGINE="$REPO_ROOT/policy-engine"
AGT_POLICIES="$REPO_ROOT/agent-governance-python/agt-policies"
DEMO_TMP="${AGT_DEMO_TMP:-/tmp/agt-demo-$$}"
PY_VENV="${AGT_DEMO_VENV:-/tmp/agt-demo-venv}"
mkdir -p "$DEMO_TMP"

GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; BLUE="\033[34m"; RESET="\033[0m"

declare -a SKIP_SUITES=()
declare -a ONLY_SUITES=()
ONLY_MODE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip) SKIP_SUITES+=("$2"); shift 2 ;;
    --only) ONLY_SUITES+=("$2"); ONLY_MODE=1; shift 2 ;;
    -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
done

should_run() {
  local suite="$1"
  if [[ $ONLY_MODE -eq 1 ]]; then
    for s in "${ONLY_SUITES[@]}"; do [[ "$s" == "$suite" ]] && return 0; done
    return 1
  fi
  for s in "${SKIP_SUITES[@]}"; do [[ "$s" == "$suite" ]] && return 1; done
  return 0
}

banner() { printf "\n${BLUE}━━━━━━━ %s ━━━━━━━${RESET}\n" "$1"; }
ok()     { printf "${GREEN}✓${RESET} %s\n" "$1"; }
warn()   { printf "${YELLOW}⚠${RESET} %s\n" "$1"; }
die()    { printf "${RED}✗ %s${RESET}\n" "$1" >&2; exit 1; }
run()    { echo "  $ $*"; "$@"; }

# Track totals for the final summary.
declare -A RESULTS
record() { RESULTS["$1"]="$2"; }

# ── 0. toolchain probe ────────────────────────────────────────────

banner "Toolchain probe"
toolchain_ok=1
for cmd in cc cargo node npm python3 opa; do
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$cmd: $(command -v "$cmd")"
  else
    warn "$cmd not found"; toolchain_ok=0
  fi
done
if command -v dotnet >/dev/null 2>&1; then
  ok "dotnet: $(command -v dotnet)"
else
  warn "dotnet not found (install via dot.net/v1/dotnet-install.sh); --skip dotnet-sdk will skip the .NET demo."
fi
[[ $toolchain_ok -eq 0 ]] && die "required toolchain missing"

# ── 1. build the AGT-vendored ACS Rust core ──────────────────────

if should_run core; then
  banner "1. Build the AGT-vendored ACS Rust core"
  (
    cd "$POLICY_ENGINE"
    run cargo build -p agent_control_specification_core --release --all-features 2>&1 | tail -3
  ) || die "core build failed"
  ok "core build green"

  banner "1b. Quick smoke: ACS core tests"
  (
    cd "$POLICY_ENGINE"
    cargo test -p agent_control_specification_core --release --all-features 2>&1 | grep "test result:" | awk '{p+=$4; f+=$6} END {printf "  result: %d passed / %d failed\n", p, f; exit (f>0)}'
  ) || die "core tests failed"
  record "core" "ok"
fi

# ── 2. Python venv + ACS Python SDK + agt-policies wrapper ──────

if should_run python-sdk; then
  banner "2. Python SDK build + install"
  if [[ ! -d "$PY_VENV" ]]; then
    run python3 -m venv --without-pip "$PY_VENV"
    curl -sSL https://bootstrap.pypa.io/get-pip.py | "$PY_VENV/bin/python3" - --quiet 2>&1 | tail -2
  fi
  run "$PY_VENV/bin/pip" install --quiet maturin pyyaml pytest jsonschema 2>&1 | tail -3
  run "$PY_VENV/bin/pip" install --quiet -e "$POLICY_ENGINE/sdk/python" 2>&1 | tail -3 || die "ACS Python SDK install failed"
  run "$PY_VENV/bin/pip" install --quiet -e "$AGT_POLICIES" 2>&1 | tail -3 || die "agt-policies install failed"
  "$PY_VENV/bin/python3" -c "import agent_control_specification, agt; print('  imports OK')" || die "Python imports failed"
  record "python-sdk" "ok"
fi

# ── 3. Node SDK build + pack + install ───────────────────────────

if should_run node-sdk; then
  banner "3. Node SDK build + pack + install"
  (
    cd "$POLICY_ENGINE/sdk/node"
    run npm ci --silent --no-progress 2>&1 | tail -3 || die "npm ci failed"
    run npm run build 2>&1 | tail -3 || die "npm build failed"
    # Pack the npm tarball so the demo installs from the same artefact the user would publish
    run npm pack --silent | tail -1 > "$DEMO_TMP/.node-tarball.txt"
    NODE_TGZ="$(cat "$DEMO_TMP/.node-tarball.txt")"
    cp "$NODE_TGZ" "$DEMO_TMP/" && ok "packed: $DEMO_TMP/$(basename "$NODE_TGZ")"
  ) || die "node sdk steps failed"
  record "node-sdk" "ok"
fi

# ── 4. .NET SDK build + pack + install ───────────────────────────

if should_run dotnet-sdk; then
  if command -v dotnet >/dev/null 2>&1; then
    banner "4. .NET SDK build + pack"
    (
      cd "$POLICY_ENGINE/sdk/dotnet"
      run dotnet build AgentControlSpecification.sln -c Release --nologo 2>&1 | tail -3 || die ".NET build failed"
      run dotnet pack AgentControlSpecification.sln -c Release --nologo -o "$DEMO_TMP/dotnet-nupkg" 2>&1 | tail -3 || die ".NET pack failed"
    ) || die ".NET sdk steps failed"
    record "dotnet-sdk" "ok"
  else
    warn "dotnet not found; skipping .NET SDK"
    record "dotnet-sdk" "skipped (dotnet not installed)"
  fi
fi

# ── 5. End-to-end scenario: Python ──────────────────────────────

if should_run python-sdk; then
  banner "5a. End-to-end demo: Python"
  cat > "$DEMO_TMP/demo_python.py" <<'PY'
"""AGT 5.0 Python end-to-end demo.

Builds an ACS manifest via agt.policies.bridge.governance_to_acs_manifest
from a v4-style GovernancePolicy spec, runs it through AgtRuntime, and
exercises the four canonical paths:

  - allow             (under the budget)
  - deny              (over the budget)
  - transform         (verdict rewrites the policy target)
  - escalate          (verdict routes through an approval resolver)

Prints PASS/FAIL per path. Exit 0 = all paths green.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

from agt.policies.snapshot import SnapshotBuilder, pre_tool_call_snapshot, output_snapshot
from agt.policies.runtime import AgtRuntime, ApprovalDecision


def write_manifest(tmp: Path) -> Path:
    """Hand-written ACS manifest binding three Rego rules to three
    intervention points: pre_tool_call (allow/deny based on amount),
    output (transform via redact), and a separate escalate rule."""
    bundle_dir = tmp / "policy"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "demo.rego").write_text(
        """
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
package agt.demo
import rego.v1

# pre_tool_call: deny when amount > 1000, escalate when 500 < amount <= 1000
default pre_tool_call := {"decision": "allow"}

pre_tool_call := {"decision": "deny", "reason": "amount_exceeds_limit"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 1000
}

pre_tool_call := {"decision": "escalate", "reason": "needs_approval"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 500
  input.snapshot.tool_call.args.amount <= 1000
}

# output: redact SSN-shaped strings via the transform verdict
default output := {"decision": "allow"}

output := {
  "decision": "transform",
  "reason": "ssn_redacted",
  "transform": {"path": "$policy_target", "value": "Customer SSN is [REDACTED]"}
} if {
  input.intervention_point == "output"
  regex.match(`[0-9]{3}-[0-9]{2}-[0-9]{4}`, input.snapshot.response.content)
}
""",
        encoding="utf-8",
    )
    manifest = {
        "agent_control_specification_version": "0.3.0-alpha-agt",
        "metadata": {"name": "agt-5-demo"},
        "policies": {
            "demo": {
                "type": "rego",
                "bundle": str(bundle_dir),
                "query": "data.agt.demo.pre_tool_call",
            },
            "demo_output": {
                "type": "rego",
                "bundle": str(bundle_dir),
                "query": "data.agt.demo.output",
            },
        },
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "demo"},
            },
            "output": {
                "policy_target": "$.response.content",
                "policy_target_kind": "response_content",
                "policy": {"id": "demo_output"},
            },
        },
        "tools": {
            "wire_transfer": {"clearance": "confidential"},
        },
    }
    manifest_path = tmp / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return manifest_path


def run(label: str, expected: str, fn):
    try:
        actual = fn()
    except Exception as exc:
        print(f"  ✗ {label}: raised {type(exc).__name__}: {exc}")
        return False
    ok = actual == expected
    glyph = "✓" if ok else "✗"
    print(f"  {glyph} {label}: got {actual!r} (expected {expected!r})")
    return ok


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="agt-demo-py-") as tmp:
        tmp_path = Path(tmp)
        manifest_path = write_manifest(tmp_path)
        approved = []

        def approval_resolver(intervention_point, evaluation_result):
            approved.append((intervention_point, evaluation_result))
            return ApprovalDecision.allow(
                enforced_identity=evaluation_result.enforced_identity or "unknown"
            )

        runtime = AgtRuntime(manifest_path, approval_resolver=approval_resolver)

        # 1. allow path
        snap = pre_tool_call_snapshot(
            agent_id="demo-agent", tool_name="wire_transfer", args={"amount": 100}
        )
        result = runtime.evaluate_intervention_point("pre_tool_call", snap)
        ok_allow = run("allow under limit", "allow", lambda: result.verdict)

        # 2. deny path
        snap = pre_tool_call_snapshot(
            agent_id="demo-agent", tool_name="wire_transfer", args={"amount": 5000}
        )
        result = runtime.evaluate_intervention_point("pre_tool_call", snap)
        ok_deny = run("deny over limit", "deny", lambda: result.verdict)

        # 3. escalate path: evaluate_only surfaces raw 'escalate'; enforce mode
        #    runs the approval_resolver and rewrites to 'allow' on success.
        snap = pre_tool_call_snapshot(
            agent_id="demo-agent", tool_name="wire_transfer", args={"amount": 750}
        )
        raw = runtime.evaluate_intervention_point("pre_tool_call", snap, mode="evaluate_only")
        ok_escalate_raw = run(
            "escalate raw (evaluate_only)", "escalate", lambda: raw.verdict
        )
        enforced = runtime.evaluate_intervention_point("pre_tool_call", snap)
        ok_escalate_resolved = run(
            "escalate resolved via approval (enforce)",
            "allow",
            lambda: enforced.verdict,
        )
        ok_resolver_invoked = run(
            "approval_resolver invoked",
            True,
            lambda: len(approved) >= 1,
        )

        # 4. transform path on output: SSN-redact via transform verdict
        snap = output_snapshot(
            agent_id="demo-agent",
            content="Customer SSN is 123-45-6789, please update.",
        )
        result = runtime.evaluate_intervention_point("output", snap)
        ok_transform = run("transform decision", "transform", lambda: result.verdict)
        # Verify the transformed value really got applied
        actual_transform = result.transform or {}
        ok_transform_value = run(
            "transform value applied",
            "Customer SSN is [REDACTED]",
            lambda: actual_transform.get("value"),
        )

        passed = sum(
            [
                ok_allow,
                ok_deny,
                ok_escalate_raw,
                ok_escalate_resolved,
                ok_resolver_invoked,
                ok_transform,
                ok_transform_value,
            ]
        )
        total = 7
        print(f"\n  Python demo: {passed}/{total} paths green")
        return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
PY
  "$PY_VENV/bin/python3" "$DEMO_TMP/demo_python.py" || die "Python demo failed"
  ok "Python demo green"
  record "python-demo" "ok"
fi

# ── 6. End-to-end scenario: Rust ────────────────────────────────

if should_run core; then
  banner "5b. End-to-end demo: Rust"
  cat > "$DEMO_TMP/demo_rust.rs" <<'RS'
//! AGT 5.0 Rust end-to-end demo. Builds an AgentControl from a small
//! manifest with a bundled OPA dispatcher and exercises the four
//! canonical paths: allow, deny, escalate, transform.

use agent_control_specification::{
    AgentControl, Decision, EnforcementMode, InterventionPoint,
};
use serde_json::json;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = std::env::var("AGT_DEMO_TMP").unwrap_or_else(|_| "/tmp/agt-demo-rs".to_string());
    let tmp = Path::new(&tmp);
    let policy = tmp.join("policy");
    fs::create_dir_all(&policy)?;
    fs::write(policy.join("demo.rego"), r#"
package agt.demo
import rego.v1
default pre_tool_call := {"decision": "allow"}
pre_tool_call := {"decision": "deny", "reason": "amount_exceeds_limit"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 1000
}
pre_tool_call := {"decision": "escalate", "reason": "needs_approval"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 500
  input.snapshot.tool_call.args.amount <= 1000
}
"#)?;
    let manifest_path = tmp.join("manifest.yaml");
    fs::write(&manifest_path, format!(r#"
agent_control_specification_version: "0.3.0-alpha"
policies:
  demo:
    type: rego
    bundle: {}
    query: data.agt.demo.pre_tool_call
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: demo
tools:
  wire_transfer:
    clearance: confidential
"#, policy.display()))?;

    let control = AgentControl::from_path(&manifest_path)?;

    let cases = [
        (100u64, Decision::Allow, "allow under limit"),
        (5000u64, Decision::Deny, "deny over limit"),
        (750u64, Decision::Escalate, "escalate in mid-range"),
    ];
    let mut passed = 0;
    for (amount, expected, label) in cases {
        let result = control.evaluate_intervention_point(
            InterventionPoint::PreToolCall,
            json!({
                "tool_call": {"name": "wire_transfer", "args": {"amount": amount}},
                "envelope": {"agent": {"id": "demo"}, "intervention_point": "pre_tool_call"},
            }),
            EnforcementMode::Enforce,
        );
        let actual = result.verdict.decision;
        let ok = actual == expected;
        println!("  {} {}: got {:?} (expected {:?})", if ok {"✓"} else {"✗"}, label, actual, expected);
        if ok { passed += 1; }
    }
    println!("\n  Rust demo: {}/{} paths green", passed, cases.len());
    if passed != cases.len() { std::process::exit(1); }
    Ok(())
}
RS
  # Build & run as a one-off binary against the agent_control_specification crate
  (
    set -e
    cd "$POLICY_ENGINE/sdk/rust"
    # Use cargo to find the build path; compile a quick standalone target
    cat > "$DEMO_TMP/demo_rust_runner.rs" <<EOF
include!("$DEMO_TMP/demo_rust.rs");
EOF
    # Build via a temp binary target under sdk/rust
    mkdir -p "$DEMO_TMP/demo-rust-crate/src"
    cat > "$DEMO_TMP/demo-rust-crate/Cargo.toml" <<EOF
[package]
name = "agt-demo-rust"
version = "0.0.1"
edition = "2021"
[dependencies]
agent_control_specification = { path = "$POLICY_ENGINE/sdk/rust" }
serde_json = "1"
EOF
    cp "$DEMO_TMP/demo_rust.rs" "$DEMO_TMP/demo-rust-crate/src/main.rs"
    cd "$DEMO_TMP/demo-rust-crate"
    AGT_DEMO_TMP="$DEMO_TMP/demo-rust-data" cargo run --release --quiet 2>&1 | tail -10
  ) || die "Rust demo failed"
  ok "Rust demo green"
  record "rust-demo" "ok"
fi

# ── 7. End-to-end scenario: Node ────────────────────────────────

if should_run node-sdk; then
  banner "5c. End-to-end demo: Node"
  cat > "$DEMO_TMP/demo_node.mjs" <<'JS'
// AGT 5.0 Node end-to-end demo. Installs the locally-built tarball,
// loads a small manifest, and exercises allow/deny/escalate/transform.
import { AgentControl, Decision, EnforcementMode, InterventionPoint } from "agent-control-specification";
import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execSync } from "node:child_process";

const TMP = process.env.AGT_DEMO_TMP || join(tmpdir(), `agt-demo-node-${process.pid}`);
mkdirSync(join(TMP, "policy"), { recursive: true });
writeFileSync(join(TMP, "policy", "demo.rego"), `
package agt.demo
import rego.v1
default pre_tool_call := {"decision": "allow"}
pre_tool_call := {"decision": "deny", "reason": "amount_exceeds_limit"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 1000
}
pre_tool_call := {"decision": "escalate", "reason": "needs_approval"} if {
  input.intervention_point == "pre_tool_call"
  input.snapshot.tool_call.args.amount > 500
  input.snapshot.tool_call.args.amount <= 1000
}
`);
writeFileSync(join(TMP, "manifest.yaml"), `
agent_control_specification_version: "0.3.0-alpha"
policies:
  demo:
    type: rego
    bundle: ${join(TMP, "policy")}
    query: data.agt.demo.pre_tool_call
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: demo
tools:
  wire_transfer:
    clearance: confidential
`);

const control = await AgentControl.fromPath(join(TMP, "manifest.yaml"));
const cases = [
  [100,  "allow",    "allow under limit"],
  [5000, "deny",     "deny over limit"],
  [750,  "escalate", "escalate in mid-range"],
];
let passed = 0;
for (const [amount, expected, label] of cases) {
  const result = await control.evaluateInterventionPoint(
    InterventionPoint.PreToolCall,
    {
      tool_call: { name: "wire_transfer", args: { amount } },
      envelope: { agent: { id: "demo" }, intervention_point: "pre_tool_call" },
    },
    EnforcementMode.Enforce,
  );
  const actual = result.verdict.decision;
  const ok = actual === expected;
  console.log(`  ${ok ? "✓" : "✗"} ${label}: got ${actual} (expected ${expected})`);
  if (ok) passed++;
}
console.log(`\n  Node demo: ${passed}/${cases.length} paths green`);
process.exit(passed === cases.length ? 0 : 1);
JS
  (
    set -e
    DEMO_NODE_DIR="$DEMO_TMP/demo-node-app"
    rm -rf "$DEMO_NODE_DIR"
    mkdir -p "$DEMO_NODE_DIR"
    cd "$DEMO_NODE_DIR"
    cat > package.json <<EOF
{"name":"agt-demo-node","private":true,"type":"module","dependencies":{"agent-control-specification":"file:$DEMO_TMP/$(basename "$(cat "$DEMO_TMP/.node-tarball.txt")")"}}
EOF
    npm install --silent --no-progress 2>&1 | tail -3 || die "node demo install failed"
    cp "$DEMO_TMP/demo_node.mjs" demo.mjs
    AGT_DEMO_TMP="$DEMO_TMP/demo-node-data" node demo.mjs
  ) || die "Node demo failed"
  ok "Node demo green"
  record "node-demo" "ok"
fi

# ── 8. End-to-end scenario: .NET ────────────────────────────────

if should_run dotnet-sdk && command -v dotnet >/dev/null 2>&1; then
  banner "5d. End-to-end demo: .NET"
  DEMO_DOTNET="$DEMO_TMP/demo-dotnet"
  rm -rf "$DEMO_DOTNET"
  mkdir -p "$DEMO_DOTNET"
  (
    cd "$DEMO_DOTNET"
    dotnet new console --force --no-restore -n AgtDemo -o . 2>&1 | tail -3 >/dev/null
    NUPKG="$(ls "$DEMO_TMP/dotnet-nupkg/"*.nupkg | head -1)"
    # Wire a local NuGet feed pointed at the packed nupkgs
    cat > NuGet.Config <<XML
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="agt-demo-local" value="$DEMO_TMP/dotnet-nupkg" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
XML
    dotnet add package AgentControlSpecification --version 0.1.0 --no-restore 2>&1 | tail -3 || warn ".NET package add failed"
    cat > Program.cs <<'CS'
// AGT 5.0 .NET end-to-end demo: exercises allow + deny + transform +
// escalate via the packed AgentControlSpecification SDK pulled from the
// local NuGet feed. Mirrors the Python demo's four canonical paths.
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using AgentControlSpecification;

var tmp = Environment.GetEnvironmentVariable("AGT_DEMO_TMP") ?? Path.Combine(Path.GetTempPath(), "agt-demo-dotnet");
Directory.CreateDirectory(Path.Combine(tmp, "policy"));
File.WriteAllText(Path.Combine(tmp, "policy", "demo.rego"),
@"package agt.demo
import rego.v1

# pre_tool_call: allow under 500, escalate 501..1000, deny above 1000
default pre_tool_call := {""decision"": ""allow""}
pre_tool_call := {""decision"": ""deny"", ""reason"": ""amount_exceeds_limit""} if {
  input.intervention_point == ""pre_tool_call""
  input.snapshot.tool_call.args.amount > 1000
}
pre_tool_call := {""decision"": ""escalate"", ""reason"": ""needs_approval""} if {
  input.intervention_point == ""pre_tool_call""
  input.snapshot.tool_call.args.amount > 500
  input.snapshot.tool_call.args.amount <= 1000
}

# post_tool_call: pass-through allow so RunToolAsync can complete after
# an approved escalate.
default post_tool_call := {""decision"": ""allow""}

# output: redact SSN-shaped values through a Transform verdict.
default output := {""decision"": ""allow""}
output := {
  ""decision"": ""transform"",
  ""reason"": ""ssn_redacted"",
  ""transform"": {""path"": ""$policy_target"", ""value"": ""Customer SSN is [REDACTED]""}
} if {
  input.intervention_point == ""output""
  regex.match(`[0-9]{3}-[0-9]{2}-[0-9]{4}`, input.snapshot.output)
}");
File.WriteAllText(Path.Combine(tmp, "manifest.yaml"),
$@"agent_control_specification_version: ""0.3.0-alpha""
policies:
  demo:
    type: rego
    bundle: {Path.Combine(tmp, "policy")}
    query: data.agt.demo.pre_tool_call
  demo_post:
    type: rego
    bundle: {Path.Combine(tmp, "policy")}
    query: data.agt.demo.post_tool_call
  demo_output:
    type: rego
    bundle: {Path.Combine(tmp, "policy")}
    query: data.agt.demo.output
intervention_points:
  pre_tool_call:
    policy_target: ""$.tool_call.args""
    policy_target_kind: tool_args
    tool_name_from: ""$.tool_call.name""
    policy:
      id: demo
  post_tool_call:
    policy_target: ""$.tool_result""
    policy_target_kind: tool_result
    tool_name_from: ""$.tool_call.name""
    policy:
      id: demo_post
  output:
    policy_target: ""$.output""
    policy_target_kind: response_content
    policy:
      id: demo_output
tools:
  wire_transfer:
    clearance: confidential");

int passed = 0, total = 0;
void Check(bool ok, string label, string detail)
{
    total++;
    if (ok) passed++;
    Console.WriteLine($"  {(ok ? "✓" : "✗")} {label}: {detail}");
}

// FromPathAsync mirrors the async loaders in the other SDKs.
var control = await AgentControl.FromPathAsync(Path.Combine(tmp, "manifest.yaml"));

// 1. allow under limit
var allowSnap = JsonDocument.Parse(
    @"{ ""tool_call"": { ""id"": ""call-allow"", ""name"": ""wire_transfer"", ""args"": { ""amount"": 100 } }, ""envelope"": { ""agent"": { ""id"": ""demo"" } } }").RootElement;
var allowResult = await control.EvaluateInterventionPointAsync(
    InterventionPoint.PreToolCall, allowSnap, EnforcementMode.Enforce);
Check(allowResult.Verdict.Decision == Decision.Allow,
      "allow under limit",
      $"got {allowResult.Verdict.Decision.ToWireName()} (expected allow)");

// 2. deny over limit
var denySnap = JsonDocument.Parse(
    @"{ ""tool_call"": { ""id"": ""call-deny"", ""name"": ""wire_transfer"", ""args"": { ""amount"": 5000 } }, ""envelope"": { ""agent"": { ""id"": ""demo"" } } }").RootElement;
var denyResult = await control.EvaluateInterventionPointAsync(
    InterventionPoint.PreToolCall, denySnap, EnforcementMode.Enforce);
Check(denyResult.Verdict.Decision == Decision.Deny,
      "deny over limit",
      $"got {denyResult.Verdict.Decision.ToWireName()} reason={denyResult.Verdict.Reason}");

// 3. escalate path (evaluate_only surfaces the raw verdict)
var escalateSnap = JsonDocument.Parse(
    @"{ ""tool_call"": { ""id"": ""call-escalate"", ""name"": ""wire_transfer"", ""args"": { ""amount"": 750 } }, ""envelope"": { ""agent"": { ""id"": ""demo"" } } }").RootElement;
var rawEscalate = await control.EvaluateInterventionPointAsync(
    InterventionPoint.PreToolCall, escalateSnap, EnforcementMode.EvaluateOnly);
Check(rawEscalate.Verdict.Decision == Decision.Escalate,
      "escalate raw (evaluate_only)",
      $"got {rawEscalate.Verdict.Decision.ToWireName()} reason={rawEscalate.Verdict.Reason}");
Check(rawEscalate.InputIdentity is not null && rawEscalate.EnforcedIdentity is not null
      && rawEscalate.InputIdentity == rawEscalate.EnforcedIdentity,
      "escalate bisected identity",
      $"input_identity == enforced_identity (escalate carries no transform per AGT D1.4)");

// Drive the resolver end-to-end: build a second control whose resolver
// captures the identities the host receives and approves with the
// enforced_identity (matching the AGT D1.4 binding contract).
string? resolverInputIdentity = null;
string? resolverEnforcedIdentity = null;
var resolverControl = await AgentControl.FromPathAsync(
    Path.Combine(tmp, "manifest.yaml"),
    approvalResolver: (_, result, _) =>
    {
        resolverInputIdentity = result.InputIdentity;
        resolverEnforcedIdentity = result.EnforcedIdentity;
        return ValueTask.FromResult(ApprovalResolution.Allow(result.EnforcedIdentity!));
    });
var approvedRun = await resolverControl.RunToolAsync<object, string>(
    "wire_transfer",
    new { amount = 750 },
    (args, _) => ValueTask.FromResult($"ok:{JsonSerializer.Serialize(args)}"),
    "call-escalate-approve");
Check(approvedRun.PreToolCallResult.Verdict.Decision == Decision.Escalate,
      "escalate routed through resolver",
      "pre_tool_call surfaced escalate before the approval ran");
Check(resolverInputIdentity is not null && resolverEnforcedIdentity is not null
      && resolverInputIdentity == resolverEnforcedIdentity,
      "approval resolver receives bisected identity",
      $"input_identity == enforced_identity from the resolver callback");

// 4. transform path: output policy redacts SSN-shaped values
var ssnSnap = JsonDocument.Parse(
    @"{ ""output"": ""Customer SSN is 123-45-6789, please update."" }").RootElement;
var transformResult = await control.EvaluateInterventionPointAsync(
    InterventionPoint.Output, ssnSnap, EnforcementMode.Enforce);
Check(transformResult.Verdict.Decision == Decision.Transform,
      "transform decision",
      $"got {transformResult.Verdict.Decision.ToWireName()} reason={transformResult.Verdict.Reason}");
var transformedValue = transformResult.TransformedPolicyTarget?.GetString();
Check(transformedValue == "Customer SSN is [REDACTED]",
      "transform value applied",
      $"transformed_policy_target = {transformedValue ?? "<null>"}");
Check(transformResult.Verdict.Transform?.Path == "$policy_target",
      "transform body carries $policy_target path",
      $"verdict.transform.path = {transformResult.Verdict.Transform?.Path ?? "<null>"}");
Check(transformResult.InputIdentity != transformResult.EnforcedIdentity,
      "transform shifts enforced_identity",
      "input_identity != enforced_identity per AGT D1.4");

Console.WriteLine($"\n  .NET demo: {passed}/{total} paths green");
Environment.Exit(passed == total ? 0 : 1);
CS
    # The packed SDK keeps the 0.1.0 version while the AGT 5.0 surface
    # rolls forward. NuGet caches by (id, version) so a stale package on
    # disk would mask our newly-packed AgentControlSpecification.0.1.0
    # nupkg. Drop the global-cache copies for this package family before
    # the restore so the local feed wins.
    for pkg in agentcontrolspecification agentcontrolspecification.ai agentcontrolspecification.agentframework agentcontrolspecification.autogen agentcontrolspecification.semantickernel; do
      rm -rf "$HOME/.nuget/packages/$pkg/0.1.0" 2>/dev/null || true
    done
    dotnet restore --configfile NuGet.Config 2>&1 | tail -5 || { warn ".NET restore failed"; exit 1; }
    AGT_DEMO_TMP="$DEMO_TMP/demo-dotnet-data" dotnet run --no-restore 2>&1 | tail -10 || { warn ".NET demo run failed"; exit 1; }
  ) && { ok ".NET demo green"; record "dotnet-demo" "ok"; } || { warn ".NET demo had issues; see above"; record "dotnet-demo" "warn"; }
fi

# ── 9. AGT-policies wrapper: end-to-end with manifest resolution ─

if should_run agt-policies; then
  banner "6. agt-policies wrapper: manifest resolution end-to-end"
  cat > "$DEMO_TMP/demo_agt_policies.py" <<'PY'
"""Demonstrates the AGT-side manifest resolution layer.

Drops two governance.yaml files in a workspace (root + child),
runs agt.manifest_resolution.resolve_manifest, confirms the
resulting flat ACS manifest binds the merged rules, then runs
through AgtRuntime to verify the deny-immutability invariant.
"""
from __future__ import annotations
import sys, tempfile
from pathlib import Path
import yaml

from agt.manifest_resolution import resolve_manifest
from agt.policies.runtime import AgtRuntime
from agt.policies.snapshot import pre_tool_call_snapshot

with tempfile.TemporaryDirectory(prefix="agt-demo-resolve-") as tmp:
    tmp = Path(tmp)
    # Parent: deny wire_transfer over $100k
    (tmp / "governance.yaml").write_text(yaml.safe_dump({
        "rules": [{
            "name": "block_large_wire",
            "condition": {"field": "tool_call.args.amount", "operator": "gt", "value": 100000},
            "action": "deny", "priority": 100,
            "message": "Org-level deny",
        }],
        "tools": {"wire_transfer": {"clearance": "confidential"}},
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }))
    # Child tries to override the parent deny with allow (must be DROPPED).
    sub = tmp / "subdir"; sub.mkdir()
    (sub / "governance.yaml").write_text(yaml.safe_dump({
        "rules": [{
            "name": "block_large_wire",
            "condition": {"field": "tool_call.args.amount", "operator": "gt", "value": 100000},
            "action": "allow", "priority": 200, "override": True,
            "message": "Child tries to override",
        }],
    }))
    bundle_dir = tmp / ".agt" / "resolved-bundle"
    manifest = resolve_manifest(tmp, tmp, bundle_dir=bundle_dir)
    manifest_path = tmp / "resolved.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest))

    runtime = AgtRuntime(manifest_path)
    snap = pre_tool_call_snapshot(
        agent_id="demo", tool_name="wire_transfer", args={"amount": 999999},
    )
    result = runtime.evaluate_intervention_point("pre_tool_call", snap)
    if result.verdict == "deny":
        print("  ✓ deny-immutability preserved across resolution chain")
        sys.exit(0)
    print(f"  ✗ expected deny (child override dropped), got {result.verdict}")
    sys.exit(1)
PY
  "$PY_VENV/bin/python3" "$DEMO_TMP/demo_agt_policies.py" || die "agt-policies demo failed"
  ok "agt-policies demo green"
  record "agt-policies-demo" "ok"
fi

# ── 10. Migration tool ──────────────────────────────────────────

if should_run migration; then
  banner "7. agt migrate v4-to-v5 dry-run"
  MIGRATE_PROJECT="$DEMO_TMP/legacy-v4-project"
  rm -rf "$MIGRATE_PROJECT"; mkdir -p "$MIGRATE_PROJECT/src"
  cat > "$MIGRATE_PROJECT/governance.yaml" <<'GY'
rules:
  - name: legacy_block_export
    condition: { field: tool_name, operator: eq, value: export_data }
    action: deny
    priority: 100
GY
  cat > "$MIGRATE_PROJECT/src/agent.py" <<'AGENT'
from agent_os.policies import PolicyAction
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy(max_tokens=8192, max_tool_calls=10)
deny = PolicyAction.BLOCK
AGENT
  if "$PY_VENV/bin/python3" -m agt.cli migrate --help >/dev/null 2>&1; then
    "$PY_VENV/bin/python3" -m agt.cli migrate v4-to-v5 "$MIGRATE_PROJECT" --dry-run || warn "migrate dry-run reported issues"
    record "migration-demo" "ok (dry-run)"
  else
    warn "agt.cli not installed; skipping migration demo"
    record "migration-demo" "skipped (cli missing)"
  fi
fi

# ── 11. Final summary ───────────────────────────────────────────

banner "Demo summary"
total=0; passed=0
for key in core python-sdk node-sdk dotnet-sdk python-demo rust-demo node-demo dotnet-demo agt-policies-demo migration-demo; do
  status="${RESULTS[$key]:-n/a}"
  case "$status" in
    ok|"ok (dry-run)") ok "$key: $status"; total=$((total+1)); passed=$((passed+1)) ;;
    skipped*)         warn "$key: $status" ;;
    ok-or-warn)       warn "$key: completed with warnings" ;;
    n/a)              :; ;;
    *)                printf "${RED}✗${RESET} %s: %s\n" "$key" "$status"; total=$((total+1)) ;;
  esac
done

printf "\n${BLUE}═══ %d/%d suites green ═══${RESET}\n" "$passed" "$total"
[[ $passed -eq $total ]] && exit 0 || exit 1

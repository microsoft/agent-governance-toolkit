# Tutorial 18 — Compliance Verification & Attestation

> **Package:** `agent-governance-toolkit` · **Time:** 30 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- Governance grading with automated compliance checks
- Regulatory framework mapping (OWASP ASI 2026)
- Cryptographic attestation records for audit trails

---

## Proving governance compliance — from internal verification to regulatory audits

Every governed agent system must answer a deceptively simple question: _"Can you prove you're compliant?"_  Not "do you think you are," but **prove** — with cryptographic attestations, coverage grades, and audit-ready reports that satisfy both your engineering team and your compliance officer.

The `agent-compliance` package turns governance from a claim into evidence. In basic mode it verifies that OWASP ASI 2026 control components are installed. In evidence mode it validates a runtime evidence manifest from a live deployment, grades your coverage, generates signed attestation records, validates source integrity against tamper-proof manifests, and gates agent promotion through lifecycle stages.

**Prerequisites:** `pip install agent-governance-toolkit[full]`
**Modules:** `agent_compliance.verify`, `agent_compliance.integrity`, `agent_compliance.promotion`

---

| What you'll learn | Where it lives |
|---|---|
| Verify governance controls are installed | `agent_compliance.verify.GovernanceVerifier` |
| Read compliance grades (A–F) | `GovernanceAttestation.compliance_grade()` |
| Map controls to regulatory frameworks | GDPR, HIPAA, SOX, EU AI Act, SOC 2 |
| Generate signed attestation records | `GovernanceAttestation.to_json()` |
| Verify source file integrity | `agent_compliance.integrity.IntegrityVerifier` |
| Gate agent promotions by maturity | `agent_compliance.promotion.PromotionChecker` |
| Generate compliance badges | `GovernanceAttestation.badge_markdown()` |
| Use the CLI for CI/CD pipelines | `agent-governance verify`, `integrity` |
| Map to OWASP Agentic Top 10 | `OWASP_ASI_CONTROLS` mapping |

---

## 1. Installation

The compliance package is included in the full toolkit install:

```bash
# Full install — includes all layers
pip install agent-governance-toolkit[full]

# Minimal — compliance verification only (still needs kernel + mesh)
pip install agent-governance-toolkit

# À la carte — add runtime or SRE extras
pip install agent-governance-toolkit[runtime]
pip install agent-governance-toolkit[sre]
```

Three CLI entry points are registered — all equivalent:

```bash
agent-governance verify
agent-governance-toolkit verify
agent-compliance verify
```

---

## 2. Quick Start — Five Lines to a Compliance Grade

```python
from agent_compliance.verify import GovernanceVerifier

verifier = GovernanceVerifier()
attestation = verifier.verify()

print(f"Grade: {attestation.compliance_grade()}")   # A, B, C, D, or F
print(f"Coverage: {attestation.coverage_pct()}%")    # 0–100
print(attestation.summary())
```

Output:

```
Grade: A
Coverage: 100%

Governance Verification Summary
================================
✅ ASI-01 Prompt Injection
✅ ASI-02 Insecure Tool Use
✅ ASI-03 Excessive Agency
✅ ASI-04 Unauthorized Escalation
✅ ASI-05 Trust Boundary Violation
✅ ASI-06 Insufficient Logging
✅ ASI-07 Insecure Identity
✅ ASI-08 Policy Bypass
✅ ASI-09 Supply Chain Integrity
✅ ASI-10 Behavioral Anomaly
================================
Result: PASSED (10/10 controls present)
```

That's it. In basic mode, `GovernanceVerifier` imports each control module, checks for the expected component, and produces a signed `GovernanceAttestation` with SHA-256 hash, coverage percentage, letter grade, and badge URL. In evidence mode, it also validates a runtime evidence manifest with loaded policy files, deny semantics, registered tools, audit sink configuration, identity state, and package versions.

---

## 3. GovernanceVerifier — How Controls Are Checked

### 3.1 OWASP ASI 2026 Control Map

The verifier checks 10 controls from the OWASP Agentic Security Initiatives (ASI) 2026 framework. Each control maps to a specific module and component in the governance toolkit:

| Control | Risk | Module | Component |
|---------|------|--------|-----------|
| ASI-01 | Prompt Injection | `agent_os.integrations.base` | `PolicyInterceptor` |
| ASI-02 | Insecure Tool Use | `agent_os.integrations.tool_aliases` | `ToolAliasRegistry` |
| ASI-03 | Excessive Agency | `agent_os.integrations.base` | `GovernancePolicy` |
| ASI-04 | Unauthorized Escalation | `agent_os.integrations.escalation` | `EscalationPolicy` |
| ASI-05 | Trust Boundary Violation | `agentmesh.trust.cards` | `CardRegistry` |
| ASI-06 | Insufficient Logging | `agentmesh.governance.audit` | `AuditChain` |
| ASI-07 | Insecure Identity | `agentmesh.identity.agent_id` | `AgentIdentity` |
| ASI-08 | Policy Bypass | `agentmesh.governance.conflict_resolution` | `PolicyConflictResolver` |
| ASI-09 | Supply Chain Integrity | `agent_compliance.integrity` | `IntegrityVerifier` |
| ASI-10 | Behavioral Anomaly | `agentmesh.governance.compliance` | `ComplianceEngine` |

### 3.2 Verification Logic

Basic mode checks whether each control module and component is importable:

    from agent_compliance.verify import GovernanceVerifier, ControlResult

    verifier = GovernanceVerifier()
    attestation = verifier.verify()

    # Inspect individual control results
    for control in attestation.controls:
        status = "✅" if control.present else "❌"
        print(f"{status} {control.control_id}: {control.name}")
        print(f"   Module: {control.module}")
        print(f"   Component: {control.component}")
        if control.error:
            print(f"   Error: {control.error}")

Behind the scenes, `_check_control()` does a straightforward import check:

    For each (control_id, spec) in OWASP_ASI_CONTROLS:
      1. Import spec["module"]
      2. Check hasattr(module, spec["check"])
      3. Return ControlResult(present=True/False)

If the module can't be imported or the component doesn't exist, the control is marked as missing — no exceptions are raised.

### 3.3 Evidence Mode

Evidence mode validates a runtime evidence manifest emitted by the deployment:

    agt verify --evidence ./agt-evidence.json
    agt verify --evidence ./agt-evidence.json --strict

The evidence manifest records:

- loaded policy files
- deny rule or deny-by-default semantics
- registered tools
- audit sink configuration
- identity state
- package/version manifest

`--strict` fails when runtime evidence is missing or weak.

### 3.4 Custom Controls

You can extend the verifier with your own controls. Pass a custom control dictionary to check organization-specific governance components:

```python
custom_controls = {
    "ORG-01": {
        "name": "Data Classification",
        "module": "myorg.governance.classification",
        "check": "DataClassifier",
    },
    "ORG-02": {
        "name": "PII Detection",
        "module": "myorg.governance.pii",
        "check": "PIIScanner",
    },
}

verifier = GovernanceVerifier(controls=custom_controls)
attestation = verifier.verify()
print(f"Custom coverage: {attestation.coverage_pct()}%")
```

---

## 4. Compliance Grading

### 4.1 The A–F Scale

`GovernanceAttestation.compliance_grade()` converts your coverage percentage into a letter grade:

| Grade | Coverage | Meaning |
|-------|----------|---------|
| **A** | ≥ 90% | Excellent — all or nearly all controls present |
| **B** | ≥ 80% | Good — most controls present, minor gaps |
| **C** | ≥ 70% | Acceptable — notable gaps need attention |
| **D** | ≥ 60% | Poor — significant governance gaps |
| **F** | < 60% | Failing — critical controls missing |

```python
attestation = GovernanceVerifier().verify()

grade = attestation.compliance_grade()    # "A"
pct = attestation.coverage_pct()          # 100
passed = attestation.controls_passed      # 10
total = attestation.controls_total        # 10
overall = attestation.passed              # True (all controls present)
```

### 4.2 Coverage Calculation

Coverage is calculated as:

```
coverage_pct = floor(controls_passed / controls_total × 100)
```

Where `controls_passed` is the number of controls with `present=True` and `controls_total` is the total number of controls checked. If `controls_total` is zero (e.g., empty custom controls), `coverage_pct()` returns `0`.

### 4.3 Grade Thresholds in CI/CD

Use the grade to gate deployments:

```python
import sys
from agent_compliance.verify import GovernanceVerifier

attestation = GovernanceVerifier().verify()
grade = attestation.compliance_grade()

if grade in ("D", "F"):
    print(f"❌ Compliance grade {grade} — deployment blocked")
    sys.exit(1)

if grade in ("B", "C"):
    print(f"⚠️  Compliance grade {grade} — review required")

print(f"✅ Compliance grade {grade} — clear for deployment")
```

---

## 5. Regulatory Frameworks

The OWASP ASI controls map directly to requirements in major regulatory frameworks. Here's how each framework leverages the toolkit's controls:

### 5.1 Framework Mapping

| Framework | Key Controls | What Gets Checked |
|-----------|-------------|-------------------|
| **GDPR** | ASI-01, ASI-06, ASI-07 | Data processing consent, audit logging, identity verification |
| **HIPAA** | ASI-05, ASI-06, ASI-07, ASI-09 | Trust boundaries for PHI, audit trails, access identity, supply chain integrity |
| **SOX** | ASI-03, ASI-04, ASI-06, ASI-08 | Agency limits, escalation controls, audit logging, policy enforcement |
| **EU AI Act** | ASI-01, ASI-03, ASI-10 | Prompt injection defense, agency constraints, behavioral monitoring |
| **SOC 2** | ASI-02, ASI-05, ASI-06, ASI-07, ASI-09 | Tool use controls, trust boundaries, logging, identity, integrity |

### 5.2 GDPR — Data Protection

GDPR requires demonstrable data protection. The toolkit addresses this through:

- **ASI-01 (Prompt Injection)**: `PolicyInterceptor` prevents prompt-based data exfiltration
- **ASI-06 (Insufficient Logging)**: `AuditChain` creates tamper-evident logs for data subject access requests
- **ASI-07 (Insecure Identity)**: `AgentIdentity` ensures every data-processing agent has a verifiable DID

```python
# GDPR audit: verify all data protection controls are present
verifier = GovernanceVerifier()
attestation = verifier.verify()

gdpr_controls = ["ASI-01", "ASI-06", "ASI-07"]
for control in attestation.controls:
    if control.control_id in gdpr_controls:
        status = "✅" if control.present else "❌ GDPR GAP"
        print(f"{status} {control.control_id}: {control.name}")
```

### 5.3 HIPAA — Healthcare Data

HIPAA compliance hinges on access controls and audit trails:

- **ASI-05 (Trust Boundary Violation)**: `CardRegistry` enforces trust boundaries around PHI
- **ASI-09 (Supply Chain Integrity)**: `IntegrityVerifier` ensures governance modules haven't been tampered with — critical for validated systems

### 5.4 SOX — Financial Controls

SOX requires segregation of duties and change control:

- **ASI-04 (Unauthorized Escalation)**: `EscalationPolicy` prevents privilege escalation outside approved workflows
- **ASI-08 (Policy Bypass)**: `PolicyConflictResolver` ensures policies can't be circumvented

### 5.5 EU AI Act — AI-Specific Regulation

The EU AI Act mandates transparency and human oversight for high-risk AI:

- **ASI-03 (Excessive Agency)**: `GovernancePolicy` constrains what agents can do autonomously
- **ASI-10 (Behavioral Anomaly)**: `ComplianceEngine` monitors for out-of-spec behavior

### 5.6 SOC 2 — Service Organization Controls

SOC 2 Type II audits require continuous monitoring across security, availability, and confidentiality:

- **ASI-02 (Insecure Tool Use)**: `ToolAliasRegistry` enforces capability-based tool access
- **ASI-05 + ASI-07**: Trust boundaries and identity form the access control foundation

---

## 6. Attestation Records

### 6.1 What Is an Attestation?

A `GovernanceAttestation` is a signed, timestamped compliance claim. It captures exactly which controls were checked, which passed, and produces a SHA-256 hash of the payload for tamper detection.

```python
from agent_compliance.verify import GovernanceVerifier

attestation = GovernanceVerifier().verify()

# Attestation metadata
print(f"Verified at: {attestation.verified_at}")         # ISO timestamp
print(f"Toolkit version: {attestation.toolkit_version}")  # e.g., "2.2.0"
print(f"Python version: {attestation.python_version}")    # e.g., "3.11.5"
print(f"Platform: {attestation.platform_info}")           # e.g., "Linux-6.1..."
print(f"Hash: {attestation.attestation_hash}")            # SHA-256
```

### 6.2 JSON Attestation for Auditors

The `to_json()` method produces a machine-readable attestation with a versioned schema:

```python
import json

attestation = GovernanceVerifier().verify()
attestation_json = attestation.to_json()

print(json.dumps(json.loads(attestation_json), indent=2))
```

Output:

```json
{
  "schema": "governance-attestation/v1",
  "passed": true,
  "controls_passed": 10,
  "controls_total": 10,
  "coverage_pct": 100,
  "compliance_grade": "A",
  "toolkit_version": "2.2.0",
  "python_version": "3.11.5",
  "platform_info": "Linux-6.1.0-x86_64",
  "verified_at": "2025-07-16T14:30:00.000000",
  "attestation_hash": "a3f8b1c2d4e5f6...",
  "controls": [
    {
      "control_id": "ASI-01",
      "name": "Prompt Injection",
      "present": true,
      "module": "agent_os.integrations.base",
      "component": "PolicyInterceptor"
    }
  ]
}
```

The `governance-attestation/v1` schema is stable — auditors and CI/CD systems can parse it reliably across toolkit versions.

### 6.3 Attestation Hash Verification

The `attestation_hash` is a SHA-256 hash of the attestation payload. It's deterministic — the same verification run produces the same hash, so you can verify that an attestation hasn't been modified after generation:

```python
import hashlib
import json

attestation = GovernanceVerifier().verify()

# The hash is computed from the payload contents
json_data = attestation.to_json()
stored_hash = json.loads(json_data)["attestation_hash"]

# Store this hash alongside the attestation for tamper detection
print(f"Attestation hash: {stored_hash}")
```

### 6.4 Storing Attestations

A common pattern is to store attestations alongside your deployment artifacts:

```python
import json
from pathlib import Path
from datetime import datetime
from agent_compliance.verify import GovernanceVerifier

attestation = GovernanceVerifier().verify()

# Write attestation to deployment artifacts
attestation_dir = Path("artifacts/compliance")
attestation_dir.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
attestation_path = attestation_dir / f"attestation-{timestamp}.json"
attestation_path.write_text(attestation.to_json())

print(f"Attestation stored: {attestation_path}")
```

---

## 7. Promotion Workflows

Agents progress through lifecycle stages — from experimental prototypes to production-stable services. The `PromotionChecker` gates these transitions with automated criteria validation.

### 7.1 Maturity Levels

```
                     promote()              promote()
  ┌──────────────┐  ──────────►  ┌────────┐  ──────────►  ┌────────┐
  │ EXPERIMENTAL │               │  BETA  │               │ STABLE │
  └──────────────┘               └────────┘               └────────┘
         │                           │                         │
         └───────────────────────────┼─────────────────────────┘
                                     │
                              deprecate()
                                     │
                                     ▼
                              ┌──────────────┐
                              │  DEPRECATED  │
                              └──────────────┘
```

| Level | Description | Allowed Transitions |
|-------|-------------|---------------------|
| `EXPERIMENTAL` | Early development, unstable APIs | → BETA, → DEPRECATED |
| `BETA` | Feature-complete, limited production use | → STABLE, → DEPRECATED |
| `STABLE` | Production-ready, full SLO coverage | → DEPRECATED |
| `DEPRECATED` | End-of-life, reachable from any level | Terminal state |

**Important:** Demotions (e.g., STABLE → BETA) and no-ops (BETA → BETA) are rejected.

### 7.2 Promotion Gates

Nine built-in gates evaluate whether an agent is ready to advance:

| Gate | What It Checks | Default Threshold | Severity |
|------|---------------|-------------------|----------|
| `test_coverage` | Minimum test coverage % | 80% | blocker |
| `security_scan` | No critical vulnerabilities | 0 critical vulns | blocker |
| `slo_compliance` | SLO target met for N days | 99% for 7+ days | blocker |
| `trust_score` | Minimum trust score | 0.7 | blocker |
| `peer_review` | Minimum peer reviews | 2 reviews | blocker |
| `error_budget` | Remaining error budget | ≥ 20% remaining | blocker |
| `observability` | Metrics + logging configured | Both required | blocker |
| `documentation` | README + API docs exist | Both required | blocker |
| `change_control` | Approved change request | Required | blocker |

### 7.3 Which Gates Apply When

Not all gates apply to every promotion:

| Transition | Gates Evaluated |
|-----------|----------------|
| EXPERIMENTAL → BETA | test_coverage, security_scan, trust_score, peer_review, observability, documentation |
| BETA → STABLE | All 9 gates (adds slo_compliance, error_budget, change_control) |
| Any → DEPRECATED | No gates — always allowed |

### 7.4 Running a Promotion Check

```python
from agent_compliance.promotion import PromotionChecker, MaturityLevel

checker = PromotionChecker()

# Build context with metrics from your CI/CD and observability systems
context = {
    "test_coverage": 87.5,
    "critical_vulns": 0,
    "slo_compliance_pct": 99.8,
    "slo_compliance_days": 14,
    "trust_score": 0.85,
    "peer_reviews": 3,
    "error_budget_remaining_pct": 42.0,
    "has_metrics": True,
    "has_logging": True,
    "has_readme": True,
    "has_api_docs": True,
    "has_approved_change_request": True,
}

report = checker.check_promotion(
    agent_id="data-processor-v2",
    current=MaturityLevel.EXPERIMENTAL,
    target=MaturityLevel.BETA,
    context=context,
)

print(f"Agent: {report.agent_id}")
print(f"Transition: {report.current_level.value} → {report.target_level.value}")
print(f"Ready: {report.overall_passed}")

if not report.overall_passed:
    print(f"Blockers: {report.blockers}")
else:
    print("✅ All gates passed — promotion approved")
```

### 7.5 Inspecting Gate Results

Each gate produces a `PromotionResult` with pass/fail status and a human-readable reason:

```python
report = checker.check_promotion(
    agent_id="my-agent",
    current=MaturityLevel.BETA,
    target=MaturityLevel.STABLE,
    context=context,
)

for gate in report.gates:
    status = "✅" if gate.passed else "❌"
    print(f"{status} {gate.gate_name}: {gate.reason}")
```

Output:

```
✅ test_coverage: Coverage 87.5% meets minimum 80.0%
✅ security_scan: No critical vulnerabilities found
✅ slo_compliance: SLO 99.8% over 14 days meets 99.0% for 7 days
✅ trust_score: Trust score 0.85 meets minimum 0.70
✅ peer_review: 3 peer reviews meets minimum 2
✅ error_budget: Error budget 42.0% remaining (threshold: 20.0%)
✅ observability: Metrics and logging configured
✅ documentation: README and API docs present
✅ change_control: Approved change request exists
```

### 7.6 Custom Promotion Gates

Register organization-specific gates using `PromotionGate`:

```python
from agent_compliance.promotion import (
    PromotionChecker,
    PromotionGate,
    MaturityLevel,
)

def _compliance_grade_check(context: dict) -> tuple[bool, str]:
    """Require minimum compliance grade for promotion."""
    grade = context.get("compliance_grade", "F")
    required = context.get("min_grade", "B")
    grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    passed = grade_order.get(grade, 0) >= grade_order.get(required, 4)
    reason = f"Grade {grade} {'meets' if passed else 'below'} minimum {required}"
    return passed, reason

checker = PromotionChecker()
checker.register_gate(PromotionGate(
    name="compliance_grade",
    check_fn=_compliance_grade_check,
    required_for={MaturityLevel.BETA, MaturityLevel.STABLE},
    severity="blocker",
))

report = checker.check_promotion(
    agent_id="my-agent",
    current=MaturityLevel.EXPERIMENTAL,
    target=MaturityLevel.BETA,
    context={**context, "compliance_grade": "A", "min_grade": "B"},
)
```

### 7.7 Warning vs. Blocker Severity

Gates with `severity="warning"` are advisory — they don't block promotion:

```python
checker.register_gate(PromotionGate(
    name="performance_regression",
    check_fn=_perf_check,
    required_for={MaturityLevel.STABLE},
    severity="warning",  # Won't block promotion if it fails
))

report = checker.check_promotion(...)
# report.overall_passed is True even if warning gates fail
# report.blockers only includes blocker-severity gates
```

---

## 8. Integrity Verification

### 8.1 Why Integrity Matters

Governance is only as strong as the code enforcing it. If someone modifies `PolicyEngine.evaluate()` to always return `allow`, your policies become decoration. The `IntegrityVerifier` catches this by hashing governance module source files and critical function bytecodes.

### 8.2 Governance Modules Verified

The verifier checks 15 core governance modules:

```python
GOVERNANCE_MODULES = [
    "agent_os.integrations.base",
    "agent_os.integrations.escalation",
    "agent_os.integrations.tool_aliases",
    "agent_os.integrations.compat",
    "agentmesh.governance.policy",
    "agentmesh.governance.conflict_resolution",
    "agentmesh.governance.audit",
    "agentmesh.governance.opa",
    "agentmesh.governance.compliance",
    "agentmesh.governance.shadow",
    "agentmesh.identity.agent_id",
    "agentmesh.identity.revocation",
    "agentmesh.identity.rotation",
    "agentmesh.trust.cards",
    "agentmesh.storage.file_trust_store",
]
```

### 8.3 Critical Function Bytecode Hashing

Beyond file-level hashing, the verifier also hashes the bytecode of critical functions — the actual compiled code that runs:

```python
CRITICAL_FUNCTIONS = [
    ("agentmesh.governance.policy", "PolicyEngine.evaluate"),
    ("agentmesh.governance.conflict_resolution", "PolicyConflictResolver.resolve"),
    ("agentmesh.governance.audit", "AuditChain.add_entry"),
    ("agentmesh.trust.cards", "CardRegistry.is_verified"),
]
```

This catches tampering that file-level hashing might miss, such as runtime monkey-patching of critical methods.

### 8.4 Generate a Manifest

A manifest captures the current state of all governance modules as a baseline:

```python
from agent_compliance.integrity import IntegrityVerifier

verifier = IntegrityVerifier()

# Generate baseline manifest from current (known-good) state
manifest = verifier.generate_manifest("integrity.json")
print(f"Manifest generated with {len(manifest)} modules")
```

This creates an `integrity.json` file containing SHA-256 hashes of every governance module source file and critical function bytecode. Commit this to your repository or store it as a build artifact.

### 8.5 Verify Against a Manifest

In CI/CD or at runtime, verify that nothing has changed:

```python
from agent_compliance.integrity import IntegrityVerifier

verifier = IntegrityVerifier(manifest_path="integrity.json")
report = verifier.verify()

print(report.summary())
print(f"Modules checked: {report.modules_checked}")
print(f"Modules missing: {report.modules_missing}")
```

Output (all passing):

```
Integrity Verification: PASSED
Modules checked: 15
Modules missing: 0
File checks: 15/15 passed
Function checks: 4/4 passed
```

Output (tampered file detected):

```
Integrity Verification: FAILED
Modules checked: 15
Modules missing: 0
File checks: 14/15 passed
Function checks: 4/4 passed

FAILED files:
  ❌ agentmesh.governance.policy — hash mismatch
     Expected: a3f8b1c2...
     Actual:   7d9e0f1a...
```

### 8.6 Verify Without a Manifest

If no manifest is provided, the verifier still checks that modules can be imported and their source files exist, but skips hash comparison. This is useful for smoke-testing that the governance stack is installed:

```python
verifier = IntegrityVerifier()  # No manifest
report = verifier.verify()
print(f"Passed: {report.passed}")  # True if all modules importable
```

### 8.7 Integrity Report Serialization

Export the report for logging or auditing:

```python
import json

report = IntegrityVerifier(manifest_path="integrity.json").verify()
report_dict = report.to_dict()

print(json.dumps(report_dict, indent=2))
# Includes: passed, verified_at, manifest_path,
#           modules_checked, modules_missing,
#           file_results (per-module), function_results (per-function)
```

---

## 9. Badge Generation

### 9.1 Shields.io Badge URL

`GovernanceAttestation` generates a [Shields.io](https://shields.io) badge URL that reflects your compliance grade:

```python
attestation = GovernanceVerifier().verify()
print(attestation.badge_url())
```

Output:

```
https://img.shields.io/badge/governance-100%25-brightgreen
```

Badge color follows coverage thresholds:

| Coverage | Color |
|----------|-------|
| 100% | `brightgreen` |
| ≥ 80% | `yellow` |
| < 80% | `red` |

### 9.2 Markdown Badge for READMEs

Embed a compliance badge directly in your README:

```python
attestation = GovernanceVerifier().verify()
print(attestation.badge_markdown())
```

Output:

```markdown
![Governance](https://img.shields.io/badge/governance-100%25-brightgreen)
```

### 9.3 Automated Badge Updates in CI

Add badge generation to your CI pipeline:

```python
from pathlib import Path
from agent_compliance.verify import GovernanceVerifier

attestation = GovernanceVerifier().verify()
badge_md = attestation.badge_markdown()

readme = Path("README.md")
content = readme.read_text()

# Replace existing badge or add new one
import re
badge_pattern = r"!\[Governance\]\(https://img\.shields\.io/badge/governance-.*?\)"
if re.search(badge_pattern, content):
    content = re.sub(badge_pattern, badge_md, content)
else:
    content = badge_md + "\n\n" + content

readme.write_text(content)
print(f"README updated with compliance badge: {attestation.compliance_grade()}")
```

---

## 10. CLI Reference

### 10.1 `agent-governance verify`

Verify governance controls and output compliance status:

```bash
# Human-readable summary (default)
agent-governance verify

# JSON attestation for CI/CD pipelines
agent-governance verify --json

# Markdown badge only
agent-governance verify --badge

# Runtime evidence manifest
agent-governance verify --evidence ./agt-evidence.json

# Strict evidence mode
agent-governance verify --evidence ./agt-evidence.json --strict
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | All controls present — verification passed |
| `1` | One or more controls missing — verification incomplete |

**CI/CD integration:**

```yaml
# GitHub Actions example
- name: Verify governance compliance
  run: |
    pip install agent-governance-toolkit[full]
    agent-governance verify --json > compliance-attestation.json

- name: Upload attestation artifact
  uses: actions/upload-artifact@v4
  with:
    name: compliance-attestation
    path: compliance-attestation.json

- name: Update README badge
  run: agent-governance verify --badge >> $GITHUB_STEP_SUMMARY
```

### 10.2 `agent-governance integrity`

Verify or generate integrity manifests:

```bash
# Generate a manifest from current module state
agent-governance integrity --generate integrity.json

# Verify against an existing manifest
agent-governance integrity --manifest integrity.json

# JSON output for automation
agent-governance integrity --manifest integrity.json --json
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Integrity verified (or manifest generated successfully) |
| `1` | Integrity check failed, or error (missing manifest, read-only dir) |

**Important:** `--manifest` and `--generate` are mutually exclusive — passing both returns exit code 1.

**Error handling:**

```bash
# Non-existent manifest — clean error, no traceback
$ agent-governance integrity --manifest nonexistent.json
Error: Manifest file not found: nonexistent.json

# Read-only output directory — clean error
$ agent-governance integrity --generate /readonly/integrity.json
Error: Cannot write to output directory: /readonly/
```

### 10.3 Pipeline Recipe — Full Verification

Combine verify and integrity checks in a single pipeline step:

```bash
#!/bin/bash
set -e

echo "=== Governance Verification ==="
agent-governance verify --json > attestation.json

echo "=== Integrity Verification ==="
agent-governance integrity --manifest integrity.json --json > integrity-report.json

echo "=== Results ==="
python -c "
import json
att = json.load(open('attestation.json'))
intg = json.load(open('integrity-report.json'))
print(f\"Compliance: {att['compliance_grade']} ({att['coverage_pct']}%)\")
print(f\"Integrity: {'PASSED' if intg['passed'] else 'FAILED'}\")
"
```

---

## 11. OWASP ASI Mapping

The toolkit provides complete coverage of the OWASP Agentic Top 10 risks. Each risk maps to a specific layer and mitigation strategy:

### 11.1 Coverage Matrix

```
ASI Risk                          Layer          Mitigation
──────────────────────────────────────────────────────────────────
ASI-01  Agent Goal Hijack         Agent OS       Policy-based action interception
ASI-02  Tool Misuse               Agent OS       Capability-based tool allowlists
ASI-03  Identity & Privilege      AgentMesh      DID identity, trust scoring
ASI-04  Supply Chain Vulns        AgentMesh      AI-BOM v2.0, provenance tracking
ASI-05  Unexpected Code Exec      Agent Runtime  CPU ring-inspired isolation (0–3)
ASI-06  Memory & Context Poison   Agent OS       VFS policies, CMVK verification
ASI-07  Insecure Inter-Agent      AgentMesh      IATP protocol, encrypted channels
ASI-08  Cascading Failures        Agent SRE      Circuit breakers, SLO enforcement
ASI-09  Human-Agent Trust         Agent OS       Approval workflows, quorum logic
ASI-10  Rogue Agents              Runtime+Mesh   Kill switch, behavioral monitoring
```

### 11.2 Cross-Cutting: Least Agency

The toolkit enforces a **Least Agency** principle at every layer:

- **Deny-by-default policies** — agents can only do what's explicitly allowed
- **Scoped capabilities** — each agent gets the minimum permissions needed
- **Delegation narrowing** — delegated permissions can never exceed the delegator's

### 11.3 Verification Proves Coverage

The `GovernanceVerifier` maps directly to this matrix. When it reports "10/10 controls present," it means every OWASP ASI risk has a corresponding mitigation component installed and importable:

```python
attestation = GovernanceVerifier().verify()

if attestation.passed:
    print("✅ Full OWASP ASI 2026 coverage verified")
    print(f"   Attestation hash: {attestation.attestation_hash[:16]}...")
else:
    missing = [c for c in attestation.controls if not c.present]
    print(f"❌ {len(missing)} OWASP ASI controls missing:")
    for c in missing:
        print(f"   - {c.control_id}: {c.name}")
```

For the full OWASP mapping with detailed mitigations, see [`docs/OWASP-COMPLIANCE.md`](../OWASP-COMPLIANCE.md).

---

## 12. End-to-End Example

Here's a complete compliance workflow that combines verification, integrity checking, promotion gating, and attestation storage:

```python
import json
from pathlib import Path
from agent_compliance.verify import GovernanceVerifier
from agent_compliance.integrity import IntegrityVerifier
from agent_compliance.promotion import PromotionChecker, MaturityLevel


def run_compliance_pipeline(agent_id: str, target_level: MaturityLevel):
    """Full compliance pipeline: verify → integrity → promote → attest."""
    results = {}

    # Step 1: Governance verification
    print("─── Step 1: Governance Verification ───")
    verifier = GovernanceVerifier()
    attestation = verifier.verify()
    results["grade"] = attestation.compliance_grade()
    results["coverage"] = attestation.coverage_pct()
    print(f"Grade: {results['grade']} ({results['coverage']}%)")

    if results["grade"] == "F":
        print("❌ Failing grade — pipeline aborted")
        return results

    # Step 2: Integrity verification
    print("\n─── Step 2: Integrity Verification ───")
    manifest_path = Path("integrity.json")
    if manifest_path.exists():
        integrity = IntegrityVerifier(manifest_path=str(manifest_path))
        report = integrity.verify()
        results["integrity"] = report.passed
        print(f"Integrity: {'PASSED' if report.passed else 'FAILED'}")
        if not report.passed:
            print("❌ Integrity failure — pipeline aborted")
            return results
    else:
        print("⚠️  No manifest found — generating baseline")
        integrity = IntegrityVerifier()
        integrity.generate_manifest(str(manifest_path))
        results["integrity"] = True

    # Step 3: Promotion check
    print(f"\n─── Step 3: Promotion Gate ({target_level.value}) ───")
    checker = PromotionChecker()
    promotion = checker.check_promotion(
        agent_id=agent_id,
        current=MaturityLevel.EXPERIMENTAL,
        target=target_level,
        context={
            "test_coverage": 87.5,
            "critical_vulns": 0,
            "slo_compliance_pct": 99.8,
            "slo_compliance_days": 14,
            "trust_score": 0.85,
            "peer_reviews": 3,
            "error_budget_remaining_pct": 42.0,
            "has_metrics": True,
            "has_logging": True,
            "has_readme": True,
            "has_api_docs": True,
            "has_approved_change_request": True,
        },
    )
    results["promotion_ready"] = promotion.overall_passed
    print(f"Promotion: {'APPROVED' if promotion.overall_passed else 'BLOCKED'}")
    if not promotion.overall_passed:
        print(f"Blockers: {promotion.blockers}")

    # Step 4: Store attestation
    print("\n─── Step 4: Store Attestation ───")
    artifacts = Path("artifacts/compliance")
    artifacts.mkdir(parents=True, exist_ok=True)
    attestation_file = artifacts / f"{agent_id}-attestation.json"
    attestation_file.write_text(attestation.to_json())
    print(f"Attestation stored: {attestation_file}")
    print(f"Badge: {attestation.badge_markdown()}")

    return results


# Run the pipeline
results = run_compliance_pipeline("data-processor-v2", MaturityLevel.BETA)
```

Output:

```
─── Step 1: Governance Verification ───
Grade: A (100%)

─── Step 2: Integrity Verification ───
⚠️  No manifest found — generating baseline

─── Step 3: Promotion Gate (beta) ───
Promotion: APPROVED

─── Step 4: Store Attestation ───
Attestation stored: artifacts/compliance/data-processor-v2-attestation.json
Badge: ![Governance](https://img.shields.io/badge/governance-100%25-brightgreen)
```

---

## Summary

| Concept | Key Class / Function | What It Does |
|---------|---------------------|-------------|
| Governance verification | `GovernanceVerifier` | Checks all 10 OWASP ASI controls are installed |
| Control result | `ControlResult` | Per-control pass/fail with module and component info |
| Attestation | `GovernanceAttestation` | Signed, timestamped compliance claim with SHA-256 hash |
| Compliance grade | `compliance_grade()` | A/B/C/D/F based on coverage percentage |
| Coverage | `coverage_pct()` | Integer percentage of controls present |
| Badge | `badge_markdown()` | Shields.io markdown for README embedding |
| JSON attestation | `to_json()` | Machine-readable `governance-attestation/v1` schema |
| Integrity verifier | `IntegrityVerifier` | SHA-256 hash verification of governance module files |
| Bytecode hashing | `CRITICAL_FUNCTIONS` | Hashes compiled bytecode of critical policy functions |
| Manifest generation | `generate_manifest()` | Creates `integrity.json` baseline for future checks |
| Integrity report | `IntegrityReport` | Per-file and per-function hash comparison results |
| Maturity levels | `MaturityLevel` | EXPERIMENTAL → BETA → STABLE → DEPRECATED |
| Promotion gates | `PromotionGate` | Named check function with severity (blocker/warning) |
| Promotion checker | `PromotionChecker` | Evaluates 9 built-in gates for level transitions |
| Promotion report | `PromotionReport` | Aggregate pass/fail with blocker list |
| CLI verify | `agent-governance verify` | `--json`, `--badge`, `--evidence`, `--strict` flags; exit code 0/1 |
| CLI integrity | `agent-governance integrity` | `--generate`, `--manifest`, `--json` flags |

---

## Cross-References

- **[Tutorial 02 — Trust & Identity](02-trust-and-identity.md)** — Agent identity (`AgentIdentity`), trust scoring, and DID credentials that underpin ASI-05 and ASI-07 controls
- **[Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md)** — `AuditChain` tamper-evident logging and `ComplianceEngine` behavioral monitoring (ASI-06, ASI-10)
- **[OWASP Compliance Mapping](../OWASP-COMPLIANCE.md)** — Full OWASP Agentic Top 10 mapping with per-risk mitigation details

---

## Next Steps

You now know how to **prove** governance compliance — from quick five-line checks to full CI/CD pipelines with attestation storage and promotion gating.

- **Automate it:** Add `agent-governance verify --json` to your CI pipeline and gate deployments on compliance grade
- **Lock it down:** Generate an `integrity.json` manifest and verify on every deploy to catch tampering
- **Promote safely:** Use `PromotionChecker` to enforce quality gates before moving agents to production
- **Audit trail:** Store JSON attestations as build artifacts for regulatory audits
- **Badge it:** Add `badge_markdown()` output to your README for visible compliance status

**Next:** [Tutorial 02 — Trust & Identity](02-trust-and-identity.md) for the identity and trust scoring system that powers ASI-05 and ASI-07 controls.

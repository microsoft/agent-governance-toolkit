# Testing & Red Team Simulation Guide

This directory contains the security verification suite for the OWASP ASI Policy Starter Packs. Follow these steps to validate the hardening against Arcanum-Sec and ASI Top 10 risks.

## 🛠️ Environment Setup

Ensure your `PYTHONPATH` includes the toolkit source trees (run from the repo root):

```bash
export PYTHONPATH=$PYTHONPATH:$(pwd)/agent-governance-python/agent-os/src:$(pwd)/agent-governance-python/agent-sre/src
```

## 🛡️ 1. Red Team Simulation (Primary)

The native replay suite executes adversarial fixtures against the starter
manifests.

```bash
pytest tests/unit/test_policy_test.py -v
```

The command fails when a recorded expected verdict drifts.

## 🧪 2. Automated Schema & Scenario Tests

Run the replay suite to verify native manifests and fixtures.

```bash
pytest tests/unit/test_policy_test.py -v
```

## ⌨️ 3. Manual Verification (CLI)

Replay the bundled fixtures through the public CLI.

### Example: General SaaS

```bash
agt test \
  examples/policy-templates/general-saas.yaml \
  examples/policy-templates/fixtures/general-saas-fixtures.json
```

---

## 🏗️ Adding New Scenarios

To add a new red team scenario, edit `tests/redteam/test_redteam_asi.py` and add a new `AdversarialScenario` object to the `SCENARIOS` list.

## 📁 Directory Structure

```text
tests/
├── ci/
├── smoke/
└── redteam/
    ├── payloads/          # (Future) YAML/JSON attack string libraries
    ├── reports/           # Local output for ad-hoc audit logs
    └── test_redteam_asi.py
```

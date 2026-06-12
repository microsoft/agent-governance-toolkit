# Google ADK + Governance Toolkit

This example demonstrates governance enforcement for Google ADK agents using `GoogleADKKernel`.

## Files

### getting_started.py

A minimal introduction to:

* Tool allowlists
* Tool blocklists
* Dangerous content detection
* Governance violations
* Audit logging

Run:

```bash
python examples/adk-governed/getting_started.py
```

### adk_governance_demo.py

An end-to-end governance demonstration covering:

1. Blocked Tool Enforcement
2. Tool Allowlist Enforcement
3. Dangerous Content Detection
4. Human Approval Workflow
5. Sensitive Tool Approval
6. Tool Call Limits
7. Budget Configuration
8. Audit Trail Review
9. Governance Summary

Run:

```bash
python examples/adk-governed/adk_governance_demo.py
```

## Policies

Policy configuration is located at:

```text
examples/adk-governed/policies/adk-governance.yaml
```

The sample policy demonstrates:

* Blocked tools
* Approval-required tools
* Delegation controls
* Audit settings

**Note:** The included policy file is illustrative. The example scripts configure governance directly through `GoogleADKKernel` for simplicity and do not currently load the YAML policy file.

## Requirements

```bash
pip install agent-os-kernel
```

## Notes

This example demonstrates governance enforcement through direct `GoogleADKKernel` callback invocation and does not require a running Google ADK agent.

The example is intentionally designed to avoid advanced AGT v5 runtime paths that require additional policy-engine components and native bindings. This keeps the demo runnable in a standard Python environment.

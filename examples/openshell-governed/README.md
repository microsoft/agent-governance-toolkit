# Governed AI Agent in OpenShell Sandbox

Demonstrates AGT policy enforcement, trust scoring, and audit inside an OpenShell sandbox.

## Quick Start

```bash
python examples/openshell-governed/demo.py
```

3 allowed (file read, python, git) + 3 denied (rm, metadata, /etc write). Trust decays 1.00 to 0.55.

## Related

- [OpenShell Integration Guide](../../docs/integrations/openshell.md)
- [Governance Skill Package](../../packages/agentmesh-integrations/openshell-skill/)

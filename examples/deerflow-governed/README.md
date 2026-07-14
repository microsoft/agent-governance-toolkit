# DeerFlow with native ACS governance

This example implements DeerFlow's guardrail provider interface with
`AgtRuntime`. Tool requests are normalized into an ACS input snapshot, then
evaluated by `policies/manifest.yaml` and its Rego bundle.

## Run

```bash
pip install -r examples/deerflow-governed/requirements.txt
PYTHONPATH=examples/deerflow-governed/provider \
  python examples/deerflow-governed/demo.py
```

The demo uses compatible request objects and does not require a DeerFlow
checkout. Audit records contain hashes and redacted previews rather than raw
tool inputs.

## Optional middleware test

```bash
DEERFLOW_REPO=/absolute/path/to/deer-flow \
  pytest examples/deerflow-governed/test_deerflow_middleware_integration.py -v
```

Configure a DeerFlow checkout with:

```yaml
guardrails:
  enabled: true
  fail_closed: true
  provider:
    use: deerflow_agt_guardrail:AGTGuardrailProvider
    config:
      manifest_path: /absolute/path/to/examples/deerflow-governed/policies/manifest.yaml
      audit_path: /absolute/path/to/audit/deerflow.jsonl
```

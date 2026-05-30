# Customer support ACS Python demo

This runnable demo wires the generated `manifest.yaml` and `policy/customer_support_guardrails.rego` into the ACS Python SDK. It uses host-side toy classifiers for `input_risk`, `refund_risk`, `recipient_scope`, and `pii_scan`, uses the bundled zero configuration OPA policy dispatcher, and enforces input, tool, and output intervention points. Redaction is declared as Rego `pattern` effects and the Rust core resolves those patterns into deterministic spans. The demo does not hand roll a policy dispatcher or compute redaction spans in Python.

Run from the repository root.

```sh
cd /home/liamcrumm/rb/AgentControlSpecification
source .venv-int/bin/activate
export PATH="$HOME/.local/bin:$PATH"
python examples/support_agent/app/run_demo.py
```

The demo prints allowed, warn, deny/block, escalate-with-approval, and redaction/transform outcomes.

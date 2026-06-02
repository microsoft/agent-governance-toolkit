# Python support agent example

This Python SDK example uses `AgentControl.from_path`, host annotators, `run`, and `run_tool` to guard a customer support loop. Rego policies return allow, warn, deny, escalate, and redaction effects.

## Threat or governance need

Support agents handle refunds, customer records, and outbound messages. The example blocks prompt injection, denies fraudulent refunds, escalates high value refunds, warns on external email, and redacts PII in tool results and final output.

## Run

```sh
python -m pip install ./sdk/python
python examples/support_agent/app/run_demo.py
```

`opa` must be available on `PATH`.

## Expected verdicts

The runner prints an allowed lookup, a warn for external email, denied input, denied refund, escalated refund approval, and redaction of customer PII.

## Where to look

`manifest.yaml` binds input, tool, and output points. `policy/customer_support_guardrails.rego` contains the governance rules. `app/run_demo.py` shows Python host orchestration and approval handling.

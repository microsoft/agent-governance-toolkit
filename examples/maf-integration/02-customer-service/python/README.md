# Contoso Support — Customer Service Governance Demo (Python)

This scenario now follows the real MAF Python agent pattern and real AGT adapter
middleware. The Python example preserves the refund-fraud and escalation story
from the tutorial while using `agent_framework.Agent` and
`agent_os.integrations.maf_adapter`.

## Governance story

- **Policy enforcement:** blocks payment-card data access and refunds above the manager threshold
- **Capability sandboxing:** permits order lookup/escalation tools and blocks direct billing changes
- **Rogue detection:** catches repeated refund-farming behavior
- **Audit trail:** records the full scenario in the AGT audit log

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Optional live model backends:

- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY` with `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`

If you do not set credentials, the example still runs the real governance
middleware walkthrough without a live model call.

## Files

- `main.py` — MAF agent wiring, scenario tools, and walkthrough
- `policies\support_governance.yaml` — real AGT rules for customer-service governance
- `requirements.txt` — runtime dependencies

## Policy example

```yaml
- name: "refund_limit"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(refund.*\$\s*(?:[5-9]\d{2}|[1-9]\d{3,}))'
  action: "deny"
```

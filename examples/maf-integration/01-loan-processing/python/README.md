# Contoso Bank — Loan Processing Governance Demo (Python)

This scenario uses the real Microsoft Agent Framework Python shape plus real AGT
middleware. `main.py` creates an `agent_framework.Agent`, configures an
`OpenAIChatClient`, and attaches middleware from
`agent_os.integrations.maf_adapter`.

## Governance story

- **Policy enforcement:** blocks SSN, tax-record, and high-value approval requests
- **Capability sandboxing:** allows loan lookup tools and blocks transfer/admin operations
- **Rogue detection:** flags repeated transfer-oriented behavior
- **Audit trail:** verifies the Merkle-chained AGT audit log at the end of the run

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Optional live model backends:

- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY` with `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`

Without credentials, the example skips the live `Agent.run(...)` preview and
still exercises the real AGT middleware pipeline in the terminal walkthrough.

## Files

- `main.py` — real MAF agent wiring plus the four-act walkthrough
- `policies\loan_governance.yaml` — real AGT policy document loaded by `PolicyEvaluator`
- `requirements.txt` — MAF and AGT package requirements for running the example

## Policy example

```yaml
- name: "block_pii_access"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(\b\d{3}-\d{2}-\d{4}\b|social security|ssn|tax records|tax returns)'
  action: "deny"
```

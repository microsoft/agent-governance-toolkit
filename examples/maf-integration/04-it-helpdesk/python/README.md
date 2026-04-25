# SecureDesk — IT Helpdesk Governance Demo (Python)

This Python example now uses a real MAF agent plus AGT middleware instead of
the old illustrative stack. The scenario keeps the helpdesk governance story
from the tutorial branch: privilege escalation, credentials, and infrastructure
changes are all blocked through the real adapter path.

## Governance story

- **Policy enforcement:** blocks credential access, privilege escalation, and infrastructure changes
- **Capability sandboxing:** permits ticket/knowledge-base actions and blocks admin tools
- **Rogue detection:** detects repeated privilege-probing behavior
- **Audit trail:** validates the AGT audit log integrity after execution

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Optional live model backends:

- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY` with `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`

Without credentials, the example still exercises the real middleware and audit
objects through the deterministic walkthrough.

## Files

- `main.py` — MAF agent setup, helpdesk tools, and walkthrough
- `policies\helpdesk_governance.yaml` — real AGT helpdesk policy document
- `requirements.txt` — runtime dependencies

## Policy example

```yaml
- name: "block_privilege_escalation"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(sudo|domain admins|elevated privileges|runas)'
  action: "deny"
```

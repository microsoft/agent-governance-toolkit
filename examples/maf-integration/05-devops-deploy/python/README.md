# DeployBot — DevOps Deployment Governance Demo (Python)

This scenario uses the real Microsoft Agent Framework Python agent pattern with
AGT middleware from `agent_os.integrations.maf_adapter`. It preserves the
deployment-safety story from the tutorial: production deploys, destructive ops,
and secret access are blocked while build, test, and staging workflows remain
available.

## Governance story

- **Policy enforcement:** blocks production deploy requests, destructive operations, and secret retrieval
- **Capability sandboxing:** allows build/test/staging tools and blocks production-only actions
- **Rogue detection:** quarantines deployment-storm behavior
- **Audit trail:** confirms audit and detector integrity chains after execution

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Optional live model backends:

- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY` with `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`

Without credentials, the example still runs the real governance middleware
walkthrough locally.

## Files

- `main.py` — MAF agent setup, deployment tools, and walkthrough
- `policies\devops_governance.yaml` — real AGT deployment policy document
- `requirements.txt` — runtime dependencies

## Policy example

```yaml
- name: "block_production_deploy"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(production deploy|deploy to production|push to prod)'
  action: "deny"
```

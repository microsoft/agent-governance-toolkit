# MedAssist — Healthcare Governance Demo (Python)

This scenario uses the real Microsoft Agent Framework Python agent model with
AGT governance middleware. It keeps the healthcare tutorial storyline while
driving the walkthrough through real `Agent.run(...)` calls with the AGT
`maf_adapter`.

## Governance story

- **Policy enforcement:** blocks PHI disclosure, unsafe controlled-substance requests, and cross-department record access
- **Capability sandboxing:** allows clinical guidance tools and blocks patient-record access
- **Rogue detection:** detects data-exfiltration style access bursts
- **Audit trail:** verifies the tamper-evident audit chain after the walkthrough

## Run it

```bash
pip install -r requirements.txt
python main.py
```

Optional live model backends:

- `GITHUB_TOKEN`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY` with `AZURE_OPENAI_ENDPOINT` or `AZURE_OPENAI_BASE_URL`

Without credentials, the example still runs the same governance story locally
through the real MAF agent/tool loop by using a deterministic scripted client.

## Files

- `main.py` — MAF agent setup, healthcare tools, and walkthrough
- `policies\healthcare_governance.yaml` — real AGT healthcare policy document
- `requirements.txt` — runtime dependencies

## Policy example

```yaml
- name: "block_phi_access"
  condition:
    field: "message"
    operator: "matches"
    value: '(?i)(insurance id|medical record|mrn|date of birth|\bdob\b)'
  action: "deny"
```

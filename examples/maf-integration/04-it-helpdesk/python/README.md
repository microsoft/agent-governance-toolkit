# IT helpdesk native governance demo

This Python example uses `MAFKernel` with a native ACS runtime. It runs a
safe request and a blocked request without requiring an LLM credential.

## Run

```bash
pip install -r requirements.txt
python main.py
```

The manifest under `policies/manifest.yaml` binds the MAF input
intervention point to Rego. Microsoft Agent Framework middleware can be added
with `kernel.as_runtime_middleware()` in a full agent application.

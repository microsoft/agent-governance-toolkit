# Python Governance E2E Tests

These tests exercise five governance scenarios through production `agent_os`
policy, prompt-injection, redaction, and sandbox APIs. External systems are
represented by in-memory adtech, healthcare, and intake resources. Each
policy-driven scenario keeps its YAML policy next to it (e.g.
`scenarios/policy_deny/test_policy_deny.py` +
`scenarios/policy_deny/policy.yaml`), parsed by the SDK the way a customer
would ship it. Four scenarios run against a real local Ollama model; prompt
injection is intentionally blocked before a model request is made.

| Package | Production boundary | Expected result |
| --- | --- | --- |
| `policy_deny` | Adtech tool call evaluated by `PolicyEvaluator` | Deny the live budget mutation; do not call the resource |
| `policy_allow` | Healthcare tool call evaluated by `PolicyEvaluator` | Allow one non-diagnostic visit-note update |
| `pii_redaction` | `MuteAgent` before model and tool boundaries | Allow sanitized intake; keep raw values out of inputs, calls, and artifacts |
| `prompt_injection` | `PromptInjectionDetector` on retrieved content | Deny the poisoned document before Ollama is called |
| `filesystem_escape` | Model-generated code passed to `ExecutionSandbox` | Raise `SANDBOX_VALIDATION_FAILED`; do not create the outside file |

## Setup

Install Ollama if `ollama` is not already on your `PATH`:

```bash
sudo snap install ollama
```

Start its server in one terminal:

```bash
ollama serve
```

In another terminal, pull the configured model:

```bash
ollama pull llama3.1
```

CI installs the Ollama version pinned in `.github/workflows/e2e-python.yml`,
verifies the release archive checksum, and verifies the pulled model digest.

## Run

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install \
  -e agent-governance-python/agent-governance-toolkit-core \
  pytest pytest-timeout
AGT_E2E_MODEL=llama3.1 \
AGT_E2E_MODEL_ATTEMPTS=3 \
.venv/bin/python -m pytest tests/e2e_python -q
```

Model output is variable. For scenarios that need a specific action, the test
tries up to `AGT_E2E_MODEL_ATTEMPTS` times and fails with `not_exercised` when the
model never produces the required tool call or code. That failure logs the
expected action and a redacted summary of the unexpected response. Once the
model participates, an unexpected policy result, tool execution, or resource
side effect fails the scenario.

The prompt-injection scenario intentionally blocks poisoned retrieval content
before it reaches the model adapter. The PII scenario calls the model only after
redaction and verifies that raw values are absent from model input, tool
arguments, resource calls, and artifacts.

Runtime defaults are defined by `support/ollama.py`:

| Setting | Default | Purpose |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama API endpoint |
| `AGT_E2E_MODEL` | `llama3.1` | Model used by model-backed scenarios |
| `AGT_E2E_MODEL_ATTEMPTS` | `3` | Maximum attempts to obtain the required model action |

## Logging

By default, the tests emit live INFO logs for each model request and response.
PII-like values are redacted before log records are written. Configure logging
from the pytest command line:

```bash
.venv/bin/python -m pytest tests/e2e_python \
  --agt-e2e-log-model-io=summary \
  --agt-e2e-log-format=pretty \
  --agt-e2e-log-text-limit=1000 \
  --agt-e2e-log-live=on \
  --agt-e2e-log-level=INFO -q
```

Set `--agt-e2e-log-model-io=off` to suppress model request/response logs, or
`--agt-e2e-log-model-io=full` to disable truncation while keeping redaction. Set
`--agt-e2e-log-format=compact` for single-line JSON logs, or
`--agt-e2e-log-live=off` to keep the pytest output quiet.

## Artifacts

Set `AGT_E2E_ARTIFACT_DIR` to preserve JSON results:

```bash
AGT_E2E_ARTIFACT_DIR=artifacts/e2e-python/ollama \
.venv/bin/python -m pytest tests/e2e_python -q
```

The suite writes `adtech.json`, `filesystem-escape.json`, `healthcare.json`,
`pii-redaction.json`, and `prompt-injection.json`. CI also writes `junit.xml`
and `runtime-metadata.json`, then uploads the directory as the
`e2e-python-ollama-artifacts` artifact.

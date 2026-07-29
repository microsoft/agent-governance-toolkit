# ATR community rules as native ACS

This example compiles Agent Threat Rules YAML into one native ACS manifest and
a Rego bundle. ATR remains an external community project and AGT takes no
runtime dependency on it.

## Generate

```bash
npm install --ignore-scripts agent-threat-rules
python examples/atr-community-rules/sync_atr_rules.py \
  --atr-dir node_modules/agent-threat-rules/rules/ \
  --output examples/atr-community-rules/atr_community_manifest.yaml
```

The command writes:

- `atr_community_manifest.yaml`
- `atr-community-rules-bundle/policy.rego`

## Load

```python
from agt.policies.runtime import AgtRuntime

runtime = AgtRuntime.from_manifest(
    "examples/atr-community-rules/atr_community_manifest.yaml"
)
result = runtime.evaluate("input", snapshot)
```

## Test

```bash
pytest examples/atr-community-rules/test_atr_policy.py -v
```

The compiler validates regex syntax and size before emitting Rego. Strict mode
fails on the first invalid pattern; default mode logs and skips it.

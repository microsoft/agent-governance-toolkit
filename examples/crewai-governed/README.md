# CrewAI with native ACS governance

This example shows the CrewAI adapter consuming an `AgtRuntime` directly.
It exercises the same input mediation used by CrewAI native hooks without
requiring an LLM credential.

## Run

```bash
pip install -e "agent-governance-python/agt-policies"
pip install -e "agent-governance-python/agent-os"
python examples/crewai-governed/getting_started.py
```

Expected output includes one allowed request and one denied prompt-injection
request.

## Integration pattern

```python
runtime = AgtRuntime.from_manifest("policies/manifest.yaml")
kernel = CrewAIKernel(runtime=runtime)
hooks = kernel.as_hooks()
hooks.register()
try:
    result = crew.kickoff()
finally:
    hooks.unregister()
    runtime.close()
```

The manifest owns policy decisions, transforms, and approvals. CrewAI hooks
own framework lifecycle and audit context.

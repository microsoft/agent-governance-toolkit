# Smolagents with native ACS governance

This example shows `SmolagentsKernel` consuming an `AgentControl` directly. The
runnable script exercises input mediation without an LLM credential.

## Run

```bash
pip install -e "agent-governance-python/agt-policies"
pip install -e "agent-governance-python/agent-os"
python examples/smolagents-governed/getting_started.py
```

## Integration pattern

```python
runtime = AgentControl.from_path(str("policies/manifest.yaml"))
kernel = SmolagentsKernel(runtime=runtime)
callback = kernel.as_step_callback()

agent = CodeAgent(
    tools=tools,
    model=model,
    step_callbacks=[callback],
)
runtime.close()
```

The callback mediates tool calls and observations through ACS before the next
agent step.

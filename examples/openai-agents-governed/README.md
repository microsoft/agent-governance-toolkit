# OpenAI Agents SDK with native ACS governance

This example shows `OpenAIAgentsKernel` using a native `AgtRuntime`. The
runnable script exercises the adapter without making a network request.

## Run

```bash
pip install -e "agent-governance-python/agt-policies"
pip install -e "agent-governance-python/agent-os"
python examples/openai-agents-governed/getting_started.py
```

## Integration pattern

```python
runtime = AgtRuntime.from_manifest("policies/manifest.yaml")
kernel = OpenAIAgentsKernel(runtime=runtime)
hooks = kernel.as_hooks()

result = await Runner.run(agent, input=user_input, hooks=hooks)
runtime.close()
```

The runtime owns governance. The hooks preserve OpenAI Agents SDK run,
handoff, tool, and output lifecycle behavior.

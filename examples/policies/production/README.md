# Production Policy Library

Native ACS manifests for common enterprise scenarios. Each profile binds input
and output intervention points to a Rego package under `rego/`.

| Policy | Risk | Default | Best For |
|--------|------|---------|----------|
| minimal.yaml | Low | allow | Startups, internal tools |
| enterprise.yaml | Medium | deny | General enterprise, SaaS |
| healthcare.yaml | High | deny | HIPAA-regulated |
| financial.yaml | High | deny | SOX/PCI-regulated |
| strict.yaml | Maximum | deny | Defense, critical infrastructure |

## Usage

```python
from agent_control_specification import AgentControl

runtime = AgentControl.from_path(str("enterprise.yaml"))
decision = runtime.evaluate(
    "input",
    {
        "envelope": {"agent_id": "example-agent"},
        "input": {"body": {"action": "write_file", "params": {}}},
    },
)
```

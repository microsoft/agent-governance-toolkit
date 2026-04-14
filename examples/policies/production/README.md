# Production Policy Library

Ready-to-use governance policies for common enterprise scenarios.
Each file uses the AGT PolicyDocument schema and works with PolicyEvaluator.

| Policy | Risk | Default | Best For |
|--------|------|---------|----------|
| minimal.yaml | Low | allow | Startups, internal tools |
| enterprise.yaml | Medium | deny | General enterprise, SaaS |
| healthcare.yaml | High | deny | HIPAA-regulated |
| financial.yaml | High | deny | SOX/PCI-regulated |
| strict.yaml | Maximum | deny | Defense, critical infrastructure |

## Usage

```python
from agentmesh.governance.policy import PolicyDocument

policy = PolicyDocument.from_yaml(open("enterprise.yaml").read())
decision = policy.evaluate({"action": "write_file"})
```

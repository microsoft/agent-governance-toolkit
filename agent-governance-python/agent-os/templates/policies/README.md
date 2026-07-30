# Policy Templates

Pre-built policy templates for common governance and compliance use cases.
Import and customize for your needs — no other governance tool ships with this.

## Available Templates

### Compliance Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| [hipaa.yaml](hipaa.yaml) | HIPAA compliance — blocks PHI, requires approval, mandatory audit | Healthcare / health-tech |
| [sox-compliance.yaml](sox-compliance.yaml) | SOX financial controls — dual approval, immutable audit, SoD | Financial services / public companies |
| [gdpr.yaml](gdpr.yaml) | GDPR data protection — PII blocking, right to erasure, cross-border | EU/EEA personal data processing |
| [pci-dss.yaml](pci-dss.yaml) | PCI-DSS payment security — card number blocking, encryption, timeouts | Payment processing |
| [content-safety.yaml](content-safety.yaml) | Content safety — profanity, hate speech, violence, self-harm | Public-facing AI applications |

### Operational Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| [development.yaml](development.yaml) | Developer-friendly — warn don't block, no approval, full logging | Local development & testing |
| [production.yaml](production.yaml) | Production lockdown — allowlist-only, approval required, rate limiting | Production deployments |
| [research.yaml](research.yaml) | Research — broad permissions with cost budgets and time limits | ML research & experimentation |

### Infrastructure Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| [secure-coding.yaml](secure-coding.yaml) | Prevents common security vulnerabilities | All development |
| [data-protection.yaml](data-protection.yaml) | PII protection and data handling | Apps handling user data |
| [cost-controls.yaml](cost-controls.yaml) | Rate limiting and spend controls | Prevent runaway API costs |
| [api-gateway.yaml](api-gateway.yaml) | External API access controls | Secure external API calls |
| [multi-tenant.yaml](multi-tenant.yaml) | Tenant isolation for SaaS | Multi-tenant deployments |
| [enterprise.yaml](enterprise.yaml) | Comprehensive enterprise governance | Production deployments |
| [rate-limiting.yaml](rate-limiting.yaml) | API call rate limiting with per-domain limits | API-heavy applications |

## Quick Start

### Using the Python Loader

```python
from agent_os.templates.policies.loader import load_policy, list_templates, load_policy_yaml

# List all available templates
print(list_templates())
# ['api-gateway', 'content-safety', 'cost-controls', 'data-protection',
#  'development', 'enterprise', 'gdpr', 'hipaa', 'multi-tenant',
#  'pci-dss', 'production', 'rate-limiting', 'research',
#  'secure-coding', 'sox-compliance']

# Load as GovernancePolicy dataclass
policy = load_policy("hipaa")
print(policy.name)                    # "hipaa"
print(policy.require_human_approval)  # True
print(policy.max_tool_calls)          # 10
print(len(policy.blocked_patterns))   # 20+ PHI patterns

# Load raw YAML as dict for full access
config = load_policy_yaml("production")
print(config["kernel"]["mode"])       # "strict"
print(len(config["policies"]))       # All policy rules
```

### Using CLI

```bash
# Initialize with a template
agentos init my-project --template hipaa

# Or apply a template to an existing project
agentos policy apply production
```

### Manual Setup

Copy the desired template to your project:

```bash
cp templates/policies/hipaa.yaml .agents/hipaa-policy.yaml
```

## Template Comparison

| Feature | HIPAA | SOX | GDPR | PCI-DSS | Content Safety | Dev | Prod | Research |
|---------|-------|-----|------|---------|---------------|-----|------|----------|
| PHI/PII Blocking | ✅ | ⚪ | ✅ | ✅ | ⚪ | ⚠️ | ✅ | ⚠️ |
| Credit Card Blocking | ⚪ | ⚪ | ⚪ | ✅ | ⚪ | ⚠️ | ✅ | ⚪ |
| Financial Data Protection | ⚪ | ✅ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ |
| Human Approval Required | ✅ | ✅ | ⚪ | ✅ | ⚪ | ❌ | ✅ | ❌ |
| Dual Approval Workflows | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ |
| Segregation of Duties | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ |
| Right to Erasure | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ |
| Cross-Border Restrictions | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ |
| Content Filtering | ⚪ | ⚪ | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ |
| Hate Speech Detection | ⚪ | ⚪ | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ |
| Rate Limiting | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚠️ | ✅ | ✅ |
| Cost Budgets | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ✅ |
| Session Timeouts | ⚪ | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ✅ |
| Immutable Audit Trail | ✅ | ✅ | ⚪ | ✅ | ⚪ | ⚪ | ✅ | ⚪ |
| Allowlist-Only Mode | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ❌ | ✅ | ⚪ |
| Encryption Requirements | ⚪ | ⚪ | ⚪ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ |

✅ = Enforced | ⚠️ = Warn only | ❌ = Explicitly disabled | ⚪ = Not applicable

## Customization

Templates are starting points. Customize by:

1. **Adding rules**: Add patterns specific to your domain
2. **Adjusting severity**: Change `SIGKILL` to `SIGSTOP` for warnings
3. **Adding exceptions**: Whitelist known-safe patterns
4. **Combining templates**: Merge multiple templates for layered governance

### Example: Combining Templates

```yaml
# .agents/security.md
kernel:
  version: "1.0"
  mode: strict

# Include multiple compliance frameworks
include:
  - templates/policies/hipaa.yaml
  - templates/policies/pci-dss.yaml
  - templates/policies/production.yaml

# Add custom rules
policies:
  - name: my_custom_rule
    deny:
      - patterns:
          - "my_specific_pattern"
```

### Example: Customizing a Template in Python

```python
from agent_os.templates.policies.loader import load_policy

# Load base template
policy = load_policy("production")

# Override specific settings
policy.max_tool_calls = 30
policy.timeout_seconds = 600
policy.blocked_patterns.append("my_custom_pattern")
```

## Contributing Templates

We welcome new policy templates! See [CONTRIBUTING.md](../../CONTRIBUTING.md).

Useful templates to contribute:
- `frontend.yaml` - React/Vue/Angular specific
- `api.yaml` - REST/GraphQL API development
- `ml.yaml` - Machine learning pipelines
- `devops.yaml` - CI/CD and infrastructure
- `fedramp.yaml` - FedRAMP government compliance
- `iso27001.yaml` - ISO 27001 information security

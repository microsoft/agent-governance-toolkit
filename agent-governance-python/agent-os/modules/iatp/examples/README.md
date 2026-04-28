# IATP Examples

This directory contains example implementations demonstrating the Inter-Agent Trust Protocol.

## Agents

### Secure Bank Agent (`secure_bank_agent.py`)
- **Trust Level**: `verified_partner` (10/10)
- **Reversibility**: Full (5-minute undo window)
- **Retention**: Ephemeral
- **Use Case**: High-trust financial transactions

Run with:
```bash
# Terminal 1: Start the agent
python examples/secure_bank_agent.py

# Terminal 2: Start the sidecar
python examples/run_secure_bank_sidecar.py
```

### Untrusted Agent (`untrusted_agent.py`)
- **Trust Level**: `untrusted` (0/10)
- **Reversibility**: None
- **Retention**: Permanent (with human review)
- **Use Case**: Honeypot for testing sidecar security

Run with:
```bash
# Terminal 1: Start the agent
python examples/untrusted_agent.py

# Terminal 2: Start the sidecar
python examples/run_untrusted_sidecar.py
```

### Backend Agent (`backend_agent.py`)
- Simple FastAPI agent template
- Generic backend that receives validated requests from sidecar
- No security logic needed (handled by sidecar)

## Clients

### Client Examples (`client.py`)
- Basic request examples
- Override flow demonstrations
- Trace retrieval examples

### Demo Client (`demo_client.py`)
- Interactive demonstration script
- Shows trust negotiation, security blocks, and user override flows
- ASCII art banner and color-coded output

Run:
```bash
python examples/demo_client.py
```

### Integration Demo (`integration_demo.py`)
- Demonstrates Policy Engine integration
- Demonstrates Recovery Engine integration (`scak`)
- Shows custom rule addition and failure recovery

Run:
```bash
python examples/integration_demo.py
```

### RBAC Demo (`demo_rbac.py`)
- Demonstrates Role-Based Access Control (RBAC) with scopes
- Shows Coder Agent with write permissions (`repo:read`, `repo:write`)
- Shows Reviewer Agent with read-only permissions (`repo:read`)
- Validates scope enforcement during handshake

Run:
```bash
python examples/demo_rbac.py
```

Key scenarios demonstrated:
- ✅ Coder Agent can read and write code
- ✅ Reviewer Agent can only read code
- ❌ Reviewer Agent denied when attempting to write code
- Multiple scope validation for admin operations

## Test Scripts

### Test Untrusted (`test_untrusted.py`)
- Tests blocked requests (credit cards to untrusted agents)
- Tests warning mechanisms (risky requests)
- Tests user override flow
- Tests trace retrieval

## Manifests

Example capability manifests in `manifests/`:

| File | Trust Level | Reversibility | Retention | Scopes |
|------|-------------|---------------|-----------|--------|
| `secure_bank.json` | verified_partner | full | ephemeral | - |
| `standard_agent.json` | standard | partial | temporary | - |
| `coder_agent.json` | trusted | full | ephemeral | repo:read, repo:write |
| `reviewer_agent.json` | standard | none | temporary | repo:read |
| `untrusted_honeypot.json` | untrusted | none | permanent | - |

Use with the IATP CLI:
```bash
iatp verify examples/manifests/secure_bank.json
iatp verify examples/manifests/coder_agent.json
iatp verify examples/manifests/reviewer_agent.json
```

## Quick Test Commands

```bash
# Health check
curl http://localhost:8081/health

# Get agent manifest
curl http://localhost:8081/.well-known/agent-manifest

# Send a request
curl -X POST http://localhost:8081/proxy \
  -H "Content-Type: application/json" \
  -d '{"task": "transfer", "data": {"amount": 100}}'

# Override a warning
curl -X POST http://localhost:8081/proxy \
  -H "Content-Type: application/json" \
  -H "X-User-Override: true" \
  -d '{"task": "risky_operation"}'
```

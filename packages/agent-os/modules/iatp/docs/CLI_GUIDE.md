# IATP CLI Guide

The IATP CLI provides developer tools for validating manifests and scanning agents.

## Installation

```bash
pip install iatp
```

Or from source:

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd inter-agent-trust-protocol
pip install -e .
```

## Commands

### `iatp verify`

Validate a capability manifest file.

**Usage:**

```bash
iatp verify <manifest-path> [OPTIONS]
```

**Options:**

- `--verbose, -v`: Show detailed validation output

**Examples:**

```bash
# Basic validation
iatp verify ./manifest.json

# Verbose output
iatp verify ./manifest.json --verbose
```

**What It Checks:**

- ✅ Valid JSON schema
- ✅ Required fields present
- ✅ Enum values are valid
- ⚠️ Logical contradictions (e.g., untrusted + no reversibility)
- ⚠️ Privacy concerns (e.g., permanent retention)

**Example Output:**

```
🔍 Validating manifest: examples/manifests/secure_bank.json

✅ Schema validation passed
   Agent ID: secure-bank-agent
   Trust Level: verified_partner
   Trust Score: 10/10

✨ Manifest is valid and ready to use!
```

### `iatp scan`

Scan a running agent and calculate its trust score.

**Usage:**

```bash
iatp scan <agent-url> [OPTIONS]
```

**Options:**

- `--timeout, -t`: Request timeout in seconds (default: 10)
- `--verbose, -v`: Show detailed scan output

**Examples:**

```bash
# Scan a local agent
iatp scan http://localhost:8001

# Scan with custom timeout
iatp scan https://api.example.com/agent --timeout 30

# Verbose scan
iatp scan http://localhost:8001 --verbose
```

**What It Does:**

1. Fetches the agent's `/.well-known/agent-manifest` endpoint
2. Parses the capability manifest
3. Calculates a trust score (0-100)
4. Displays security indicators
5. Provides recommendations

**Example Output:**

```
🔍 Scanning agent: http://localhost:8001

✅ Trust Score: 100/100 (🟢 LOW RISK)

📊 Agent Profile:
   Agent ID: secure-bank-agent
   Trust Level: verified_partner
   Reversibility: full
   Data Retention: ephemeral

🔒 Security Indicators:
   ✅ Idempotent operations
   ✅ Reversibility support
   ✅ Limited data retention
   ✅ Automated processing
```

### `iatp version`

Show version information.

**Usage:**

```bash
iatp version
```

## Trust Score Calculation

Trust scores range from 0-100:

- **80-100**: 🟢 LOW RISK - Highly trustworthy
- **50-79**: 🟡 MEDIUM RISK - Use with caution
- **0-49**: 🔴 HIGH RISK - Avoid sensitive data

**Scoring Factors:**

| Factor | Impact |
|--------|--------|
| Trust Level: verified_partner | +30 |
| Trust Level: trusted | +20 |
| Trust Level: untrusted | -50 |
| Idempotency enabled | +10 |
| Reversibility support | +10 |
| Ephemeral retention | +20 |
| Permanent retention | -20 |
| No human review | +10 |

## Exit Codes

- `0`: Success
- `1`: Validation failed or error occurred

## Integration Examples

### In CI/CD

```yaml
# GitHub Actions
- name: Validate manifest
  run: iatp verify ./config/manifest.json
```

### Pre-deployment Check

```bash
#!/bin/bash
if iatp verify ./manifest.json; then
  echo "✅ Manifest valid, deploying..."
  docker compose up -d
else
  echo "❌ Manifest invalid, aborting"
  exit 1
fi
```

### Agent Health Monitoring

```bash
#!/bin/bash
SCORE=$(iatp scan http://localhost:8001 --verbose | grep "Trust Score" | awk '{print $3}' | cut -d/ -f1)
if [ "$SCORE" -lt 50 ]; then
  echo "⚠️ Low trust score detected: $SCORE"
  # Send alert
fi
```

## Troubleshooting

### "Manifest endpoint not found"

The agent doesn't expose `/.well-known/agent-manifest`. Ensure:
- The agent has an IATP sidecar
- The sidecar is running
- The URL is correct

### "Connection error"

The agent is unreachable. Check:
- Agent is running
- Network connectivity
- Firewall rules

### "Validation failed"

The manifest has issues. Run with `--verbose` to see details:

```bash
iatp verify ./manifest.json --verbose
```

## Additional Resources

- [Docker Deployment Guide](DOCKER_DEPLOYMENT.md)
- [Main README](../README.md)
- [API Documentation](../spec/README.md)

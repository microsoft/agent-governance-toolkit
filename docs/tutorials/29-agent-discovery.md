# Tutorial 29 — Agent Discovery: Finding Shadow AI in Your Organization

> **Package:** `agent-discovery` · **Time:** 20 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- How to scan your environment for AI agents running outside governance
- How deduplication prevents overcounting across scanners
- How to reconcile discovered agents against your registry
- How risk scoring identifies the most urgent shadow agents
- How to integrate discovery into your CI/CD pipeline

---

## Why Agent Discovery?

The Agent Governance Toolkit excels at governing agents that register with it. But you can't govern what you can't see.

**68% of enterprises** have AI agents running outside IT visibility. These "shadow agents" operate without identity, without audit trails, and without policy enforcement — creating compliance risk and security exposure.

Agent Discovery closes the loop:

```
Discover → Inventory → Reconcile → Govern
    ↑                                  │
    └──────────────────────────────────┘
                 Continuous
```

---

## Step 1: Install

```bash
pip install agent-discovery
```

For GitHub scanning:
```bash
pip install agent-discovery[github]
```

---

## Step 2: Scan Local Processes

The process scanner detects running AI agent processes by matching command-line patterns against 11 known frameworks.

```python
import asyncio
from agent_discovery.scanners import ProcessScanner

async def main():
    scanner = ProcessScanner()
    result = await scanner.scan()
    
    print(f"Scanned {result.scanned_targets} processes")
    print(f"Found {result.agent_count} agents")
    
    for agent in result.agents:
        print(f"  🤖 {agent.name}")
        print(f"     Type: {agent.agent_type}")
        print(f"     Confidence: {agent.confidence:.0%}")
        for ev in agent.evidence:
            print(f"     Evidence: {ev.detail}")

asyncio.run(main())
```

> **Security note:** The process scanner automatically redacts API keys, tokens, and JWTs from command-line arguments. No secrets are stored.

---

## Step 3: Scan Filesystem for Config Artifacts

The config scanner walks directories looking for agent configuration files — `agentmesh.yaml`, `crewai.yaml`, `mcp.json`, Dockerfiles with agent images, etc.

```python
import asyncio
from agent_discovery.scanners import ConfigScanner

async def main():
    scanner = ConfigScanner()
    result = await scanner.scan(
        paths=["/opt/agents", "/home/deploy/projects"],
        max_depth=5,
    )
    
    print(f"Found {result.agent_count} agent configurations")
    for agent in result.agents:
        print(f"  📁 {agent.name}")
        print(f"     Path: {agent.tags.get('config_file', 'N/A')}")

asyncio.run(main())
```

---

## Step 4: Build an Inventory with Deduplication

When the same agent is found by multiple scanners (e.g., running as a process AND has a config file), the inventory merges them into one logical agent:

```python
import asyncio
from agent_discovery import AgentInventory
from agent_discovery.scanners import ProcessScanner, ConfigScanner

async def main():
    inventory = AgentInventory(storage_path="~/.agent-governance-python/agent-discovery/inventory.json")
    
    # Run multiple scanners
    process_result = await ProcessScanner().scan()
    config_result = await ConfigScanner().scan(paths=["."])
    
    # Ingest — deduplication happens automatically via fingerprints
    stats1 = inventory.ingest(process_result)
    stats2 = inventory.ingest(config_result)
    
    print(f"Process scan: {stats1['new']} new, {stats1['updated']} updated")
    print(f"Config scan:  {stats2['new']} new, {stats2['updated']} updated")
    print(f"Total unique agents: {inventory.count}")
    
    # Search and filter
    mcp_servers = inventory.search(agent_type="mcp-server")
    print(f"\nMCP Servers found: {len(mcp_servers)}")

asyncio.run(main())
```

---

## Step 5: Reconcile Against Your Registry

The reconciler compares discovered agents against your governance registry to find shadow agents:

```python
import asyncio
from agent_discovery import AgentInventory, Reconciler, RiskScorer
from agent_discovery.reconciler import StaticRegistryProvider
from agent_discovery.scanners import ProcessScanner, ConfigScanner

async def main():
    # Build inventory
    inventory = AgentInventory()
    inventory.ingest(await ProcessScanner().scan())
    inventory.ingest(await ConfigScanner().scan(paths=["."]))
    
    # Define known/registered agents
    registry = StaticRegistryProvider([
        {"did": "did:agent:prod-assistant", "name": "Production Assistant"},
        {"did": "did:agent:code-reviewer", "name": "Code Review Bot"},
        {"fingerprint": "abc123", "name": "Deploy Agent"},
    ])
    
    # Reconcile
    reconciler = Reconciler(inventory, registry)
    shadow_agents = await reconciler.reconcile()
    
    # Score risk
    scorer = RiskScorer()
    for shadow in shadow_agents:
        shadow.risk = scorer.score(shadow.agent)
        
        print(f"\n⚠️  SHADOW AGENT: {shadow.agent.name}")
        print(f"   Risk: {shadow.risk.level.value.upper()} ({shadow.risk.score:.0f}/100)")
        print(f"   Factors:")
        for factor in shadow.risk.factors:
            print(f"     - {factor}")
        print(f"   Actions:")
        for action in shadow.recommended_actions:
            print(f"     → {action}")

asyncio.run(main())
```

---

## Step 6: Use the CLI

For quick scans, use the CLI directly:

```bash
# Full scan with table output
agent-discovery scan

# Scan specific paths
agent-discovery scan -s config -p /opt/agents -p /home/deploy

# GitHub org scan
agent-discovery scan -s github --github-org my-company

# View inventory
agent-discovery inventory -o summary

# Reconcile against registered agents
agent-discovery reconcile --registry-file known-agents.json

# JSON output for automation
agent-discovery scan -o json | jq '.[] | select(.agent_type == "mcp-server")'
```

---

## Step 7: Write a Custom Scanner

Extend discovery by writing your own scanner:

```python
from agent_discovery.scanners.base import BaseScanner, registry
from agent_discovery.models import (
    ScanResult, DiscoveredAgent, Evidence, DetectionBasis
)

@registry.register
class KubernetesScanner(BaseScanner):
    """Scan Kubernetes for agent pods."""
    
    @property
    def name(self) -> str:
        return "kubernetes"
    
    async def scan(self, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # Your K8s discovery logic here:
        # - List pods with agent labels
        # - Check container images for agent frameworks
        # - Inspect service annotations
        return result
```

---

## Step 8: CI/CD Integration

Add agent discovery to your CI pipeline to catch new shadow agents:

```yaml
# .github/workflows/agent-audit.yml
name: Agent Discovery Audit
on:
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday 8am
  workflow_dispatch:

jobs:
  discover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install agent-discovery
        run: pip install agent-discovery[github]
      
      - name: Scan repository
        run: |
          agent-discovery scan -s config -p . -o json > discovery.json
          
      - name: Check for shadow agents
        run: |
          SHADOW_COUNT=$(agent-discovery reconcile \
            --registry-file known-agents.json \
            -o json | python -c "import sys,json; print(len(json.load(sys.stdin)))")
          if [ "$SHADOW_COUNT" -gt "0" ]; then
            echo "::warning::Found $SHADOW_COUNT shadow agents!"
          fi
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: agent-discovery-report
          path: discovery.json
```

---

## Risk Scoring Reference

| Factor | Points | Description |
|--------|--------|-------------|
| No identity (DID/SPIFFE) | +30 | Agent has no cryptographic identity |
| No owner | +20 | No responsible party assigned |
| Shadow/unregistered status | +20 | Not in any governance registry |
| High-risk agent type | +15 | AutoGen, CrewAI, LangChain, OpenAI Agents |
| Medium-risk agent type | +10 | MCP Server, Semantic Kernel, PydanticAI |
| Ungoverned >30 days | +10 | Long time without governance |
| Ungoverned 7-30 days | +5 | Growing governance gap |
| Low confidence detection | -10 | May be false positive |

**Risk Levels:** Critical (75+) · High (50-74) · Medium (25-49) · Low (10-24) · Info (<10)

---

## Next Steps

- **Register shadow agents:** `agentmesh identity create --name "My Agent"`
- **Apply governance:** [Tutorial 01 — Policy Engine](01-policy-engine.md)
- **Secure MCP servers:** [Tutorial 27 — MCP Scan CLI](27-mcp-scan-cli.md)
- **Set up monitoring:** [Tutorial 13 — Observability](13-observability-and-tracing.md)

---

## Related

- [Agent Discovery README](../../agent-governance-python/agent-discovery/README.md) — Full API reference
- [Trust & Identity](02-trust-and-identity.md) — Register agents with AgentMesh
- [Compliance Verification](18-compliance-verification.md) — Prove governance coverage

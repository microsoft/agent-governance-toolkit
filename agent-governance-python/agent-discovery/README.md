# Agent Discovery

> **Shadow AI Agent Discovery & Inventory for the Agent Governance Toolkit**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## The Problem

**68% of employees use unsanctioned AI tools.** Most enterprises cannot answer a simple question: *How many AI agents are running in my organization right now?*

The Agent Governance Toolkit governs agents that register with it — but **you can't govern what you can't see.** Agent Discovery closes this gap by finding AI agents across your environment, inventorying them with deduplication, and reconciling against your governance registry to surface **shadow agents** operating outside governance.

---

## Quick Start

### Install

```bash
pip install agent-discovery                  # Core (process + config scanners)
pip install agent-discovery[github]          # + GitHub scanner
pip install agent-discovery[all]             # Everything including AgentMesh integration
```

### Scan Your Environment

```bash
# Scan local processes and filesystem for AI agents
agent-discovery scan

# Scan specific directories
agent-discovery scan -s config -p /path/to/projects -p /path/to/deployments

# Scan a GitHub organization
agent-discovery scan -s github --github-org my-org

# JSON output for CI/CD
agent-discovery scan -o json
```

### View Inventory

```bash
agent-discovery inventory                    # Table view
agent-discovery inventory -o summary         # Summary stats
agent-discovery inventory -o json            # JSON export
```

### Reconcile Against Registry

```bash
# Compare discovered agents against a registry of known agents
agent-discovery reconcile --registry-file registered-agents.json
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT DISCOVERY                          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Process   │  │ Config   │  │ GitHub   │   ← Scanners     │
│  │ Scanner   │  │ Scanner  │  │ Scanner  │     (pluggable)   │
│  └────┬──────┘  └────┬─────┘  └────┬─────┘                  │
│       │              │              │                         │
│       ▼              ▼              ▼                         │
│  ┌──────────────────────────────────────┐                    │
│  │         Agent Inventory              │  ← Deduplication   │
│  │   (fingerprint-based merge keys)     │    & correlation   │
│  └──────────────┬───────────────────────┘                    │
│                 │                                             │
│       ┌─────────┴──────────┐                                 │
│       ▼                    ▼                                  │
│  ┌──────────┐     ┌──────────────┐                           │
│  │Reconciler│     │ Risk Scorer  │                           │
│  │          │     │              │                            │
│  │ Registry │     │ Identity?    │                            │
│  │ Provider │     │ Owner?       │                            │
│  │ (adapter)│     │ Audit trail? │                            │
│  └──────────┘     └──────────────┘                           │
│       │                    │                                  │
│       ▼                    ▼                                  │
│  Shadow Agents    Risk Assessments                           │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Evidence-based discovery** — Every finding carries provenance, confidence scores, and detection basis. No black-box results.

2. **Fingerprint deduplication** — The same agent found by multiple scanners is merged into one logical agent with multiple observations. Prevents overcounting.

3. **Scanner plugin architecture** — `BaseScanner` ABC makes it easy to add new scanner types. Each scanner is independent, stateless, and read-only.

4. **Registry adapter pattern** — `RegistryProvider` interface decouples reconciliation from any specific governance system. Ship with `StaticRegistryProvider` and optional AgentMesh adapter.

5. **Security-first defaults** — Read-only scanning, secret redaction in process args, allowlist scoping, passive-only by default.

---

## Scanners

### Process Scanner (`process`)
Inspects running processes for signatures of 11 known AI agent frameworks:
- LangChain / LangGraph
- CrewAI
- AutoGen
- OpenAI Agents SDK
- Semantic Kernel
- AGT (AgentMesh / Agent OS)
- MCP Servers
- LlamaIndex
- Haystack
- PydanticAI
- Google ADK

**Security:** Command-line secrets (API keys, tokens, JWTs) are automatically redacted.

### Config Scanner (`config`)
Walks directories looking for agent configuration artifacts:
- `agentmesh.yaml`, `crewai.yaml`, `mcp.json`, etc.
- Docker/Compose files referencing agent frameworks
- Copilot setup files

### GitHub Scanner (`github`)
Searches repositories for agent indicators:
- Known config files in repo contents
- Agent framework dependencies in `requirements.txt`, `pyproject.toml`, `package.json`

Requires `httpx`: `pip install agent-discovery[github]`

---

## Python API

```python
import asyncio
from agent_discovery import AgentInventory, RiskScorer
from agent_discovery.scanners import ProcessScanner, ConfigScanner
from agent_discovery.reconciler import Reconciler, StaticRegistryProvider

async def discover():
    inventory = AgentInventory(storage_path="~/.agent-governance-python/agent-discovery/inventory.json")
    
    # Run scanners
    process_result = await ProcessScanner().scan()
    config_result = await ConfigScanner().scan(paths=["/opt/agents", "/home/deploy"])
    
    # Ingest with automatic deduplication
    inventory.ingest(process_result)
    inventory.ingest(config_result)
    
    # Reconcile against known agents
    registry = StaticRegistryProvider([
        {"did": "did:agent:prod-assistant", "name": "Production Assistant"},
        {"did": "did:agent:code-reviewer", "name": "Code Reviewer"},
    ])
    reconciler = Reconciler(inventory, registry)
    shadow_agents = await reconciler.reconcile()
    
    # Score risk
    scorer = RiskScorer()
    for shadow in shadow_agents:
        shadow.risk = scorer.score(shadow.agent)
        print(f"⚠ {shadow.agent.name}: {shadow.risk.level.value} ({shadow.risk.score:.0f}/100)")
        for action in shadow.recommended_actions:
            print(f"  → {action}")

asyncio.run(discover())
```

---

## Data Models

### `DiscoveredAgent`
| Field | Type | Description |
|-------|------|-------------|
| `fingerprint` | `str` | Stable dedup key (SHA-256 of merge keys) |
| `name` | `str` | Best-guess name |
| `agent_type` | `str` | Framework type (langchain, crewai, etc.) |
| `did` | `str?` | DID if registered with AgentMesh |
| `owner` | `str?` | Human/team owner |
| `status` | `AgentStatus` | registered / shadow / unregistered / unknown |
| `evidence` | `list[Evidence]` | All observations supporting this finding |
| `confidence` | `float` | Max confidence across all evidence (0.0-1.0) |
| `merge_keys` | `dict` | Stable identifiers for deduplication |

### `Evidence`
| Field | Type | Description |
|-------|------|-------------|
| `scanner` | `str` | Which scanner found this |
| `basis` | `DetectionBasis` | How it was detected |
| `source` | `str` | Where (PID, URL, path) |
| `confidence` | `float` | 0.0 = guess, 1.0 = certain |

### `RiskAssessment`
| Field | Type | Description |
|-------|------|-------------|
| `level` | `RiskLevel` | critical / high / medium / low / info |
| `score` | `float` | 0-100 numeric score |
| `factors` | `list[str]` | Contributing risk factors |

---

## Integration with Agent Governance Toolkit

Agent Discovery is designed to feed into the broader AGT governance stack:

```
Discovery → Inventory → Reconcile → Govern
    │            │           │          │
    │            │           │          └─ Agent OS (policy enforcement)
    │            │           └─ AgentMesh (register identity)
    │            └─ Persistent agent catalog
    └─ Process / Config / GitHub scanners
```

1. **Discover** agents with `agent-discovery scan`
2. **Register** shadow agents with AgentMesh: `agentmesh identity create`
3. **Govern** with Agent OS policies: capability model, privilege rings
4. **Monitor** with Agent SRE: SLOs, circuit breakers

---

## Writing Custom Scanners

```python
from agent_discovery.scanners.base import BaseScanner, registry
from agent_discovery.models import ScanResult, DiscoveredAgent, Evidence, DetectionBasis

@registry.register
class MyCustomScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "my-scanner"
    
    async def scan(self, **kwargs) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # Your discovery logic here
        agent = DiscoveredAgent(
            fingerprint=DiscoveredAgent.compute_fingerprint({"my_key": "value"}),
            name="Found Agent",
            agent_type="custom",
        )
        agent.add_evidence(Evidence(
            scanner=self.name,
            basis=DetectionBasis.MANUAL,
            source="my-source",
            detail="Custom detection logic",
            confidence=0.9,
        ))
        result.agents.append(agent)
        return result
```

---

## Security Considerations

- **Read-only** — All scanners are passive and never modify the target environment
- **Secret redaction** — Process scanner automatically redacts API keys, tokens, and JWTs from command-line arguments
- **Scoped access** — Scanners only examine what's explicitly requested (directories, repos, etc.)
- **No content storage** — File contents are never stored in the inventory, only metadata and paths
- **Least-privilege credentials** — GitHub scanner needs only read access to repos

---

## Contributing

See the [Agent Governance Toolkit contributing guide](../../CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

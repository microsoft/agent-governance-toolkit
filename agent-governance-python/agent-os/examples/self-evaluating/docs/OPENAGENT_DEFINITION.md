# OpenAgent Definition (OAD)

## The "USB Port" Moment for AI

### The Problem

**The Old World:**
> "Just read the system prompt to figure out what the agent does."

**The Engineering Reality:**
That is unscalable. If we want to pull specialized agents from a marketplace (e.g., a "GitHub Coder" or an "OpenAI Analyst"), we cannot guess how to talk to them.

### The Solution

We need an **Interface Definition Language (IDL) for Agents**—an "OpenAgent Definition" (OAD) similar to Swagger/OpenAPI for REST APIs.

Every agent in the ecosystem must publish a **Metadata Manifest** that includes:

1. **Capabilities** (The "Can-Do"): "I can write Python 3.9 code. I can parse CSVs."
2. **Constraints** (The "Won't-Do"): "I have no internet access. I have a 4k token limit."
3. **IO Contract**: "I accept a CodeContext object. I return a Diff object."
4. **Trust Score**: "My code compiles 95% of the time."

### The Lesson

This is the **"USB Port" moment for AI**. The startup that defines the Standard Agent Protocol wins the platform war.

---

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    AgentMetadata                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Capabilities │  │ Constraints  │  │ IO Contract  │      │
│  │              │  │              │  │              │      │
│  │ - math       │  │ - no internet│  │ input_schema │      │
│  │ - python     │  │ - 4k tokens  │  │ output_schema│      │
│  │ - git        │  │ - read-only  │  │ examples     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │            TrustScore (Performance Metrics)           │   │
│  │  - success_rate: 0.95                                │   │
│  │  - avg_latency_ms: 1200                             │   │
│  │  - total_executions: 1547                           │   │
│  │  - metrics: {compilation_rate: 0.95, ...}          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    agent_manifest.json
                    (Publishable Format)
```

### Metadata Manifest Structure

```json
{
  "agent_id": "self-evolving-agent",
  "name": "Self-Evolving Agent",
  "version": "1.0.0",
  "description": "A self-evolving AI agent...",
  "capabilities": [
    {
      "name": "mathematical_calculations",
      "description": "Can evaluate mathematical expressions",
      "tags": ["math", "calculations"],
      "version": "1.0"
    }
  ],
  "constraints": [
    {
      "type": "resource",
      "description": "No direct internet access",
      "severity": "high"
    }
  ],
  "io_contract": {
    "input_schema": {
      "type": "object",
      "properties": {
        "query": {"type": "string"}
      }
    },
    "output_schema": {
      "type": "object",
      "properties": {
        "response": {"type": "string"}
      }
    }
  },
  "trust_score": {
    "success_rate": 0.95,
    "avg_latency_ms": 1200.0,
    "total_executions": 1547,
    "metrics": {
      "code_compilation_rate": 0.95
    }
  }
}
```

---

## Usage

### Creating a Metadata Manifest

```python
from agent_metadata import AgentMetadata

# Create metadata for your agent
metadata = AgentMetadata(
    agent_id="github-coder",
    name="GitHub Coder Agent",
    version="2.3.1",
    description="Specialized agent for GitHub code operations"
)

# Add capabilities (The "Can-Do")
metadata.add_capability(
    name="python_code_generation",
    description="Can generate Python 3.9+ code following PEP 8",
    tags=["python", "code-generation"],
    version="2.0"
)

# Add constraints (The "Won't-Do")
metadata.add_constraint(
    type="access",
    description="No internet access outside of GitHub API",
    severity="high"
)

# Define IO contract
metadata.set_io_contract(
    input_schema={
        "type": "object",
        "properties": {
            "repository": {"type": "string"},
            "task": {"type": "string"}
        }
    },
    output_schema={
        "type": "object",
        "properties": {
            "code": {"type": "string"},
            "commit_sha": {"type": "string"}
        }
    }
)

# Set trust score
metadata.set_trust_score(
    success_rate=0.93,
    avg_latency_ms=2400.0,
    total_executions=1547,
    metrics={
        "code_compilation_rate": 0.95,
        "test_pass_rate": 0.87
    }
)
```

### Saving and Loading Manifests

```python
from agent_metadata import AgentMetadataManager

# Create manager
manager = AgentMetadataManager("agent_manifest.json")

# Save manifest
manager.save_manifest(metadata)

# Load manifest
loaded_metadata = manager.load_manifest()

# Get manifest (auto-loads if not already loaded)
metadata = manager.get_manifest()
```

### Publishing to Marketplace

```python
# Publish manifest (returns publishable format)
result = manager.publish_manifest()

print(result["status"])  # "published"
print(result["published_at"])  # ISO timestamp
```

### Dynamic Trust Score Updates

```python
# Trust scores update automatically based on execution results
metadata.update_trust_score(success=True, latency_ms=1000.0)
metadata.update_trust_score(success=False, latency_ms=2000.0)

print(f"Success Rate: {metadata.trust_score.success_rate:.1%}")
print(f"Avg Latency: {metadata.trust_score.avg_latency_ms:.0f}ms")
```

### Integration with DoerAgent

The `DoerAgent` automatically publishes and maintains an OAD manifest:

```python
from agent import DoerAgent

# Create agent with metadata enabled (default)
doer = DoerAgent(enable_metadata=True)

# Get the agent's metadata manifest
manifest = doer.get_metadata_manifest()

print(f"Agent: {manifest['name']}")
print(f"Capabilities: {len(manifest['capabilities'])}")
print(f"Trust Score: {manifest['trust_score']['success_rate']:.1%}")

# Publish to marketplace
result = doer.publish_manifest()
```

The agent automatically updates its trust score after each execution:

```python
# Run tasks - trust score updates automatically
result = doer.run("What is 10 + 20?")

# Trust score reflects real performance
manifest = doer.get_metadata_manifest()
trust_score = manifest['trust_score']
print(f"Updated Success Rate: {trust_score['success_rate']:.1%}")
```

---

## Agent Discovery and Composition

### Marketplace Discovery

```python
# Search for agents with specific capabilities
manager = AgentMetadataManager()
agents = manager.discover_agents(capability_filter="python")

for agent in agents:
    print(f"{agent['name']} - v{agent['version']}")
    print(f"  Capabilities: {agent['capabilities']}")
```

### Compatibility Validation

```python
# Check if two agents can work together
manager1 = AgentMetadataManager("agent1_manifest.json")
agent1_metadata = manager1.get_manifest()

agent2_metadata = load_other_agent_manifest()

# Validate IO contract compatibility
compatibility = manager1.validate_compatibility(agent2_metadata)

if compatibility["compatible"]:
    print("✓ Agents can be composed together")
else:
    print("✗ Incompatible agents")
    for warning in compatibility["warnings"]:
        print(f"  - {warning}")
```

### Agent Pipelines

```python
# Compose agents into a pipeline based on IO contracts

# Agent 1: Data Fetcher
#   Output: {"data": [...], "format": "json"}

# Agent 2: Data Transformer  
#   Input: {"data": [...], "format": "..."}
#   Output: {"cleaned_data": [...], "summary": {...}}

# Agent 3: Report Generator
#   Input: {"cleaned_data": [...], "summary": {...}}
#   Output: {"report": "...", "format": "pdf"}

# The OAD system validates that outputs match inputs
```

---

## Examples

### Example 1: Basic Manifest Creation

```bash
python example_agent_metadata.py
```

This demonstrates:
- Creating an agent metadata manifest
- Defining capabilities, constraints, IO contracts, and trust scores
- Saving and loading manifests

### Example 2: Marketplace Discovery

See how agents can be discovered in a marketplace based on their capabilities.

### Example 3: Agent Composition

Learn how to compose multiple agents into a pipeline using IO contracts.

### Example 4: Trust Score Updates

See how trust scores update dynamically based on real execution results.

---

## Testing

Run the test suite:

```bash
python test_agent_metadata.py
```

Tests include:
- Capability, Constraint, IOContract, TrustScore creation
- AgentMetadata CRUD operations
- Serialization/deserialization (JSON)
- Manager operations (save, load, publish)
- Trust score dynamic updates
- Compatibility validation

---

## Use Cases

### 1. Agent Marketplace

**Scenario:** You need a specialized agent for a task

```python
# Search marketplace for "Python coder" agents
results = marketplace.search(capability="python_code_generation")

# Compare agents by trust score
best_agent = max(results, key=lambda a: a.trust_score.success_rate)

# Instantiate and use
agent = marketplace.instantiate(best_agent.agent_id)
result = agent.run(task)
```

### 2. Multi-Agent Orchestration

**Scenario:** Build a complex workflow with multiple specialized agents

```python
# Load agent manifests
coder = load_agent("github-coder")
reviewer = load_agent("code-reviewer")
deployer = load_agent("deployment-agent")

# Validate pipeline compatibility
validate_pipeline([coder, reviewer, deployer])

# Execute pipeline
code = coder.run(specification)
review = reviewer.run(code)
if review.approved:
    deployment = deployer.run(code)
```

### 3. Dynamic Agent Selection

**Scenario:** Choose the best agent based on real-time metrics

```python
# Find all agents that can handle the task
candidates = discover_agents(capability="data_analysis")

# Filter by trust score
reliable_agents = [a for a in candidates 
                   if a.trust_score.success_rate > 0.90]

# Select fastest agent
fastest_agent = min(reliable_agents, 
                   key=lambda a: a.trust_score.avg_latency_ms)

# Use selected agent
result = fastest_agent.run(query)
```

### 4. Contract Enforcement

**Scenario:** Ensure agents follow specified IO contracts

```python
# Define required IO contract
required_contract = {
    "input_schema": {...},
    "output_schema": {...}
}

# Validate agent meets contract
agent_manifest = load_agent_manifest("agent.json")
if validates_contract(agent_manifest.io_contract, required_contract):
    # Safe to use agent
    agent = instantiate_agent(agent_manifest)
else:
    raise ContractViolationError("Agent doesn't meet required contract")
```

---

## Key Benefits

### 1. **Discoverability**
- Agents can be found in a marketplace based on capabilities
- No need to "guess" what an agent does
- Standard format makes search and filtering easy

### 2. **Composability**
- IO contracts ensure agents can work together
- Validate compatibility before runtime
- Build complex pipelines with confidence

### 3. **Transparency**
- Capabilities clearly state what agent can do
- Constraints clearly state what agent won't/can't do
- Trust scores provide real performance metrics

### 4. **Trust**
- Real metrics (not marketing claims)
- Dynamic updates based on actual performance
- Compare agents objectively

### 5. **Standardization**
- Common format across all agents
- Platform-agnostic protocol
- Enables agent marketplaces and ecosystems

---

## The Future: Agent Marketplaces

With OAD, we can build:

### Agent Discovery Platforms
```
┌─────────────────────────────────────┐
│     Agent Marketplace               │
├─────────────────────────────────────┤
│                                     │
│  Search: "Python code generator"   │
│  ─────────────────────────────────  │
│                                     │
│  ✓ GitHub Coder Pro                │
│    Trust: 93% | Latency: 2.4s      │
│    $0.10/request                    │
│                                     │
│  ✓ OpenAI Code Assistant           │
│    Trust: 87% | Latency: 1.8s      │
│    $0.05/request                    │
│                                     │
│  ✓ Local Code Generator            │
│    Trust: 78% | Latency: 3.2s      │
│    Free                             │
│                                     │
└─────────────────────────────────────┘
```

### Agent Composition Tools
```
Pipeline Builder:
  [Data Fetcher] → [Transformer] → [Reporter]
       ↓                 ↓              ↓
  Compatible?      Compatible?     Compatible?
       ✓                 ✓              ✓
```

### Agent Certification
```
Agent: GitHub Coder v2.3.1
├─ Capabilities: ✓ Verified
├─ Constraints: ✓ Verified  
├─ IO Contract: ✓ Validated
└─ Trust Score: ✓ 1000+ executions
```

---

## API Reference

See the module docstrings in `agent_metadata.py` for complete API documentation:

- `AgentMetadata`: Main metadata container
- `Capability`: Represents an agent capability
- `Constraint`: Represents an agent constraint
- `IOContract`: Input/output contract specification
- `TrustScore`: Performance and reliability metrics
- `AgentMetadataManager`: Manager for loading/saving/publishing manifests

---

## Conclusion

The OpenAgent Definition (OAD) system provides:

✅ **Standard interface** for describing AI agents  
✅ **Marketplace-ready** format for discovery  
✅ **Composability** through IO contracts  
✅ **Transparency** through capabilities and constraints  
✅ **Trust** through real performance metrics  

**This is the "USB Port" moment for AI.**

The platform that defines the Standard Agent Protocol wins the platform war.

---

## License

MIT

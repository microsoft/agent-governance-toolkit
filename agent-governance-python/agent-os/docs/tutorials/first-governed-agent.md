# Building Your First Governed Agent

> **A complete guide to creating a production-ready governed agent.**

## What We're Building

A document analysis agent that:
- Reads files from a sandboxed directory
- Uses an LLM to analyze content
- Returns structured results
- Is protected by kernel-level policies

## Prerequisites

```bash
pip install agent-os-kernel[full]
```

## Step 1: Project Structure

```bash
agentos init doc-analyzer
cd doc-analyzer
```

This creates:

```
doc-analyzer/
├── .agents/
│   ├── agents.md        # Agent instructions
│   └── security.md      # Kernel policies
├── agent.py             # Your agent code
├── data/                # Sandboxed data directory
└── pyproject.toml
```

## Step 2: Define Security Policies

Edit `.agents/security.md`:

```yaml
kernel:
  version: "1.0"
  mode: strict

signals:
  enabled:
    - SIGSTOP   # Pause for human review
    - SIGKILL   # Terminate on violation
    - SIGCONT   # Resume after review

policies:
  # Only allow reading from /data directory
  - name: sandboxed_reads
    allow:
      - action: file_read
        paths:
          - "./data/**"
    deny:
      - action: file_read
        paths:
          - "/**"  # Deny all other reads
  
  # Block all writes
  - name: read_only
    deny:
      - action: file_write
      - action: file_delete
  
  # Block network except allowed APIs
  - name: network_restricted
    allow:
      - action: http_request
        domains:
          - "api.openai.com"
          - "api.anthropic.com"
    deny:
      - action: http_request
  
  # Block dangerous patterns in output
  - name: no_sensitive_data
    deny:
      - action: output
        patterns:
          - "\\b\\d{3}-\\d{2}-\\d{4}\\b"  # SSN
          - "\\b\\d{16}\\b"                # Credit card
          - "password\\s*[:=]"             # Passwords

audit:
  enabled: true
  log_path: "./logs/audit.log"
  include:
    - all_actions
    - policy_checks
    - signals
```

## Step 3: Write the Agent

Edit `agent.py`:

```python
"""Document Analysis Agent with Kernel Governance."""

import asyncio
from pathlib import Path
from typing import Dict, Any

from agent_os import KernelSpace, AgentSignal
from agent_os.integrations import OpenAIKernel

# Initialize kernel with policies
kernel = KernelSpace(
    policy_file=".agents/security.md",
    audit=True
)


@kernel.register
async def analyze_document(file_path: str) -> Dict[str, Any]:
    """
    Analyze a document and return structured insights.
    
    This function is governed by the kernel - any policy
    violations will result in automatic termination.
    
    Args:
        file_path: Path to document (must be in ./data/)
    
    Returns:
        Analysis results including summary, key points, and sentiment
    """
    # Read the document (kernel checks this against sandboxed_reads policy)
    path = Path(file_path)
    
    if not path.exists():
        return {"error": f"File not found: {file_path}"}
    
    content = path.read_text()
    
    # Use LLM to analyze (kernel checks network policy)
    from openai import OpenAI
    client = OpenAI()
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": """You are a document analyst. Analyze the document and return:
                1. A brief summary (2-3 sentences)
                2. Key points (bullet list)
                3. Sentiment (positive/negative/neutral)
                4. Suggested actions
                
                Format as JSON."""
            },
            {
                "role": "user",
                "content": f"Analyze this document:\n\n{content}"
            }
        ],
        response_format={"type": "json_object"}
    )
    
    # Parse and return results
    import json
    analysis = json.loads(response.choices[0].message.content)
    
    return {
        "file": file_path,
        "analysis": analysis,
        "status": "success"
    }


@kernel.register
async def batch_analyze(directory: str) -> list:
    """Analyze all documents in a directory."""
    results = []
    dir_path = Path(directory)
    
    for file_path in dir_path.glob("*.txt"):
        result = await analyze_document(str(file_path))
        results.append(result)
    
    return results


async def main():
    """Run the document analyzer."""
    print("📄 Document Analyzer Agent")
    print("=" * 40)
    
    # Analyze a single document
    result = await kernel.execute(
        analyze_document,
        "data/sample.txt"
    )
    
    print("\n📊 Analysis Result:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    import json
    asyncio.run(main())
```

## Step 4: Add Sample Data

Create `data/sample.txt`:

```text
Q3 2024 Performance Report

Executive Summary:
Our team exceeded quarterly targets by 15%, driven by strong 
performance in the enterprise segment. Customer satisfaction 
scores reached an all-time high of 94%.

Key Achievements:
- Launched 3 new product features
- Reduced customer churn by 20%
- Expanded into 2 new markets
- Achieved SOC 2 Type II certification

Challenges:
- Supply chain delays affected hardware delivery
- Increased competition in SMB segment

Outlook:
We remain optimistic about Q4 with a strong pipeline and 
positive customer feedback on upcoming releases.
```

## Step 5: Run the Agent

```bash
agentos run
```

Or directly:

```bash
python agent.py
```

## Step 6: Test Policy Enforcement

Try to read a file outside the sandbox:

```python
# This will be blocked by the kernel
result = await kernel.execute(analyze_document, "/etc/passwd")
```

Output:
```
⚠️  POLICY VIOLATION DETECTED
⚠️  Signal: SIGKILL
⚠️  Agent: analyze_document
⚠️  Action: file_read
⚠️  Path: /etc/passwd
⚠️  Policy: sandboxed_reads
⚠️  Reason: Path not in allowed sandbox
```

## Step 7: Add Observability

Update your agent to include metrics:

```python
from agent_os.observability import metrics

@kernel.register
@metrics.track(name="document_analysis")
async def analyze_document(file_path: str) -> Dict[str, Any]:
    with metrics.timer("llm_call"):
        # ... LLM call
        pass
    
    metrics.increment("documents_analyzed")
    return result
```

Start with observability:

```bash
agentos run --observability
# Opens Grafana at http://localhost:3000
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER SPACE                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  analyze_document()                                       │   │
│  │  - Reads files                                            │   │
│  │  - Calls OpenAI API                                       │   │
│  │  - Returns analysis                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                       KERNEL SPACE                               │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐    │
│  │ Policy Engine│ │ Signal Disp. │ │ Flight Recorder      │    │
│  │              │ │              │ │                      │    │
│  │ sandboxed_   │ │ SIGKILL ──►  │ │ audit.log            │    │
│  │ reads        │ │ SIGSTOP ──►  │ │ - all actions        │    │
│  │ read_only    │ │ SIGCONT ──►  │ │ - policy checks      │    │
│  │ network_     │ │              │ │ - signals            │    │
│  │ restricted   │ │              │ │                      │    │
│  └──────────────┘ └──────────────┘ └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Best Practices

### 1. Defense in Depth

```yaml
# Layer multiple policies
policies:
  - name: sandboxed_reads    # Restrict file access
  - name: read_only          # No writes at all
  - name: network_restricted # Limit network
  - name: no_sensitive_data  # Filter outputs
```

### 2. Audit Everything

```python
# Enable comprehensive auditing
kernel = KernelSpace(
    policy_file=".agents/security.md",
    audit=True,
    audit_level="verbose"
)
```

### 3. Use Signals for Human-in-the-Loop

```python
@kernel.register
async def risky_operation(data: str):
    # Pause for human review
    kernel.signal(AgentSignal.SIGSTOP, reason="High-value operation")
    
    # Human reviews in dashboard, sends SIGCONT to continue
    
    return result
```

### 4. Test Policy Violations

```python
# test_policies.py
import pytest
from agent_os.testing import PolicyTestKit

def test_sandbox_enforcement():
    """Verify sandbox policy blocks unauthorized reads."""
    kit = PolicyTestKit(".agents/security.md")
    
    # Should pass
    kit.assert_allowed("file_read", path="./data/test.txt")
    
    # Should fail
    kit.assert_denied("file_read", path="/etc/passwd")
    kit.assert_denied("file_write", path="./data/test.txt")
```

## Next Steps

| Tutorial | Description |
|----------|-------------|
| [Message Bus Adapters](./message-bus-adapters.md) | Connect multiple agents |
| [Custom Tools](./custom-tools.md) | Build safe tools for agents |
| [Observability](../observability.md) | Prometheus + Grafana setup |
| [Multi-Agent Systems](./multi-agent.md) | Coordinate agent teams |

---

<div align="center">

**Want to connect multiple agents?**

[Message Bus Adapters →](./message-bus-adapters.md)

</div>

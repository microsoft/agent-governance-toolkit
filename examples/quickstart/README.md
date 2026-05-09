# Quickstart Examples

Runnable examples showing AGT governance enforcement across major agent frameworks and patterns. Each script demonstrates a real policy violation being caught and a compliant call succeeding, with a printed audit trail.

## Prerequisites

- Python 3.10+
- No API keys required for core demos (`govern_in_60_seconds.py`, `retrofit_governed.py`)
- OpenAI API key (for LangChain, AutoGen, OpenAI Agents examples)
- Google ADK credentials (for ADK example)

```bash
pip install agent-governance-toolkit[full]
```

## How to Run

```bash
# Govern in 60 seconds (no API key needed)
python examples/quickstart/govern_in_60_seconds.py

# Retrofit governance onto an existing agent (no API key needed)
python examples/quickstart/retrofit_governed.py

# MCP receipt signing (no API key needed)
python examples/quickstart/mcp_receipts_in_60_seconds.py

# LangChain
python examples/quickstart/langchain_governed.py

# CrewAI
python examples/quickstart/crewai_governed.py

# AutoGen
python examples/quickstart/autogen_governed.py

# Google ADK
python examples/quickstart/google_adk_governed.py

# OpenAI Agents
python examples/quickstart/openai_agents_governed.py
```

## Expected Output

Each script prints a governance decision log showing blocked and allowed actions, followed by an audit trail summary.

## Related

- [Policies](../policies/) — Sample YAML governance policies to use with these examples
- [Tutorial 01: Policy Engine](../../docs/tutorials/01-policy-engine.md)
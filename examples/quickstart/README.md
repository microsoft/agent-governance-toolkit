# Quickstart Examples

Runnable examples showing AgentMesh governance enforcement across five major agent frameworks. Each script demonstrates a real policy violation being caught and a compliant call succeeding, with a printed audit trail.

Refer to the individual scripts for framework-specific implementations.

## Prerequisites

- Python 3.x
- OpenAI API key (for LangChain, AutoGen, OpenAI Agents examples)
- Google ADK credentials (for ADK example)

```bash
pip install agent-governance-toolkit[full]
```

## How to Run

```bash
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

## Related

- [Policies](../policies/) — Sample YAML governance policies to use with these examples
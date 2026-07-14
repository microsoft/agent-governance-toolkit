# Quickstart Examples

Runnable examples showing AGT governance enforcement across major agent frameworks and patterns. Each script demonstrates a real policy violation being caught and a compliant call succeeding, with a printed audit trail.

## Prerequisites

- Python 3.10+
- No API keys required for `govern_in_60_seconds.py`
- Google ADK credentials (for ADK example)

```bash
pip install agent-governance-toolkit[full]
```

## How to Run

```bash
# Govern in 60 seconds (no API key needed)
python examples/quickstart/govern_in_60_seconds.py

# MCP receipt signing (no API key needed)
python examples/quickstart/mcp_receipts_in_60_seconds.py

# Google ADK
python examples/quickstart/google_adk_governed.py
```

Native framework examples also live under `examples/crewai-governed/`,
`examples/openai-agents-governed/`, `examples/smolagents-governed/`, and
`examples/maf-integration/`.

## Expected Output

Each script prints a governance decision log showing blocked and allowed actions, followed by an audit trail summary.

## Related

- [Policies](../policies/) — Sample YAML governance policies to use with these examples
- [Tutorial 01: Policy Engine](../../docs/tutorials/01-policy-engine.md)
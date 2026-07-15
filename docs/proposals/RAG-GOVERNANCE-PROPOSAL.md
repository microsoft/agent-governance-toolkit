---
title: "RAG Governance — Retrieval-Level Policy Enforcement"
last_reviewed: 2026-05-05
owner: agt-maintainers
---

# RAG Governance — Retrieval-Level Policy Enforcement

**Submissions:**

- [microsoft/agent-governance-toolkit#1700](https://github.com/microsoft/agent-governance-toolkit/issues/1700) — RAG governance package proposal (Open Issue)

**Type:** New package (`agent-rag-governance`)

**Date Submitted:** May 4, 2026

## Summary

Retrieval-level governance for RAG pipelines using Agent-OS. Adds
collection-level access control, rate limiting, content scanning, and
audit trails before retrieved chunks reach the LLM. The core
`RAGGovernor` works with any retriever — framework-specific wrappers
for LangChain and LlamaIndex are provided as separate adapters, with
room for more frameworks to be added without changing the core.

## Problem

RAG pipelines lack built-in policy enforcement at retrieval time:

- Agents can query any vector DB collection without restriction
- No audit trail of which documents influenced an answer
- No rate limiting if an agent gets stuck in a retrieval loop
- No content scanning on retrieved chunks before they reach the LLM

## Solution: `agent-rag-governance` Package

### RAGGovernor

```python
from agent_rag_governance import RAGGovernor
from agent_rag_governance.policies import CollectionACL, ContentPolicy

governor = RAGGovernor(
    acl=CollectionACL(
        allowed=["public_docs", "product_manuals"],
        denied=["hr_records", "financial_data"],
    ),
    rate_limit=100,
    content_policies=[ContentPolicy.BLOCK_PII, ContentPolicy.BLOCK_INJECTIONS],
    audit_enabled=True,
)
```

### Framework Adapters

Framework-specific wrappers over the core `RAGGovernor`, kept separate
from the core so new frameworks can be added without touching `RAGGovernor`:

```python
# LangChain adapter
from agent_rag_governance.adapters.langchain import GovernedRetriever

governed_retriever = GovernedRetriever(
    retriever=your_langchain_retriever,
    governor=governor,
)
docs = governed_retriever.get_relevant_documents("your query")
print(f"Blocked retrievals: {governed_retriever.violations}")

# LlamaIndex adapter
from agent_rag_governance.adapters.llamaindex import GovernedQueryEngine

governed_engine = GovernedQueryEngine(
    query_engine=your_llama_query_engine,
    governor=governor,
)
```

### Key Features

- **Collection ACL** — Allow/deny vector DB collections per agent
  identity using existing Cedar/Rego PolicyEvaluator
- **Rate limiting** — Cap retrieval calls per minute to prevent
  runaway agent loops
- **Content scanning** — PII detection and injection pattern scanning
  on retrieved chunks before they reach the LLM
- **Audit trail** — Full logging of every retrieval call with
  timestamp, agent ID, collection, document IDs, and policy decision
- **Framework-agnostic core** — Works with any retriever that returns
  documents; LangChain and LlamaIndex as first adapters. Future
  contributors can add adapters for CrewAI, AutoGen, Haystack, and
  others without touching the core `RAGGovernor` — following the same
  pattern already used in `agentmesh-integrations`

## API Surface

The public API has three entry points:

**RAGGovernor** — core engine, framework-agnostic:

```python
governor.retrieve(
    query: str,
    collection: str,
    agent_id: str,
    retriever_fn: Callable,
) -> GovernedRetrievalResult
```

**GovernedRetrievalResult** — returned from every retrieval call:

```python
@dataclass
class GovernedRetrievalResult:
    allowed: bool             # whether retrieval was permitted
    documents: list[Document] # retrieved chunks (empty if blocked)
    reason: str | None        # policy decision reason
    audit_id: str             # unique ID for this retrieval call
```

**Framework adapters** — thin wrappers over the core:

```python
# LangChain
GovernedRetriever(retriever, governor) -> BaseRetriever

# LlamaIndex
GovernedQueryEngine(query_engine, governor) -> BaseQueryEngine
```

## Where it sits in the AGT package tree

```
agent-governance-python/
├── agent-os/               # Policy engine (PolicyEvaluator)
├── agent-mesh/             # Zero-trust identity
├── agent-mcp-governance/   # MCP tool governance
├── agent-rag-governance/   # NEW — retrieval governance
│   ├── src/
│   │   └── agent_rag_governance/
│   │       ├── __init__.py       # Public exports
│   │       ├── governor.py       # RAGGovernor core
│   │       ├── policies.py       # CollectionACL, ContentPolicy
│   │       ├── audit.py          # Audit trail logging
│   │       └── adapters/
│   │           ├── langchain.py  # GovernedRetriever (Phase 1)
│   │           ├── llamaindex.py # GovernedQueryEngine (Phase 1)
│   │           └── ...           # CrewAI, AutoGen, Haystack (future)
│   ├── tests/
│   ├── pyproject.toml
│   └── README.md
└── agent-sre/              # SLOs, circuit breakers
```

`agent-rag-governance` sits alongside `agent-mcp-governance` —
both follow the same wrapper pattern, governing a specific action
category (MCP tool calls vs retrieval calls) using the shared
`agent-os` policy engine.

## How it interacts with existing PolicyEvaluator

`RAGGovernor` delegates all policy decisions to the existing
PolicyEvaluator from `agent-os` — no parallel policy system.
Collection ACLs are expressed in Cedar/Rego and evaluated through
the same PEP/PDP pair used everywhere else in AGT:

```python
from agent_os.policies import PolicyEvaluator
from agent_rag_governance import RAGGovernor

# Reuse existing PolicyEvaluator
evaluator = PolicyEvaluator(policies=[your_cedar_policy])

governor = RAGGovernor(
    policy_evaluator=evaluator,  # plugs in directly
    rate_limit=100,
    audit_enabled=True,
)
```

Cedar policy example for collection ACL:

```
permit(
  principal == Agent::"my-agent",
  action == Action::"retrieve",
  resource in Collection::"public_docs"
);

forbid(
  principal,
  action == Action::"retrieve",
  resource in Collection::"hr_records"
);
```

The `RAGGovernor` calls `evaluator.evaluate()` before every
retrieval — the same call pattern used by `agent-mcp-governance`
and `agent-os` tool governance. This means existing policies
can cover both tool calls and retrieval calls in one policy file.

## Value Proposition

| Feature | Without Package | With agent-rag-governance |
| --- | --- | --- |
| Collection access control | None | Cedar/Rego per agent identity |
| Rate limiting | None | Configurable per agent |
| Content scanning | None | PII + injection detection |
| Audit trail | None | Full per-retrieval log |
| Framework support | N/A | LangChain + LlamaIndex |

## Example PR

End-to-end example demonstrating `agent-rag-governance` in action:

- `RAGGovernor` setup with `CollectionACL` and `ContentPolicy`
- Cedar/Rego policy configuration for collection access control
- Framework-agnostic retrieval with governance enforcement
- Rate limiting triggering on a runaway retrieval loop
- PII detection blocking a chunk before it reaches the LLM
- Audit trail output showing timestamp, agent ID, collection,
  document IDs, and policy decision per retrieval call

## Links

- [Issue #1700](https://github.com/microsoft/agent-governance-toolkit/issues/1700)
- [agent-mcp-governance](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mcp-governance/README.md)
- [agent-os PolicyEvaluator](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-os)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit/blob/main/README.md)

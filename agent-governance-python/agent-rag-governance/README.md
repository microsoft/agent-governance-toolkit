# agent-rag-governance

> Retrieval access control and vector store policy enforcement for RAG pipelines.

Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## The Gap This Fills

AGT covers write-time memory protection (`MemoryGuard`) and output quality (`ContentGovernance`) — but nothing at **retrieval time**. Without retrieval-level governance:

- An agent can query any collection it wants — no access control
- No audit trail of which documents influenced an answer
- No rate limiting if an agent gets stuck in a retrieval loop
- No content scanning before retrieved chunks reach the LLM

`agent-rag-governance` closes that gap.

## Quick Start

```bash
pip install agent-rag-governance
```

```python
from agent_rag_governance import RAGGovernor, RAGPolicy

policy = RAGPolicy(
    allowed_collections=["public_docs", "product_manuals"],
    denied_collections=["hr_records", "financial_data"],
    max_retrievals_per_minute=100,
    content_policies=["block_pii", "block_injections"],
    audit_enabled=True,
)

governor = RAGGovernor(policy=policy, agent_id="sales-agent-001")
governed_retriever = governor.wrap(your_langchain_retriever, collection="public_docs")

# Drop-in replacement — same API as the original retriever
docs = governed_retriever.invoke("what is our refund policy?")
```

## What It Enforces

| Layer | What It Does |
|---|---|
| **Collection access control** | Allow/deny lists per agent — blocks cross-tenant data leaks |
| **Rate limiting** | Sliding-window cap on retrievals/min — stops runaway loops |
| **Content scanning** | PII and prompt-injection detection on chunks before LLM sees them |
| **Audit logging** | Structured JSON-lines record per call — enables EU AI Act traceability |

## Governance Pipeline

Every `governed_retriever.invoke(query)` call runs this sequence:

```
1. check_collection()   →  CollectionDeniedError if blocked
2. check_rate()         →  RateLimitExceededError if exceeded
3. retrieve()           →  calls underlying retriever
4. scan_chunks()        →  filters blocked chunks, logs warnings
5. audit()              →  emits JSON-lines audit entry
```

## Policy Reference

```python
RAGPolicy(
    # None = allow all (unless denied). List = explicit allow list.
    allowed_collections=["public_docs"],

    # Always blocked, even if in allowed_collections.
    denied_collections=["hr_records", "financial_data"],

    # 0 = unlimited. Per agent per 60-second sliding window.
    max_retrievals_per_minute=100,

    # "block_pii": block chunks with emails, phones, SSNs, credit cards
    # "block_injections": block chunks with prompt-injection payloads
    content_policies=["block_pii", "block_injections"],

    # Write structured JSON-lines audit entries.
    audit_enabled=True,

    # None = stdout. Provide a path for file-based logging.
    audit_log_path="/var/log/rag-audit.jsonl",
)
```

## Audit Log Format

Each retrieval call emits one JSON line:

```json
{
  "timestamp": "2026-05-05T12:34:56.789012+00:00",
  "agent_id": "sales-agent-001",
  "collection": "public_docs",
  "query_hash": "a3f1...",
  "num_chunks_retrieved": 5,
  "num_chunks_blocked": 1,
  "decision": "allowed",
  "policy_triggered": null
}
```

Raw query text is **never logged** — only a SHA-256 hash — to avoid leaking sensitive search terms.

## Compatibility

Works with any retriever that implements `.invoke()` or `.get_relevant_documents()`. LangChain is an optional dependency — `agent-rag-governance` has no required framework dependencies.

```bash
# With LangChain integration
pip install "agent-rag-governance[langchain]"
```

## Related Packages

| Package | Protects |
|---|---|
| `agent-os-kernel` (MemoryGuard) | Write-time memory poisoning |
| **`agent-rag-governance`** | **Retrieval-time access control** |
| `agent-os-kernel` (ContentGovernance) | Output-time quality enforcement |

# Changelog

## Unreleased

### Added
- `cedar_policy` field on `RAGPolicy` — inline Cedar policy string for
  collection access control via `CedarBackend` from `agent-os`
- `cedar_policy_path` field on `RAGPolicy` — path to a `.cedar` policy
  file, loaded automatically at construction time
- Cedar policy takes precedence over `allowed_collections` /
  `denied_collections` when configured — fully opt-in, existing list
  behaviour unchanged
- `LlamaIndex` adapter — `GovernedQueryEngine` wraps any LlamaIndex
  `BaseQueryEngine` or `BaseRetriever` with the same four governance
  controls (collection ACL, rate limiting, content scanning, audit logging)

## 0.1.0 (2026-05-05)

Initial release.
- `RAGGovernor` — governance wrapper for LangChain-compatible retrievers
- `RAGPolicy` — declarative allow/deny list, rate limiting, content policy config
- `RateLimiter` — pure-Python sliding-window per-agent rate limiter
- `ContentScanner` — PII and prompt-injection detection on retrieved chunks
- `AuditLogger` — structured JSON-lines audit logging (file or stdout)
- Custom exceptions: `CollectionDeniedError`, `RateLimitExceededError`, `ContentScanError`

# Changelog

## 0.1.0 (2026-05-05)

Initial release.

- `RAGGovernor` — governance wrapper for LangChain-compatible retrievers
- `RAGPolicy` — declarative allow/deny list, rate limiting, content policy config
- `RateLimiter` — pure-Python sliding-window per-agent rate limiter
- `ContentScanner` — PII and prompt-injection detection on retrieved chunks
- `AuditLogger` — structured JSON-lines audit logging (file or stdout)
- Custom exceptions: `CollectionDeniedError`, `RateLimitExceededError`, `ContentScanError`

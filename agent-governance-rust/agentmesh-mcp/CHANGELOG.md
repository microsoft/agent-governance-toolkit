# Changelog

All notable changes to the `agentmesh-mcp` crate will be documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Fixed: MCP signature field reframing (#4199)**: `McpMessageSigner` now
  signs the shared agent-os MCP message v2 JSON array canonical encoding
  instead of the ambiguous `{timestamp_secs}:{nonce}:{payload}` colon join.
  A nonce or payload containing `:` no longer merges distinct field tuples
  into one identical HMAC input. Timestamps are microsecond UTC, an absent
  sender is JSON `null` and distinct from an empty string, and signatures
  use standard padded base64, matching the Python agent-os signer (#4132).

### Changed
- **Breaking**: `McpSignedMessage.timestamp_secs` is now `timestamp_us` and
  the struct gains `sender_id: Option<String>`; `McpMessageSigner::sign`
  takes `sender_id: Option<&str>`. Envelopes signed with the previous Rust
  format fail verification with no legacy fallback. Python and Rust peers
  must upgrade together. See `docs/security/canonical-signing-v2.md` for the
  shared specification and cross-SDK test vectors.

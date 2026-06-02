# Rust AES-GCM Credential Vault Dependency

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.toml` adds direct workspace dependency `aes-gcm = "=0.10.3"`.
- `agent-governance-rust/agentmesh/Cargo.toml` adds `aes-gcm.workspace = true` for the `agentmesh` crate.
- `agent-governance-rust/Cargo.lock` updates to include `aes-gcm` and its small cryptographic support dependency set selected by Cargo.
- The dependency is required for the Rust credential vault port in issue #2535 so credentials can be encrypted at rest with AES-256-GCM.

## Security Advisory Relevance

- `aes-gcm 0.10.3` is an established RustCrypto crate and is pinned exactly per the repository supply-chain policy.
- No CVE or RustSec advisory was identified for this dependency addition during local review.
- The implementation uses randomized 12-byte nonces generated per write and relies on the crate's AEAD API rather than custom encryption primitives.

## Breaking Change Risk Assessment

- Risk is low and scoped to the new `agentmesh::credential_vault` module.
- Existing Rust public APIs are unchanged except for adding a new module export.
- Validation performed locally: `cargo build -p agentmesh`, `cargo clippy -p agentmesh --lib --tests -- -D warnings`, and `cargo test -p agentmesh --test credential_vault` all passed.

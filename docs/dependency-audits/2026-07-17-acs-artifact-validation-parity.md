---
title: ACS artifact validation parity dependency audit
last_reviewed: 2026-07-17
owner: agent-governance
---

# ACS artifact validation parity dependency audit

## Which dependencies changed and why

The ACS SDK packages move from `0.3.1-beta.0` to `0.3.1-beta.1` so the same
artifact-validation contract can ship through Rust, Python, Node, and .NET.
The Node lockfile updates the ten first-party native and OPA optional package
pins to the matching `0.3.1-beta.1` release.

The Rust core moves its existing `jsonschema` crate from test-only use to the
OPA feature. This lets the shared core validate the canonical manifest schema
once rather than reimplementing schema behavior in each language SDK. No new
third-party package name is introduced.

The npm install-script scanner now recognizes exact-version first-party
packages defined by checked-in `package.json` files. It audits their local
`preinstall`, `install`, and `postinstall` fields instead of failing on the
expected registry 404 before coordinated packages are published.

## Security advisory relevance

No CVE-specific remediation is claimed. `jsonschema` was already present in the
committed Rust lockfile and is now used in production code behind the existing
OPA feature.

The Node packages are first-party ACS platform artifacts generated from this
repository. Their checked-in manifests declare no install-time lifecycle
scripts. The scanner continues to query npm and fail closed for packages that
are not defined locally at the exact changed version.

## Breaking change risk assessment

The new validation API is additive across the four SDKs. The shared parity
corpus checks identical validity and diagnostic-code ordering through Rust,
Python, Node, and .NET.

The `acs-generator` package separately moves to `0.4.0b0` because its
implementation-class re-exports are removed. That migration is documented in
`BREAKING_CHANGES.md`. CLI commands remain unchanged.

Release ordering matters for prerelease packages. Publish the Rust core and
platform-specific Node artifacts before the SDK packages that reference their
new exact versions.

# Dependency audit — ACS Node publish support

## Which dependencies changed and why

This PR updates `policy-engine/sdk/node/package-lock.json` to align the ACS
Node SDK lockfile with the native support packages that are now published by
the ESRP release pipeline. The lockfile removes optional dependencies for
musl packages that are not part of the published artifact set in this PR:

- `agent-control-specification-linux-x64-musl`
- `agent-control-specification-linux-arm64-musl`

The published Node runtime support set is now the root
`agent-control-specification` package, glibc Linux native bindings, macOS
native bindings, the Windows x64 MSVC native binding, and the bundled OPA
packages declared in `policy-engine/sdk/node/package.json`.

## Security advisory relevance

No third-party package version is upgraded or downgraded by this lockfile
change. The lockfile only removes optional references to unpublished ACS native
support packages and keeps the existing pinned dependency graph for the Node
SDK build and test toolchain.

No CVE-specific remediation is claimed. The native support packages are built
from the in-repository ACS Rust source during release and are not fetched from
third-party registries during CI.

## Breaking change risk assessment

Risk is low for the published artifact set. The removed musl package entries
were not backed by package manifests or release jobs, so they could not be
published correctly before this change. The PR adds package manifests and ESRP
jobs for the native artifacts that are actually released:

- Linux x64 glibc
- Linux arm64 glibc
- macOS x64
- macOS arm64
- Windows x64 MSVC

Hosts on unsupported musl Linux environments still need a future musl native
package matrix or must build from source. The change avoids advertising musl
optional packages that the release flow does not produce.

# Dependency audit: ACS Node lockfile sync

## Which dependencies changed and why

This PR updates `policy-engine/sdk/node/package-lock.json` to match the
optional native packages already declared in
`policy-engine/sdk/node/package.json`. `npm ci` failed in
`policy-engine-ci / Node SDK` because npm requires each optional dependency
declared by the root package to have a corresponding lockfile package entry.

The lockfile now records registry metadata for these first-party ACS packages:

| Package | Version | Reason |
|---|---:|---|
| `agent-control-specification-darwin-arm64` | `0.3.1-beta.0` | macOS arm64 native binding already declared as optional |
| `agent-control-specification-darwin-x64` | `0.3.1-beta.0` | macOS x64 native binding already declared as optional |
| `agent-control-specification-linux-arm64-gnu` | `0.3.1-beta.0` | Linux arm64 glibc native binding already declared as optional |
| `agent-control-specification-linux-x64-gnu` | `0.3.1-beta.0` | Linux x64 glibc native binding already declared as optional |
| `agent-control-specification-win32-x64-msvc` | `0.3.1-beta.0` | Windows x64 MSVC native binding already declared as optional |
| `agent-control-specification-opa-darwin-arm64` | `0.3.1-beta.0` | macOS arm64 OPA companion package already declared as optional |
| `agent-control-specification-opa-darwin-x64` | `0.3.1-beta.0` | macOS x64 OPA companion package already declared as optional |
| `agent-control-specification-opa-linux-arm64` | `0.3.1-beta.0` | Linux arm64 OPA companion package already declared as optional |
| `agent-control-specification-opa-linux-x64` | `0.3.1-beta.0` | Linux x64 OPA companion package already declared as optional |
| `agent-control-specification-opa-win32-x64` | `0.3.1-beta.0` | Windows x64 OPA companion package already declared as optional |

No `package.json` dependency intent changed. The lockfile was regenerated with
`npm install --package-lock-only --ignore-scripts --no-audit --no-fund`, then
validated with `npm ci` and `npm test`.

## Security advisory relevance

No CVE-specific remediation is claimed. The changed entries are first-party ACS
native and OPA companion packages for the same `0.3.1-beta.0` release already
declared in the root Node package.

The entries are new to the lockfile because the native packages were published
after the optional dependency declarations landed. The usual release-age risk is
lower here than for an arbitrary third-party dependency because these packages
are part of the ACS artifact set produced by this repository's release flow and
must match the root package version exactly.

## Breaking change risk assessment

Risk is low. The change does not alter source code, exported APIs, scripts, or
declared dependencies. It only records the resolved tarballs, integrity hashes,
license metadata, and OS/CPU constraints that `npm ci` requires for packages
already listed under `optionalDependencies`.

The runtime selection behavior remains unchanged. npm will still install only
the optional native and OPA packages compatible with the host platform.

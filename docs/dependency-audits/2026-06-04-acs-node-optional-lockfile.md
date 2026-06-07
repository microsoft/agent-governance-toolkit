# Dependency audit - ACS Node optional lockfile entries

## Which dependencies changed and why

This PR updates `policy-engine/sdk/node/package-lock.json` so it matches the
optional native and OPA support packages declared in
`policy-engine/sdk/node/package.json`.

The package versions did not change. The lockfile now includes package entries
for the existing `0.3.1-beta.0` optional dependencies:

- `agent-control-specification-darwin-arm64`
- `agent-control-specification-darwin-x64`
- `agent-control-specification-linux-arm64-gnu`
- `agent-control-specification-linux-x64-gnu`
- `agent-control-specification-opa-darwin-arm64`
- `agent-control-specification-opa-darwin-x64`
- `agent-control-specification-opa-linux-arm64`
- `agent-control-specification-opa-linux-x64`
- `agent-control-specification-opa-win32-x64`
- `agent-control-specification-win32-x64-msvc`

The change is required because `npm ci` fails when optional dependencies are
declared in `package.json` but missing from `package-lock.json`.

## Security advisory relevance

No third-party package version is upgraded or downgraded by this lockfile
change. The added entries are first-party ACS support packages at the same
version as the root `agent-control-specification` package.

No CVE-specific remediation is claimed. The native and OPA support packages are
published as part of the ACS release flow and are not new external package
families.

## Breaking change risk assessment

Risk is low. The lockfile change makes clean installs deterministic for the
already-declared optional support package set and does not change runtime API
behavior.

The practical compatibility effect is positive: CI and package consumers using
`npm ci` can install the Node SDK from a lockfile that is synchronized with the
package manifest.

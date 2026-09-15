---
title: "Dependency audit: @hono/node-server 1.19.14 -> 2.1.1 in mcp-proxy and mcp-server"
last_reviewed: 2026-09-15
owner: agt-maintainers
---

# 2026-09-15 - @hono/node-server 1.19.14 -> 2.1.1 in mcp-proxy and mcp-server

Supersedes Dependabot PRs #3723 (mcp-proxy) and #3724 (mcp-server). A
major bump is not exempt from the audit-trail gate, and Dependabot cannot
author this document, so both lockfile changes land here together with it.

## Which dependencies changed and why

| Package | Lockfile | From | To |
|---|---|---|---|
| `@hono/node-server` | `agent-governance-python/agent-mesh/packages/mcp-proxy/package-lock.json` | 1.19.14 | 2.1.1 |
| `@hono/node-server` | `agent-governance-python/agent-os/extensions/mcp-server/package-lock.json` | 1.19.14 | 2.1.1 |

Each lockfile changes in one entry: `version`, `resolved`, `integrity`, and
`engines.node` (`>=18.14.1` -> `>=20`). Neither `package.json` changes.

In both packages `@hono/node-server` is transitive. Neither declares it;
it arrives through `@modelcontextprotocol/sdk` 1.30.0, whose range is
`"^1.19.9 || ^2.0.5"`. The hono core package stays at 4.13.7 in both
lockfiles.

Reasons for taking the bump:

- 1.19.14 sits in the affected range of GHSA-frvp-7c67-39w9 (see below);
  2.1.1 is fixed.
- The SDK already accepts 2.x, so the lockfile follows the SDK's
  declared range and matches what a fresh `npm install` resolves.

## Provenance and version

`@hono/node-server` is published from https://github.com/honojs/node-server
under the MIT license. 2.1.1 was released on 2026-08-14, 32 days before
this change, which clears the 7-day cooling-off rule.
`scripts/check_lockfile_integrity.py --base origin/main` verified both new
`integrity` hashes against the npm registry (2 entries checked, all match).
`scripts/check_install_scripts.py --base origin/main --strict` confirmed
2.1.1 declares no install-time scripts.

## Breaking change risk assessment

Risk: low. The 2.0.0 release notes list two breaking changes and state
that the public API is otherwise unchanged:

1. Node.js 18 support dropped; 2.x requires Node.js 20 or later.
2. The Vercel adapter (`@hono/node-server/vercel`) removed.

How each applies here:

- Neither package's source imports `@hono/node-server` or `hono`
  (`grep -ri 'hono\|vercel'` over each package outside `node_modules`
  returns nothing). Inside `@modelcontextprotocol/sdk` 1.30.0 only
  `server/streamableHttp.js` (and an example file) import it, and they
  call `getRequestListener` only. The SDK `dist` contains no reference
  to the Vercel adapter.
- mcp-proxy: no source file imports the SDK at all. The proxy spawns the
  wrapped MCP server as a child process and relays stdio. Loading
  `dist/index.js` under Node loads neither the SDK nor any hono module.
- mcp-server: imports `@modelcontextprotocol/sdk/server/index.js`,
  `server/stdio.js` and `types.js`. Loading `dist/index.js` plus those
  three modules loads no hono module; `server/streamableHttp.js` is not
  loaded.
- Node.js floor: both `package.json` files declare `engines.node
  ">=18.0.0"`. CI builds and tests both packages on Node 20 and 22. On
  Node 18 (end of life since 2025-04-30) `npm install` prints an
  `EBADENGINE` warning for the transitive package; nothing loads it at
  runtime, so behavior does not change. Raising the packages' own
  `engines` floor to 20 is left for a separate change.

## Security advisory relevance

GitHub Advisory Database, queried 2026-09-15 for `@hono/node-server`:

| Advisory | CVE | Affected | Fixed in | Status after this change |
|---|---|---|---|---|
| GHSA-frvp-7c67-39w9 | none | `<1.19.15`, `>=2.0.0 <2.0.5` | 1.19.15 / 2.0.5 | Fixed. 1.19.14 was affected. Path traversal in `serve-static` on Windows via encoded backslash. Neither package uses `serve-static`. |
| GHSA-9mqv-5hh9-4cgg | CVE-2026-73565 | `>=2.0.0 <=2.0.9` | 2.0.10 | Fixed. Memory-leak DoS via aborted WebSocket handshake in `upgradeWebSocket`. Not used here. |
| GHSA-92pp-h63x-v22m | CVE-2026-39406 | `<1.19.13` | 1.19.13 | Already fixed in 1.19.14; stays fixed. |
| GHSA-wc8c-qw6v-h7f6 | CVE-2026-29087 | `<1.19.10` | 1.19.10 | Already fixed in 1.19.14; stays fixed. |
| GHSA-hgxw-5xg3-69jx | CVE-2024-32652 | `>=1.3.0 <1.10.1` | 1.10.1 | Already fixed; stays fixed. |
| GHSA-rjq5-w47x-x359 | CVE-2024-23340 | `>=1.3.0 <1.4.1` | 1.4.1 | Already fixed; stays fixed. |

`npm audit` after the bump reports no finding for `@hono/node-server` or
`hono` in either package. The findings it does report (mcp-proxy:
body-parser, brace-expansion, js-yaml, nanoid; mcp-server:
brace-expansion, nanoid) predate this change and are out of its scope.

## Tests run

Node 22.22.3, npm 11.14.1.

- mcp-proxy: `npm ci --ignore-scripts`, `npm run build` (tsc, clean),
  `npm test` (vitest): 1 file, 5 tests passed.
- mcp-server: `npm ci --ignore-scripts --legacy-peer-deps`, the flag CI
  uses. Plain `npm ci` fails on `origin/main` too, because
  `@vitest/coverage-v8` 4.1.10 pins peer `vitest` 4.1.10 while the
  package pins `vitest` 4.1.11; this predates the bump. `npm run build`
  (tsc, clean); `npm test` (vitest `--passWithNoTests`): no test files,
  exit 0.
- Runtime load probes described above, run against the built `dist` of
  each package.
- Supply-chain gates against `origin/main`: `check_lockfile_integrity.py`
  (2 entries OK), `check_install_scripts.py --strict` (OK),
  `check_release_age.py --min-age-days 7` (no exact-pinned manifest
  changes to check), `check_build_hooks.py --strict` (OK),
  `check_dependency_confusion.py --strict` (exit 0).

## Rollback plan

Revert both `package-lock.json` files to the prior commit. No other file
depends on this change.

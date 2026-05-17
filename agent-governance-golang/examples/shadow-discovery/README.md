# Shadow Discovery

Exercises the three caller-driven entry points on `ShadowDiscoveryScanner`:

- **`ScanText`** — pattern hits in an arbitrary content blob.
- **`ScanProcessCommands`** — scan supplied command lines (no need to
  shell out to `ps`).
- **`ScanConfigPaths`** — walk a real directory tree. The example builds
  a small fixture in a temp dir so it's fully self-contained and CI-safe.

Covers [`discovery.go`](../../packages/agentmesh/discovery.go):
`NewShadowDiscoveryScanner`, `ScanText`, `ScanProcessCommands`,
`ScanConfigPaths`, and the `DiscoveryFinding` / `DiscoveryScanResult` /
`DiscoveredAgent` types.

Not demonstrated: `ScanCurrentHostProcessList` (shells out to
`ps -axo`/`Get-CimInstance`) and `ScanGitHubRepositories` (needs a token).
Both are documented in [the SDK README](../../README.md).

## Run it

```bash
go run .
```

## Expected output

```text
ScanText: 2 findings
  [framework/medium] inline.py:1 import langchain
  [credential/high] inline.py:2 OPENAI_[REDACTED]

ScanProcessCommands: 2 findings
  [framework/medium] process[0] /usr/bin/python -m crewai.run
  [protocol/medium] process[1] node /opt/agent/mcp-server.js

ScanConfigPaths: scanner=config scanned=1 agents=5 errors=0
  mcp-server agent at mcp.json    type=mcp-server confidence=0.85 evidence=1
  mcp-server signal in mcp.json   type=mcp-server confidence=0.85 evidence=1
  agt signal in agentmesh.yaml    type=agt        confidence=0.90 evidence=1
  agt agent at agentmesh.yaml     type=agt        confidence=0.95 evidence=1
  langchain signal in src/handler.py type=langchain confidence=0.80 evidence=1
```

`ScanConfigPaths` records each match as its own `DiscoveredAgent`,
so a single config file matching both the *config-name* pattern and
a *content* rule appears twice with different evidence — that's how
the fingerprinting groups by `(scanner, source)` rather than by file.
Agent ordering is by fingerprint, so the exact row order can vary
between runs.

## Where to go next

- [`mcp-scan/`](../mcp-scan/) — once you've discovered an MCP server,
  scan its tool inventory for poisoning and typosquatting.
- [`http-middleware-fail-closed/`](../http-middleware-fail-closed/) —
  bring a freshly discovered shadow agent under verified governance.
- [`../README.md`](../../README.md) — full SDK overview.

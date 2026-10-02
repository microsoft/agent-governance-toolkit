---
title: "Tutorial 27 — MCP Scan CLI"
last_reviewed: 2026-09-18
owner: agt-maintainers
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 27 — MCP Scan CLI

Use `mcp-scan` to inspect MCP (Model Context Protocol) server configs, enumerate
advertised tools, resources, resource templates, and prompts across stdio,
Streamable HTTP, and legacy HTTP+SSE transports, and scan the discovered
metadata with AGT's `MCPSecurityScanner`. The scanner checks
MCP primitive metadata before an agent relies on it: hidden instructions, description
injection, schema abuse, cross-server impersonation, and rug-pull fingerprint
drift.

`mcp-scan` is local-first governance before adoption. In the current main-branch implementation, Streamable HTTP
live inspection first attempts the scanner's stateless `2026-07-28` flow:
`server/discover` followed by self-contained primitive-list requests carrying
client metadata in `_meta`. If a peer rejects or cannot validate stateless
discovery, the scanner falls back on the same endpoint to the legacy
`2025-11-25` `initialize` / `notifications/initialized` lifecycle. Stdio
and legacy HTTP+SSE inspection still use the legacy lifecycle today. Live stdio
scans launch configured local commands; live HTTP and SSE scans connect to
configured endpoints. For pull requests, staged commits, downloaded configs, or
any other untrusted input, use `--static-only` so the CLI does not launch
commands or connect to remote endpoints.

> **Package:** `agent-os-kernel`
> **CLI:** `mcp-scan`
> **Scanner:** `agent_os.mcp_security.MCPSecurityScanner`
> **Runtime model:** deterministic inspection and policy evidence, not a prompt-only guardrail
>
> **Release note:** the stateless dual-stack Streamable HTTP flow landed on `main` after the 5.0.0 release and is not yet present in the currently published `agent-os-kernel` / `agent-governance-toolkit-core` packages.

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Install](#install) | Install the package and verify the CLI |
| [Scan a config](#scan-a-config) | Enumerate MCP primitives and scan metadata |
| [MCP lifecycle and transports](#mcp-dual-stack-lifecycle-and-transports) | Protocol lifecycle and transport coverage |
| [Live vs static scans](#live-transport-scans-vs-static-scans) | When commands or network connections happen |
| [Fingerprinting](#fingerprinting-for-rug-pull-detection) | Detect primitive metadata drift |
| [Reports and CI](#reports-and-ci) | JSON, Markdown, OWASP MCP review evidence, and exit codes |
| [MCP Inspector](#cross-check-with-mcp-inspector) | Use the official Inspector for interactive debugging |
| [Python API](#python-api) | Use the scanner directly |

---

## Install

```bash
pip install agent-os-kernel

# Verify installation
mcp-scan --help
```

For development from this repository:

```bash
cd agent-governance-python/agent-os
pip install -e "../agent-primitives"
pip install -e ".[dev]"
mcp-scan --help
```

`mcp-scan` is also importable as a Python module:

```bash
python -m agent_os.cli.mcp_scan --help
```

---

## Threat landscape

MCP tool, resource, resource template, and prompt definitions are agent-facing instructions. An agent may use the tool
name, description, and schema to decide what to call and what arguments to pass.
A malicious or compromised MCP server can therefore attack through metadata even
before a tool call executes.

| Threat type | What `mcp-scan` checks |
|-------------|------------------------|
| Tool poisoning | Instruction-like metadata and suspicious schema defaults |
| Hidden instruction | Invisible Unicode, HTML comments, Markdown comments, encoded payloads |
| Description injection | Prompt-injection patterns in descriptions |
| Schema abuse / confused deputy | Overly permissive schemas and suspicious required fields |
| Cross-server attack | Duplicate or typosquatted scanner-visible primitive names across scanned servers |
| Rug pull | Description/schema drift from a stored fingerprint baseline |

The scanner uses the existing AGT code in
`agent-governance-python/agent-os/src/agent_os/mcp_security.py` rather than a
separate CLI-only detection engine.

---

## MCP dual-stack lifecycle and transports

For **Streamable HTTP**, the current main-branch `mcp-scan` implementation first attempts a stateless
`2026-07-28` path and keeps `2025-11-25` as a compatibility fallback. The steps below describe what the scanner currently sends and expects; they are not a statement of the released MCP specification's wire requirements.

The scanner's preferred Streamable HTTP flow is:

1. The scanner sends `server/discover` with client metadata in `_meta` and sends `Mcp-Name` on that request.
2. The scanner validates the discovery result and expects
   `protocolVersion: "2026-07-28"` before entering stateless operation. The validator also requires at least one inspectable primitive capability (`tools`, `resources`, or `prompts`), and treats returned server metadata as scan evidence rather than scanner instructions.
3. The scanner enumerates advertised primitive definitions with `tools/list`,
   `resources/list`, `resources/templates/list`, and `prompts/list`,
   following `nextCursor` pagination when present.
4. The scanner sends each stateless request with client metadata in `_meta` and
   `Mcp-Protocol-Version: 2026-07-28`. Streamable HTTP requests also carry
   `Mcp-Method`.
5. The scanner does **not** send or retain `Mcp-Session-Id` in this stateless flow.

If the peer rejects stateless discovery at the HTTP layer, returns an error, or
returns a discovery result that does not validate, the scanner falls back to
the legacy flow on the same Streamable HTTP endpoint:

1. Send `initialize` with `protocolVersion: "2025-11-25"`, client
   capabilities, and client info.
2. Validate the negotiated protocol version, advertised capabilities, and
   `serverInfo`. The shared validator requires at least one inspectable primitive capability (`tools`, `resources`, or `prompts`) and treats server metadata as scan evidence rather than scanner instructions. Accepted versions are `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `2026-07-28`; versions older than `2025-11-25` produce a warning.
3. Send `notifications/initialized`.
4. Enumerate the same advertised primitive definitions. If the server issues
   `Mcp-Session-Id`, the scanner carries it only on this legacy compatibility
   path.

Transport behavior:

| Transport | Live scan behavior | Protocol behavior |
|-----------|--------------------|-------------------|
| stdio | Launches the configured command and exchanges newline-delimited JSON-RPC over stdin/stdout | Currently uses the legacy `initialize` lifecycle |
| Streamable HTTP | Sends JSON-RPC POST requests and accepts `application/json` or `text/event-stream` responses | Current `main` first attempts the scanner's stateless `2026-07-28` flow; falls back to legacy `2025-11-25` |
| legacy HTTP+SSE | Opens an SSE stream, receives the message endpoint, and POSTs JSON-RPC requests there | Legacy compatibility path |
| static-only | Scans inline `tools` arrays and validates launch/endpoint metadata already present in the config | No MCP connection or lifecycle messages are sent |

The scan is metadata-only: live inspection uses discovery and listing calls. It
does not call tools, read resources, or render prompts by default.

> **AGT session helpers are not MCP protocol sessions.** Components such as
> `MCPSessionAuthenticator` and `MCPSessionStore` can still maintain
> application-level authentication or state handles for AGT. They are not
> required transport-session semantics in the MCP `2026-07-28` stateless
> flow.

---

## Scan a config

A typical Claude Desktop config contains stdio server launch definitions:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

A Streamable HTTP server can be scanned when it is already running:

```json
{
  "servers": {
    "docs-remote": {
      "type": "streamable-http",
      "url": "https://mcp.example.com/mcp",
      "headers": {"Authorization": "Bearer ${MCP_TOKEN}"}
    }
  }
}
```

A legacy HTTP+SSE server can be scanned for compatibility:

```json
{
  "servers": {
    "legacy-remote": {"type": "sse", "url": "https://mcp.example.com/sse"}
  }
}
```

Run:

```bash
mcp-scan scan ~/.config/Claude/claude_desktop_config.json
```

What happens:

1. The config file is parsed.
2. Static launch and endpoint-risk checks run over command, args, env keys, URLs,
   and headers.
3. For stdio, each local MCP server is launched with `subprocess` without
   `shell=True`. The child receives a minimal sanitized environment plus explicit
   `env` values from the server config, not the operator's full parent
   environment.
4. For Streamable HTTP, the CLI first probes `server/discover` using MCP
   `2026-07-28`. A valid stateless peer is inspected with self-contained
   listing requests carrying client metadata in `_meta`; no
   `Mcp-Session-Id` is used.
5. If Streamable HTTP stateless discovery is rejected or invalid, the CLI falls
   back on the same endpoint to the legacy `2025-11-25` `initialize` flow.
6. For stdio and legacy HTTP+SSE, the CLI uses the legacy lifecycle and sends
   the advertised listing calls for tools, resources, resource templates, and
   prompts.
7. Discovered primitive metadata is normalized into scanner-visible definitions and passed to `MCPSecurityScanner.scan_server()`.
8. The transport is closed after inspection.

Example clean output:

```text
MCP Security Scan Results
=========================

Server: file-server
  OK  read_file — no threats
  OK  write_file — no threats

Summary: 2 primitives scanned, 0 warnings, 0 critical — No threats detected
```

Example findings output:

```text
MCP Security Scan Results
=========================

Server: suspicious-server
  !!  admin_tool — 3 critical threat(s)
      CRITICAL: Hidden comment detected in tool description
      CRITICAL: Instruction-like pattern in tool description: ignore\s+(all\s+)?previous
      CRITICAL: Data exfiltration pattern in description: https?://

Summary: 1 primitive scanned, 0 warnings, 3 critical
```

---

## Live transport scans vs static scans

By default, `mcp-scan scan` performs live inspection. Live inspection has side
effects:

- stdio: launches configured local commands.
- Streamable HTTP / SSE: connects to configured network endpoints.
- live transports: sends the lifecycle supported by that transport plus advertised primitive listing messages.

Use live mode only for trusted configs and trusted endpoints. For stdio, launching a configured server is local code execution: the
scanner avoids `shell=True` and passes only a sanitized child environment, but
that is not a sandbox. For HTTP transports, prefer HTTPS and authenticated endpoints; the scanner sends metadata-only MCP
requests and does not call tools, read resources, or render prompts by default.

Use `--static-only` when you want to avoid launching configured commands or
connecting to configured endpoints:

```bash
mcp-scan scan mcp-config.json --static-only
```

Static mode scans only inline `tools` arrays plus launch and endpoint metadata
already present in the file. It cannot discover live server primitives, but
it is safe for pull-request review because it neither launches configured commands nor connects to configured endpoints, and it is the right mode for untrusted pull-request, CI, or pre-commit configs.

Supported config shapes include `mcpServers` and `servers` entries with `stdio`,
`streamable-http`/`http`, or `sse` transports. Streamable HTTP is the preferred
HTTP transport and, in the current `main` implementation, is dual-stack: the scanner's stateless `2026-07-28` flow is attempted
first, with `2025-11-25` retained as compatibility. Legacy HTTP+SSE is
supported only for older servers and is reported distinctly in JSON inspection
metadata.

---

## Output formats

### JSON

```bash
mcp-scan scan mcp-config.json --format json
```

Some JSON fields and scanner APIs retain historical `tool_*` names because
`MCPSecurityScanner` is tool-shaped internally. In `mcp-scan` output these
aliases may refer to normalized MCP primitives, including resources, resource
templates, and prompts.

```json
{
  "servers": {
    "suspicious-server": {
      "safe": false,
      "primitives_scanned": 1,
      "primitives_flagged": 1,
      "tools_scanned": 1,
      "tools_flagged": 1,
      "threats": [
        {
          "threat_type": "hidden_instruction",
          "severity": "critical",
          "tool_name": "admin_tool",
          "server_name": "suspicious-server",
          "message": "Hidden comment detected in primitive metadata",
          "matched_pattern": "<!--.*?-->",
          "details": {}
        }
      ]
    }
  },
  "summary": {
    "servers_scanned": 1,
    "primitives_scanned": 1,
    "primitives_flagged": 1,
    "tools_scanned": 1,
    "tools_flagged": 1,
    "warnings": 0,
    "critical": 1
  },
  "config_findings": [],
  "inspection_errors": [],
  "inspections": {
    "suspicious-server": {
      "ok": true,
      "transport": "streamable-http",
      "protocol_version": "2026-07-28",
      "tools_discovered": 1,
      "resources_discovered": 0,
      "resource_templates_discovered": 0,
      "prompts_discovered": 0,
      "primitives_discovered": 1,
      "error": null
    }
  }
}
```

### Markdown

```bash
mcp-scan scan mcp-config.json --format markdown
```

### Filtering

```bash
# Scan one server
mcp-scan scan mcp-config.json --server filesystem

# Show only critical threats
mcp-scan scan mcp-config.json --severity critical

# Set a shorter per-request MCP timeout
mcp-scan scan mcp-config.json --timeout 3
```

---

## Fingerprinting for rug-pull detection

Fingerprinting stores a SHA-256 baseline for each discovered primitive's normalized description
and schema. This catches primitive metadata drift between trusted setup time
and later runs. Baseline creation uses live inspection by default, so create
baselines only from trusted configs/endpoints or add `--static-only` for inline-only
configs you do not want to execute or connect to. If live inspection fails,
`mcp-scan fingerprint --output ...` exits with code `2` and refuses to save a
partial baseline.

Create a baseline:

```bash
mcp-scan fingerprint mcp-config.json --output fingerprints.json
```

Example baseline shape:

```json
{
  "file-server::read_file": {
    "tool_name": "read_file",
    "server_name": "file-server",
    "description_hash": "...",
    "schema_hash": "..."
  }
}
```

Compare a later run:

```bash
mcp-scan fingerprint mcp-config.json --compare fingerprints.json
```

No changes:

```text
No changes
```

Changes:

```text
Tool definition changes detected:
  file-server::read_file: description
  file-server::write_file: schema
  web-tools::new_search: new_tool:new_search, new_search
  web-tools::old_search: removed
```

---

## Reports and CI

Generate Markdown:

```bash
mcp-scan report mcp-config.json --format markdown > mcp-owasp-mcp-top10-report.md
```

`mcp-scan report` is evidence for MCP security review, not a certification. A
complete review package should include report scope, lifecycle evidence,
transport coverage, primitive metadata findings, limitations, reviewer-owned OWASP MCP Top 10
interpretation, and separate `mcp-scan fingerprint --compare` output when
evaluating rug-pull drift.

Generate JSON:

```bash
mcp-scan report mcp-config.json --format json > mcp-security-report.json
```

Exit codes:

| Exit code | Meaning |
|-----------|---------|
| `0` | Command succeeded, no critical scan/config/inspection findings, and no fingerprint drift |
| `1` | Config, usage, or file error |
| `2` | Critical primitive metadata findings, critical config findings, live inspection failures, or fingerprint drift detected |

For untrusted repository content, keep CI static-only. A live CI scan is
appropriate only in a protected job where the config has already been reviewed
and is trusted to execute on the runner.

GitHub Actions example:

```yaml
name: MCP Security Scan
on:
  pull_request:
    paths:
      - '**/mcp.json'
      - '**/mcp-config.json'
      - '**/claude_desktop_config.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install agent-os-kernel
      - name: Scan MCP configuration
        run: mcp-scan scan mcp-config.json --format json --static-only
      - name: Check MCP primitive fingerprints
        run: |
          if [ -f fingerprints.json ]; then
            mcp-scan fingerprint mcp-config.json --compare fingerprints.json --static-only
          fi
```

Pre-commit example:

```bash
#!/bin/bash
mcp_configs=$(git diff --cached --name-only | grep -E '(mcp-config|mcp|claude_desktop_config)\.json$')

if [ -n "$mcp_configs" ]; then
  for config in $mcp_configs; do
    echo "Scanning MCP config: $config"
    if ! mcp-scan scan "$config" --severity critical --static-only; then
      echo "MCP scan failed or reported critical findings in $config — commit blocked"
      exit 1
    fi
  done
fi
```

---

## Cross-check with MCP Inspector

Use the official MCP Inspector to debug connectivity, lifecycle negotiation, and
primitive metadata before or after running `mcp-scan`:

```bash
npx -y @modelcontextprotocol/inspector <command> <arg1> <arg2>
```

The Inspector is useful for interactive development: it shows tools, resources,
prompts, notifications, and transport connection state. It is not a replacement
for `mcp-scan` security reporting because it does not produce AGT scanner
findings, fingerprint drift evidence, or reviewer-owned OWASP MCP Top 10 interpretation.

---

## Python API

Use the detection engine directly when your application already has normalized MCP
metadata:

```python
from agent_os.mcp_security import MCPSecurityScanner

scanner = MCPSecurityScanner()
result = scanner.scan_server("web-tools", [
    {
        "name": "search",
        "description": "Search the web",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    }
])

print(result.safe)
for threat in result.threats:
    print(threat.severity.value, threat.tool_name, threat.message)
```

---

## Source files

| Component | Location |
|-----------|----------|
| MCP scan CLI | `agent-governance-python/agent-os/src/agent_os/cli/mcp_scan.py` |
| MCP security scanner | `agent-governance-python/agent-os/src/agent_os/mcp_security.py` |
| MCP scan CLI tests | `agent-governance-python/agent-os/tests/test_mcp_scan_cli.py` |
| MCP gateway (runtime enforcement) | `agent-governance-python/agent-os/src/agent_os/mcp_gateway.py` |

---

## Sanitized child environment

When `mcp-scan` launches a stdio MCP server, it does **not** pass the operator's
full environment to the child process. The child receives only:

| Variable | Source |
|----------|--------|
| `PATH` | Inherited from parent |
| `SYSTEMROOT` | Inherited from parent (Windows only) |
| Server-specific `env` keys except command-loading overrides | From the MCP config `env` object |

This prevents accidental credential leakage (tokens, cloud keys, secrets in
`$HOME/.bashrc`) to untrusted MCP servers. Launch-policy validation in both live
and `--static-only` modes also blocks config-provided environment overrides
that hijack child execution:

- **Loader / PATH hijack**: `PATH`, `PATHEXT`, `PYTHONPATH`, `PYTHONHOME`,
  `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`
- **Runtime startup hooks**: `DOTNET_STARTUP_HOOKS`, `JAVA_TOOL_OPTIONS`,
  `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `RUBYOPT`, `BASH_ENV`, `ENV`,
  `PERL5OPT`, `PERL5LIB`
- **User-config-file hijack** (child reads attacker-controlled rc files):
  `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `XDG_CONFIG_HOME`,
  `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `ZDOTDIR`, `PSMODULEPATH`, `COMSPEC`
- **Tool-specific config/index redirects**: `UV_*`, `NPM_CONFIG_*`, `PIP_*`,
  `POETRY_*`, `GEM_*`, `GIT_*`

The launch resolver only honors **absolute, non-UNC** entries in the host
`PATH`, so relative entries like `.` or `bin` cannot let a repo-local binary
shadow the trusted host runtime. Config-provided server `cwd` values are also
rejected in live mode (use `--allow-untrusted-cwd` to opt in when you trust the
config source), because the child runtime loads config files like
`./package.json` (`preinstall`), `./nuget.config`, and `./sitecustomize.py`
relative to that directory.

A bare allowlisted command name is required unless you opt in with
`--allow-commands`. **The allowlist only gates which interpreter runs**; it does
not validate args. For example, `python -c "..."`, `node -e "..."`, or
`docker run -v /:/host evil` remain full code execution. Treat any MCP config
from an untrusted source as untrusted in full.

If a server needs additional environment variables, declare them explicitly in
the config (excluding the categories above):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": "${MCP_API_KEY}"
      }
    }
  }
}
```

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Timed out waiting for initialize response` | A stdio server does not answer the initialization request in time | Verify the server works with the official MCP Inspector; increase `--timeout` |
| `Timed out waiting for Streamable HTTP SSE response id N` | A Streamable HTTP SSE response does not arrive before the request timeout | Verify endpoint responsiveness and authentication; increase `--timeout` |
| `Timed out waiting for SSE response id N` | A legacy HTTP+SSE response does not arrive before the request timeout | Verify the SSE endpoint and message endpoint; increase `--timeout` |
| `timed out` | The underlying HTTP request timed out before a protocol-specific response was received | Verify network reachability and endpoint responsiveness; increase `--timeout` |
| `Server exited before responding` | Command not found, crash on startup, or missing runtime dependency | Run the command manually to check stderr output |
| `Server args contain unresolved variables` | Config uses `${VAR}` placeholders without matching environment values | Set the variables in your shell or use `--static-only` to skip live inspection |
| `HTTP Error 401: Unauthorized` | Remote server requires authentication headers | Add `"headers": {"Authorization": "Bearer <token>"}` to the server config |
| `HTTP Error 404: Not Found` | Incorrect MCP endpoint URL | Verify the URL points to the MCP JSON-RPC endpoint (not a docs page) |
| `Connection refused` | Remote server is not running or blocked by firewall | Confirm the server is reachable with `curl` before scanning |

### Windows usage

On Windows, scan your Claude Desktop config at:

```powershell
mcp-scan scan "$env:APPDATA\Claude\claude_desktop_config.json"
```

Or use the Python module directly:

```powershell
python -m agent_os.cli.mcp_scan scan "$env:APPDATA\Claude\claude_desktop_config.json" --json
```

---

## Next steps

- Scan your local MCP config:
  - Linux/macOS: `mcp-scan scan ~/.config/Claude/claude_desktop_config.json`
  - Windows: `mcp-scan scan "$env:APPDATA\Claude\claude_desktop_config.json"`
- Store a fingerprint baseline for servers you trust.
- Add `mcp-scan` to CI for repositories that ship MCP configs.
- Validate server behavior interactively with the official MCP Inspector.
- Generate `mcp-scan report` output as evidence for an OWASP MCP Top 10 review.
- Read [Tutorial 07 — MCP Security Gateway](./07-mcp-security-gateway.md) for runtime tool-call filtering and human approval.

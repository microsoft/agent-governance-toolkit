# MCP Tool Scan

Runs the MCP security scanner against four tool definitions: one benign, one
tool-poisoning attempt (prompt-injection text inside a tool description),
one homoglyph attack (Cyrillic `с` impersonating ASCII `c`), and one
typosquatting attempt (`send_emai1` versus the well-known `send_email`).

Covers [`mcp.go`](../../packages/agentmesh/mcp.go):
`NewMcpSecurityScanner`, `Scan`, `ScanAll`, `McpToolDefinition`,
`McpScanResult`, `McpThreatType`.

## Run it

```bash
go run .
```

## Expected output

The exact threat fired per tool depends on the built-in heuristics, but the
shape is:

```text
search       safe=true  risk=0   threats=none
fetch_url    safe=false risk=40  threats=[tool_poisoning/critical: tool description contains prompt injection pattern]
fetсh        safe=false risk=25  threats=[typosquatting/high: tool name is suspiciously similar to known tool]
send_emai1   safe=false risk=25  threats=[typosquatting/high: tool name is suspiciously similar to known tool]
```

The scanner inspects threats in order — `tool_poisoning`,
`typosquatting`, `hidden_instruction`, `rug_pull` — and returns the
first hit. The homoglyph `fetсh` is caught by the typosquatting check
(Cyrillic `с` makes the name Levenshtein-distance-1 from `fetch`)
before the hidden-character check would fire on the description.

`safe=true` means no threats fired; `risk` is the 0–100 aggregate score.

## Where to go next

- [`prompt-defense/`](../prompt-defense/) — scan prompts (rather than tool
  definitions) for instruction-override and exfiltration patterns.
- [`shadow-discovery/`](../shadow-discovery/) — find ungoverned MCP servers
  before scanning their tool inventories.
- [`../README.md`](../../README.md) — full SDK overview.

# Flowise + Agent Governance Toolkit

Enforce AGT governance policies inside any Flowise flow. Because Flowise runs in Node.js and AGT governance logic lives in Python, the integration uses a **lightweight FastAPI sidecar** that Flowise calls over HTTP before each tool invocation.

## Architecture

The included `flowise-flow.json` is a 5-node sequential demo flow (Flowise 2.x / 3.x):

```
[Chat Input]
     |
     v
[Custom Function]  -- builds {"tool": "search_web", "content": <msg>, "agent_id": "flowise-agent"}
     |
     v
[HTTP Request]     -- POST http://localhost:8000/govern
     |
     v
[AGT Governance Sidecar :8000]
     |-- rate limit check  (token bucket per agent/tool)
     |-- policy check      (allowlist, blocklist, content patterns)
     |-- audit log         (hash-chain tamper-evident JSONL)
     |
     v  {"allowed": true/false, "reason": "..."}
[Custom Function]  -- formats response as "[ALLOWED] ..." or "[BLOCKED] ..."
     |
     v
[Chat Output]
```

The demo flow returns the raw governance decision in the chat. To add a full LLM response for allowed requests, wire a ChatOpenAI node between the Format node and Chat Output, and add your OpenAI API key to it.

## Quick Start

### 1. Install and run the governance sidecar

```bash
cd examples/flowise-governance
pip install -r requirements.txt
uvicorn governance_server:app --port 8000
```

Verify it is running:

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

Test an allowed tool call:

```bash
curl -s -X POST http://localhost:8000/govern \
  -H "Content-Type: application/json" \
  -d '{"tool": "search_web", "content": "latest AI news", "agent_id": "flowise-agent"}' | python -m json.tool
```

Test a blocked tool call:

```bash
curl -s -X POST http://localhost:8000/govern \
  -H "Content-Type: application/json" \
  -d '{"tool": "execute_shell", "content": "ls /", "agent_id": "flowise-agent"}' | python -m json.tool
```

### 2. Import the flow into Flowise

1. Open your Flowise instance (2.x or 3.x).
2. Go to **Chatflows** and click **Add New**.
3. Click the **import** icon (top right toolbar) and select `flowise-flow.json` from this directory.
4. The flow loads with five nodes already connected.
5. Click **Save** and then **Deploy**.

### 3. Test the full flow

Send a message through the Flowise chat UI. The flow:

- Builds a governance payload from your message.
- Calls the sidecar at `http://localhost:8000/govern`.
- Routes to the LLM if allowed, or returns a block message if denied.

## Configuration

### Policy

Edit `policy.yaml` to control which tools are permitted.

Key fields:

| Field | Description |
|-------|-------------|
| `allowed_tools` | Patterns (fnmatch) for permitted tool names. Supports `*` wildcards. |
| `blocked_tools` | Always-blocked patterns. Takes priority over `allowed_tools`. |
| `blocked_content_patterns` | Regex patterns matched against the `content` field. |
| `blocked_argument_patterns` | Regex patterns matched against argument values. |
| `default_action` | `deny` (recommended) or `allow` for tools not on any list. |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGT_POLICY_PATH` | `policy.yaml` next to the server script | Path to the YAML policy file |
| `AGT_AUDIT_PATH` | `audit.jsonl` in the working directory | Path for the hash-chain audit log |
| `AGT_MAX_REQUESTS` | `100` | Maximum requests per agent per window |
| `AGT_WINDOW_SECONDS` | `60` | Rate limit window in seconds |

### Request payload

The sidecar accepts:

```json
{
  "tool": "search_web",
  "content": "user message or tool argument string",
  "agent_id": "flowise-agent",
  "arguments": { "key": "value" }
}
```

`content` and `arguments` are optional. `tool` and `agent_id` are required.

### Response

```json
{ "allowed": true,  "reason": null,                     "tool": "search_web",    "agent_id": "flowise-agent" }
{ "allowed": false, "reason": "Tool 'execute_shell' is not allowed by policy", "tool": "execute_shell", "agent_id": "flowise-agent" }
```

## Audit log

Each request is written as a JSONL entry to `audit.jsonl`. Each entry includes:

```json
{
  "index": 0,
  "timestamp": 1718640000.123,
  "data": { "agent_id": "flowise-agent", "tool": "search_web", "decision": "allowed" },
  "previous_hash": "0000...0000",
  "hash": "a3f4..."
}
```

The hash chain gives tamper evidence: any modification to a past entry breaks all subsequent hashes.

## Extending the flow

**Dynamic tool name**: Replace the hardcoded `tool` value in the "Build Payload" node with a variable or LLM extraction step.

**Trust gating**: Add a second call to `/govern` with a `trust_score` field and wire through `TrustGateNode` by extending `governance_server.py`.

**Remote deployment**: Change `http://localhost:8000/govern` in the HTTP Request node to the sidecar's public URL. Protect it with a reverse proxy and API key if exposed to the internet.

## Files

| File | Description |
|------|-------------|
| `governance_server.py` | FastAPI sidecar server |
| `policy.yaml` | Sample governance policy |
| `flowise-flow.json` | Importable Flowise chatflow |
| `requirements.txt` | Python dependencies |

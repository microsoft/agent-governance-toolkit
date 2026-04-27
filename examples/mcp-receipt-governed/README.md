# MCP Receipt Governed — Example

Demonstrates MCP tool-call receipt signing with Cedar policy evaluation.

## What This Shows

Every MCP tool invocation is:
1. **Policy-checked** against a Cedar policy (permit/forbid rules)
2. **Receipted** with a `GovernanceReceipt` linking the decision to the tool call
3. **Signed** with Ed25519 for non-repudiation
4. **Stored** in an audit trail for later verification

## Setup

```bash
# From the repository root
pip install -e "agent-governance-python/agentmesh-integrations/mcp-receipt-governed[crypto]"
```

## Run

```bash
python examples/mcp-receipt-governed/demo.py
```

## Expected Output

```
🛡️  MCP Receipt Governed — Demo

Cedar policy loaded from: policies/mcp-tools.cedar
Signing: Ed25519

────────────────────────────────────────────────────────────

Agent                    Tool             Decision   Signed   Verified
────────────────────────────────────────────────────────────
  ✅ researcher             ReadData         allow      yes      True
  ✅ researcher             ListFiles        allow      yes      True
  ✅ researcher             SearchData       allow      yes      True
  ✅ analyst                ReadData         allow      yes      True
  🚫 analyst                DeleteFile       deny       yes      True
  🚫 analyst                DropTable        deny       yes      True
  🚫 researcher             SendEmail        deny       yes      True

📊 Audit Summary:
   Total receipts:  7
   Allowed:         4
   Denied:          3
   Unique agents:   2
   Unique tools:    5
```

## Cedar Policy

The sample policy at `policies/mcp-tools.cedar` permits read-oriented operations
and denies destructive ones:

| Action      | Decision |
|-------------|----------|
| ReadData    | ✅ permit |
| ListFiles   | ✅ permit |
| SearchData  | ✅ permit |
| DeleteFile  | 🚫 forbid |
| DropTable   | 🚫 forbid |
| SendEmail   | 🚫 forbid |

## Files

| File | Purpose |
|------|---------|
| `demo.py` | Self-contained demo script |
| `policies/mcp-tools.cedar` | Cedar policy for MCP tool access |

## Next Steps

- **Trust proxy**: Combine with `mcp-trust-proxy` for DID + trust score gating
- **Custom policies**: Write your own `.cedar` files for your tool set
- **Verification**: Export receipts and verify signatures offline

## License

MIT

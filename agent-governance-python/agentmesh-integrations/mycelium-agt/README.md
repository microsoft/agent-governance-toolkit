# mycelium-agt

> Mycelium Trails backend for AGT — tamper-evident action accountability for autonomous agents.

[![PyPI](https://img.shields.io/pypi/v/mycelium-agt)](https://pypi.org/project/mycelium-agt/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![argentum-core conformance](https://verify.crestsystems.ai/badge/argentum-core.svg)](https://crestsystems.ai/conformance)

## What it does

Every agent action anchored through `MyceliumBackend` produces a **TrailRecord** with:

- A deterministic `action_ref` (JCS RFC 8785 + SHA-256) any party can independently recompute.
- An on-chain anchor (`tx_hash`) on Base mainnet or Arbitrum One once the trail transitions to `COMMITTED`.
- A public verify URL — no authentication required.

## Installation

```bash
pip install mycelium-agt
```

## Quick start

```python
from agent_os.audit import EvidenceCollector
from mycelium_agt import MyceliumBackend

collector = EvidenceCollector()
collector.add_backend(MyceliumBackend(
    agent_id="my-agent-001",
    mycelium_url="https://argentum-api.rgiskard.xyz",
))

receipt = collector.record({"action_type": "file:write", "scope": "audit"})

print(receipt.anchored)     # True if trail was submitted
print(receipt.action_ref)   # 64-char SHA-256 hex
print(receipt.verify_url)   # public verification URL
```

## action_ref derivation

`action_ref` is a content-addressed identifier derived from four canonical fields:

```
preimage  = JCS({
    "action_type": action_type,
    "agent_id":    agent_id,
    "scope":       scope,
    "timestamp":   "2026-05-15T10:00:00.123Z",  # RFC 3339 UTC, 3-digit ms
})
action_ref = SHA-256(preimage) → lowercase hex (64 chars)
```

Keys are sorted by Unicode code point order (`action_type < agent_id < scope < timestamp`).
Spec: [docs/spec/action-ref.md](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md)

## Verification

```bash
curl 'https://argentum-api.rgiskard.xyz/trails/verify?agent_id=<id>&action_ref=<ref>'
```

Live conformance fixtures:

| Status | action_ref |
|--------|------------|
| `committed` | `31ddbd9f89f0e54700744addc7fa23f41518cf8c9d63d206e6da5cc3669defdd` |
| `pending` | `30cce7e7d538d5fb3f60152335b1da47f318425ccec12155efebc8aa8ac1e42a` |

```bash
# Verify committed fixture
curl 'https://argentum-api.rgiskard.xyz/trails/verify?agent_id=nobulex-gogani&action_ref=31ddbd9f89f0e54700744addc7fa23f41518cf8c9d63d206e6da5cc3669defdd'
# {"verified": true, "trail_status": "committed", "tx_hash": "0x7fd0a..."}
```

## Trail states

| State | `anchored` | `tx_hash` | Meaning |
|-------|-----------|-----------|---------|
| `committed` | `True` | non-null | On-chain. Terminal. |
| `pending` | `True` | non-null or null | In progress. |
| `failed` | `False` | null | Terminal. No anchor. |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 — see [LICENSE](../../../../LICENSE).

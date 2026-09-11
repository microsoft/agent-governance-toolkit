---
title: Agent Governance Toolkit v5.0.1
last_reviewed: 2026-09-10
owner: agt-maintainers
---

# Agent Governance Toolkit v5.0.1

**Release Date:** TBD

> [!IMPORTANT]
> This is a security release for AgentMesh HTTP trust middleware. Upgrade
> `agent-governance-toolkit-core` or `agentmesh-platform` deployments that use
> Flask, FastAPI, or Django trust middleware promptly.

## Security Fix

The HTTP trust middleware accepted caller-controlled identity data without
binding authentication to the complete request. The Django middleware verified
an Ed25519 signature over only the agent DID, so a captured request could be
replayed or altered. The shared Flask and FastAPI path also treated a supplied
`X-Agent-DID` as authenticated at full trust and honored caller-supplied
capabilities.

Version 5.0.1 requires a versioned signature envelope containing:

- the agent DID and configured service audience;
- a timezone-aware timestamp and unique 16-to-64-byte nonce;
- the HTTP method, undecoded request target, target mode, and server-selected
   covered headers;
- a SHA-256 digest of the exact request body.

Verified nonces are claimed atomically in a shared Redis or memcached cache and
retained through the request-signature validity window. Identity keys and
capabilities are resolved from a trusted registry, protected routes require an
authenticated result, and invalid configuration or dependency failures fail
closed. Django resolves the replay cache per request to avoid sharing unpooled
Memcached clients across threads, and Memcached claims include a one-second
expiry allowance for the backend's second-resolution expiration.

## Compatibility

This release intentionally rejects clients that sign only the agent DID. Before
deploying the server update:

1. Update clients to sign requests with `build_request_signature_payload` and
   send `X-Agent-Timestamp` and `X-Agent-Nonce` headers.
2. Configure a unique `AGENTMESH_AUDIENCE` for the receiving service.
3. Configure `AGENTMESH_REPLAY_CACHE_ALIAS` to use a shared Django Redis or
   memcached cache across every worker and replica.
4. Configure the server's request-target mode and covered headers, and update
   clients to sign the same server-selected envelope.

Do not enable `AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE` in production. The local
memory cache cannot reject replay across processes.

See the
[Django middleware guide](../../agent-governance-python/agent-mesh/docs/integrations/django-middleware.md)
for the complete signing and deployment configuration.

## Upgrade

```bash
python -m pip install --upgrade "agent-governance-toolkit-core[django]==5.0.1"
```

`agentmesh_platform` is a deprecated dependency-only compatibility package.
Pin or upgrade `agent-governance-toolkit-core` directly to ensure the fixed code
is installed.

Verify the installed version:

```bash
python -c "from importlib.metadata import version; assert version('agent-governance-toolkit-core') == '5.0.1'"
```

## Supply Chain Verification

Release artifacts are built and attested by the repository's `Publish Packages`
workflow. After downloading the wheel, verify its GitHub build provenance:

```bash
gh attestation verify agent_governance_toolkit_core-5.0.1-py3-none-any.whl \
  --repo microsoft/agent-governance-toolkit
```

The implementation and regression tests were reviewed in
[#3782](https://github.com/microsoft/agent-governance-toolkit/pull/3782) and
[#3813](https://github.com/microsoft/agent-governance-toolkit/pull/3813).
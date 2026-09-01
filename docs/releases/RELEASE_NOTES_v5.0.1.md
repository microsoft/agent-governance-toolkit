# Agent Governance Toolkit v5.0.1

**Release Date:** 2026-09-01

> [!IMPORTANT]
> This is a security release for the Django AgentMesh trust middleware. Upgrade
> `agent-governance-toolkit-core` deployments that use this middleware promptly.

## Security Fix

`AgentTrustMiddleware` in `agent-governance-toolkit-core` versions 4.0.0 through
5.0.0 verified an Ed25519 signature over only the agent DID. The signature did
not prove the freshness or uniqueness of a request and did not bind the HTTP
method, target, content type, or body. An attacker able to obtain a valid signed
request could replay it against a middleware-protected endpoint or alter
unsigned request components while reusing the signature.

Version 5.0.1 requires a versioned signature envelope containing:

- the agent DID and configured service audience;
- a timezone-aware timestamp and unique 16-to-64-byte nonce;
- the HTTP method, path and query, and content type;
- a SHA-256 digest of the exact request body.

Verified nonces are claimed atomically in a shared Redis or memcached cache and
retained through the request-signature validity window. Invalid replay-cache
configuration and cache failures fail closed.

## Compatibility

This release intentionally rejects clients that sign only the agent DID. Before
deploying the server update:

1. Update clients to sign requests with `build_request_signature_payload` and
   send `X-Agent-Timestamp` and `X-Agent-Nonce` headers.
2. Configure a unique `AGENTMESH_AUDIENCE` for the receiving service.
3. Configure `AGENTMESH_REPLAY_CACHE_ALIAS` to use a shared Django Redis or
   memcached cache across every worker and replica.

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
[#3782](https://github.com/microsoft/agent-governance-toolkit/pull/3782).
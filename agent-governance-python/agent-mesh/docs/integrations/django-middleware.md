# Django Trust Middleware

`AgentTrustMiddleware` authenticates each request with an Ed25519 signature bound to the
request contents and rejects reused nonces. Install the Django optional dependency before using
the integration:

```bash
pip install "agent-governance-toolkit-core[django,redis]"
```

## Server Configuration

Configure Django's `RedisCache` or a shared memcached backend across every worker and replica.
These backends provide atomic `add()` semantics so that only one request can claim a nonce.

```python
CACHES = {
    "agentmesh_replay": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://redis:6379/2",
    }
}

AGENTMESH_AUDIENCE = "billing-api"
AGENTMESH_REPLAY_CACHE_ALIAS = "agentmesh_replay"
AGENTMESH_REPLAY_WINDOW_SECONDS = 300
AGENTMESH_MAX_SIGNED_BODY_BYTES = 2_621_440
AGENTMESH_AGENT_KEYS = {
    "did:mesh:alice": alice_ed25519_public_key,
}

MIDDLEWARE = [
    "agentmesh.integrations.django_middleware.middleware.AgentTrustMiddleware",
    # Other middleware...
]
```

The middleware fails closed at startup for unsupported backends, including dummy, file-based,
database, and custom caches whose shared atomic nonce claims cannot be guaranteed. It also refuses
to start with Django's local-memory cache because that backend cannot detect replay across
processes. Tests and single-process development servers can explicitly set
`AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE = True`; do not enable this setting in production.

Signed request bodies are limited to `AGENTMESH_MAX_SIGNED_BODY_BYTES` (2.5 MiB by default). The
middleware enforces the limit while reading the stream, including when `Content-Length` is absent
or understated.

## Signing Requests

Every authenticated request requires these headers:

| Header | Value |
|--------|-------|
| `X-Agent-DID` | DID registered in `AGENTMESH_AGENT_KEYS` |
| `X-Agent-Timestamp` | Timezone-aware ISO-8601 timestamp within the replay window |
| `X-Agent-Nonce` | Unique base64url value containing 16 to 64 random bytes |
| `X-Agent-Signature` | Base64-encoded Ed25519 signature of the canonical request payload |

Use `build_request_signature_payload` to produce the canonical bytes. The path must include the
query string in its transmitted order, and `body` must contain the exact bytes sent on the wire.

```python
import base64
import secrets
from datetime import datetime, timezone

from agentmesh.integrations.django_middleware import build_request_signature_payload

agent_did = "did:mesh:alice"
audience = "billing-api"
timestamp = datetime.now(timezone.utc).isoformat()
nonce = secrets.token_urlsafe(16)
body = b'{"amount":100,"currency":"USD"}'
content_type = "application/json"

payload = build_request_signature_payload(
    agent_did=agent_did,
    audience=audience,
    timestamp=timestamp,
    nonce=nonce,
    method="POST",
    request_target="/v1/payments?mode=immediate",
    body=body,
    content_type=content_type,
)
signature = base64.b64encode(private_key.sign(payload)).decode("ascii")

headers = {
    "Content-Type": content_type,
    "X-Agent-DID": agent_did,
    "X-Agent-Timestamp": timestamp,
    "X-Agent-Nonce": nonce,
    "X-Agent-Signature": signature,
}
```

The signed envelope binds the DID, configured audience, timestamp, nonce, HTTP method, path and
query, content type, and SHA-256 body digest. Changing any of these values invalidates the
signature. A correctly signed nonce is accepted once and retained in the replay cache for the
configured replay window. Cache errors fail closed.

Signatures over only the agent DID are not accepted.
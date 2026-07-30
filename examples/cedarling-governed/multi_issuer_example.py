# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Capability-based authorization for autonomous agents with Cedarling + AGT.

An operations agent manages infrastructure config. Whether it may *write* is a
capability that depends on two things together:

  - **who it is** — a ``role`` claim carried by a verified access token, and
  - **how it connected** — the device posture, passed as request context.

An admin agent on a managed laptop may write. The *same admin token* presented
from an insecure device (a personal mobile) may not — the capability is revoked
by context. Reading is allowed from any device. A non-admin token never writes.

Nothing in the request can assert the role: it comes only from a token a trusted
issuer vouched for. That verified claim, combined with the request context, is
the capability — this is what sets Cedarling apart from role-based access
control, where the caller asserts its own role.

This is Cedarling's *multi-issuer* authorization mode: tokens may come from one
or more trusted issuers declared in the policy store, and policies reason over
the claims those issuers vouch for plus the request context.

Run:
    pip install -r requirements.txt
    pip install -e ../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh
    python multi_issuer_example.py

For the no-JWT path (identity asserted by the caller), see unsigned_example.py.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

from agent_os.policies import PolicyEvaluator

try:
    from cedarling_agentmesh import CedarlingBackend
except ImportError:
    sys.exit(
        "This example needs the Cedarling bindings. Install them with:\n"
        "    pip install -r requirements.txt\n"
        "    pip install -e ../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh\n"
        "(requirements.txt provides cedarling-python; cedarling_agentmesh installs from source)."
    )

POLICY_STORE = str(Path(__file__).resolve().parent / "policy-stores" / "multi-issuer")

# The Cedar entity type each access token maps to. Must match the
# entity_type_name declared in policy-stores/multi-issuer/trusted-issuers/janssen.json.
ACCESS_TOKEN_TYPE = "AGT::Access_Token"


# ---------------------------------------------------------------------------
# Mint demo access tokens
# ---------------------------------------------------------------------------
#
# In production these come from your identity provider. Here we forge them
# locally so the claims are readable — the backend is configured below with
# signature validation disabled, exactly as the integration tests run, so the
# decision turns purely on the claims, not on a real signature. The `iss` must
# match the trusted issuer's configuration endpoint host (test.jans.org).


def _mint_access_token(*, subject: str, role: str) -> str:
    """Build an unsigned demo JWT carrying a ``role`` capability claim."""

    def b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "iss": "https://test.jans.org",
        "aud": "operations-console",
        "client_id": "operations-console",
        "token_type": "Bearer",
        "scope": ["openid", "profile"],
        "role": role,
        "iat": now,
        "exp": now + 3600,
        "jti": f"jti-{subject}",
    }
    # Signature is irrelevant (validation disabled for the demo).
    return f"{b64(header)}.{b64(payload)}.demo-signature"


# Admin token grants the write capability — gated on device posture below.
ADMIN_TOKEN = _mint_access_token(subject="agent-ops", role="admin")
# Operator token: same trusted issuer, but not admin — no write capability.
OPERATOR_TOKEN = _mint_access_token(subject="agent-helpdesk", role="operator")


# ---------------------------------------------------------------------------
# Configure the backend (multi-issuer / JWT authorization)
# ---------------------------------------------------------------------------

backend = CedarlingBackend(
    application_name="cedarling-governed-example",
    # The Cedar schema in policy-stores/multi-issuer/ declares its entities under
    # the "AGT" namespace, so the backend prefixes principal/resource/action
    # accordingly (e.g. AGT::Resource, AGT::Action::"Write").
    namespace="AGT",
    auth_type="multi-issuer",
    bootstrap_config={
        "CEDARLING_POLICY_STORE_LOCAL_FN": POLICY_STORE,
        # Demo tokens are unsigned and not status-listed — skip those checks so
        # the decision rests on the issuer + claims. Keep both ON in production.
        "CEDARLING_JWT_SIG_VALIDATION": "disabled",
        "CEDARLING_JWT_STATUS_VALIDATION": "disabled",
        "CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED": ["HS256"],
        # Keep the example output clean; flip to "std_out" to see engine logs.
        "CEDARLING_LOG_TYPE": "off",
    },
)

# ---------------------------------------------------------------------------
# Build the evaluator and register the backend
# ---------------------------------------------------------------------------

evaluator = PolicyEvaluator()
evaluator.add_backend(backend)

# ---------------------------------------------------------------------------
# Evaluate tool calls
# ---------------------------------------------------------------------------
#
# Each request maps to a Cedar authorization query:
#   tool_name -> action  (snake_case -> PascalCase, e.g. read_data -> ReadData)
#   resource  -> resource id (AGT::Resource)
#   tokens    -> JWTs, keyed by the Cedar entity type they map to
#   device    -> extra context attribute (the connecting device posture)
#
# Cedarling validates each token against the trusted issuer, exposes its claims
# as context.tokens.janssen_access_token, and evaluates the policies in
# policy-stores/multi-issuer/policies/ against those claims plus the context:
#   allow-admin-read  : permit Read/ReadData when the token role is "admin"
#   allow-admin-write : permit Write when the token role is "admin" AND the
#                       request device is not "mobile" (insecure)
# Anything not permitted is denied by default.

test_cases = [
    # admin on a managed laptop -> role + secure device -> ALLOW
    {
        "label": "admin agent on managed laptop writes config",
        "request": {
            "tool_name": "write",
            "resource": "infra-config",
            "device": "laptop",
            "tokens": {ACCESS_TOKEN_TYPE: ADMIN_TOKEN},
        },
    },
    # admin on a personal mobile -> right role, insecure device -> DENY
    {
        "label": "admin agent on personal mobile writes config",
        "request": {
            "tool_name": "write",
            "resource": "infra-config",
            "device": "mobile",
            "tokens": {ACCESS_TOKEN_TYPE: ADMIN_TOKEN},
        },
    },
    # admin reading from that same mobile -> read isn't device-gated -> ALLOW
    {
        "label": "admin agent on personal mobile reads config",
        "request": {
            "tool_name": "read_data",
            "resource": "infra-config",
            "device": "mobile",
            "tokens": {ACCESS_TOKEN_TYPE: ADMIN_TOKEN},
        },
    },
    # operator on a managed laptop -> not admin -> DENY (default deny)
    {
        "label": "operator agent on managed laptop writes config",
        "request": {
            "tool_name": "write",
            "resource": "infra-config",
            "device": "laptop",
            "tokens": {ACCESS_TOKEN_TYPE: OPERATOR_TOKEN},
        },
    },
]

print(f"Cedarling backend : {backend.name!r}")
print(f"Policy store       : {POLICY_STORE}")
print()

for case in test_cases:
    request = case["request"]
    decision = evaluator.evaluate(request)
    audit = decision.audit_entry
    status = "ALLOW" if decision.allowed else "DENY "
    print(
        f"[{status}] {case['label']} → "
        f"{request['tool_name']} on {request['resource']} (device={request['device']})"
    )
    print(f"         reason : {decision.reason}")
    print(f"         backend: {audit['backend']}  timing: {audit['evaluation_ms']:.2f}ms")
    print()

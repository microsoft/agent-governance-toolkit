# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Capability-based authorization for autonomous agents with Cedarling + AGT ACS v5.

An operations agent manages infrastructure config. Whether it may write is a
capability that depends on two things together:

  - **who it is**: a ``role`` claim carried by a verified access token, and
  - **how it connected**: the device posture, passed as request context.

An admin agent on a managed laptop may write. The *same admin token* presented
from an insecure device (a personal mobile) may not, because the capability is
revoked by context. Reading is allowed from any device. A non-admin token never
writes.

Nothing in the request can assert the role: it comes only from a token a trusted
issuer vouched for. That verified claim, combined with the request context, is
the capability. This is what sets Cedarling apart from role-based access
control, where the caller asserts its own role.

This is Cedarling's *multi-issuer* mode, reached through the ACS v5 custom
policy extension point. The ``CedarlingPolicyDispatcher`` implements
``agent_control_specification.PolicyDispatcher``, so decisions flow through the
native runtime with no change to AGT core.

Run:
    pip install -r requirements.txt
    python multi_issuer_example.py

For the no-JWT path (identity asserted by the caller), see unsigned_example.py.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

# Run straight from a source checkout: if cedarling_acs is not installed, add
# its package source to the path before importing.
_PKG_SRC = (
    Path(__file__).resolve().parents[2]
    / "agent-governance-python"
    / "agentmesh-integrations"
    / "cedarling-acs"
)
if _PKG_SRC.is_dir() and str(_PKG_SRC) not in sys.path:
    sys.path.insert(0, str(_PKG_SRC))

try:
    from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher
except ImportError:
    sys.exit(
        "This example needs the Cedarling dispatcher and the cedarling-python\n"
        "engine. Install them with:\n"
        "    pip install -r requirements.txt\n"
        "and run from a checkout of the repository."
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
# locally so the claims are readable. The dispatcher is configured below with
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


# Admin token grants the write capability, gated on device posture below.
ADMIN_TOKEN = _mint_access_token(subject="agent-ops", role="admin")
# Operator token: same trusted issuer, but not admin, so no write capability.
OPERATOR_TOKEN = _mint_access_token(subject="agent-helpdesk", role="operator")


# ---------------------------------------------------------------------------
# Configure the dispatcher (multi-issuer / JWT authorization)
# ---------------------------------------------------------------------------

dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {
        "CEDARLING_POLICY_STORE_LOCAL_FN": POLICY_STORE,
        # Demo tokens are unsigned and not status-listed. Skip those checks so
        # the decision rests on the issuer + claims. Keep both ON in production.
        "CEDARLING_JWT_SIG_VALIDATION": "disabled",
        "CEDARLING_JWT_STATUS_VALIDATION": "disabled",
        "CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED": ["HS256"],
        # Keep the example output clean; flip to "std_out" to see engine logs.
        "CEDARLING_LOG_TYPE": "off",
    },
    application_name="cedarling-governed-example",
    config=CedarlingConfig(namespace="AGT", auth_type="multi-issuer"),
)


# ---------------------------------------------------------------------------
# Build an ACS policy input
# ---------------------------------------------------------------------------
#
# In multi-issuer mode the principal comes from the tokens, not the request, so
# the dispatcher reads the token map from the snapshot (default:
# envelope.agent.tokens) and passes it to Cedarling. The device posture rides in
# the snapshot outside envelope, so it lands in the Cedar context. The dispatcher
# maps the input to a Cedar query:
#   envelope.agent.tokens -> validated JWTs, keyed by their Cedar entity type
#   intervention_point    -> action   (AGT::Action::"pre_tool_call")
#   tool.name             -> resource  (AGT::Tool)
#   snapshot (minus envelope) -> Cedar context (carries `device`)
#
# Cedarling validates each token against the trusted issuer, exposes its claims
# as context.tokens.janssen_access_token, and evaluates the policies in
# policy-stores/multi-issuer/policies/ against those claims plus the context:
#   allow-admin-read  : permit pre_tool_call on Tool::"read_config" when role admin
#   allow-admin-write : permit pre_tool_call on Tool::"write_config" when role admin
#                       AND device != "mobile" (insecure)
# Anything not permitted is denied by default.


def policy_input(*, tool: str, device: str, token: str) -> dict:
    return {
        "input": {
            "intervention_point": "pre_tool_call",
            "policy_target": {
                "kind": "tool_args",
                "path": "$.tool_call.args",
                "value": {},
            },
            "snapshot": {
                "envelope": {
                    "agent": {"id": "agent-ops", "tokens": {ACCESS_TOKEN_TYPE: token}}
                },
                "device": device,
            },
            "annotations": {},
            "tool": {"name": tool},
        }
    }


test_cases = [
    {
        "label": "admin agent on managed laptop writes config",
        "tool": "write_config",
        "device": "laptop",
        "token": ADMIN_TOKEN,
    },
    {
        "label": "admin agent on personal mobile writes config",
        "tool": "write_config",
        "device": "mobile",
        "token": ADMIN_TOKEN,
    },
    {
        "label": "admin agent on personal mobile reads config",
        "tool": "read_config",
        "device": "mobile",
        "token": ADMIN_TOKEN,
    },
    {
        "label": "operator agent on managed laptop writes config",
        "tool": "write_config",
        "device": "laptop",
        "token": OPERATOR_TOKEN,
    },
    {
        "label": "admin agent deletes production (hard-blocked)",
        "tool": "delete_prod",
        "device": "laptop",
        "token": ADMIN_TOKEN,
    },
]

print(f"Policy store : {POLICY_STORE}")
print()

for case in test_cases:
    verdict = dispatcher.evaluate(
        policy_input(tool=case["tool"], device=case["device"], token=case["token"])
    )
    status = "ALLOW" if verdict["decision"] == "allow" else "DENY "
    print(
        f"[{status}] {case['label']} → "
        f"pre_tool_call on {case['tool']} (device={case['device']})"
    )
    print(f"         decision: {verdict['decision']}  reason: {verdict.get('reason')}")
    print()

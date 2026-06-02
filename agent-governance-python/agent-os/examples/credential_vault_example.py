# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Example: credential offload and injection for an agent tool call.

Run with: ``python examples/credential_vault_example.py``

This shows the issue #2481 flow end-to-end:

1. An operator provisions a credential in the vault.
2. An agent's profile binds an action capability to that credential.
3. The agent's prompt / saved plan only ever sees the opaque placeholder
   ``{{cred:NAME}}`` — never the resolved value.
4. The injector evaluates the workflow policy, resolves the placeholder
   inside the trust boundary, and returns the rendered request.
5. Audit records show *who* used *which handle* for *which service* — but
   never the secret itself.
"""

from __future__ import annotations

from agent_os.credential_vault import (
    CredentialInjector,
    CredentialProfile,
    CredentialVault,
    InjectionContext,
    PolicyOutcome,
)


def main() -> None:
    # 1. Operator provisions the credential.
    vault = CredentialVault()
    vault.put("github_pat", "ghp_real_token_value", cred_type="bearer_token")

    # 2. Bind an agent identity to an action capability -> handle.
    vault.register_profile(
        CredentialProfile(
            agent_did="did:web:agent-ci",
            bindings={"github:read_issues": "github_pat"},
        )
    )

    # 3. The agent's saved tool-call template uses only the placeholder.
    headers = {"Authorization": "Bearer {{cred:github_pat}}"}

    # 4. Workflow policy decides whether this call is allowed at all,
    #    before the injector ever reads the value.
    def policy(ctx: InjectionContext) -> PolicyOutcome:
        return PolicyOutcome(
            allow=ctx.action_class == "github:read_issues",
            reason="only read-only github calls are permitted in this workflow",
        )

    injector = CredentialInjector(vault)
    result = injector.inject_headers(
        "did:web:agent-ci",
        headers,
        action_class="github:read_issues",
        target_service="api.github.com",
        allowed_handles=["github_pat"],
        policy_check=policy,
        policy_version="v1",
    )

    print("allowed:", result.allowed)
    print("rendered Authorization length:", len(result.payload["Authorization"]))

    # 5. Audit log has no value, only the handle name and decision.
    for ev in vault.audit_log():
        print("audit:", ev.to_dict())


if __name__ == "__main__":
    main()

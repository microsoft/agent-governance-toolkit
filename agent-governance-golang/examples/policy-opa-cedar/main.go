// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

const regoPolicy = `
package agentmesh

default allow = false

allow {
    input.tool_name == "data.read"
}
`

const cedarPolicy = `
permit (
    principal,
    action == Action::"DataRead",
    resource
);
`

func main() {
	// Start with no native rules; let the backends decide. Both backends
	// are configured in builtin mode so the example runs without the OPA
	// or Cedar CLIs installed.

	fmt.Println("== OPA / Rego backend (builtin) ==")
	opa := agentmesh.NewPolicyEngine(nil)
	opa.LoadRego(agentmesh.OPAOptions{
		Mode:        agentmesh.OPABuiltin,
		RegoContent: regoPolicy,
		Package:     "agentmesh",
	})
	for _, action := range []string{"data.read", "data.write"} {
		fmt.Printf("  %-12s -> %s\n", action, opa.Evaluate(action, nil))
	}

	fmt.Println("\n== Cedar backend (builtin) ==")
	cedar := agentmesh.NewPolicyEngine(nil)
	cedar.LoadCedar(agentmesh.CedarOptions{
		Mode:          agentmesh.CedarBuiltin,
		PolicyContent: cedarPolicy,
	})
	for _, action := range []string{"data.read", "data.write"} {
		fmt.Printf("  %-12s -> %s\n", action, cedar.Evaluate(action, nil))
	}

	// Fail-closed demonstration: a backend that returns an error must
	// produce Deny, never Allow. Easiest way to trigger it here is to
	// configure the OPA backend in CLI mode while the `opa` binary is
	// absent — the engine catches the error and denies.
	fmt.Println("\n== Fail-closed when backend errors ==")
	broken := agentmesh.NewPolicyEngine(nil)
	broken.AddBackend(agentmesh.NewOPABackend(agentmesh.OPAOptions{
		Mode:        agentmesh.OPACLI,
		RegoContent: regoPolicy,
	}))
	fmt.Printf("  data.read    -> %s  (no opa CLI available => deny)\n",
		broken.Evaluate("data.read", nil))
}

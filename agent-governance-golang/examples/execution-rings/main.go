// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	enforcer := agentmesh.NewRingEnforcer()

	enforcer.SetRingPermissions(agentmesh.RingAdmin, []string{"*"})
	enforcer.SetRingPermissions(agentmesh.RingStandard, []string{"data.read", "data.write"})
	enforcer.SetRingPermissions(agentmesh.RingRestricted, []string{"data.read"})
	enforcer.SetRingPermissions(agentmesh.RingSandboxed, []string{})

	enforcer.Assign("admin-agent", agentmesh.RingAdmin)
	enforcer.Assign("worker-agent", agentmesh.RingStandard)
	enforcer.Assign("readonly-agent", agentmesh.RingRestricted)
	enforcer.Assign("sandboxed-agent", agentmesh.RingSandboxed)

	agents := []string{"admin-agent", "worker-agent", "readonly-agent", "sandboxed-agent", "unassigned-agent"}
	actions := []string{"data.read", "data.write", "system.shutdown"}

	fmt.Printf("%-20s %-8s", "agent", "ring")
	for _, a := range actions {
		fmt.Printf(" %-16s", a)
	}
	fmt.Println()

	for _, agent := range agents {
		ring, assigned := enforcer.GetRing(agent)
		ringLabel := fmt.Sprintf("%d", ring)
		if !assigned {
			ringLabel = "-"
		}
		fmt.Printf("%-20s %-8s", agent, ringLabel)
		for _, a := range actions {
			fmt.Printf(" %-16v", enforcer.CheckAccess(agent, a))
		}
		fmt.Println()
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	manager := agentmesh.NewLifecycleManager("worker-agent-001")
	fmt.Printf("start state: %s\n\n", manager.State())

	transitions := []struct {
		to     agentmesh.LifecycleState
		reason string
	}{
		{agentmesh.StateActive, "provisioning complete"},
		{agentmesh.StateSuspended, "operator paused for maintenance"},
		{agentmesh.StateActive, "maintenance complete"},
		{agentmesh.StateQuarantined, "anomalous traffic detected"},
		{agentmesh.StateDecommissioning, "retiring agent"},
		{agentmesh.StateDecommissioned, "teardown finished"},
	}

	for _, t := range transitions {
		event, err := manager.Transition(t.to, t.reason, "operator")
		if err != nil {
			fmt.Printf("transition to %-16s rejected: %v\n", t.to, err)
			continue
		}
		fmt.Printf("%-16s -> %-16s reason=%q\n", event.From, event.To, event.Reason)
	}

	fmt.Println("\nAttempting invalid transition (decommissioned -> active):")
	if _, err := manager.Transition(agentmesh.StateActive, "oops", "operator"); err != nil {
		fmt.Printf("  rejected: %v\n", err)
	}

	fmt.Printf("\nfinal state:   %s\n", manager.State())
	fmt.Printf("event count:   %d\n", len(manager.Events()))
}

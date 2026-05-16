// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	registry := agentmesh.NewKillSwitchRegistry()

	printDecision := func(label, agentID, capability string) {
		decision := registry.DecisionFor(agentID, capability)
		scope := "-"
		if decision.Scope != nil {
			scope = decision.Scope.String()
		}
		fmt.Printf("%-40s agent=%-15s tool=%-12s allowed=%-5v blocked_by=%s\n",
			label, agentID, capability, decision.Allowed, scope)
	}

	printDecision("baseline:", "agent-A", "tool.run")
	printDecision("baseline:", "agent-B", "tool.run")

	if _, err := registry.Activate(
		agentmesh.AgentKillSwitchScope("agent-A"),
		agentmesh.KillSwitchReasonSecurityIncident,
		"contain suspicious behavior on agent-A",
	); err != nil {
		log.Fatalf("activating agent scope: %v", err)
	}
	fmt.Println("\n[activated agent scope: agent-A]")
	printDecision("after agent block:", "agent-A", "tool.run")
	printDecision("after agent block:", "agent-B", "tool.run")

	if _, err := registry.Activate(
		agentmesh.CapabilityKillSwitchScope("shell.exec"),
		agentmesh.KillSwitchReasonPolicyViolation,
		"block shell across all agents",
	); err != nil {
		log.Fatalf("activating capability scope: %v", err)
	}
	fmt.Println("\n[activated capability scope: shell.exec]")
	printDecision("after capability block:", "agent-B", "shell.exec")
	printDecision("after capability block:", "agent-B", "tool.run")

	if _, err := registry.Activate(
		agentmesh.GlobalKillSwitchScope(),
		agentmesh.KillSwitchReasonOperatorRequest,
		"freeze all execution",
	); err != nil {
		log.Fatalf("activating global scope: %v", err)
	}
	fmt.Println("\n[activated global scope]")
	printDecision("after global block:", "agent-B", "tool.run")
	printDecision("after global block:", "any-other-agent", "any-tool")

	fmt.Printf("\nHistory (%d events recorded):\n", len(registry.History()))
	for _, entry := range registry.History() {
		fmt.Printf("  %s active=%-5v reason=%s\n", entry.Scope, entry.Event.Active, entry.Event.Reason)
	}
}

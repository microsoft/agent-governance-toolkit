// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	audit := agentmesh.NewAuditLogger()

	entries := []struct {
		agent, action string
		decision      agentmesh.PolicyDecision
	}{
		{"did:agentmesh:reader", "data.read", agentmesh.Allow},
		{"did:agentmesh:reader", "data.write", agentmesh.Review},
		{"did:agentmesh:reader", "shell:rm", agentmesh.Deny},
	}
	for _, e := range entries {
		entry := audit.Log(e.agent, e.action, e.decision)
		fmt.Printf("logged %-12s decision=%-7s hash=%s prev=%s\n",
			e.action,
			entry.Decision,
			entry.Hash[:12],
			truncate(entry.PreviousHash, 12),
		)
	}

	fmt.Printf("\nVerify (clean chain): %v\n", audit.Verify())

	// GetEntries returns clones — mutating a returned entry cannot break the
	// chain. The internal entries slice is unexported, so external code has
	// no path to tamper with stored records. That's the design: Log appends,
	// Verify reads, and there is no Set/Update on the public API.
	clones := audit.GetEntries(agentmesh.AuditFilter{})
	if len(clones) > 0 {
		clones[0].Action = "data.exfiltrate"
	}
	fmt.Printf("Verify after caller mutates a returned clone: %v\n", audit.Verify())

	exported, err := audit.ExportJSON()
	if err != nil {
		log.Fatalf("exporting audit: %v", err)
	}
	fmt.Printf("\nExported chain (%d bytes): %s\n", len(exported), truncate(exported, 120))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		if s == "" {
			return "(genesis)"
		}
		return s
	}
	return s[:n] + "…"
}

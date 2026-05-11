// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	client, err := agentmesh.NewClient("quickstart-agent",
		agentmesh.WithCapabilities([]string{"data.read", "data.write"}),
		agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
			{Action: "data.read", Effect: agentmesh.Allow},
			{Action: "data.write", Effect: agentmesh.Review},
			{Action: "shell:*", Effect: agentmesh.Deny},
			{Action: "*", Effect: agentmesh.Deny},
		}),
	)
	if err != nil {
		log.Fatalf("creating client: %v", err)
	}

	fmt.Printf("Agent identity: %s\n\n", client.Identity.DID)

	for _, action := range []string{"data.read", "data.write", "shell:rm"} {
		result, err := client.ExecuteWithGovernance(action, nil)
		if err != nil {
			log.Fatalf("evaluating %q: %v", action, err)
		}
		fmt.Printf("%-12s allowed=%-5v decision=%-8s trust=%.2f (%s)\n",
			action,
			result.Allowed,
			result.Decision,
			result.TrustScore.Overall,
			result.TrustScore.Tier,
		)
	}

	fmt.Printf("\nAudit chain intact: %v\n", client.Audit.Verify())
}

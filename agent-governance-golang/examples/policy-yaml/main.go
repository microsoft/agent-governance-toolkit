// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	engine := agentmesh.NewPolicyEngine(nil)
	if err := engine.LoadFromYAML("policy.yaml"); err != nil {
		log.Fatalf("loading policy.yaml: %v", err)
	}

	cases := []struct {
		label   string
		action  string
		context map[string]interface{}
	}{
		{"simple allow", "data.read", nil},
		{"conditional review", "data.write", map[string]interface{}{"classification": "internal"}},
		{"conditional deny", "data.write", map[string]interface{}{"classification": "confidential"}},
		{"unmatched classification falls through to default deny", "data.write", map[string]interface{}{"classification": "public"}},
		{"wildcard action match", "api.fetch", nil},
		{"default deny", "shell:rm", nil},
	}

	for _, c := range cases {
		fmt.Printf("%-55s action=%-12s decision=%s\n", c.label, c.action, engine.Evaluate(c.action, c.context))
	}

	fmt.Println("\nRate limit demo (api.* rule allows 3 calls / minute):")
	for i := 1; i <= 5; i++ {
		fmt.Printf("  call %d: %s\n", i, engine.Evaluate("api.fetch", map[string]interface{}{"agent_id": "demo"}))
	}
}

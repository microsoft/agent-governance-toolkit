// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"
	"net/http"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	policy := agentmesh.NewPolicyEngine([]agentmesh.PolicyRule{{
		Action:     "http.get",
		Effect:     agentmesh.Allow,
		Conditions: map[string]interface{}{"path": "/run"},
	}})

	middleware, err := agentmesh.NewHTTPGovernanceMiddleware(agentmesh.HTTPMiddlewareConfig{
		Policy:          policy,
		AgentIDResolver: agentmesh.LegacyTrustedHeaderAgentIDResolver("X-Agent-ID"),
		AllowedTools:    []string{"http.get"},
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "governed request accepted")
	}))

	http.Handle("/run", handler)
	log.Println("listening on http://localhost:8080/run")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

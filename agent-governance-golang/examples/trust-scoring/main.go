// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"errors"
	"fmt"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	tm := agentmesh.NewTrustManager(agentmesh.DefaultTrustConfig())

	const agentID = "did:agentmesh:peer-1"

	printScore := func(label string) {
		s := tm.GetTrustScore(agentID)
		fmt.Printf("%-25s overall=%.3f tier=%s\n", label, s.Overall, s.Tier)
	}

	printScore("initial:")
	for i := 0; i < 5; i++ {
		tm.RecordSuccess(agentID, 0.2)
	}
	printScore("after 5 successes (x0.2):")

	// One failure with the default 1.5x asymmetric multiplier outweighs
	// several smaller successes — the score moves further down than a
	// matching-magnitude success would have moved it up.
	tm.RecordFailure(agentID, 0.2)
	printScore("after 1 failure (x0.2):")

	for i := 0; i < 10; i++ {
		tm.RecordSuccess(agentID, 0.01)
	}
	printScore("after 10 tiny successes:")

	fmt.Println()

	peer, _ := agentmesh.GenerateIdentity("peer-1", []string{"data.read"})
	result, err := tm.VerifyPeer(agentID, peer)
	fmt.Printf("VerifyPeer with self-attested identity only:\n")
	fmt.Printf("  Verified=%v score=%.3f tier=%s\n", result.Verified, result.Score.Overall, result.Score.Tier)
	if errors.Is(err, agentmesh.ErrPeerVerificationEvidenceRequired) {
		fmt.Printf("  err=%v\n", err)
	}
}

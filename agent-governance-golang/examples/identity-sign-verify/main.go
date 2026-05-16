// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	identity, err := agentmesh.GenerateIdentity("signer-001", []string{"data.read"})
	if err != nil {
		log.Fatalf("generating identity: %v", err)
	}
	fmt.Printf("DID:          %s\n", identity.DID)
	fmt.Printf("Capabilities: %v\n\n", identity.Capabilities)

	message := []byte("transfer 10 units to account 42")
	signature, err := identity.Sign(message)
	if err != nil {
		log.Fatalf("signing message: %v", err)
	}
	fmt.Printf("Message:      %s\n", message)
	fmt.Printf("Signature:    %x...\n\n", signature[:8])

	fmt.Printf("Verify with original identity:  %v\n", identity.Verify(message, signature))

	tampered := append([]byte{}, message...)
	tampered[len(tampered)-1] ^= 0x01
	fmt.Printf("Verify with tampered message:   %v\n\n", identity.Verify(tampered, signature))

	exported, err := identity.ToJSON()
	if err != nil {
		log.Fatalf("exporting identity: %v", err)
	}
	fmt.Printf("Public JSON: %s\n\n", exported)

	peerView, err := agentmesh.FromJSON(exported)
	if err != nil {
		log.Fatalf("importing identity: %v", err)
	}
	fmt.Printf("Peer-rehydrated DID verifies signature: %v\n", peerView.Verify(message, signature))

	if _, err := peerView.Sign([]byte("forged")); err != nil {
		fmt.Printf("Peer-rehydrated DID cannot sign:        %v\n", err)
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Example: HTTP governance middleware with a cryptographically-verified
// agent identity resolver.
//
// The agent-governance toolkit ships LegacyTrustedHeaderAgentIDResolver
// for fixtures and short-lived migrations, but that resolver trusts a
// plain header — anyone who can reach the endpoint can claim to be any
// agent. Production deployments need to bind the asserted identity to
// something the caller can't forge. This example demonstrates one such
// pattern: an HMAC-SHA256 signature over (agent_id || timestamp) keyed
// by a shared secret, with a five-minute timestamp window to bound
// replay.
//
// Wire it to a real key store (KMS, Vault, file with restricted ACL —
// not a literal in production source) before deploying.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

// signedHeaderResolver verifies a signed agent-identity header set of the form:
//   X-Agent-Id: <agent_id>
//   X-Agent-Timestamp: <unix-seconds>
//   X-Agent-Signature: hex(HMAC-SHA256(secret, agent_id || ":" || timestamp))
//
// The timestamp window prevents indefinite replay of a captured header
// set. The shared secret must come from a real key store; the literal
// here is for example purposes only.
func signedHeaderResolver(sharedSecret []byte, maxAge time.Duration) agentmesh.HTTPAgentIDResolver {
	return func(request *http.Request) (agentmesh.HTTPResolvedAgentIdentity, error) {
		agentID := strings.TrimSpace(request.Header.Get("X-Agent-Id"))
		tsStr := strings.TrimSpace(request.Header.Get("X-Agent-Timestamp"))
		sigHex := strings.TrimSpace(request.Header.Get("X-Agent-Signature"))
		if agentID == "" || tsStr == "" || sigHex == "" {
			return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf("%w: missing X-Agent-{Id,Timestamp,Signature}", agentmesh.ErrVerifiedAgentIdentityRequired)
		}

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf("%w: invalid timestamp", agentmesh.ErrVerifiedAgentIdentityRequired)
		}
		age := time.Since(time.Unix(ts, 0))
		if age < -maxAge || age > maxAge {
			return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf("%w: timestamp outside %s window", agentmesh.ErrVerifiedAgentIdentityRequired, maxAge)
		}

		expectedSig, err := hex.DecodeString(sigHex)
		if err != nil {
			return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf("%w: signature not hex", agentmesh.ErrVerifiedAgentIdentityRequired)
		}

		mac := hmac.New(sha256.New, sharedSecret)
		mac.Write([]byte(agentID + ":" + tsStr))
		computed := mac.Sum(nil)
		if !hmac.Equal(computed, expectedSig) {
			return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf("%w: signature mismatch", agentmesh.ErrVerifiedAgentIdentityRequired)
		}

		return agentmesh.HTTPResolvedAgentIdentity{
			AgentID:            agentID,
			Verified:           true,
			VerificationSource: "hmac_signed_header",
		}, nil
	}
}

func main() {
	policy := agentmesh.NewPolicyEngine([]agentmesh.PolicyRule{{
		Action:     "http.get",
		Effect:     agentmesh.Allow,
		Conditions: map[string]interface{}{"path": "/run"},
	}})

	// SECRET HANDLING: in production, load this from KMS / Vault / a
	// restricted-ACL file. Never commit a real secret.
	sharedSecret := []byte("replace-with-secret-from-real-key-store")

	middleware, err := agentmesh.NewHTTPGovernanceMiddleware(agentmesh.HTTPMiddlewareConfig{
		Policy:          policy,
		AgentIDResolver: signedHeaderResolver(sharedSecret, 5*time.Minute),
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

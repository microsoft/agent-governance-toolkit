// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

// sharedSecret is a placeholder — real deployments would source this
// from a secret manager. Treat the HMAC resolver below as a minimum
// viable production resolver, not a recommended final shape: JWT or
// mTLS are stronger.
const sharedSecret = "rotate-me-in-production"

// signedHeaderResolver verifies an HMAC-of-(agent_id || ":" || timestamp)
// supplied in the X-Agent-Signature header. It rejects requests whose
// timestamp drifts more than two minutes from server time, which closes
// the trivial replay window.
func signedHeaderResolver(r *http.Request) (agentmesh.HTTPResolvedAgentIdentity, error) {
	agentID := strings.TrimSpace(r.Header.Get("X-Agent-ID"))
	timestamp := strings.TrimSpace(r.Header.Get("X-Agent-Timestamp"))
	provided := strings.TrimSpace(r.Header.Get("X-Agent-Signature"))
	if agentID == "" || timestamp == "" || provided == "" {
		return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf(
			"%w: missing X-Agent-ID, X-Agent-Timestamp, or X-Agent-Signature",
			agentmesh.ErrVerifiedAgentIdentityRequired)
	}

	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte(agentID + ":" + timestamp))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf(
			"%w: signature mismatch", agentmesh.ErrVerifiedAgentIdentityRequired)
	}

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf(
			"%w: bad timestamp", agentmesh.ErrVerifiedAgentIdentityRequired)
	}
	if drift := time.Since(ts); drift > 2*time.Minute || drift < -2*time.Minute {
		return agentmesh.HTTPResolvedAgentIdentity{}, fmt.Errorf(
			"%w: timestamp drift %s outside allowed window",
			agentmesh.ErrVerifiedAgentIdentityRequired, drift.Round(time.Second))
	}

	return agentmesh.HTTPResolvedAgentIdentity{
		AgentID:            agentID,
		Verified:           true,
		VerificationSource: "hmac-shared-secret",
	}, nil
}

func signFor(agentID string, ts time.Time) (string, string) {
	timestamp := ts.UTC().Format(time.RFC3339)
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte(agentID + ":" + timestamp))
	return timestamp, hex.EncodeToString(mac.Sum(nil))
}

func main() {
	policy := agentmesh.NewPolicyEngine([]agentmesh.PolicyRule{
		{Action: "http.get", Effect: agentmesh.Allow},
	})

	// =============================================================
	// STEP 1 — Migration phase (DO NOT SHIP).
	//
	// LegacyTrustedHeaderAgentIDResolver trusts whatever the caller puts
	// in X-Agent-ID. Anyone who can reach the endpoint can claim to be
	// any agent. This resolver exists only to ease the migration of a
	// service that has no agent-identity story yet.
	// =============================================================
	legacy, err := agentmesh.NewHTTPGovernanceMiddleware(agentmesh.HTTPMiddlewareConfig{
		Policy:          policy,
		AgentIDResolver: agentmesh.LegacyTrustedHeaderAgentIDResolver("X-Agent-ID"),
	})
	if err != nil {
		log.Fatalf("legacy middleware: %v", err)
	}
	legacyServer := httptest.NewServer(legacy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "legacy server: ok\n")
	})))
	defer legacyServer.Close()

	fmt.Println("== STEP 1: Legacy trusted-header resolver ==")
	// An attacker who can hit the endpoint can pose as anyone.
	probe(legacyServer.URL, func(req *http.Request) {
		req.Header.Set("X-Agent-ID", "attacker-posing-as-admin")
	}, "  attacker-posing-as-admin:")
	probe(legacyServer.URL, func(req *http.Request) {}, "  no header:                ")

	// =============================================================
	// STEP 2 — Production phase. Replace with a signature-verifying
	// resolver. NewHTTPGovernanceMiddleware still requires a resolver
	// (fails closed) but now the resolver only marks Verified=true
	// when the HMAC checks out.
	// =============================================================
	verified, err := agentmesh.NewHTTPGovernanceMiddleware(agentmesh.HTTPMiddlewareConfig{
		Policy:          policy,
		AgentIDResolver: signedHeaderResolver,
	})
	if err != nil {
		log.Fatalf("verified middleware: %v", err)
	}
	verifiedServer := httptest.NewServer(verified(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "verified server: ok\n")
	})))
	defer verifiedServer.Close()

	fmt.Println("\n== STEP 2: Signed-credential resolver (production shape) ==")

	// Honest, signed request — server accepts.
	ts, sig := signFor("did:agentmesh:worker-001", time.Now())
	probe(verifiedServer.URL, func(req *http.Request) {
		req.Header.Set("X-Agent-ID", "did:agentmesh:worker-001")
		req.Header.Set("X-Agent-Timestamp", ts)
		req.Header.Set("X-Agent-Signature", sig)
	}, "  honest signed request:    ")

	// Forged X-Agent-ID — signature doesn't match.
	probe(verifiedServer.URL, func(req *http.Request) {
		req.Header.Set("X-Agent-ID", "attacker-posing-as-admin")
		req.Header.Set("X-Agent-Timestamp", ts)
		req.Header.Set("X-Agent-Signature", sig)
	}, "  forged X-Agent-ID:        ")

	// No signature headers at all.
	probe(verifiedServer.URL, func(req *http.Request) {
		req.Header.Set("X-Agent-ID", "did:agentmesh:worker-001")
	}, "  unsigned request:         ")
}

func probe(serverURL string, decorate func(*http.Request), label string) {
	req, _ := http.NewRequest(http.MethodGet, serverURL, nil)
	decorate(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("%s transport error: %v\n", label, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s status=%d body=%q\n", label, resp.StatusCode, strings.TrimSpace(string(body)))
}

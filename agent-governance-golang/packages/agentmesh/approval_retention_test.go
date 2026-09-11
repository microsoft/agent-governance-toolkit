// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"sync"
	"testing"
	"time"
)

func TestApprovalStorePruneExpired(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	for _, status := range []ApprovalStatus{ApprovalPending, ApprovalAllowed, ApprovalDenied, ApprovalExpired, ApprovalCancelled, ApprovalConsumed} {
		t.Run(string(status), func(t *testing.T) {
			store := NewInMemoryApprovalStore()
			if err := store.SaveRequest(ApprovalPolicyDecisionRecord{}, ApprovalRequest{ApprovalRequestID: "request", ExpiresAt: now, Status: status}); err != nil {
				t.Fatal(err)
			}
			if err := store.AppendEntry(ApprovalChainEntry{ApprovalRequestID: "request"}); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveResolution(ApprovalResolution{ApprovalRequestID: "request", ResolvedAt: now.Add(-time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if n, err := store.PruneExpired(now.Add(time.Hour-time.Nanosecond), time.Hour); err != nil || n != 0 {
				t.Fatalf("early prune = %d, %v", n, err)
			}
			if n, err := store.PruneExpired(now.Add(time.Hour), time.Hour); err != nil || n != 1 {
				t.Fatalf("boundary prune = %d, %v", n, err)
			}
			if _, _, ok := store.GetRequest("request"); ok {
				t.Fatal("request retained")
			}
			if _, ok := store.ListEntries("request"); ok {
				t.Fatal("entries retained")
			}
			if _, ok := store.GetResolution("request"); ok {
				t.Fatal("resolution retained")
			}
			if _, ok := store.ConsumeApproval("request"); ok {
				t.Fatal("removed approval consumed")
			}
			if err := store.AppendEntry(ApprovalChainEntry{ApprovalRequestID: "request"}); err != ErrApprovalRequestNotFound {
				t.Fatalf("append = %v", err)
			}
			coordinator := NewApprovalCoordinator(ApprovalChain{}, WithApprovalStore(store), WithApprovalClock(func() time.Time { return now }))
			if result := coordinator.ValidateForExecution("request", productionBinding()); result.Allowed || result.ReasonCode != "approval_request_not_found" {
				t.Fatalf("execution = %#v", result)
			}
			if n, err := store.PruneExpired(now.Add(time.Hour), time.Hour); n != 0 || err != nil {
				t.Fatalf("repeat prune = %d, %v", n, err)
			}
		})
	}
}

func TestApprovalStorePrunePreservesLiveAndRecentRecords(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	store := NewInMemoryApprovalStore()
	for _, r := range []ApprovalRequest{
		{ApprovalRequestID: "live", ExpiresAt: now.Add(time.Hour), Status: ApprovalAllowed},
		{ApprovalRequestID: "no-expiry", Status: ApprovalConsumed},
		{ApprovalRequestID: "recent-resolution", ExpiresAt: now.Add(-2 * time.Hour), Status: ApprovalDenied},
	} {
		if err := store.SaveRequest(ApprovalPolicyDecisionRecord{}, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveResolution(ApprovalResolution{ApprovalRequestID: "recent-resolution", ResolvedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		now       time.Time
		retention time.Duration
	}{{time.Time{}, 0}, {now, -1}} {
		if n, err := store.PruneExpired(args.now, args.retention); n != 0 || err == nil {
			t.Fatalf("invalid cleanup = %d, %v", n, err)
		}
	}
	if n, err := store.PruneExpired(now, time.Hour); n != 0 || err != nil {
		t.Fatalf("retained cleanup = %d, %v", n, err)
	}
	if n, err := store.PruneExpired(now, 0); n != 1 || err != nil {
		t.Fatalf("zero retention = %d, %v", n, err)
	}
	if _, _, ok := store.GetRequest("live"); !ok {
		t.Fatal("live record removed")
	}
	if _, _, ok := store.GetRequest("no-expiry"); !ok {
		t.Fatal("unknown expiry removed")
	}
}

func TestApprovalStoreConcurrentPruneAndAccess(t *testing.T) {
	store := NewInMemoryApprovalStore()
	now := time.Now().UTC()
	if err := store.SaveRequest(ApprovalPolicyDecisionRecord{}, ApprovalRequest{ApprovalRequestID: "old", ExpiresAt: now, Status: ApprovalAllowed}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.GetRequest("old")
			store.ListEntries("old")
			store.ConsumeApproval("old")
			_ = store.AppendEntry(ApprovalChainEntry{ApprovalRequestID: "old"})
			_ = store.SaveResolution(ApprovalResolution{ApprovalRequestID: "old", ResolvedAt: now})
			if _, err := store.PruneExpired(now, 0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, _, ok := store.GetRequest("old"); ok {
		t.Fatal("old record remains")
	}
}

func TestApprovalRetryRespectsLifecycle(t *testing.T) {
	for _, state := range []string{"allowed", "consumed", "cancelled", "expired", "clock-expired"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC()
			coordinator := NewApprovalCoordinator(ApprovalChain{ChainID: "retry", Version: "1", Stages: []ApprovalStage{{AllowedIdentities: []string{"alice"}}}}, WithApprovalClock(func() time.Time { return now }))
			opened, err := coordinator.OpenRequest(productionBinding())
			if err != nil {
				t.Fatal(err)
			}
			id := opened.Request.ApprovalRequestID
			vote := ApprovalVote{ChainEntryID: "vote", ApproverIdentity: "alice", Decision: ApprovalEntryAllow}
			approved, err := coordinator.SubmitEntry(id, 0, vote)
			if err != nil || !approved.Allowed {
				t.Fatalf("approve = %#v, %v", approved, err)
			}
			switch state {
			case "consumed":
				if result := coordinator.ValidateForExecution(id, productionBinding()); !result.Allowed {
					t.Fatalf("consume = %#v", result)
				}
			case "cancelled":
				coordinator.store.UpdateRequestStatus(id, ApprovalCancelled)
			case "expired":
				coordinator.store.UpdateRequestStatus(id, ApprovalExpired)
			case "clock-expired":
				now = opened.Request.ExpiresAt
			}
			retried, err := coordinator.SubmitEntry(id, 0, vote)
			if err != nil {
				t.Fatal(err)
			}
			if retried.Allowed != (state == "allowed") {
				t.Fatalf("retry = %#v", retried)
			}
			if state != "allowed" && retried.Decision != Deny {
				t.Fatalf("decision = %s", retried.Decision)
			}
			if len(retried.Entries) != 1 || retried.Resolution.ApprovalResolutionID != approved.Resolution.ApprovalResolutionID {
				t.Fatal("retry changed audit evidence")
			}
		})
	}
}

func TestApprovalRequiredStageNeedsAuthority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage ApprovalStage
		valid bool
	}{
		{"none", ApprovalStage{}, false},
		{"blank", ApprovalStage{AllowedIdentities: []string{"", " \t"}, AllowedRoles: []string{"\u2003"}}, false},
		{"identity", ApprovalStage{AllowedIdentities: []string{"alice"}}, true},
		{"role", ApprovalStage{AllowedRoles: []string{"reviewer"}}, true},
		{"optional", ApprovalStage{Optional: true}, true},
		{"advisory", ApprovalStage{ApproverKind: ApproverLLMAdvisory}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coordinator := NewApprovalCoordinator(ApprovalChain{ChainID: "authority", Version: "1", Stages: []ApprovalStage{tc.stage}})
			result, err := coordinator.OpenRequest(productionBinding())
			if (err == nil) != tc.valid {
				t.Fatalf("OpenRequest = %#v, %v", result, err)
			}
			if !tc.valid && (result.Allowed || result.Resolution.ReasonCode != "invalid_approval_chain") {
				t.Fatalf("invalid chain result = %#v", result)
			}
		})
	}
}

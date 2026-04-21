package agentmesh

import (
	"path/filepath"

	"sync"
	"testing"
)

func TestGetTrustScoreDefault(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	score := tm.GetTrustScore("unknown-agent")
	if score.Overall != 0.5 {
		t.Errorf("default score = %f, want 0.5", score.Overall)
	}
	if score.Tier != "medium" {
		t.Errorf("default tier = %q, want medium", score.Tier)
	}
}

func TestRecordSuccessIncreases(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	tm.RecordSuccess("a1", 0.1)
	score := tm.GetTrustScore("a1")
	if score.Overall <= 0.5 {
		t.Errorf("score after success = %f, want > 0.5", score.Overall)
	}
}

func TestRecordFailureDecreases(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	tm.RecordFailure("a2", 0.2)
	score := tm.GetTrustScore("a2")
	if score.Overall >= 0.5 {
		t.Errorf("score after failure = %f, want < 0.5", score.Overall)
	}
}

func TestAsymmetricPenalty(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	tm.RecordSuccess("a3", 0.1)
	afterSuccess := tm.GetTrustScore("a3").Overall
	tm.RecordFailure("a3", 0.1)
	afterFailure := tm.GetTrustScore("a3").Overall

	delta := afterSuccess - afterFailure
	if delta <= 0.1 {
		t.Errorf("penalty should be asymmetrically larger, delta = %f", delta)
	}
}

func TestDecayReducesScore(t *testing.T) {
	cfg := DefaultTrustConfig()
	cfg.DecayRate = 0.1
	tm := NewTrustManager(cfg)

	tm.RecordSuccess("a4", 0.0) // trigger decay only
	score := tm.GetTrustScore("a4")
	if score.Overall >= 0.5 {
		t.Errorf("score after decay = %f, want < 0.5", score.Overall)
	}
}

func TestTierAssignment(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())

	// Push to high tier
	for i := 0; i < 10; i++ {
		tm.RecordSuccess("tier-agent", 0.1)
	}
	score := tm.GetTrustScore("tier-agent")
	if score.Tier != "high" {
		t.Errorf("tier = %q after many successes, want high", score.Tier)
	}
}

func TestVerifyPeer(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	id, _ := GenerateIdentity("peer1", nil)
	result, err := tm.VerifyPeer("peer1", id)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified {
		t.Error("expected peer to be verified")
	}
}

func TestScoreBounds(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	for i := 0; i < 100; i++ {
		tm.RecordSuccess("bounded", 1.0)
	}
	s := tm.GetTrustScore("bounded")
	if s.Overall > 1.0 {
		t.Errorf("score = %f, should not exceed 1.0", s.Overall)
	}

	for i := 0; i < 100; i++ {
		tm.RecordFailure("bounded", 1.0)
	}
	s = tm.GetTrustScore("bounded")
	if s.Overall < 0.0 {
		t.Errorf("score = %f, should not go below 0.0", s.Overall)
	}
}

func TestTrustPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	cfg := DefaultTrustConfig()
	cfg.PersistPath = path

	tm := NewTrustManager(cfg)
	tm.RecordSuccess("agent-p1", 0.1)
	score1 := tm.GetTrustScore("agent-p1")

	// Create a new manager that loads from disk
	tm2 := NewTrustManager(cfg)
	score2 := tm2.GetTrustScore("agent-p1")

	if score2.Overall != score1.Overall {
		t.Errorf("persisted score = %f, want %f", score2.Overall, score1.Overall)
	}
}

func TestTrustPersistenceNoPath(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	tm.RecordSuccess("agent-np", 0.1)
	score := tm.GetTrustScore("agent-np")
	if score.Overall <= 0.5 {
		t.Errorf("score = %f, want > 0.5", score.Overall)
	}
}

// --- New comprehensive tests ---

func TestMultipleAgentsTrackedIndependently(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())

	tm.RecordSuccess("agent-A", 0.2)
	tm.RecordFailure("agent-B", 0.3)

	scoreA := tm.GetTrustScore("agent-A")
	scoreB := tm.GetTrustScore("agent-B")

	if scoreA.Overall <= 0.5 {
		t.Errorf("agent-A score = %f, want > 0.5 after success", scoreA.Overall)
	}
	if scoreB.Overall >= 0.5 {
		t.Errorf("agent-B score = %f, want < 0.5 after failure", scoreB.Overall)
	}

	// Verify they don't interfere
	tm.RecordFailure("agent-A", 0.1)
	scoreA2 := tm.GetTrustScore("agent-A")
	scoreB2 := tm.GetTrustScore("agent-B")

	// agent-B score should be unchanged
	if scoreB2.Overall != scoreB.Overall {
		t.Errorf("agent-B score changed from %f to %f without any interaction", scoreB.Overall, scoreB2.Overall)
	}
	_ = scoreA2
}

func TestTrustScoreNeverExceedsOne(t *testing.T) {
	cfg := DefaultTrustConfig()
	cfg.DecayRate = 0.0 // no decay to maximize growth
	tm := NewTrustManager(cfg)

	for i := 0; i < 1000; i++ {
		tm.RecordSuccess("max-agent", 1.0)
	}
	s := tm.GetTrustScore("max-agent")
	if s.Overall > 1.0 {
		t.Errorf("score = %f, should never exceed 1.0", s.Overall)
	}
	if s.Overall != 1.0 {
		t.Logf("score after 1000 successes with no decay = %f", s.Overall)
	}
}

func TestTrustScoreNeverBelowZero(t *testing.T) {
	cfg := DefaultTrustConfig()
	cfg.DecayRate = 0.0
	tm := NewTrustManager(cfg)

	for i := 0; i < 1000; i++ {
		tm.RecordFailure("min-agent", 1.0)
	}
	s := tm.GetTrustScore("min-agent")
	if s.Overall < 0.0 {
		t.Errorf("score = %f, should never go below 0.0", s.Overall)
	}
	if s.Overall != 0.0 {
		t.Logf("score after 1000 failures = %f", s.Overall)
	}
}

func TestCustomTrustConfigValues(t *testing.T) {
	cfg := TrustConfig{
		InitialScore:  0.8,
		DecayRate:     0.0,
		RewardFactor:  2.0,
		PenaltyFactor: 0.5,
		TierThresholds: TierThresholds{
			High:   0.9,
			Medium: 0.4,
		},
		MinInteractions: 10,
	}
	tm := NewTrustManager(cfg)

	// Initial score is custom
	s := tm.GetTrustScore("custom-agent")
	if s.Overall != 0.8 {
		t.Errorf("initial score = %f, want 0.8", s.Overall)
	}

	// Reward factor is 2.0, so reward of 0.1 adds 0.2
	tm.RecordSuccess("custom-agent", 0.1)
	s = tm.GetTrustScore("custom-agent")
	if s.Overall != 1.0 { // 0.8 + 0.1*2.0 = 1.0
		t.Errorf("score after success = %f, want 1.0", s.Overall)
	}

	// Penalty factor is 0.5, so penalty of 0.1 subtracts 0.05
	tm.RecordFailure("custom-agent", 0.1)
	s = tm.GetTrustScore("custom-agent")
	expected := 1.0 - 0.1*0.5
	if s.Overall != expected {
		t.Errorf("score after failure = %f, want %f", s.Overall, expected)
	}
}

func TestTrustTierBoundaries(t *testing.T) {
	cfg := TrustConfig{
		InitialScore:  0.5,
		DecayRate:     0.0,
		RewardFactor:  1.0,
		PenaltyFactor: 1.0,
		TierThresholds: TierThresholds{
			High:   0.8,
			Medium: 0.5,
		},
		MinInteractions: 1,
	}
	tm := NewTrustManager(cfg)

	tests := []struct {
		score float64
		tier  string
	}{
		{0.0, "low"},
		{0.1, "low"},
		{0.49, "low"},
		{0.5, "medium"},  // boundary: exactly at medium threshold
		{0.6, "medium"},
		{0.79, "medium"},
		{0.8, "high"},    // boundary: exactly at high threshold
		{0.9, "high"},
		{1.0, "high"},
	}

	for _, tc := range tests {
		tier := tm.tierFor(tc.score)
		if tier != tc.tier {
			t.Errorf("tierFor(%f) = %q, want %q", tc.score, tier, tc.tier)
		}
	}
}

func TestSetTrustDirectly(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())

	// Create an agent by recording a success first, then manipulate via getOrCreate
	tm.RecordSuccess("direct-agent", 0.0)
	s := tm.GetTrustScore("direct-agent")
	// After one success with 0 reward, score should be initial * (1 - decay) + 0
	initialDecayed := 0.5 * (1.0 - 0.01)
	if s.Overall < initialDecayed-0.001 || s.Overall > initialDecayed+0.001 {
		t.Errorf("score = %f, want ~%f", s.Overall, initialDecayed)
	}
}

func TestGetTrustScoreForUnknownAgent(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	s := tm.GetTrustScore("never-seen")
	if s.Overall != 0.5 {
		t.Errorf("unknown agent score = %f, want 0.5 (initial)", s.Overall)
	}
	if s.Tier != "medium" {
		t.Errorf("unknown agent tier = %q, want medium", s.Tier)
	}
	if s.Dimensions["reliability"] != 0.5 {
		t.Errorf("reliability dimension = %f, want 0.5", s.Dimensions["reliability"])
	}
}

func TestVerifyPeerWithNilIdentity(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	result, err := tm.VerifyPeer("nil-peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Error("nil identity should not be verified")
	}
}

func TestVerifyPeerWithInvalidKeyLength(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	id := &AgentIdentity{
		DID:       "did:agentmesh:short-key",
		PublicKey: []byte("too-short"),
	}
	result, err := tm.VerifyPeer("short-key-peer", id)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Error("identity with short key should not be verified")
	}
}

func TestConcurrentTrustAccess(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	var wg sync.WaitGroup

	// Launch 50 goroutines recording successes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.RecordSuccess("concurrent-agent", 0.01)
		}()
	}

	// Launch 50 goroutines recording failures
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.RecordFailure("concurrent-agent", 0.01)
		}()
	}

	// Launch 50 goroutines reading scores
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tm.GetTrustScore("concurrent-agent")
		}()
	}

	wg.Wait()

	// Just verify no panic occurred and score is within bounds
	s := tm.GetTrustScore("concurrent-agent")
	if s.Overall < 0.0 || s.Overall > 1.0 {
		t.Errorf("score = %f, should be in [0, 1]", s.Overall)
	}
}

func TestConcurrentMultipleAgents(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())
	var wg sync.WaitGroup

	agents := []string{"agent-1", "agent-2", "agent-3", "agent-4", "agent-5"}
	for _, agent := range agents {
		agent := agent
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				tm.RecordSuccess(agent, 0.01)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = tm.GetTrustScore(agent)
			}
		}()
	}

	wg.Wait()

	// All agents should have valid scores
	for _, agent := range agents {
		s := tm.GetTrustScore(agent)
		if s.Overall < 0.0 || s.Overall > 1.0 {
			t.Errorf("%s score = %f, out of bounds", agent, s.Overall)
		}
	}
}

func TestDecayWithZeroRate(t *testing.T) {
	cfg := DefaultTrustConfig()
	cfg.DecayRate = 0.0
	tm := NewTrustManager(cfg)

	tm.RecordSuccess("no-decay", 0.1)
	s := tm.GetTrustScore("no-decay")
	// With zero decay: score = 0.5 + 0.1*1.0 = 0.6
	if s.Overall != 0.6 {
		t.Errorf("score with zero decay = %f, want 0.6", s.Overall)
	}
}

func TestDimensionsMapAlwaysPopulated(t *testing.T) {
	tm := NewTrustManager(DefaultTrustConfig())

	// Unknown agent
	s := tm.GetTrustScore("dim-agent")
	if s.Dimensions == nil {
		t.Fatal("Dimensions should not be nil")
	}
	rel, ok := s.Dimensions["reliability"]
	if !ok {
		t.Error("reliability dimension should exist")
	}
	if rel != s.Overall {
		t.Errorf("reliability = %f, want %f (same as overall)", rel, s.Overall)
	}

	// Known agent
	tm.RecordSuccess("dim-agent", 0.1)
	s = tm.GetTrustScore("dim-agent")
	if s.Dimensions == nil {
		t.Fatal("Dimensions should not be nil after interaction")
	}
	if s.Dimensions["reliability"] != s.Overall {
		t.Errorf("reliability = %f, want %f", s.Dimensions["reliability"], s.Overall)
	}
}

func TestTrustScoreAfterAlternatingSuccessFailure(t *testing.T) {
	cfg := DefaultTrustConfig()
	cfg.DecayRate = 0.0
	tm := NewTrustManager(cfg)

	// Alternate success and failure with equal magnitudes but asymmetric factors
	for i := 0; i < 5; i++ {
		tm.RecordSuccess("alternating", 0.1)
		tm.RecordFailure("alternating", 0.1)
	}

	s := tm.GetTrustScore("alternating")
	// With asymmetric penalty (penalty factor 1.5 vs reward factor 1.0),
	// alternating should trend downward
	if s.Overall >= 0.5 {
		t.Errorf("alternating success/failure with asymmetric penalty should trend down, got %f", s.Overall)
	}
}

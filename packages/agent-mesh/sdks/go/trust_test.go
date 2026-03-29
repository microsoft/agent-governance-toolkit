package agentmesh

import (
	"path/filepath"
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

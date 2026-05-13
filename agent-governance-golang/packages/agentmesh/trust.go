// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
)

// ErrPeerVerificationEvidenceRequired is returned when VerifyPeer lacks independent verification evidence.
var ErrPeerVerificationEvidenceRequired = errors.New("peer verification requires independent evidence")

// TrustScore represents an agent's current trust standing.
type TrustScore struct {
	Overall    float64            `json:"overall"`
	Dimensions map[string]float64 `json:"dimensions"`
	Tier       string             `json:"tier"`
}

type scoreState struct {
	score        float64
	interactions int
}

type persistedScores struct {
	Scores map[string]*persistedState `json:"scores"`
}

type persistedState struct {
	Score        float64 `json:"score"`
	Interactions int     `json:"interactions"`
}

// maxTrackedAgents caps the number of unique agent IDs tracked in the
// scores map to bound memory growth.  When exceeded the least-recently-
// updated entry is evicted.
const maxTrackedAgents = 10_000

// TrustManager tracks and updates per-agent trust scores.
type TrustManager struct {
	mu     sync.RWMutex
	config TrustConfig
	scores map[string]*scoreState
}

// NewTrustManager creates a TrustManager with the given config.
func NewTrustManager(config TrustConfig) *TrustManager {
	tm := &TrustManager{
		config: config,
		scores: make(map[string]*scoreState),
	}
	if config.PersistPath != "" {
		_ = tm.loadFromDisk()
	}
	return tm
}

// VerifyPeer returns the current trust score but fails closed unless the caller has
// independent verification evidence beyond the peer's self-attested identity data.
func (tm *TrustManager) VerifyPeer(peerID string, peerIdentity *AgentIdentity) (*TrustVerificationResult, error) {
	score := tm.GetTrustScore(peerID)
	result := &TrustVerificationResult{
		PeerID:   peerID,
		Verified: false,
		Score:    score,
	}

	if peerIdentity == nil {
		return result, fmt.Errorf("%w: no peer identity provided for %q", ErrPeerVerificationEvidenceRequired, peerID)
	}
	if len(peerIdentity.PublicKey) != ed25519.PublicKeySize {
		return result, fmt.Errorf(
			"%w: peer %q presented a self-attested public key with invalid length %d",
			ErrPeerVerificationEvidenceRequired,
			peerID,
			len(peerIdentity.PublicKey),
		)
	}

	return result, fmt.Errorf(
		"%w: peer %q only presented self-attested identity data",
		ErrPeerVerificationEvidenceRequired,
		peerID,
	)
}

// GetTrustScore returns the current trust score for an agent.
func (tm *TrustManager) GetTrustScore(agentID string) TrustScore {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	s, ok := tm.scores[agentID]
	if !ok {
		return TrustScore{
			Overall:    tm.config.InitialScore,
			Dimensions: map[string]float64{"reliability": tm.config.InitialScore},
			Tier:       tm.tierFor(tm.config.InitialScore),
		}
	}

	return TrustScore{
		Overall:    s.score,
		Dimensions: map[string]float64{"reliability": s.score},
		Tier:       tm.tierFor(s.score),
	}
}

// RecordSuccess increases an agent's trust score with decay.
func (tm *TrustManager) RecordSuccess(agentID string, reward float64) {
	snapshot := func() persistedScores {
		tm.mu.Lock()
		defer tm.mu.Unlock()

		s := tm.getOrCreate(agentID)
		s.interactions++
		decayed := tm.applyDecay(s.score)
		s.score = math.Min(1.0, decayed+reward*tm.config.RewardFactor)
		return tm.snapshotForPersist()
	}()
	_ = tm.persistSnapshot(snapshot)
}

// RecordFailure decreases an agent's trust score with asymmetric penalty.
func (tm *TrustManager) RecordFailure(agentID string, penalty float64) {
	snapshot := func() persistedScores {
		tm.mu.Lock()
		defer tm.mu.Unlock()

		s := tm.getOrCreate(agentID)
		s.interactions++
		decayed := tm.applyDecay(s.score)
		s.score = math.Max(0.0, decayed-penalty*tm.config.PenaltyFactor)
		return tm.snapshotForPersist()
	}()
	_ = tm.persistSnapshot(snapshot)
}

func (tm *TrustManager) getOrCreate(agentID string) *scoreState {
	s, ok := tm.scores[agentID]
	if !ok {
		if len(tm.scores) >= maxTrackedAgents {
			tm.evictOldest()
		}
		s = &scoreState{score: tm.config.InitialScore}
		tm.scores[agentID] = s
	}
	return s
}

// evictOldest removes the entry with the fewest interactions (least active).
func (tm *TrustManager) evictOldest() {
	var evictKey string
	minInteractions := int(^uint(0) >> 1) // max int
	for k, v := range tm.scores {
		if v.interactions < minInteractions {
			minInteractions = v.interactions
			evictKey = k
		}
	}
	if evictKey != "" {
		delete(tm.scores, evictKey)
	}
}

func (tm *TrustManager) applyDecay(score float64) float64 {
	return score * (1.0 - tm.config.DecayRate)
}

func (tm *TrustManager) tierFor(score float64) string {
	switch {
	case score >= tm.config.TierThresholds.High:
		return "high"
	case score >= tm.config.TierThresholds.Medium:
		return "medium"
	default:
		return "low"
	}
}

func (tm *TrustManager) loadFromDisk() error {
	if tm.config.PersistPath == "" {
		return nil
	}
	data, err := os.ReadFile(tm.config.PersistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading trust state: %w", err)
	}
	var persisted persistedScores
	if err := json.Unmarshal(data, &persisted); err != nil {
		return fmt.Errorf("unmarshalling trust state: %w", err)
	}
	for id, ps := range persisted.Scores {
		tm.scores[id] = &scoreState{
			score:        ps.Score,
			interactions: ps.Interactions,
		}
	}
	return nil
}

// snapshotForPersist returns a deep-copied view of the current scores
// suitable for persisting outside the lock. Callers MUST hold tm.mu
// (any mode) when invoking this; the snapshot itself is independent of
// the live map afterwards.
func (tm *TrustManager) snapshotForPersist() persistedScores {
	persisted := persistedScores{
		Scores: make(map[string]*persistedState, len(tm.scores)),
	}
	for id, s := range tm.scores {
		persisted.Scores[id] = &persistedState{
			Score:        s.score,
			Interactions: s.interactions,
		}
	}
	return persisted
}

// persistSnapshot writes a previously-captured snapshot to disk
// atomically (write to a sibling temp file, then rename). Marshalling
// and the disk write happen WITHOUT holding tm.mu — concurrent readers
// and writers are not blocked on disk I/O. A crash mid-write leaves
// either the old file or the new one, never a half-written file.
func (tm *TrustManager) persistSnapshot(persisted persistedScores) error {
	if tm.config.PersistPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling trust state: %w", err)
	}

	dir := filepath.Dir(tm.config.PersistPath)
	tmp, err := os.CreateTemp(dir, ".trust-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, tm.config.PersistPath); err != nil {
		cleanup()
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

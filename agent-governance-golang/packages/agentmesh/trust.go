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
	tm.mu.Lock()
	defer tm.mu.Unlock()

	s := tm.getOrCreate(agentID)
	s.interactions++
	decayed := tm.applyDecay(s.score)
	s.score = math.Min(1.0, decayed+reward*tm.config.RewardFactor)
	_ = tm.saveToDisk()
}

// RecordFailure decreases an agent's trust score with asymmetric penalty.
func (tm *TrustManager) RecordFailure(agentID string, penalty float64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	s := tm.getOrCreate(agentID)
	s.interactions++
	decayed := tm.applyDecay(s.score)
	s.score = math.Max(0.0, decayed-penalty*tm.config.PenaltyFactor)
	_ = tm.saveToDisk()
}

func (tm *TrustManager) getOrCreate(agentID string) *scoreState {
	s, ok := tm.scores[agentID]
	if !ok {
		s = &scoreState{score: tm.config.InitialScore}
		tm.scores[agentID] = s
	}
	return s
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

func (tm *TrustManager) saveToDisk() error {
	if tm.config.PersistPath == "" {
		return nil
	}
	persisted := persistedScores{
		Scores: make(map[string]*persistedState),
	}
	for id, s := range tm.scores {
		persisted.Scores[id] = &persistedState{
			Score:        s.score,
			Interactions: s.interactions,
		}
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling trust state: %w", err)
	}
	return os.WriteFile(tm.config.PersistPath, data, 0644)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AuditEntry represents a single immutable audit record.
type AuditEntry struct {
	Timestamp    time.Time      `json:"timestamp"`
	AgentID      string         `json:"agent_id"`
	Action       string         `json:"action"`
	Decision     PolicyDecision `json:"decision"`
	Hash         string         `json:"hash"`
	PreviousHash string         `json:"previous_hash"`
}

// Clone returns a value-copy of the entry. Used at the AuditLogger
// API boundary so callers cannot mutate the in-store record (and
// thereby break the hash chain) through the returned pointer.
// AuditEntry contains only value types, so a struct copy is a deep
// copy.
func (ae *AuditEntry) Clone() *AuditEntry {
	if ae == nil {
		return nil
	}
	c := *ae
	return &c
}

// AuditLogger maintains an append-only hash-chained audit log.
type AuditLogger struct {
	mu         sync.Mutex
	entries    []*AuditEntry
	seamHash   string
	MaxEntries int
}

// NewAuditLogger creates an empty AuditLogger.
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

// Log appends a new entry to the audit chain.
// When MaxEntries is set and exceeded, the oldest entries are evicted and
// their final hash is retained as a seam so Verify() can re-anchor the
// surviving chain.
func (al *AuditLogger) Log(agentID, action string, decision PolicyDecision) *AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.MaxEntries > 0 && len(al.entries) >= al.MaxEntries {
		sliceFrom := len(al.entries) - al.MaxEntries + 1
		al.seamHash = al.entries[sliceFrom-1].Hash
		al.entries = al.entries[sliceFrom:]
	}

	prevHash := al.seamHash
	if len(al.entries) > 0 {
		prevHash = al.entries[len(al.entries)-1].Hash
	}

	entry := &AuditEntry{
		Timestamp:    time.Now().UTC(),
		AgentID:      agentID,
		Action:       action,
		Decision:     decision,
		PreviousHash: prevHash,
	}
	entry.Hash = computeHash(entry)
	al.entries = append(al.entries, entry)
	// Return a clone so callers cannot mutate the in-store entry
	// (and break the chain) through the returned pointer.
	return entry.Clone()
}

// Verify checks the integrity of the entire hash chain. After rollover
// eviction, the surviving head's PreviousHash is checked against the seam
// hash recorded at eviction time, so tampering with it is still detected.
func (al *AuditLogger) Verify() bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	for i, entry := range al.entries {
		expected := computeHash(entry)
		if entry.Hash != expected {
			return false
		}
		if i == 0 {
			if entry.PreviousHash != al.seamHash {
				return false
			}
		} else {
			if entry.PreviousHash != al.entries[i-1].Hash {
				return false
			}
		}
	}
	return true
}

// GetEntries returns entries matching the given filter.
func (al *AuditLogger) GetEntries(filter AuditFilter) []*AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	var result []*AuditEntry
	for _, e := range al.entries {
		if filter.AgentID != "" && e.AgentID != filter.AgentID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.Decision != nil && e.Decision != *filter.Decision {
			continue
		}
		if filter.StartTime != nil && e.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && e.Timestamp.After(*filter.EndTime) {
			continue
		}
		result = append(result, e.Clone())
	}
	return result
}

func computeHash(e *AuditEntry) string {
	data := e.Timestamp.Format(time.RFC3339Nano) + "|" +
		e.AgentID + "|" +
		e.Action + "|" +
		string(e.Decision) + "|" +
		e.PreviousHash
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ExportJSON serialises all audit entries to a JSON string.
func (al *AuditLogger) ExportJSON() (string, error) {
	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := json.Marshal(al.entries)
	if err != nil {
		return "", fmt.Errorf("marshalling audit entries: %w", err)
	}
	return string(data), nil
}

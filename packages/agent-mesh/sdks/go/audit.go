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

// AuditLogger maintains an append-only hash-chained audit log.
type AuditLogger struct {
	mu         sync.Mutex
	entries    []*AuditEntry
	MaxEntries int
}

// NewAuditLogger creates an empty AuditLogger.
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

// Log appends a new entry to the audit chain.
// When MaxEntries is set and exceeded, the oldest entries are evicted.
func (al *AuditLogger) Log(agentID, action string, decision PolicyDecision) *AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.MaxEntries > 0 && len(al.entries) >= al.MaxEntries {
		al.entries = al.entries[len(al.entries)-al.MaxEntries+1:]
	}

	prevHash := ""
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
	return entry
}

// Verify checks the integrity of the entire hash chain.
func (al *AuditLogger) Verify() bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	for i, entry := range al.entries {
		expected := computeHash(entry)
		if entry.Hash != expected {
			return false
		}
		if i == 0 {
			// Allow non-empty PreviousHash when retention eviction is active
			if al.MaxEntries == 0 && entry.PreviousHash != "" {
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
		result = append(result, e)
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

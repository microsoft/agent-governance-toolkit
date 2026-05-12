// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/sha256"
	"encoding/binary"
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

// auditHashVersion identifies the wire format of the hash input. Bumping
// this invalidates any persisted hashes and is required when the field
// layout below changes.
const auditHashVersion byte = 1

// computeHash returns the SHA-256 hash of a length-prefixed encoding of the
// entry's fields. Each variable-length field is encoded as a 4-byte
// big-endian length followed by the raw bytes, with a fixed-position
// version byte at the start. The encoding is unambiguous regardless of the
// field contents, which closes the forgery seam in the previous
// "|"-separated format (where e.g. AgentID="a", Action="b|c" hashed
// identically to AgentID="a|b", Action="c").
func computeHash(e *AuditEntry) string {
	timestamp := e.Timestamp.Format(time.RFC3339Nano)

	// 1 byte version + 5 fields, each prefixed by a 4-byte length.
	size := 1 + 5*4 + len(timestamp) + len(e.AgentID) + len(e.Action) + len(e.Decision) + len(e.PreviousHash)
	buf := make([]byte, 0, size)
	buf = append(buf, auditHashVersion)
	buf = appendLengthPrefixed(buf, timestamp)
	buf = appendLengthPrefixed(buf, e.AgentID)
	buf = appendLengthPrefixed(buf, e.Action)
	buf = appendLengthPrefixed(buf, string(e.Decision))
	buf = appendLengthPrefixed(buf, e.PreviousHash)

	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:])
}

func appendLengthPrefixed(buf []byte, s string) []byte {
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(s)))
	buf = append(buf, lenBytes[:]...)
	buf = append(buf, s...)
	return buf
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

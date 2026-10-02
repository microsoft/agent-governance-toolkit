// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AuditEntry represents a single immutable audit record.
type AuditEntry struct {
	Timestamp          time.Time           `json:"timestamp"`
	AgentID            string              `json:"agent_id"`
	Action             string              `json:"action"`
	Decision           PolicyDecision      `json:"decision"`
	Hash               string              `json:"hash"`
	PreviousHash       string              `json:"previous_hash"`
	SkillAuditMetadata *SkillAuditMetadata `json:"skill_audit_metadata,omitempty"`
}

// Clone returns a value-copy of the entry. Used at the AuditLogger
// API boundary so callers cannot mutate the in-store record (and
// thereby break the hash chain) through the returned pointer.
// The optional skill metadata is copied separately so callers cannot mutate
// the in-store record through its pointer.
func (ae *AuditEntry) Clone() *AuditEntry {
	if ae == nil {
		return nil
	}
	c := *ae
	c.SkillAuditMetadata = cloneSkillAuditMetadata(ae.SkillAuditMetadata)
	return &c
}

// AuditLogger maintains an append-only hash-chained audit log.
type AuditLogger struct {
	mu         sync.RWMutex
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
	return al.logWithSkillAuditMetadata(agentID, action, decision, nil)
}

// LogWithSkillAuditMetadata appends an audit entry with framework-owned skill
// metadata and hashes of the before/after context snapshots.
func (al *AuditLogger) LogWithSkillAuditMetadata(
	agentID, action string,
	decision PolicyDecision,
	trustedSource *TrustedSkillMetadataSource,
	contextBefore, contextAfter any,
) *AuditEntry {
	metadata := BuildSkillAuditMetadata(trustedSource, contextBefore, contextAfter)
	return al.logWithSkillAuditMetadata(agentID, action, decision, metadata)
}

func (al *AuditLogger) logWithSkillAuditMetadata(
	agentID, action string,
	decision PolicyDecision,
	skillAuditMetadata *SkillAuditMetadata,
) *AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.MaxEntries > 0 && len(al.entries) >= al.MaxEntries {
		sliceFrom := len(al.entries) - al.MaxEntries + 1
		al.seamHash = al.entries[sliceFrom-1].Hash
		// Allocate a fresh slice so the original backing array (and
		// evicted *AuditEntry pointers in the dropped prefix) can be
		// garbage-collected. A plain reslice keeps the old array alive.
		retained := make([]*AuditEntry, len(al.entries)-sliceFrom)
		copy(retained, al.entries[sliceFrom:])
		al.entries = retained
	}

	prevHash := al.seamHash
	if len(al.entries) > 0 {
		prevHash = al.entries[len(al.entries)-1].Hash
	}

	entry := &AuditEntry{
		Timestamp:          time.Now().UTC(),
		AgentID:            agentID,
		Action:             action,
		Decision:           decision,
		PreviousHash:       prevHash,
		SkillAuditMetadata: cloneSkillAuditMetadata(skillAuditMetadata),
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
	al.mu.RLock()
	defer al.mu.RUnlock()

	for i, entry := range al.entries {
		expected := computeHash(entry)
		if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(expected)) != 1 {
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
	al.mu.RLock()
	defer al.mu.RUnlock()

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

// auditHashVersion identifies legacy entries without skill metadata.
const auditHashVersion byte = 1

// auditSkillHashVersion identifies entries that also hash skill metadata.
const auditSkillHashVersion byte = 2

// computeHash returns the SHA-256 hash of a length-prefixed encoding of the
// entry's fields. Each variable-length field is encoded as a 4-byte
// big-endian length followed by the raw bytes, with a fixed-position
// version byte at the start. The encoding is unambiguous regardless of the
// field contents, which closes the forgery seam in the previous
// "|"-separated format (where e.g. AgentID="a", Action="b|c" hashed
// identically to AgentID="a|b", Action="c").
func computeHash(e *AuditEntry) string {
	timestamp := e.Timestamp.Format(time.RFC3339Nano)

	// Entries without skill metadata keep the original wire version and hash.
	size := 1 + 5*4 + len(timestamp) + len(e.AgentID) + len(e.Action) + len(e.Decision) + len(e.PreviousHash)
	version := auditHashVersion
	if e.SkillAuditMetadata != nil {
		version = auditSkillHashVersion
		metadata := e.SkillAuditMetadata
		size += 5*4 +
			len(metadata.SkillName) +
			len(metadata.SkillOrigin) +
			len(metadata.ProvenanceSourceTrust) +
			len(metadata.ContextHashBefore) +
			len(metadata.ContextHashAfter)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, version)
	buf = appendLengthPrefixed(buf, timestamp)
	buf = appendLengthPrefixed(buf, e.AgentID)
	buf = appendLengthPrefixed(buf, e.Action)
	buf = appendLengthPrefixed(buf, string(e.Decision))
	buf = appendLengthPrefixed(buf, e.PreviousHash)
	if metadata := e.SkillAuditMetadata; metadata != nil {
		buf = appendLengthPrefixed(buf, metadata.SkillName)
		buf = appendLengthPrefixed(buf, metadata.SkillOrigin)
		buf = appendLengthPrefixed(buf, metadata.ProvenanceSourceTrust)
		buf = appendLengthPrefixed(buf, metadata.ContextHashBefore)
		buf = appendLengthPrefixed(buf, metadata.ContextHashAfter)
	}

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

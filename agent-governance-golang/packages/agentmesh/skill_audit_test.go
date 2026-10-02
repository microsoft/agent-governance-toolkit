// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHashContextStableForNestedMapKeyOrdering(t *testing.T) {
	left := map[string]any{
		"outer": map[string]any{"z": 2, "a": 1},
		"items": []any{map[string]any{"b": 2, "a": 1}},
	}
	right := map[string]any{
		"items": []any{map[string]any{"a": 1, "b": 2}},
		"outer": map[string]any{"a": 1, "z": 2},
	}

	leftHash, leftOK := HashContext(left)
	rightHash, rightOK := HashContext(right)
	if !leftOK || !rightOK {
		t.Fatal("expected both contexts to be hashable")
	}
	if leftHash != rightHash {
		t.Fatalf("key-order changes produced different hashes: %q != %q", leftHash, rightHash)
	}
}

func TestHashContextMatchesSharedCanonicalUTF8JSON(t *testing.T) {
	hash, ok := HashContext(map[string]any{"text": "<&>+ café"})
	if !ok {
		t.Fatal("expected context to be hashable")
	}
	if hash != "64fc8ac088af1d1df47ae20c50f35b46a0037eb05a13c2cd6745da93e03ad9e9" {
		t.Fatalf("hash = %q, want shared canonical JSON hash", hash)
	}
}

func TestHashContextFailsSafelyForUnsupportedValues(t *testing.T) {
	if hash, ok := HashContext(make(chan int)); ok || hash != "" {
		t.Fatalf("unsupported context returned hash %q", hash)
	}
	if hash, ok := HashContext(nil); ok || hash != "" {
		t.Fatalf("nil context returned hash %q", hash)
	}
}

func TestBuildSkillAuditMetadataDoesNotPromotePayloadFields(t *testing.T) {
	payload := map[string]any{
		"skill_name":   "spoofed_skill",
		"skill_origin": "untrusted_request",
	}

	metadata := BuildSkillAuditMetadata(nil, payload, nil)
	if metadata == nil {
		t.Fatal("expected a context hash")
	}
	if metadata.SkillName != "" || metadata.SkillOrigin != "" || metadata.ProvenanceSourceTrust != "" {
		t.Fatalf("payload values were promoted to trusted metadata: %#v", metadata)
	}
	if len(metadata.ContextHashBefore) != 64 {
		t.Fatalf("context hash length = %d, want 64", len(metadata.ContextHashBefore))
	}
}

func TestLogWithSkillAuditMetadataStoresTrustedValuesAndOnlyHashesContext(t *testing.T) {
	logger := NewAuditLogger()
	source := NewTrustedSkillMetadataSource(" search_skill ", " framework ")
	before := map[string]any{
		"skill_name": "spoofed_skill",
		"query":      "private query",
	}

	entry := logger.LogWithSkillAuditMetadata("agent-1", "tool.search", Allow, source, before, nil)
	metadata := entry.SkillAuditMetadata
	if metadata == nil {
		t.Fatal("expected skill audit metadata")
	}
	if metadata.SkillName != "search_skill" || metadata.SkillOrigin != "framework" {
		t.Fatalf("unexpected trusted metadata: %#v", metadata)
	}
	if metadata.ProvenanceSourceTrust != trustedSkillProvenance {
		t.Fatalf("provenance trust = %q, want %q", metadata.ProvenanceSourceTrust, trustedSkillProvenance)
	}
	if len(metadata.ContextHashBefore) != 64 || metadata.ContextHashAfter != "" {
		t.Fatalf("unexpected context hashes: %#v", metadata)
	}
	if _, offset := entry.Timestamp.Zone(); offset != 0 {
		t.Fatalf("timestamp offset = %d, want UTC", offset)
	}
	if !logger.Verify() {
		t.Fatal("skill-aware audit entry should verify")
	}

	serialized, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal audit entry: %v", err)
	}
	if strings.Contains(string(serialized), "spoofed_skill") || strings.Contains(string(serialized), "private query") {
		t.Fatalf("raw request context leaked into the audit entry: %s", serialized)
	}

	entry.SkillAuditMetadata.SkillName = "caller_mutation"
	if !logger.Verify() {
		t.Fatal("mutating the returned metadata copy must not change the stored chain")
	}
}

func TestSkillAuditMetadataTamperingBreaksHashChain(t *testing.T) {
	logger := NewAuditLogger()
	logger.LogWithSkillAuditMetadata(
		"agent-1",
		"tool.search",
		Allow,
		NewTrustedSkillMetadataSource("search_skill", "framework"),
		map[string]any{"query": "safe"},
		nil,
	)

	logger.entries[0].SkillAuditMetadata.SkillName = "tampered"
	if logger.Verify() {
		t.Fatal("metadata tampering should invalidate the hash chain")
	}
}

func TestBuildSkillAuditMetadataOmitsOnlyUnsupportedContexts(t *testing.T) {
	metadata := BuildSkillAuditMetadata(
		NewTrustedSkillMetadataSource("search_skill", ""),
		make(chan int),
		nil,
	)
	if metadata == nil {
		t.Fatal("trusted source should still be recorded")
	}
	if metadata.SkillName != "search_skill" || metadata.ProvenanceSourceTrust != trustedSkillProvenance {
		t.Fatalf("trusted source was lost: %#v", metadata)
	}
	if metadata.ContextHashBefore != "" || metadata.ContextHashAfter != "" {
		t.Fatalf("unsupported contexts should not produce hashes: %#v", metadata)
	}
}

func TestAuditTimestampRemainsUTCWithSkillMetadata(t *testing.T) {
	entry := NewAuditLogger().LogWithSkillAuditMetadata(
		"agent-1",
		"tool.search",
		Allow,
		NewTrustedSkillMetadataSource("search_skill", ""),
		map[string]string{"query": "hello"},
		map[string]string{"result": "ok"},
	)
	if entry.Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", entry.Timestamp.Location())
	}
}

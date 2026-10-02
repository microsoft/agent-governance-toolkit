// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const trustedSkillProvenance = "trusted"

// TrustedSkillMetadataSource contains skill identifiers obtained from a
// framework-owned source, rather than from request payload fields.
type TrustedSkillMetadataSource struct {
	skillName   string
	skillOrigin string
}

// NewTrustedSkillMetadataSource creates a trusted source after trimming empty values.
func NewTrustedSkillMetadataSource(skillName, skillOrigin string) *TrustedSkillMetadataSource {
	source := &TrustedSkillMetadataSource{
		skillName:   strings.TrimSpace(skillName),
		skillOrigin: strings.TrimSpace(skillOrigin),
	}
	if source.skillName == "" && source.skillOrigin == "" {
		return nil
	}
	return source
}

// SkillAuditMetadata contains normalized skill provenance and context hashes.
type SkillAuditMetadata struct {
	SkillName             string `json:"skill_name,omitempty"`
	SkillOrigin           string `json:"skill_origin,omitempty"`
	ProvenanceSourceTrust string `json:"provenance_source_trust,omitempty"`
	ContextHashBefore     string `json:"context_hash_before,omitempty"`
	ContextHashAfter      string `json:"context_hash_after,omitempty"`
}

// BuildSkillAuditMetadata builds metadata only from an explicit trusted source.
// Context values are hashed and are never inspected for skill names or origins.
func BuildSkillAuditMetadata(
	trustedSource *TrustedSkillMetadataSource,
	contextBefore, contextAfter any,
) *SkillAuditMetadata {
	metadata := &SkillAuditMetadata{}
	if trustedSource != nil {
		metadata.SkillName = trustedSource.skillName
		metadata.SkillOrigin = trustedSource.skillOrigin
		if metadata.SkillName != "" || metadata.SkillOrigin != "" {
			metadata.ProvenanceSourceTrust = trustedSkillProvenance
		}
	}

	if hash, ok := HashContext(contextBefore); ok {
		metadata.ContextHashBefore = hash
	}
	if hash, ok := HashContext(contextAfter); ok {
		metadata.ContextHashAfter = hash
	}

	if metadata.SkillName == "" &&
		metadata.SkillOrigin == "" &&
		metadata.ProvenanceSourceTrust == "" &&
		metadata.ContextHashBefore == "" &&
		metadata.ContextHashAfter == "" {
		return nil
	}
	return metadata
}

// HashContext returns the SHA-256 hash of compact JSON with stable object-key
// ordering. It reports false for nil or non-serializable contexts.
func HashContext(context any) (string, bool) {
	if context == nil {
		return "", false
	}

	canonical, err := canonicalContextJSON(context)
	if err != nil || len(canonical) == 0 {
		return "", false
	}

	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), true
}

func canonicalContextJSON(context any) ([]byte, error) {
	raw, err := json.Marshal(context)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	if normalized == nil {
		return nil, nil
	}

	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'}), nil
}

func cloneSkillAuditMetadata(metadata *SkillAuditMetadata) *SkillAuditMetadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	return &cloned
}

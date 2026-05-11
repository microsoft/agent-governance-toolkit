// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"strings"
	"sync"
	"unicode"
)

// McpThreatType categorises MCP tool-level threats.
type McpThreatType string

const (
	ToolPoisoning     McpThreatType = "tool_poisoning"
	Typosquatting     McpThreatType = "typosquatting"
	HiddenInstruction McpThreatType = "hidden_instruction"
	RugPull           McpThreatType = "rug_pull"
)

// McpThreat describes a single threat detected in a tool definition.
type McpThreat struct {
	Type        McpThreatType `json:"type"`
	Severity    string        `json:"severity"` // low, medium, high, critical
	Description string        `json:"description"`
	Evidence    string        `json:"evidence,omitempty"`
}

// McpScanResult is the outcome of scanning one tool definition.
type McpScanResult struct {
	ToolName  string      `json:"tool_name"`
	Threats   []McpThreat `json:"threats"`
	RiskScore int         `json:"risk_score"` // 0-100
	Safe      bool        `json:"safe"`
}

// McpToolDefinition is the metadata for a single MCP tool.
type McpToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// McpSecurityScanner detects poisoning, typosquatting, hidden instructions,
// and rug-pull patterns in MCP tool definitions.
//
// Safe for concurrent use; ``knownTools`` is guarded by ``mu``.
type McpSecurityScanner struct {
	mu         sync.RWMutex
	knownTools []string
}

// NewMcpSecurityScanner creates a scanner with an empty known-tools registry.
func NewMcpSecurityScanner() *McpSecurityScanner {
	return &McpSecurityScanner{}
}

// Scan inspects a single tool definition and returns the scan result.
func (s *McpSecurityScanner) Scan(tool McpToolDefinition) McpScanResult {
	var threats []McpThreat

	threats = append(threats, s.detectToolPoisoning(tool)...)
	threats = append(threats, s.detectTyposquatting(tool)...)
	threats = append(threats, s.detectHiddenInstructions(tool)...)
	threats = append(threats, s.detectRugPull(tool)...)

	score := computeRiskScore(threats)
	return McpScanResult{
		ToolName:  tool.Name,
		Threats:   threats,
		RiskScore: score,
		Safe:      len(threats) == 0,
	}
}

// ScanAll scans every tool in the slice and returns per-tool results.
func (s *McpSecurityScanner) ScanAll(tools []McpToolDefinition) []McpScanResult {
	results := make([]McpScanResult, 0, len(tools))
	for _, t := range tools {
		results = append(results, s.Scan(t))
	}
	return results
}

// detectToolPoisoning looks for hidden prompt-injection instructions inside
// a tool's description (e.g. "ignore previous instructions").
func (s *McpSecurityScanner) detectToolPoisoning(tool McpToolDefinition) []McpThreat {
	lower := strings.ToLower(tool.Description)
	patterns := []string{
		"ignore previous",
		"ignore all previous",
		"disregard above",
		"override the instructions",
		"you must now",
		"system prompt",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return []McpThreat{{
				Type:        ToolPoisoning,
				Severity:    "critical",
				Description: "tool description contains prompt injection pattern",
				Evidence:    p,
			}}
		}
	}
	return nil
}

// detectTyposquatting compares the tool name against known common tool names
// and flags suspiciously similar names (Levenshtein distance ≤ 2, but not exact).
func (s *McpSecurityScanner) detectTyposquatting(tool McpToolDefinition) []McpThreat {
	wellKnown := []string{
		"search", "fetch", "read_file", "write_file",
		"execute", "query", "send_email", "list_files",
	}

	// Snapshot ``knownTools`` under the read lock so we can scan against
	// it without holding the lock during the (relatively expensive)
	// Levenshtein loop. Concurrent ``Scan`` callers race on the slice
	// header otherwise — both reading at line 114 and writing at the
	// final ``append`` below are unsynchronized today, which goes loud
	// under ``go test -race`` and risks lost updates / torn reads when
	// the scanner is shared across request goroutines.
	s.mu.RLock()
	candidates := make([]string, 0, len(wellKnown)+len(s.knownTools))
	candidates = append(candidates, wellKnown...)
	candidates = append(candidates, s.knownTools...)
	s.mu.RUnlock()

	for _, known := range candidates {
		if tool.Name == known {
			continue
		}
		if levenshteinDistance(tool.Name, known) <= 2 {
			return []McpThreat{{
				Type:        Typosquatting,
				Severity:    "high",
				Description: "tool name is suspiciously similar to known tool",
				Evidence:    known,
			}}
		}
	}

	// Register this tool name for future comparisons.
	s.mu.Lock()
	s.knownTools = append(s.knownTools, tool.Name)
	s.mu.Unlock()
	return nil
}

// detectHiddenInstructions catches zero-width and homoglyph characters.
func (s *McpSecurityScanner) detectHiddenInstructions(tool McpToolDefinition) []McpThreat {
	for _, r := range tool.Description {
		if isHiddenChar(r) {
			return []McpThreat{{
				Type:        HiddenInstruction,
				Severity:    "critical",
				Description: "description contains hidden/zero-width characters",
				Evidence:    "zero-width or control character detected",
			}}
		}
	}

	// Homoglyph check: description has letters that look Latin but aren't.
	for _, r := range tool.Description {
		if unicode.IsLetter(r) && !isBasicLatin(r) && looksLikeLatinHomoglyph(r) {
			return []McpThreat{{
				Type:        HiddenInstruction,
				Severity:    "high",
				Description: "description contains homoglyph characters",
				Evidence:    "non-Latin character resembling ASCII letter detected",
			}}
		}
	}
	return nil
}

// detectRugPull flags oversized descriptions that embed instruction-like payloads.
func (s *McpSecurityScanner) detectRugPull(tool McpToolDefinition) []McpThreat {
	if len(tool.Description) <= 500 {
		return nil
	}

	lower := strings.ToLower(tool.Description)
	instructionPatterns := []string{
		"do not tell the user",
		"send the following",
		"exfiltrate",
		"curl ",
		"wget ",
		"http://",
		"https://",
	}
	for _, p := range instructionPatterns {
		if strings.Contains(lower, p) {
			return []McpThreat{{
				Type:        RugPull,
				Severity:    "critical",
				Description: "oversized description with suspicious instruction pattern",
				Evidence:    p,
			}}
		}
	}
	return nil
}

// levenshteinDistance returns the edit distance between two strings.
func levenshteinDistance(a, b string) int {
	aRunes := []rune(a)
	bRunes := []rune(b)
	la, lb := len(aRunes), len(bRunes)

	costs := make([]int, lb+1)
	for j := range costs {
		costs[j] = j
	}

	for i := 0; i < la; i++ {
		prev := costs[0]
		costs[0] = i + 1
		for j := 0; j < lb; j++ {
			old := costs[j+1]
			sub := prev
			if aRunes[i] != bRunes[j] {
				sub++
			}
			ins := costs[j] + 1
			del := old + 1
			best := sub
			if ins < best {
				best = ins
			}
			if del < best {
				best = del
			}
			costs[j+1] = best
			prev = old
		}
	}
	return costs[lb]
}

// isHiddenChar returns true for zero-width and invisible control characters.
func isHiddenChar(r rune) bool {
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\uFEFF', // byte-order mark / zero-width no-break space
		'\u200E', // left-to-right mark
		'\u200F', // right-to-left mark
		'\u202A', // left-to-right embedding
		'\u202B', // right-to-left embedding
		'\u202C', // pop directional formatting
		'\u202D', // left-to-right override
		'\u202E': // right-to-left override
		return true
	}
	return false
}

// isBasicLatin returns true for common ASCII letters, digits, and whitespace.
func isBasicLatin(r rune) bool {
	return r <= 0x007F
}

// looksLikeLatinHomoglyph returns true for characters often used to impersonate
// ASCII letters (Cyrillic а/е/о, Greek ο, etc.).
func looksLikeLatinHomoglyph(r rune) bool {
	homoglyphs := []rune{
		'\u0430', // Cyrillic а (looks like 'a')
		'\u0435', // Cyrillic е (looks like 'e')
		'\u043E', // Cyrillic о (looks like 'o')
		'\u0440', // Cyrillic р (looks like 'p')
		'\u0441', // Cyrillic с (looks like 'c')
		'\u0443', // Cyrillic у (looks like 'y')
		'\u03BF', // Greek omicron (looks like 'o')
	}
	for _, h := range homoglyphs {
		if r == h {
			return true
		}
	}
	return false
}

// computeRiskScore calculates a 0-100 risk score from threat severity.
func computeRiskScore(threats []McpThreat) int {
	if len(threats) == 0 {
		return 0
	}
	score := 0
	for _, t := range threats {
		switch t.Severity {
		case "critical":
			score += 40
		case "high":
			score += 25
		case "medium":
			score += 15
		case "low":
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

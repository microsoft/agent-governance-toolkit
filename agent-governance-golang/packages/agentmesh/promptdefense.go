// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"regexp"
)

// PromptThreatType categorizes a prompt-defense finding.
type PromptThreatType string

const (
	InstructionOverride PromptThreatType = "instruction_override"
	PromptExfiltration  PromptThreatType = "prompt_exfiltration"
	CredentialLeak      PromptThreatType = "credential_exfiltration"
	ApprovalBypass      PromptThreatType = "approval_bypass"
)

// PromptDefenseFinding describes one risky pattern in a prompt.
type PromptDefenseFinding struct {
	Type        PromptThreatType `json:"type"`
	Severity    string           `json:"severity"`
	Description string           `json:"description"`
	Evidence    string           `json:"evidence"`
}

// PromptDefenseResult is the outcome of evaluating a prompt.
type PromptDefenseResult struct {
	Findings  []PromptDefenseFinding `json:"findings"`
	RiskScore int                    `json:"risk_score"`
	Safe      bool                   `json:"safe"`
}

type promptDefenseRule struct {
	threatType  PromptThreatType
	severity    string
	description string
	pattern     *regexp.Regexp
}

// PromptDefenseEvaluator detects prompt injection and exfiltration patterns.
type PromptDefenseEvaluator struct {
	rules []promptDefenseRule
}

// NewPromptDefenseEvaluator creates a prompt defense evaluator.
func NewPromptDefenseEvaluator() *PromptDefenseEvaluator {
	return &PromptDefenseEvaluator{
		rules: []promptDefenseRule{
			{
				threatType:  InstructionOverride,
				severity:    "critical",
				description: "prompt attempts to override prior instructions",
				pattern:     regexp.MustCompile(`(?i)ignore (all )?(previous|prior) instructions|disregard (all )?(above|previous)`),
			},
			{
				threatType:  PromptExfiltration,
				severity:    "critical",
				description: "prompt requests hidden or system instructions",
				pattern:     regexp.MustCompile(`(?i)reveal (your )?(system prompt|hidden instructions)|show (me )?(the )?system prompt`),
			},
			{
				threatType:  CredentialLeak,
				severity:    "critical",
				description: "prompt requests secrets or credentials",
				pattern:     regexp.MustCompile(`(?i)(show|print|reveal|send|export).*(api key|token|password|secret|credential)`),
			},
			{
				threatType:  ApprovalBypass,
				severity:    "high",
				description: "prompt attempts to bypass approval or safety controls",
				pattern:     regexp.MustCompile(`(?i)without approval|bypass (safety|guardrails|policy|policies)|disable (safety|filters|guardrails)`),
			},
		},
	}
}

// Evaluate returns structured findings for a prompt.
func (e *PromptDefenseEvaluator) Evaluate(prompt string) PromptDefenseResult {
	findings := make([]PromptDefenseFinding, 0)
	severities := make([]string, 0)
	for _, rule := range e.rules {
		if match := rule.pattern.FindString(prompt); match != "" {
			findings = append(findings, PromptDefenseFinding{
				Type:        rule.threatType,
				Severity:    rule.severity,
				Description: rule.description,
				Evidence:    match,
			})
			severities = append(severities, rule.severity)
		}
	}

	return PromptDefenseResult{
		Findings:  findings,
		RiskScore: scoreFromSeverities(severities),
		Safe:      len(findings) == 0,
	}
}

func scoreFromSeverities(severities []string) int {
	score := 0
	for _, severity := range severities {
		switch severity {
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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "strings"

// ConflictResolutionStrategy defines how conflicting policy decisions are resolved.
type ConflictResolutionStrategy string

const (
	DenyOverrides      ConflictResolutionStrategy = "deny_overrides"
	AllowOverrides     ConflictResolutionStrategy = "allow_overrides"
	PriorityFirstMatch ConflictResolutionStrategy = "priority_first_match"
	MostSpecificWins   ConflictResolutionStrategy = "most_specific_wins"
)

// CandidateDecision pairs a matched rule with its resulting decision.
type CandidateDecision struct {
	Rule     PolicyRule
	Decision PolicyDecision
}

// PolicyConflictResolver resolves conflicts between multiple matching rules.
type PolicyConflictResolver struct {
	Strategy ConflictResolutionStrategy
}

// Resolve returns a single PolicyDecision from a set of candidates using the configured strategy.
func (r *PolicyConflictResolver) Resolve(candidates []CandidateDecision) PolicyDecision {
	if len(candidates) == 0 {
		return Deny
	}

	switch r.Strategy {
	case DenyOverrides:
		for _, c := range candidates {
			if c.Decision == Deny {
				return Deny
			}
		}
		return candidates[0].Decision

	case AllowOverrides:
		for _, c := range candidates {
			if c.Decision == Allow {
				return Allow
			}
		}
		return candidates[0].Decision

	case PriorityFirstMatch:
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.Rule.Priority < best.Rule.Priority {
				best = c
			}
		}
		return best.Decision

	case MostSpecificWins:
		best := candidates[0]
		bestSpec := ruleSpecificity(best)
		for _, c := range candidates[1:] {
			s := ruleSpecificity(c)
			if s > bestSpec {
				best = c
				bestSpec = s
			}
		}
		return best.Decision

	default:
		return candidates[0].Decision
	}
}

func ruleSpecificity(c CandidateDecision) int {
	score := len(c.Rule.Conditions)
	switch c.Rule.Scope {
	case Agent:
		score += 3
	case Tenant:
		score += 2
	case Global:
		score += 1
	}
	if c.Rule.Action != "*" && !strings.HasSuffix(c.Rule.Action, ".*") {
		score += 2
	}
	return score
}

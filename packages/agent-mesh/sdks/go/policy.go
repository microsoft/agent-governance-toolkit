// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyScope represents the scope at which a policy rule applies.
type PolicyScope string

const (
	Global PolicyScope = "global"
	Tenant PolicyScope = "tenant"
	Agent  PolicyScope = "agent"
)

// PolicyRule defines a single governance rule.
type PolicyRule struct {
	Action       string                 `json:"action" yaml:"action"`
	Effect       PolicyDecision         `json:"effect" yaml:"effect"`
	Conditions   map[string]interface{} `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Priority     int                    `json:"priority,omitempty" yaml:"priority,omitempty"`
	Scope        PolicyScope            `json:"scope,omitempty" yaml:"scope,omitempty"`
	MaxCalls     int                    `json:"max_calls,omitempty" yaml:"max_calls,omitempty"`
	Window       string                 `json:"window,omitempty" yaml:"window,omitempty"`
	MinApprovals int                    `json:"min_approvals,omitempty" yaml:"min_approvals,omitempty"`
	Approvers    []string               `json:"approvers,omitempty" yaml:"approvers,omitempty"`
}

// rateLimitState tracks call counts within a time window.
type rateLimitState struct {
	count       int
	windowStart time.Time
}

// PolicyEngine evaluates actions against a set of rules.
type PolicyEngine struct {
	mu         sync.RWMutex
	rules      []PolicyRule
	rateLimits map[string]*rateLimitState
}

// NewPolicyEngine creates a PolicyEngine with the supplied rules.
func NewPolicyEngine(rules []PolicyRule) *PolicyEngine {
	return &PolicyEngine{
		rules:      rules,
		rateLimits: make(map[string]*rateLimitState),
	}
}

// Evaluate returns the decision for the given action and context.
// Rules are evaluated in order; first match wins. Default is Deny.
func (pe *PolicyEngine) Evaluate(action string, context map[string]interface{}) PolicyDecision {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	for _, rule := range pe.rules {
		if matchAction(rule.Action, action) && matchConditions(rule.Conditions, context) {
			if rule.MaxCalls > 0 {
				return pe.checkRateLimit(rule)
			}
			if rule.MinApprovals > 0 {
				return RequiresApproval
			}
			return rule.Effect
		}
	}
	return Deny
}

// checkRateLimit tracks and enforces per-rule call limits within a time window.
func (pe *PolicyEngine) checkRateLimit(rule PolicyRule) PolicyDecision {
	key := rule.Action
	now := time.Now()

	window, err := time.ParseDuration(rule.Window)
	if err != nil {
		window = time.Minute
	}

	state, ok := pe.rateLimits[key]
	if !ok {
		pe.rateLimits[key] = &rateLimitState{count: 1, windowStart: now}
		return Allow
	}

	if now.Sub(state.windowStart) > window {
		state.count = 1
		state.windowStart = now
		return Allow
	}

	state.count++
	if state.count > rule.MaxCalls {
		return RateLimit
	}
	return Allow
}

// LoadFromYAML loads rules from a YAML file, appending to existing rules.
func (pe *PolicyEngine) LoadFromYAML(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var loaded struct {
		Rules []PolicyRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		return err
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.rules = append(pe.rules, loaded.Rules...)
	return nil
}

func matchAction(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(action, prefix+".")
	}
	return pattern == action
}

func matchConditions(conditions map[string]interface{}, context map[string]interface{}) bool {
	for key, expected := range conditions {
		switch key {
		case "$and":
			subs, ok := toConditionList(expected)
			if !ok {
				return false
			}
			for _, sub := range subs {
				if !matchConditions(sub, context) {
					return false
				}
			}
		case "$or":
			subs, ok := toConditionList(expected)
			if !ok {
				return false
			}
			matched := false
			for _, sub := range subs {
				if matchConditions(sub, context) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		case "$not":
			sub, ok := expected.(map[string]interface{})
			if !ok {
				return false
			}
			if matchConditions(sub, context) {
				return false
			}
		default:
			actual, ok := context[key]
			if !ok {
				return false
			}
			if !matchValue(expected, actual) {
				return false
			}
		}
	}
	return true
}

func toConditionList(v interface{}) ([]map[string]interface{}, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result = append(result, m)
	}
	return result, true
}

func matchValue(expected, actual interface{}) bool {
	if ops, ok := expected.(map[string]interface{}); ok {
		return matchComparison(ops, actual)
	}
	return valuesEqual(expected, actual)
}

func matchComparison(ops map[string]interface{}, actual interface{}) bool {
	actualFloat, isFloat := toFloat64(actual)
	for op, expected := range ops {
		switch op {
		case "$gt":
			ev, ok := toFloat64(expected)
			if !ok || !isFloat || !(actualFloat > ev) {
				return false
			}
		case "$gte":
			ev, ok := toFloat64(expected)
			if !ok || !isFloat || !(actualFloat >= ev) {
				return false
			}
		case "$lt":
			ev, ok := toFloat64(expected)
			if !ok || !isFloat || !(actualFloat < ev) {
				return false
			}
		case "$lte":
			ev, ok := toFloat64(expected)
			if !ok || !isFloat || !(actualFloat <= ev) {
				return false
			}
		case "$ne":
			if valuesEqual(expected, actual) {
				return false
			}
		case "$in":
			arr, ok := expected.([]interface{})
			if !ok {
				return false
			}
			found := false
			for _, item := range arr {
				if valuesEqual(item, actual) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func valuesEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	default:
		return false
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrPolicyDenied is returned when a governed operation is rejected by policy.
var ErrPolicyDenied = errors.New("policy denied action")

// GovernedOperation is the common request envelope for middleware-based integrations.
type GovernedOperation struct {
	AgentID  string
	Action   string
	ToolName string
	Message  string
	Input    map[string]interface{}
	Metadata map[string]interface{}
	Output   interface{}
}

// OperationHandler executes a governed operation.
type OperationHandler func(*GovernedOperation) error

// OperationMiddleware composes around a handler.
type OperationMiddleware func(OperationHandler) OperationHandler

// GovernanceMiddlewareStack executes a chain of middleware around an operation.
type GovernanceMiddlewareStack struct {
	middlewares []OperationMiddleware
}

// NewGovernanceMiddlewareStack creates an empty stack.
func NewGovernanceMiddlewareStack() *GovernanceMiddlewareStack {
	return &GovernanceMiddlewareStack{
		middlewares: make([]OperationMiddleware, 0),
	}
}

// Use appends middleware to the stack.
func (s *GovernanceMiddlewareStack) Use(middleware OperationMiddleware) {
	if middleware != nil {
		s.middlewares = append(s.middlewares, middleware)
	}
}

// Execute runs the middleware stack and final handler.
func (s *GovernanceMiddlewareStack) Execute(operation *GovernedOperation, final OperationHandler) error {
	handler := final
	if handler == nil {
		handler = func(*GovernedOperation) error { return nil }
	}
	for index := len(s.middlewares) - 1; index >= 0; index-- {
		handler = s.middlewares[index](handler)
	}
	return handler(operation)
}

// MiddlewareStackConfig configures a standard governance middleware stack.
type MiddlewareStackConfig struct {
	Policy                    *PolicyEngine
	Audit                     *AuditLogger
	SLO                       *SLOEngine
	SLOObjective              string
	AllowedTools              []string
	DeniedTools               []string
	PromptDefense             *PromptDefenseEvaluator
	PromptDefenseMaxRiskScore int
}

// CreateGovernanceMiddlewareStack creates a composed stack similar to the Python middleware factory.
func CreateGovernanceMiddlewareStack(config MiddlewareStackConfig) (*GovernanceMiddlewareStack, error) {
	if config.Policy == nil {
		return nil, fmt.Errorf("governance middleware stack requires a policy engine")
	}
	if config.SLO != nil && config.SLOObjective != "" && !config.SLO.HasObjective(config.SLOObjective) {
		return nil, fmt.Errorf("unknown slo objective %q", config.SLOObjective)
	}

	stack := NewGovernanceMiddlewareStack()
	if config.Audit != nil {
		stack.Use(AuditTrailMiddleware(config.Audit))
	}
	stack.Use(PolicyEvaluationMiddleware(config.Policy))
	if len(config.AllowedTools) > 0 || len(config.DeniedTools) > 0 {
		stack.Use(CapabilityGuardMiddleware(config.AllowedTools, config.DeniedTools))
	}
	if config.PromptDefense != nil {
		stack.Use(PromptDefenseMiddleware(config.PromptDefense, config.PromptDefenseMaxRiskScore))
	}
	if config.SLO != nil && config.SLOObjective != "" {
		stack.Use(SLOTrackingMiddleware(config.SLO, config.SLOObjective))
	}
	return stack, nil
}

// PolicyEvaluationMiddleware enforces policy before the next handler executes.
func PolicyEvaluationMiddleware(policy *PolicyEngine) OperationMiddleware {
	return func(next OperationHandler) OperationHandler {
		return func(operation *GovernedOperation) error {
			if policy == nil {
				return fmt.Errorf("policy middleware requires a policy engine")
			}

			context := operationContext(operation)
			action := operation.Action
			if action == "" {
				action = defaultString(operation.ToolName, "operation.execute")
			}
			decision := policy.Evaluate(action, context)
			ensureOperationMetadata(operation)
			operation.Metadata["policy_decision"] = decision
			if decision != Allow {
				return fmt.Errorf("%w: %s", ErrPolicyDenied, action)
			}
			return next(operation)
		}
	}
}

// CapabilityGuardMiddleware enforces allow/deny lists on tool usage.
func CapabilityGuardMiddleware(allowedTools []string, deniedTools []string) OperationMiddleware {
	allowedSet := stringSet(allowedTools)
	deniedSet := stringSet(deniedTools)

	return func(next OperationHandler) OperationHandler {
		return func(operation *GovernedOperation) error {
			toolName := defaultString(operation.ToolName, operation.Action)
			if toolName == "" {
				return next(operation)
			}
			if deniedSet[toolName] {
				return fmt.Errorf("%w: tool %q denied", ErrPolicyDenied, toolName)
			}
			if len(allowedSet) > 0 && !allowedSet[toolName] {
				return fmt.Errorf("%w: tool %q not in allowed list", ErrPolicyDenied, toolName)
			}
			return next(operation)
		}
	}
}

// PromptDefenseMiddleware evaluates prompt content before execution.
func PromptDefenseMiddleware(evaluator *PromptDefenseEvaluator, maxRiskScore int) OperationMiddleware {
	if maxRiskScore <= 0 {
		maxRiskScore = 24
	}

	return func(next OperationHandler) OperationHandler {
		return func(operation *GovernedOperation) error {
			if evaluator == nil {
				return next(operation)
			}

			prompt := operation.Message
			if prompt == "" {
				prompt = stringifyOperationInput(operation.Input)
			}
			if prompt == "" {
				return next(operation)
			}

			result := evaluator.Evaluate(prompt)
			ensureOperationMetadata(operation)
			operation.Metadata["prompt_defense"] = result
			if result.RiskScore > maxRiskScore {
				return fmt.Errorf("%w: prompt defense risk score %d exceeded max %d", ErrPolicyDenied, result.RiskScore, maxRiskScore)
			}
			return next(operation)
		}
	}
}

// AuditTrailMiddleware records start and completion audit entries.
func AuditTrailMiddleware(audit *AuditLogger) OperationMiddleware {
	return func(next OperationHandler) OperationHandler {
		return func(operation *GovernedOperation) error {
			if audit == nil {
				return next(operation)
			}

			agentID := defaultString(operation.AgentID, "unknown")
			action := defaultString(operation.Action, defaultString(operation.ToolName, "operation.execute"))
			startEntry := audit.Log(agentID, action+".start", Allow)
			ensureOperationMetadata(operation)
			operation.Metadata["audit_entry_id"] = startEntry.Hash

			err := next(operation)
			decision := Allow
			if err != nil {
				decision = Deny
			}
			audit.Log(agentID, action+".complete", decision)
			return err
		}
	}
}

// SLOTrackingMiddleware records operation outcomes against an SLO objective.
func SLOTrackingMiddleware(slo *SLOEngine, objective string) OperationMiddleware {
	return func(next OperationHandler) OperationHandler {
		return func(operation *GovernedOperation) error {
			if slo == nil || objective == "" {
				return next(operation)
			}

			start := time.Now()
			err := next(operation)
			recordErr := slo.RecordEvent(objective, err == nil, time.Since(start))
			if recordErr != nil {
				if err != nil {
					return errors.Join(err, recordErr)
				}
				return recordErr
			}
			return err
		}
	}
}

// HTTPMiddlewareConfig configures the net/http governance middleware.
type HTTPMiddlewareConfig struct {
	Policy         *PolicyEngine
	Audit          *AuditLogger
	SLO            *SLOEngine
	SLOObjective   string
	ActionResolver func(*http.Request) string
	ContextBuilder func(*http.Request) map[string]interface{}
	AllowedTools   []string
	DeniedTools    []string
	PromptDefense  *PromptDefenseEvaluator
}

// NewHTTPGovernanceMiddleware creates net/http middleware backed by the governance stack.
func NewHTTPGovernanceMiddleware(config HTTPMiddlewareConfig) (func(http.Handler) http.Handler, error) {
	stack, err := CreateGovernanceMiddlewareStack(MiddlewareStackConfig{
		Policy:        config.Policy,
		Audit:         config.Audit,
		SLO:           config.SLO,
		SLOObjective:  config.SLOObjective,
		AllowedTools:  config.AllowedTools,
		DeniedTools:   config.DeniedTools,
		PromptDefense: config.PromptDefense,
	})
	if err != nil {
		return nil, err
	}

	actionResolver := config.ActionResolver
	if actionResolver == nil {
		actionResolver = defaultHTTPActionResolver
	}
	contextBuilder := config.ContextBuilder
	if contextBuilder == nil {
		contextBuilder = defaultHTTPContextBuilder
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			operation := &GovernedOperation{
				AgentID:  r.Header.Get("X-Agent-ID"),
				Action:   actionResolver(r),
				ToolName: actionResolver(r),
				Message:  requestMessage(r),
				Input:    contextBuilder(r),
			}

			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			err := stack.Execute(operation, func(*GovernedOperation) error {
				next.ServeHTTP(recorder, r)
				if recorder.status >= http.StatusBadRequest {
					return fmt.Errorf("http handler returned status %d", recorder.status)
				}
				return nil
			})
			if err == nil {
				return
			}
			if recorder.status != http.StatusOK {
				return
			}
			statusCode := http.StatusForbidden
			if !errors.Is(err, ErrPolicyDenied) {
				statusCode = http.StatusInternalServerError
			}
			http.Error(w, err.Error(), statusCode)
		})
	}, nil
}

// GovernOperation executes a single operation behind the standard governance stack.
func GovernOperation(action string, policyContext map[string]interface{}, policy *PolicyEngine, audit *AuditLogger, slo *SLOEngine, sloObjective string, operation func() error) error {
	stack, err := CreateGovernanceMiddlewareStack(MiddlewareStackConfig{
		Policy:       policy,
		Audit:        audit,
		SLO:          slo,
		SLOObjective: sloObjective,
	})
	if err != nil {
		return err
	}
	return stack.Execute(&GovernedOperation{
		AgentID:  stringValueFromContext(policyContext, "agent_id", "agent", ""),
		Action:   action,
		ToolName: action,
		Input:    policyContext,
	}, func(*GovernedOperation) error {
		return operation()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func defaultHTTPActionResolver(request *http.Request) string {
	return "http." + strings.ToLower(request.Method)
}

func defaultHTTPContextBuilder(request *http.Request) map[string]interface{} {
	return map[string]interface{}{
		"agent_id":       request.Header.Get("X-Agent-ID"),
		"method":         request.Method,
		"path":           request.URL.Path,
		"host":           request.Host,
		"user_agent":     request.UserAgent(),
		"content_length": request.ContentLength,
	}
}

func requestMessage(request *http.Request) string {
	return strings.TrimSpace(strings.Join([]string{request.Method, request.URL.Path, request.URL.RawQuery}, " "))
}

func operationContext(operation *GovernedOperation) map[string]interface{} {
	context := make(map[string]interface{})
	for key, value := range operation.Input {
		context[key] = value
	}
	if operation.AgentID != "" {
		context["agent_id"] = operation.AgentID
	}
	if operation.Action != "" {
		context["action"] = operation.Action
	}
	if operation.ToolName != "" {
		context["tool_name"] = operation.ToolName
	}
	if operation.Message != "" {
		context["message"] = operation.Message
	}
	return context
}

func ensureOperationMetadata(operation *GovernedOperation) {
	if operation.Metadata == nil {
		operation.Metadata = make(map[string]interface{})
	}
}

func stringifyOperationInput(input map[string]interface{}) string {
	if len(input) == 0 {
		return ""
	}
	parts := make([]string, 0, len(input))
	for key, value := range input {
		parts = append(parts, fmt.Sprintf("%s=%v", key, value))
	}
	sortStrings(parts)
	return strings.Join(parts, " ")
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result[trimmed] = true
		}
	}
	return result
}

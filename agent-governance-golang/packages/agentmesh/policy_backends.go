// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	stdcontext "context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// OPAMode controls how an OPA/Rego backend evaluates policies.
type OPAMode string

const (
	OPAAuto    OPAMode = "auto"
	OPARemote  OPAMode = "remote"
	OPACLI     OPAMode = "cli"
	OPABuiltin OPAMode = "builtin"
)

// OPAOptions configures an OPA/Rego backend.
type OPAOptions struct {
	Mode        OPAMode
	OPAURL      string
	RegoPath    string
	RegoContent string
	Package     string
	Query       string
	Timeout     time.Duration
	// AllowBuiltinFallback permits auto mode to use the builtin evaluator when the OPA CLI is unavailable.
	AllowBuiltinFallback bool
}

// OPABackend evaluates execution contexts using OPA/Rego.
type OPABackend struct {
	mode        OPAMode
	opaURL      string
	regoContent string
	packageName string
	query       string
	timeout     time.Duration
	httpClient  *http.Client
	allowBuiltinFallback bool
}

var opaLookPath = exec.LookPath

// NewOPABackend creates an OPA/Rego backend.
func NewOPABackend(options OPAOptions) *OPABackend {
	regoContent := options.RegoContent
	if regoContent == "" && options.RegoPath != "" {
		data, err := os.ReadFile(options.RegoPath)
		if err == nil {
			regoContent = string(data)
		}
	}

	mode := options.Mode
	if mode == "" {
		mode = OPAAuto
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	packageName := options.Package
	if packageName == "" {
		packageName = "agentmesh"
	}

	query := options.Query
	if query == "" {
		query = fmt.Sprintf("data.%s.allow", packageName)
	}

	opaURL := options.OPAURL
	if opaURL == "" {
		opaURL = "http://localhost:8181"
	}

	return &OPABackend{
		mode:        mode,
		opaURL:      strings.TrimRight(opaURL, "/"),
		regoContent: regoContent,
		packageName: packageName,
		query:       query,
		timeout:     timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		allowBuiltinFallback: options.AllowBuiltinFallback,
	}
}

// Name returns the backend name.
func (b *OPABackend) Name() string {
	return "opa"
}

// Evaluate evaluates the given context using the configured OPA backend mode.
func (b *OPABackend) Evaluate(context map[string]interface{}) (BackendDecision, error) {
	start := time.Now()
	result, err := b.evaluateWithMode(context)
	result.Backend = b.Name()
	result.EvaluationMs = time.Since(start).Seconds() * 1000
	return result, err
}

func (b *OPABackend) evaluateWithMode(context map[string]interface{}) (BackendDecision, error) {
	switch b.mode {
	case OPARemote:
		return b.evaluateRemote(context)
	case OPACLI:
		return b.evaluateCLI(context)
	case OPABuiltin:
		return b.evaluateBuiltin(context)
	default:
		if b.regoContent == "" {
			return BackendDecision{}, fmt.Errorf("opa backend requires rego content or file")
		}
		if _, err := opaLookPath("opa"); err == nil {
			return b.evaluateCLI(context)
		}
		if b.allowBuiltinFallback {
			result, err := b.evaluateBuiltin(context)
			if err != nil {
				return BackendDecision{}, err
			}
			result.Reason = fmt.Sprintf("%s (auto fallback enabled)", result.Reason)
			return result, nil
		}
		return BackendDecision{}, fmt.Errorf("opa auto mode requires the opa CLI; use builtin mode explicitly or set AllowBuiltinFallback to true")
	}
}

func (b *OPABackend) evaluateRemote(context map[string]interface{}) (BackendDecision, error) {
	pathParts := strings.Replace(strings.TrimPrefix(b.query, "data."), ".", "/", -1)
	url := fmt.Sprintf("%s/v1/data/%s", b.opaURL, pathParts)

	payload, err := json.Marshal(map[string]interface{}{
		"input": context,
	})
	if err != nil {
		return BackendDecision{}, fmt.Errorf("marshalling opa payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return BackendDecision{}, fmt.Errorf("creating opa request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return BackendDecision{}, fmt.Errorf("calling opa server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return BackendDecision{}, fmt.Errorf("reading opa response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return BackendDecision{}, fmt.Errorf("opa server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return BackendDecision{}, fmt.Errorf("decoding opa response: %w", err)
	}

	allowed := extractOPAAllowed(decoded)
	return BackendDecision{
		Allowed:   allowed,
		Decision:  boolToDecision(allowed),
		Reason:    fmt.Sprintf("OPA remote (%s): %s", b.packageName, decisionVerb(allowed)),
		RawResult: decoded,
	}, nil
}

func (b *OPABackend) evaluateCLI(context map[string]interface{}) (BackendDecision, error) {
	if b.regoContent == "" {
		return BackendDecision{}, fmt.Errorf("opa cli mode requires rego content or file")
	}

	tempDir, err := os.MkdirTemp("", "agentmesh-opa-*")
	if err != nil {
		return BackendDecision{}, fmt.Errorf("creating opa temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	regoPath := filepath.Join(tempDir, "policy.rego")
	inputPath := filepath.Join(tempDir, "input.json")

	if err := os.WriteFile(regoPath, []byte(b.regoContent), 0644); err != nil {
		return BackendDecision{}, fmt.Errorf("writing rego file: %w", err)
	}

	inputJSON, err := json.Marshal(context)
	if err != nil {
		return BackendDecision{}, fmt.Errorf("marshalling opa input: %w", err)
	}
	if err := os.WriteFile(inputPath, inputJSON, 0644); err != nil {
		return BackendDecision{}, fmt.Errorf("writing opa input file: %w", err)
	}

	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), b.timeout)
	defer cancel()
	// The trailing `--` stops OPA's flag parser before it reaches the
	// query positional; without it, a query that starts with `-` (e.g.
	// from an attacker-supplied Options.Query) would be interpreted as
	// an OPA flag.
	cmd := exec.CommandContext(
		ctx,
		"opa",
		"eval",
		"--format", "json",
		"--input", inputPath,
		"--data", regoPath,
		"--",
		b.query,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == stdcontext.DeadlineExceeded {
			return BackendDecision{}, fmt.Errorf("opa eval timed out after %s", b.timeout)
		}
		return BackendDecision{}, fmt.Errorf("opa eval failed: %s", strings.TrimSpace(string(output)))
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(output, &decoded); err != nil {
		return BackendDecision{}, fmt.Errorf("decoding opa cli response: %w", err)
	}

	allowed := extractOPAEvalValue(decoded)
	return BackendDecision{
		Allowed:   allowed,
		Decision:  boolToDecision(allowed),
		Reason:    fmt.Sprintf("OPA cli (%s): %s", b.packageName, decisionVerb(allowed)),
		RawResult: decoded,
	}, nil
}

func (b *OPABackend) evaluateBuiltin(context map[string]interface{}) (BackendDecision, error) {
	if b.regoContent == "" {
		return BackendDecision{}, fmt.Errorf("opa builtin mode requires rego content or file")
	}

	targetRule := b.query[strings.LastIndex(b.query, ".")+1:]
	defaults := make(map[string]bool)
	result := false
	inRule := false
	ruleConditions := make([]string, 0)

	for _, line := range strings.Split(b.regoContent, "\n") {
		stripped := strings.TrimSpace(line)
		if strings.HasPrefix(stripped, "default ") {
			parts := strings.SplitN(strings.TrimPrefix(stripped, "default "), "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.EqualFold(strings.TrimSpace(parts[1]), "true")
				defaults[key] = value
			}
		}
	}
	result = defaults[targetRule]

	for _, line := range strings.Split(b.regoContent, "\n") {
		stripped := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(stripped, targetRule+" {"):
			if strings.HasSuffix(stripped, "}") {
				body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(stripped, targetRule+" {"), "}"))
				if evalRegoCondition(body, context) {
					result = true
				}
			} else {
				inRule = true
				ruleConditions = ruleConditions[:0]
			}
		case inRule && stripped == "}":
			matched := true
			for _, condition := range ruleConditions {
				if !evalRegoCondition(condition, context) {
					matched = false
					break
				}
			}
			if matched && len(ruleConditions) > 0 {
				result = true
			}
			inRule = false
			ruleConditions = ruleConditions[:0]
		case inRule && stripped != "" && !strings.HasPrefix(stripped, "#"):
			ruleConditions = append(ruleConditions, stripped)
		}
	}

	return BackendDecision{
		Allowed:   result,
		Decision:  boolToDecision(result),
		Reason:    fmt.Sprintf("OPA builtin (%s): %s", b.packageName, decisionVerb(result)),
		RawResult: map[string]interface{}{"parsed": true},
	}, nil
}

func evalRegoCondition(condition string, context map[string]interface{}) bool {
	condition = strings.TrimSpace(strings.TrimSuffix(condition, ";"))
	if condition == "" {
		return false
	}
	if strings.HasPrefix(condition, "not ") {
		return !evalRegoCondition(strings.TrimSpace(strings.TrimPrefix(condition, "not ")), context)
	}
	if strings.Contains(condition, "==") {
		parts := strings.SplitN(condition, "==", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		leftValue := resolveRegoPath(left, context)
		switch right {
		case "true":
			actual, ok := leftValue.(bool)
			return ok && actual
		case "false":
			actual, ok := leftValue.(bool)
			return ok && !actual
		default:
			return fmt.Sprint(leftValue) == right
		}
	}
	if strings.Contains(condition, "!=") {
		parts := strings.SplitN(condition, "!=", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		leftValue := resolveRegoPath(left, context)
		return fmt.Sprint(leftValue) != right
	}
	return truthy(resolveRegoPath(condition, context))
}

func resolveRegoPath(path string, data map[string]interface{}) interface{} {
	current := interface{}(data)
	for _, part := range strings.Split(path, ".") {
		if part == "input" {
			continue
		}
		asMap, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = asMap[part]
	}
	return current
}

func extractOPAAllowed(decoded map[string]interface{}) bool {
	result, ok := decoded["result"]
	if !ok {
		return false
	}
	switch typed := result.(type) {
	case bool:
		return typed
	case map[string]interface{}:
		if allow, ok := typed["allow"].(bool); ok {
			return allow
		}
	}
	return false
}

func extractOPAEvalValue(decoded map[string]interface{}) bool {
	results, ok := decoded["result"].([]interface{})
	if !ok || len(results) == 0 {
		return false
	}
	first, ok := results[0].(map[string]interface{})
	if !ok {
		return false
	}
	expressions, ok := first["expressions"].([]interface{})
	if !ok || len(expressions) == 0 {
		return false
	}
	expression, ok := expressions[0].(map[string]interface{})
	if !ok {
		return false
	}
	value, _ := expression["value"].(bool)
	return value
}

// CedarMode controls how a Cedar backend evaluates policies.
type CedarMode string

const (
	CedarAuto    CedarMode = "auto"
	CedarCLI     CedarMode = "cli"
	CedarBuiltin CedarMode = "builtin"
)

// CedarOptions configures a Cedar backend.
type CedarOptions struct {
	Mode          CedarMode
	PolicyPath    string
	PolicyContent string
	EntitiesPath  string
	Entities      []map[string]interface{}
	SchemaPath    string
	Timeout       time.Duration
	// AllowBuiltinFallback permits auto mode to use the builtin evaluator when the Cedar CLI is unavailable.
	AllowBuiltinFallback bool
}

// CedarBackend evaluates execution contexts using Cedar policies.
type CedarBackend struct {
	mode          CedarMode
	policyContent string
	entities      []map[string]interface{}
	schemaPath    string
	timeout       time.Duration
	allowBuiltinFallback bool
}

var cedarLookPath = exec.LookPath

// NewCedarBackend creates a Cedar backend.
func NewCedarBackend(options CedarOptions) *CedarBackend {
	policyContent := options.PolicyContent
	if policyContent == "" && options.PolicyPath != "" {
		data, err := os.ReadFile(options.PolicyPath)
		if err == nil {
			policyContent = string(data)
		}
	}

	entities := options.Entities
	if len(entities) == 0 && options.EntitiesPath != "" {
		data, err := os.ReadFile(options.EntitiesPath)
		if err == nil {
			_ = json.Unmarshal(data, &entities)
		}
	}

	mode := options.Mode
	if mode == "" {
		mode = CedarAuto
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &CedarBackend{
		mode:          mode,
		policyContent: policyContent,
		entities:      entities,
		schemaPath:    options.SchemaPath,
		timeout:       timeout,
		allowBuiltinFallback: options.AllowBuiltinFallback,
	}
}

// Name returns the backend name.
func (b *CedarBackend) Name() string {
	return "cedar"
}

// Evaluate evaluates the given context using the configured Cedar mode.
func (b *CedarBackend) Evaluate(context map[string]interface{}) (BackendDecision, error) {
	start := time.Now()
	result, err := b.evaluateWithMode(context)
	result.Backend = b.Name()
	result.EvaluationMs = time.Since(start).Seconds() * 1000
	return result, err
}

func (b *CedarBackend) evaluateWithMode(context map[string]interface{}) (BackendDecision, error) {
	switch b.mode {
	case CedarCLI:
		return b.evaluateCLI(context)
	case CedarBuiltin:
		return b.evaluateBuiltin(context)
	default:
		if b.policyContent == "" {
			return BackendDecision{}, fmt.Errorf("cedar backend requires policy content or file")
		}
		if _, err := cedarLookPath("cedar"); err == nil {
			return b.evaluateCLI(context)
		}
		if b.allowBuiltinFallback {
			result, err := b.evaluateBuiltin(context)
			if err != nil {
				return BackendDecision{}, err
			}
			result.Reason = fmt.Sprintf("%s (auto fallback enabled)", result.Reason)
			return result, nil
		}
		return BackendDecision{}, fmt.Errorf("cedar auto mode requires the cedar CLI; use builtin mode explicitly or set AllowBuiltinFallback to true")
	}
}

func (b *CedarBackend) evaluateCLI(context map[string]interface{}) (BackendDecision, error) {
	if b.policyContent == "" {
		return BackendDecision{}, fmt.Errorf("cedar cli mode requires policy content or file")
	}

	tempDir, err := os.MkdirTemp("", "agentmesh-cedar-*")
	if err != nil {
		return BackendDecision{}, fmt.Errorf("creating cedar temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	policyPath := filepath.Join(tempDir, "policy.cedar")
	entitiesPath := filepath.Join(tempDir, "entities.json")
	requestPath := filepath.Join(tempDir, "request.json")

	if err := os.WriteFile(policyPath, []byte(b.policyContent), 0644); err != nil {
		return BackendDecision{}, fmt.Errorf("writing cedar policy: %w", err)
	}

	entityJSON, err := json.Marshal(b.entities)
	if err != nil {
		return BackendDecision{}, fmt.Errorf("marshalling cedar entities: %w", err)
	}
	if err := os.WriteFile(entitiesPath, entityJSON, 0644); err != nil {
		return BackendDecision{}, fmt.Errorf("writing cedar entities: %w", err)
	}

	request := buildCedarRequest(context)
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return BackendDecision{}, fmt.Errorf("marshalling cedar request: %w", err)
	}
	if err := os.WriteFile(requestPath, requestJSON, 0644); err != nil {
		return BackendDecision{}, fmt.Errorf("writing cedar request: %w", err)
	}

	args := []string{
		"authorize",
		"--policies", policyPath,
		"--entities", entitiesPath,
		"--request-json", requestPath,
	}
	if b.schemaPath != "" {
		// Use --flag=value form so a schemaPath that starts with `-`
		// cannot be parsed as a separate flag by cedar's CLI parser.
		args = append(args, fmt.Sprintf("--schema=%s", b.schemaPath))
	}

	ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), b.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cedar", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == stdcontext.DeadlineExceeded {
			return BackendDecision{}, fmt.Errorf("cedar authorize timed out after %s", b.timeout)
		}
		return BackendDecision{}, fmt.Errorf("cedar authorize failed: %s", strings.TrimSpace(string(output)))
	}

	normalized := strings.ToLower(string(output))
	allowed := strings.Contains(normalized, "allow") && !strings.Contains(normalized, "deny")
	return BackendDecision{
		Allowed:   allowed,
		Decision:  boolToDecision(allowed),
		Reason:    fmt.Sprintf("Cedar cli: %s", strings.TrimSpace(string(output))),
		RawResult: map[string]interface{}{"stdout": string(output)},
	}, nil
}

func (b *CedarBackend) evaluateBuiltin(context map[string]interface{}) (BackendDecision, error) {
	if b.policyContent == "" {
		return BackendDecision{}, fmt.Errorf("cedar builtin mode requires policy content or file")
	}

	request := buildCedarRequest(context)
	action := request["action"].(string)
	statements := parseCedarStatements(b.policyContent)
	hasPermit := false

	for _, statement := range statements {
		if statement.ActionConstraint != "" && statement.ActionConstraint != action {
			continue
		}
		if statement.Effect == "forbid" {
			return BackendDecision{
				Allowed:   false,
				Decision:  Deny,
				Reason:    fmt.Sprintf("Cedar builtin: forbid matched for %s", action),
				RawResult: statement,
			}, nil
		}
		if statement.Effect == "permit" {
			hasPermit = true
		}
	}

	return BackendDecision{
		Allowed:   hasPermit,
		Decision:  boolToDecision(hasPermit),
		Reason:    fmt.Sprintf("Cedar builtin: %s", map[bool]string{true: "permit matched", false: "no permit matched (default deny)"}[hasPermit]),
		RawResult: map[string]interface{}{"statements_checked": len(statements)},
	}, nil
}

type cedarStatement struct {
	Effect           string
	ActionConstraint string
	Raw              string
}

func buildCedarRequest(context map[string]interface{}) map[string]interface{} {
	agentID := stringValueFromContext(context, "agent_id", "agent", `Agent::"anonymous"`)
	resource := stringValueFromContext(context, "resource", "", `Resource::"default"`)
	actionName := toolToCedarAction(stringValueFromContext(context, "tool_name", "action", "unknown"))

	if !strings.Contains(agentID, "::") {
		agentID = fmt.Sprintf(`Agent::"%s"`, agentID)
	}
	if !strings.Contains(resource, "::") {
		resource = fmt.Sprintf(`Resource::"%s"`, resource)
	}

	requestContext := make(map[string]interface{}, len(context))
	for key, value := range context {
		if key == "agent_id" || key == "agent" || key == "tool_name" || key == "action" || key == "resource" {
			continue
		}
		requestContext[key] = value
	}

	return map[string]interface{}{
		"principal": agentID,
		"action":    fmt.Sprintf(`Action::"%s"`, actionName),
		"resource":  resource,
		"context":   requestContext,
	}
}

func parseCedarStatements(content string) []cedarStatement {
	pattern := regexp.MustCompile(`(?s)(permit|forbid)\s*\((.*?)\)\s*;`)
	actionPattern := regexp.MustCompile(`action\s*==\s*Action::"([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(content, -1)
	statements := make([]cedarStatement, 0, len(matches))

	for _, match := range matches {
		constraint := ""
		if actionMatch := actionPattern.FindStringSubmatch(match[2]); len(actionMatch) == 2 {
			constraint = fmt.Sprintf(`Action::"%s"`, actionMatch[1])
		}
		statements = append(statements, cedarStatement{
			Effect:           match[1],
			ActionConstraint: constraint,
			Raw:              match[0],
		})
	}

	return statements
}

func toolToCedarAction(toolName string) string {
	splitter := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	parts := splitter.Split(toolName, -1)
	builder := strings.Builder{}
	for _, part := range parts {
		if part == "" {
			continue
		}
		builder.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			builder.WriteString(strings.ToLower(part[1:]))
		}
	}
	if builder.Len() == 0 {
		return "Unknown"
	}
	return builder.String()
}

func stringValueFromContext(context map[string]interface{}, primary string, fallback string, defaultValue string) string {
	keys := []string{primary}
	if fallback != "" {
		keys = append(keys, fallback)
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if value, ok := context[key]; ok {
			if asString, ok := value.(string); ok && asString != "" {
				return asString
			}
		}
	}
	return defaultValue
}

func boolToDecision(allowed bool) PolicyDecision {
	if allowed {
		return Allow
	}
	return Deny
}

func decisionVerb(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}

func truthy(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed != "" && !strings.EqualFold(typed, "false")
	case nil:
		return false
	default:
		return true
	}
}

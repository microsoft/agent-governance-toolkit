// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// DetectionBasis describes how a discovery finding was produced.
type DetectionBasis string

const (
	DetectionProcess    DetectionBasis = "process"
	DetectionConfigFile DetectionBasis = "config_file"
	DetectionGitHubRepo DetectionBasis = "github_repo"
)

// AgentStatus describes the governance state of a discovered agent.
type AgentStatus string

const (
	AgentStatusRegistered   AgentStatus = "registered"
	AgentStatusUnregistered AgentStatus = "unregistered"
	AgentStatusShadow       AgentStatus = "shadow"
	AgentStatusUnknown      AgentStatus = "unknown"
)

// DiscoveryEvidence captures a single supporting signal for a discovered agent.
type DiscoveryEvidence struct {
	Scanner    string                 `json:"scanner"`
	Basis      DetectionBasis         `json:"basis"`
	Source     string                 `json:"source"`
	Detail     string                 `json:"detail"`
	RawData    map[string]interface{} `json:"raw_data,omitempty"`
	Confidence float64                `json:"confidence"`
	Timestamp  time.Time              `json:"timestamp"`
}

// DiscoveredAgent represents a logical agent merged across one or more observations.
type DiscoveredAgent struct {
	Fingerprint string              `json:"fingerprint"`
	Name        string              `json:"name"`
	AgentType   string              `json:"agent_type"`
	Description string              `json:"description,omitempty"`
	DID         string              `json:"did,omitempty"`
	Owner       string              `json:"owner,omitempty"`
	Status      AgentStatus         `json:"status"`
	Evidence    []DiscoveryEvidence `json:"evidence,omitempty"`
	Confidence  float64             `json:"confidence"`
	MergeKeys   map[string]string   `json:"merge_keys,omitempty"`
	Tags        map[string]string   `json:"tags,omitempty"`
	FirstSeenAt time.Time           `json:"first_seen_at"`
	LastSeenAt  time.Time           `json:"last_seen_at"`
}

// AddEvidence appends evidence and updates the aggregate confidence and timestamps.
func (a *DiscoveredAgent) AddEvidence(evidence DiscoveryEvidence) {
	a.Evidence = append(a.Evidence, evidence)
	if evidence.Confidence > a.Confidence {
		a.Confidence = evidence.Confidence
	}
	if a.FirstSeenAt.IsZero() || evidence.Timestamp.Before(a.FirstSeenAt) {
		a.FirstSeenAt = evidence.Timestamp
	}
	if evidence.Timestamp.After(a.LastSeenAt) {
		a.LastSeenAt = evidence.Timestamp
	}
}

// ComputeDiscoveryFingerprint returns a stable deduplication key from merge keys.
func ComputeDiscoveryFingerprint(mergeKeys map[string]string) string {
	parts := make([]string, 0, len(mergeKeys))
	for key, value := range mergeKeys {
		parts = append(parts, key+"="+value)
	}
	sortStrings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(hash[:])[:16]
}

// DiscoveryScanResult is the result of a single scanner execution.
type DiscoveryScanResult struct {
	ScannerName    string            `json:"scanner_name"`
	Agents         []DiscoveredAgent `json:"agents,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
	StartedAt      time.Time         `json:"started_at"`
	CompletedAt    time.Time         `json:"completed_at"`
	ScannedTargets int               `json:"scanned_targets"`
}

// DiscoveryFinding describes a low-level text hit for callers that only need raw findings.
type DiscoveryFinding struct {
	Category string `json:"category"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Line     int    `json:"line"`
	Evidence string `json:"evidence"`
}

type discoveryRule struct {
	category   string
	id         string
	severity   string
	agentType  string
	confidence float64
	pattern    *regexp.Regexp
}

type configPattern struct {
	glob       string
	agentType  string
	confidence float64
}

type processSignature struct {
	pattern    *regexp.Regexp
	agentType  string
	nameHint   string
	confidence float64
}

// ProcessInfo is a caller-supplied process description for passive scanning.
type ProcessInfo struct {
	PID         int
	CommandLine string
	Host        string
}

// GitHubDiscoveryClient performs read-only GitHub API calls for repository scanning.
type GitHubDiscoveryClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewGitHubDiscoveryClient creates a GitHub API client using the standard public API.
func NewGitHubDiscoveryClient(token string) *GitHubDiscoveryClient {
	return &GitHubDiscoveryClient{
		BaseURL: "https://api.github.com",
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

var (
	discoveryRules = []discoveryRule{
		{category: "credential", id: "openai-api-key", severity: "high", agentType: "openai-agents", confidence: 0.7, pattern: regexp.MustCompile(`(?i)\bOPENAI_API_KEY\b`)},
		{category: "credential", id: "anthropic-api-key", severity: "high", agentType: "unknown", confidence: 0.7, pattern: regexp.MustCompile(`(?i)\bANTHROPIC_API_KEY\b`)},
		{category: "framework", id: "langchain", severity: "medium", agentType: "langchain", confidence: 0.8, pattern: regexp.MustCompile(`(?i)\blangchain|langgraph|langserve\b`)},
		{category: "framework", id: "crewai", severity: "medium", agentType: "crewai", confidence: 0.8, pattern: regexp.MustCompile(`(?i)\bcrewai|crew\.run\b`)},
		{category: "framework", id: "autogen", severity: "medium", agentType: "autogen", confidence: 0.8, pattern: regexp.MustCompile(`(?i)\bautogen|groupchat\b`)},
		{category: "framework", id: "semantic-kernel", severity: "medium", agentType: "semantic-kernel", confidence: 0.8, pattern: regexp.MustCompile(`(?i)\bsemantic[-_. ]kernel|sk_agent\b`)},
		{category: "framework", id: "google-adk", severity: "medium", agentType: "google-adk", confidence: 0.75, pattern: regexp.MustCompile(`(?i)\bgoogle.*adk|genai.*agent\b`)},
		{category: "protocol", id: "mcp-server", severity: "medium", agentType: "mcp-server", confidence: 0.85, pattern: regexp.MustCompile(`(?i)\bmcp(?:[_\-. ]server)?|model context protocol\b`)},
		{category: "framework", id: "agentmesh", severity: "medium", agentType: "agt", confidence: 0.9, pattern: regexp.MustCompile(`(?i)\bagentmesh|agent[._ -]?governance|agent[._ -]?os\b`)},
		{category: "framework", id: "llamaindex", severity: "medium", agentType: "llamaindex", confidence: 0.75, pattern: regexp.MustCompile(`(?i)\bllamaindex|llama\.index\b`)},
		{category: "framework", id: "pydantic-ai", severity: "medium", agentType: "pydantic-ai", confidence: 0.75, pattern: regexp.MustCompile(`(?i)\bpydantic\.?ai\b`)},
	}

	configPatterns = []configPattern{
		{glob: "agentmesh.yaml", agentType: "agt", confidence: 0.95},
		{glob: "agentmesh.yml", agentType: "agt", confidence: 0.95},
		{glob: ".agentmesh/config.yaml", agentType: "agt", confidence: 0.95},
		{glob: "agent-governance.yaml", agentType: "agt", confidence: 0.9},
		{glob: "crewai.yaml", agentType: "crewai", confidence: 0.9},
		{glob: "crewai.yml", agentType: "crewai", confidence: 0.9},
		{glob: "mcp.json", agentType: "mcp-server", confidence: 0.85},
		{glob: "mcp-config.json", agentType: "mcp-server", confidence: 0.85},
		{glob: ".mcp/config.json", agentType: "mcp-server", confidence: 0.85},
		{glob: "claude_desktop_config.json", agentType: "mcp-server", confidence: 0.8},
		{glob: ".copilot-setup-steps.yml", agentType: "copilot-agent", confidence: 0.8},
		{glob: "copilot-setup-steps.yml", agentType: "copilot-agent", confidence: 0.8},
	}

	processSignatures = []processSignature{
		{pattern: regexp.MustCompile(`(?i)langchain|langgraph|langserve`), agentType: "langchain", nameHint: "LangChain Agent", confidence: 0.85},
		{pattern: regexp.MustCompile(`(?i)crewai|crew\.run`), agentType: "crewai", nameHint: "CrewAI Agent", confidence: 0.85},
		{pattern: regexp.MustCompile(`(?i)autogen|groupchat`), agentType: "autogen", nameHint: "AutoGen Agent", confidence: 0.8},
		{pattern: regexp.MustCompile(`(?i)openai.*agents|swarm`), agentType: "openai-agents", nameHint: "OpenAI Agents SDK", confidence: 0.8},
		{pattern: regexp.MustCompile(`(?i)semantic[._ -]?kernel|sk_agent`), agentType: "semantic-kernel", nameHint: "Semantic Kernel Agent", confidence: 0.85},
		{pattern: regexp.MustCompile(`(?i)agentmesh|agent[._ -]?os|agent[._ -]?governance`), agentType: "agt", nameHint: "AGT Governed Agent", confidence: 0.95},
		{pattern: regexp.MustCompile(`(?i)mcp[._ -]?server|model[._ -]?context[._ -]?protocol`), agentType: "mcp-server", nameHint: "MCP Server", confidence: 0.9},
		{pattern: regexp.MustCompile(`(?i)llamaindex|llama\.index`), agentType: "llamaindex", nameHint: "LlamaIndex Agent", confidence: 0.8},
		{pattern: regexp.MustCompile(`(?i)pydantic\.?ai`), agentType: "pydantic-ai", nameHint: "PydanticAI Agent", confidence: 0.8},
		{pattern: regexp.MustCompile(`(?i)google.*adk|genai.*agent`), agentType: "google-adk", nameHint: "Google ADK Agent", confidence: 0.75},
	}

	discoverySecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password|credential|auth)[=:\s]+)\S+`),
		regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`gh[pous]_[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`xox[bapors]-[a-zA-Z0-9\-]+`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+`),
	}

	dependencyFiles = []string{"requirements.txt", "pyproject.toml", "package.json", "go.mod"}

	skipDiscoveryDirs = map[string]bool{
		".git": true, "node_modules": true, "__pycache__": true, ".venv": true, "venv": true,
		".tox": true, ".mypy_cache": true, ".pytest_cache": true, "dist": true, "build": true,
		".eggs": true, "vendor": true, "target": true, "bin": true, "obj": true,
	}
)

// ShadowDiscoveryScanner provides SDK-level discovery scanners for text, process, filesystem, and GitHub sources.
type ShadowDiscoveryScanner struct {
	rules []discoveryRule
}

// NewShadowDiscoveryScanner creates a scanner with built-in discovery heuristics.
func NewShadowDiscoveryScanner() *ShadowDiscoveryScanner {
	return &ShadowDiscoveryScanner{
		rules: append([]discoveryRule(nil), discoveryRules...),
	}
}

// ScanText returns low-level findings from a text blob.
func (s *ShadowDiscoveryScanner) ScanText(source string, content string) []DiscoveryFinding {
	lines := strings.Split(content, "\n")
	findings := make([]DiscoveryFinding, 0)
	for lineIndex, line := range lines {
		for _, rule := range s.rules {
			if rule.pattern.MatchString(line) {
				findings = append(findings, DiscoveryFinding{
					Category: rule.category,
					RuleID:   rule.id,
					Severity: rule.severity,
					Source:   source,
					Line:     lineIndex + 1,
					Evidence: strings.TrimSpace(redactDiscoverySecrets(line)),
				})
			}
		}
	}
	return findings
}

// ScanProcessCommands returns low-level findings from supplied command lines.
func (s *ShadowDiscoveryScanner) ScanProcessCommands(commands []string) []DiscoveryFinding {
	findings := make([]DiscoveryFinding, 0)
	for index, command := range commands {
		findings = append(findings, s.ScanText(fmt.Sprintf("process[%d]", index), command)...)
	}
	return findings
}

// ScanDirectory returns low-level findings from a repository or folder tree.
func (s *ShadowDiscoveryScanner) ScanDirectory(root string) ([]DiscoveryFinding, error) {
	findings := make([]DiscoveryFinding, 0)
	errs := make([]error, 0)

	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if entry.IsDir() {
			if shouldSkipDiscoveryDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldScanDiscoveryFile(path) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errs = append(errs, readErr)
			return nil
		}
		findings = append(findings, s.ScanText(path, string(data))...)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}

	return findings, errors.Join(errs...)
}

// ScanProcesses returns merged discovered agents from caller-supplied process metadata.
func (s *ShadowDiscoveryScanner) ScanProcesses(processes []ProcessInfo) DiscoveryScanResult {
	result := DiscoveryScanResult{
		ScannerName:    "process",
		StartedAt:      time.Now().UTC(),
		ScannedTargets: len(processes),
	}
	agentsByFingerprint := make(map[string]*DiscoveredAgent)

	for _, process := range processes {
		cmdline := strings.ToLower(process.CommandLine)
		for _, signature := range processSignatures {
			if !signature.pattern.MatchString(cmdline) {
				continue
			}

			mergeKeys := map[string]string{
				"pid":     fmt.Sprintf("%d", process.PID),
				"cmdline": truncateForFingerprint(process.CommandLine, 200),
			}
			fingerprint := ComputeDiscoveryFingerprint(mergeKeys)

			agent, ok := agentsByFingerprint[fingerprint]
			if !ok {
				agent = &DiscoveredAgent{
					Fingerprint: fingerprint,
					Name:        fmt.Sprintf("%s (PID %d)", signature.nameHint, process.PID),
					AgentType:   signature.agentType,
					Description: fmt.Sprintf("Detected via process signature %q", signature.pattern.String()),
					Status:      AgentStatusUnknown,
					MergeKeys:   mergeKeys,
					Tags:        map[string]string{"pid": fmt.Sprintf("%d", process.PID), "host": defaultString(process.Host, "localhost")},
				}
				agentsByFingerprint[fingerprint] = agent
			}

			agent.AddEvidence(DiscoveryEvidence{
				Scanner:    "process",
				Basis:      DetectionProcess,
				Source:     fmt.Sprintf("PID %d", process.PID),
				Detail:     fmt.Sprintf("Command line matches %s", signature.agentType),
				RawData:    map[string]interface{}{"cmdline_redacted": truncateForFingerprint(redactDiscoverySecrets(process.CommandLine), 500)},
				Confidence: signature.confidence,
				Timestamp:  time.Now().UTC(),
			})
			break
		}
	}

	result.Agents = flattenDiscoveredAgents(agentsByFingerprint)
	result.CompletedAt = time.Now().UTC()
	return result
}

// ScanCurrentHostProcessList scans the current machine's process command lines using OS-native tools.
func (s *ShadowDiscoveryScanner) ScanCurrentHostProcessList() DiscoveryScanResult {
	processes, err := currentHostProcesses()
	result := s.ScanProcesses(processes)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	return result
}

// ScanConfigPaths scans directories for agent configs, containers, and dependency markers.
func (s *ShadowDiscoveryScanner) ScanConfigPaths(paths []string, maxDepth int) DiscoveryScanResult {
	result := DiscoveryScanResult{
		ScannerName:    "config",
		StartedAt:      time.Now().UTC(),
		ScannedTargets: len(paths),
	}
	if maxDepth <= 0 {
		maxDepth = 10
	}

	agentsByFingerprint := make(map[string]*DiscoveredAgent)
	for _, scanRoot := range paths {
		root := filepath.Clean(scanRoot)
		if stat, err := os.Stat(root); err != nil || !stat.IsDir() {
			result.Errors = append(result.Errors, fmt.Sprintf("not a directory: %s", scanRoot))
			continue
		}

		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return nil
			}
			if entry.IsDir() {
				if shouldSkipDiscoveryDir(entry.Name()) {
					return filepath.SkipDir
				}
				depth, depthErr := relativeDepth(root, path)
				if depthErr == nil && depth > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}

			relPath, _ := filepath.Rel(root, path)
			lowerRelPath := filepath.ToSlash(strings.ToLower(relPath))
			filename := strings.ToLower(entry.Name())

			for _, pattern := range configPatterns {
				if filename == strings.ToLower(filepath.Base(pattern.glob)) || strings.HasSuffix(lowerRelPath, strings.ToLower(filepath.ToSlash(pattern.glob))) {
					mergeKeys := map[string]string{"config_path": path}
					agent := upsertDiscoveredAgent(agentsByFingerprint, mergeKeys, DiscoveredAgent{
						Fingerprint: ComputeDiscoveryFingerprint(mergeKeys),
						Name:        fmt.Sprintf("%s agent at %s", pattern.agentType, filepath.ToSlash(relPath)),
						AgentType:   pattern.agentType,
						Description: fmt.Sprintf("Config file found: %s", filepath.ToSlash(relPath)),
						Status:      AgentStatusUnknown,
						MergeKeys:   mergeKeys,
						Tags:        map[string]string{"root": root, "config_file": filepath.ToSlash(relPath)},
					})
					agent.AddEvidence(DiscoveryEvidence{
						Scanner:    "config",
						Basis:      DetectionConfigFile,
						Source:     path,
						Detail:     fmt.Sprintf("Agent config file: %s", entry.Name()),
						RawData:    map[string]interface{}{"path": path, "type": pattern.agentType},
						Confidence: pattern.confidence,
						Timestamp:  time.Now().UTC(),
					})
				}
			}

			if shouldInspectDiscoveryContent(entry.Name()) {
				content, readErr := os.ReadFile(path)
				if readErr != nil {
					result.Errors = append(result.Errors, readErr.Error())
					return nil
				}
				trimmed := string(content)
				for _, rule := range s.rules {
					if !rule.pattern.MatchString(trimmed) {
						continue
					}
					mergeKeys := map[string]string{"content_path": path, "rule_id": rule.id}
					agent := upsertDiscoveredAgent(agentsByFingerprint, mergeKeys, DiscoveredAgent{
						Fingerprint: ComputeDiscoveryFingerprint(mergeKeys),
						Name:        fmt.Sprintf("%s signal in %s", rule.agentType, filepath.ToSlash(relPath)),
						AgentType:   defaultString(rule.agentType, "unknown"),
						Description: fmt.Sprintf("Discovery signal %s found in %s", rule.id, filepath.ToSlash(relPath)),
						Status:      AgentStatusUnknown,
						MergeKeys:   mergeKeys,
						Tags:        map[string]string{"root": root, "source_file": filepath.ToSlash(relPath)},
					})
					agent.AddEvidence(DiscoveryEvidence{
						Scanner:    "config",
						Basis:      DetectionConfigFile,
						Source:     path,
						Detail:     fmt.Sprintf("Discovery rule %s matched", rule.id),
						RawData:    map[string]interface{}{"path": path, "rule_id": rule.id},
						Confidence: rule.confidence,
						Timestamp:  time.Now().UTC(),
					})
				}
			}

			if isDependencyFile(entry.Name()) {
				content, readErr := os.ReadFile(path)
				if readErr != nil {
					result.Errors = append(result.Errors, readErr.Error())
					return nil
				}
				lowerContent := strings.ToLower(string(content))
				for _, rule := range s.rules {
					if !rule.pattern.MatchString(lowerContent) || rule.agentType == "" {
						continue
					}
					mergeKeys := map[string]string{"repo_path": path, "dependency": rule.id}
					agent := upsertDiscoveredAgent(agentsByFingerprint, mergeKeys, DiscoveredAgent{
						Fingerprint: ComputeDiscoveryFingerprint(mergeKeys),
						Name:        fmt.Sprintf("%s dependency in %s", rule.agentType, filepath.ToSlash(relPath)),
						AgentType:   rule.agentType,
						Description: fmt.Sprintf("Dependency or package signal %q found in %s", rule.id, filepath.ToSlash(relPath)),
						Status:      AgentStatusUnknown,
						MergeKeys:   mergeKeys,
						Tags:        map[string]string{"root": root, "dependency_file": filepath.ToSlash(relPath)},
					})
					agent.AddEvidence(DiscoveryEvidence{
						Scanner:    "config",
						Basis:      DetectionConfigFile,
						Source:     path,
						Detail:     fmt.Sprintf("Dependency signal %s found in %s", rule.id, entry.Name()),
						RawData:    map[string]interface{}{"path": path, "dependency": rule.id},
						Confidence: rule.confidence,
						Timestamp:  time.Now().UTC(),
					})
				}
			}

			return nil
		})
		if walkErr != nil {
			result.Errors = append(result.Errors, walkErr.Error())
		}
	}

	result.Agents = flattenDiscoveredAgents(agentsByFingerprint)
	result.CompletedAt = time.Now().UTC()
	return result
}

// ScanGitHubRepositories scans GitHub repositories for configs and dependency markers.
func (s *ShadowDiscoveryScanner) ScanGitHubRepositories(client *GitHubDiscoveryClient, repos []string) DiscoveryScanResult {
	result := DiscoveryScanResult{
		ScannerName:    "github",
		StartedAt:      time.Now().UTC(),
		ScannedTargets: len(repos),
	}
	if client == nil {
		result.Errors = append(result.Errors, "github discovery client is required")
		result.CompletedAt = time.Now().UTC()
		return result
	}

	agentsByFingerprint := make(map[string]*DiscoveredAgent)
	for _, repo := range repos {
		for _, pattern := range configPatterns {
			content, err := client.getRepositoryFile(repo, pattern.glob)
			if err == nil && content != "" {
				mergeKeys := map[string]string{"repo": repo, "config_path": pattern.glob}
				agent := upsertDiscoveredAgent(agentsByFingerprint, mergeKeys, DiscoveredAgent{
					Fingerprint: ComputeDiscoveryFingerprint(mergeKeys),
					Name:        fmt.Sprintf("%s agent in %s", pattern.agentType, repo),
					AgentType:   pattern.agentType,
					Description: fmt.Sprintf("Config file %s found in %s", pattern.glob, repo),
					Status:      AgentStatusUnknown,
					MergeKeys:   mergeKeys,
					Tags:        map[string]string{"repo": repo, "config_file": pattern.glob},
				})
				agent.AddEvidence(DiscoveryEvidence{
					Scanner:    "github",
					Basis:      DetectionGitHubRepo,
					Source:     fmt.Sprintf("https://github.com/%s/blob/main/%s", repo, pattern.glob),
					Detail:     fmt.Sprintf("Agent config file %s exists", pattern.glob),
					RawData:    map[string]interface{}{"repo": repo, "path": pattern.glob},
					Confidence: pattern.confidence,
					Timestamp:  time.Now().UTC(),
				})
				_ = content
			}
		}

		for _, dependencyFile := range dependencyFiles {
			content, err := client.getRepositoryFile(repo, dependencyFile)
			if err != nil || content == "" {
				continue
			}
			lowerContent := strings.ToLower(content)
			for _, rule := range s.rules {
				if !rule.pattern.MatchString(lowerContent) || rule.agentType == "" {
					continue
				}
				mergeKeys := map[string]string{"repo": repo, "dep_file": dependencyFile, "dependency": rule.id}
				agent := upsertDiscoveredAgent(agentsByFingerprint, mergeKeys, DiscoveredAgent{
					Fingerprint: ComputeDiscoveryFingerprint(mergeKeys),
					Name:        fmt.Sprintf("%s dependency in %s", rule.agentType, repo),
					AgentType:   rule.agentType,
					Description: fmt.Sprintf("Dependency %q found in %s", rule.id, dependencyFile),
					Status:      AgentStatusUnknown,
					MergeKeys:   mergeKeys,
					Tags:        map[string]string{"repo": repo, "dependency_file": dependencyFile},
				})
				agent.AddEvidence(DiscoveryEvidence{
					Scanner:    "github",
					Basis:      DetectionGitHubRepo,
					Source:     fmt.Sprintf("https://github.com/%s/blob/main/%s", repo, dependencyFile),
					Detail:     fmt.Sprintf("Dependency signal %s found in %s", rule.id, dependencyFile),
					RawData:    map[string]interface{}{"repo": repo, "dep_file": dependencyFile, "dependency": rule.id},
					Confidence: rule.confidence,
					Timestamp:  time.Now().UTC(),
				})
			}
		}
	}

	result.Agents = flattenDiscoveredAgents(agentsByFingerprint)
	result.CompletedAt = time.Now().UTC()
	return result
}

// ListOrganizationRepositories lists repositories for a GitHub organization.
func (c *GitHubDiscoveryClient) ListOrganizationRepositories(org string) ([]string, error) {
	repositories := make([]string, 0)
	page := 1
	for {
		path := fmt.Sprintf("/orgs/%s/repos?per_page=100&page=%d&type=all", org, page)
		body, err := c.doRequest(path)
		if err != nil {
			return nil, err
		}
		var payload []struct {
			FullName string `json:"full_name"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("decoding github repo list: %w", err)
		}
		if len(payload) == 0 {
			break
		}
		for _, repository := range payload {
			repositories = append(repositories, repository.FullName)
		}
		if len(payload) < 100 {
			break
		}
		page++
	}
	return repositories, nil
}

func (c *GitHubDiscoveryClient) getRepositoryFile(repo string, path string) (string, error) {
	body, err := c.doRequest(fmt.Sprintf("/repos/%s/contents/%s", repo, path))
	if err != nil {
		return "", err
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decoding github content response: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("decoding github content payload: %w", err)
	}
	return string(decoded), nil
}

func (c *GitHubDiscoveryClient) doRequest(path string) ([]byte, error) {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating github request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("calling github api: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading github api response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("github api returned %d", response.StatusCode)
	}
	return body, nil
}

func currentHostProcesses() ([]ProcessInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return currentWindowsProcesses()
	default:
		return currentUnixProcesses()
	}
}

func currentWindowsProcesses() ([]ProcessInfo, error) {
	command := exec.Command(
		"powershell",
		"-NoProfile",
		"-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress",
	)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("listing windows processes: %w", err)
	}

	type windowsProcess struct {
		ProcessID   int    `json:"ProcessId"`
		CommandLine string `json:"CommandLine"`
	}

	processes := make([]windowsProcess, 0)
	if len(strings.TrimSpace(string(output))) == 0 {
		return nil, nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(output)), "[") {
		if err := json.Unmarshal(output, &processes); err != nil {
			return nil, fmt.Errorf("decoding windows process list: %w", err)
		}
	} else {
		var single windowsProcess
		if err := json.Unmarshal(output, &single); err != nil {
			return nil, fmt.Errorf("decoding windows process list: %w", err)
		}
		processes = append(processes, single)
	}

	discovered := make([]ProcessInfo, 0, len(processes))
	for _, process := range processes {
		if strings.TrimSpace(process.CommandLine) == "" {
			continue
		}
		discovered = append(discovered, ProcessInfo{
			PID:         process.ProcessID,
			CommandLine: redactDiscoverySecrets(process.CommandLine),
			Host:        os.Getenv("COMPUTERNAME"),
		})
	}
	return discovered, nil
}

func currentUnixProcesses() ([]ProcessInfo, error) {
	command := exec.Command("ps", "-axo", "pid=,command=")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("listing unix processes: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	processes := make([]ProcessInfo, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid := 0
		fmt.Sscanf(fields[0], "%d", &pid)
		commandLine := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		processes = append(processes, ProcessInfo{
			PID:         pid,
			CommandLine: redactDiscoverySecrets(commandLine),
			Host:        "localhost",
		})
	}
	return processes, nil
}

func flattenDiscoveredAgents(agents map[string]*DiscoveredAgent) []DiscoveredAgent {
	result := make([]DiscoveredAgent, 0, len(agents))
	for _, agent := range agents {
		result = append(result, *agent)
	}
	sortDiscoveredAgents(result)
	return result
}

func upsertDiscoveredAgent(agents map[string]*DiscoveredAgent, mergeKeys map[string]string, candidate DiscoveredAgent) *DiscoveredAgent {
	fingerprint := ComputeDiscoveryFingerprint(mergeKeys)
	if existing, ok := agents[fingerprint]; ok {
		return existing
	}
	candidate.Fingerprint = fingerprint
	agents[fingerprint] = &candidate
	return &candidate
}

func redactDiscoverySecrets(text string) string {
	redacted := text
	for _, pattern := range discoverySecretPatterns {
		redacted = pattern.ReplaceAllString(redacted, "[REDACTED]")
	}
	return redacted
}

func shouldSkipDiscoveryDir(name string) bool {
	return skipDiscoveryDirs[strings.ToLower(name)]
}

func shouldScanDiscoveryFile(path string) bool {
	if strings.EqualFold(filepath.Base(path), ".env") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".py", ".go", ".js", ".ts", ".md", ".env":
		return true
	default:
		return false
	}
}

func shouldInspectDiscoveryContent(filename string) bool {
	switch strings.ToLower(filename) {
	case "dockerfile", "docker-compose.yml", "docker-compose.yaml", "requirements.txt", "pyproject.toml", "package.json", "go.mod":
		return true
	default:
		return shouldScanDiscoveryFile(filename)
	}
}

func isDependencyFile(filename string) bool {
	lower := strings.ToLower(filename)
	for _, candidate := range dependencyFiles {
		if lower == strings.ToLower(candidate) {
			return true
		}
	}
	return false
}

func relativeDepth(root string, path string) (int, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return 0, err
	}
	if relative == "." {
		return 0, nil
	}
	return len(strings.Split(filepath.ToSlash(relative), "/")), nil
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func truncateForFingerprint(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func sortStrings(values []string) {
	for index := 0; index < len(values); index++ {
		for inner := index + 1; inner < len(values); inner++ {
			if values[inner] < values[index] {
				values[index], values[inner] = values[inner], values[index]
			}
		}
	}
}

func sortDiscoveredAgents(values []DiscoveredAgent) {
	for index := 0; index < len(values); index++ {
		for inner := index + 1; inner < len(values); inner++ {
			if values[inner].Fingerprint < values[index].Fingerprint {
				values[index], values[inner] = values[inner], values[index]
			}
		}
	}
}

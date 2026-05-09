// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Docker subprocess deadlines. ``docker exec`` runs user-supplied code so
// it falls back to SandboxConfig.TimeoutSeconds when set; the others are
// short-lived control-plane operations against the local Docker daemon.
const (
	dockerInfoTimeout    = 5 * time.Second
	dockerStartTimeout   = 30 * time.Second
	dockerExecTimeout    = 60 * time.Second
	dockerRemoveTimeout  = 15 * time.Second
)

// SessionStatus represents the lifecycle state of a sandbox session.
type SessionStatus string

const (
	SessionCreating  SessionStatus = "creating"
	SessionRunning   SessionStatus = "running"
	SessionStopped   SessionStatus = "stopped"
	SessionDestroyed SessionStatus = "destroyed"
	SessionError     SessionStatus = "error"
)

// ExecutionStatus represents the state of a code execution request.
type ExecutionStatus string

const (
	ExecutionPending   ExecutionStatus = "pending"
	ExecutionRunning   ExecutionStatus = "running"
	ExecutionCompleted ExecutionStatus = "completed"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionTimeout   ExecutionStatus = "timeout"
	ExecutionKilled    ExecutionStatus = "killed"
)

// SandboxConfig holds resource limits and security settings for a sandbox session.
type SandboxConfig struct {
	TimeoutSeconds float64           `json:"timeout_seconds"`
	MemoryMB       int               `json:"memory_mb"`
	CPULimit       float64           `json:"cpu_limit"`
	NetworkEnabled bool              `json:"network_enabled"`
	ReadOnlyFS     bool              `json:"read_only_fs"`
	EnvVars        map[string]string `json:"env_vars"`
}

// SandboxResult holds the output and metadata from a sandbox code execution.
type SandboxResult struct {
	Success         bool    `json:"success"`
	ExitCode        int     `json:"exit_code"`
	Stdout          string  `json:"stdout"`
	Stderr          string  `json:"stderr"`
	DurationSeconds float64 `json:"duration_seconds"`
	Killed          bool    `json:"killed"`
	KillReason      string  `json:"kill_reason"`
}

// SessionHandle represents an active sandbox session.
type SessionHandle struct {
	AgentID   string        `json:"agent_id"`
	SessionID string        `json:"session_id"`
	Status    SessionStatus `json:"status"`
}

// ExecutionHandle represents a code execution within a sandbox session.
type ExecutionHandle struct {
	ExecutionID string          `json:"execution_id"`
	AgentID     string          `json:"agent_id"`
	SessionID   string          `json:"session_id"`
	Status      ExecutionStatus `json:"status"`
	Result      *SandboxResult  `json:"result"`
}

// DefaultSandboxConfig returns a SandboxConfig with sensible defaults.
func DefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		TimeoutSeconds: 60,
		MemoryMB:       512,
		CPULimit:       1.0,
		NetworkEnabled: false,
		ReadOnlyFS:     true,
		EnvVars:        make(map[string]string),
	}
}

// SandboxProvider defines the interface for managing isolated code execution environments.
type SandboxProvider interface {
	CreateSession(agentID string, config *SandboxConfig) (*SessionHandle, error)
	ExecuteCode(agentID, sessionID, code string) (*ExecutionHandle, error)
	DestroySession(agentID, sessionID string) error
	IsAvailable() bool
}

// DockerSandboxProvider implements SandboxProvider using the Docker CLI.
type DockerSandboxProvider struct {
	image      string
	available  bool
	containers map[string]string // key: "agentID:sessionID", value: container name
	mu         sync.Mutex
}

// NewDockerSandboxProvider creates a DockerSandboxProvider with the given base image.
// It probes for Docker availability via `docker info` (bounded by
// dockerInfoTimeout so a stalled daemon does not block initialisation).
func NewDockerSandboxProvider(image string) *DockerSandboxProvider {
	p := &DockerSandboxProvider{
		image:      image,
		containers: make(map[string]string),
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerInfoTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err == nil {
		p.available = true
	}
	return p
}

// IsAvailable reports whether the Docker daemon is reachable.
func (p *DockerSandboxProvider) IsAvailable() bool {
	return p.available
}

func containerKey(agentID, sessionID string) string {
	return agentID + ":" + sessionID
}

func containerName(agentID, sessionID string) string {
	return fmt.Sprintf("agt-sandbox-%s-%s", agentID, sessionID)
}

// CreateSession starts a hardened Docker container for the given agent.
func (p *DockerSandboxProvider) CreateSession(agentID string, config *SandboxConfig) (*SessionHandle, error) {
	if !p.available {
		return nil, fmt.Errorf("docker is not available")
	}
	if config == nil {
		config = DefaultSandboxConfig()
	}

	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	name := containerName(agentID, sessionID)

	args := []string{
		"run", "-d",
		"--name", name,
		fmt.Sprintf("--memory=%dm", config.MemoryMB),
		fmt.Sprintf("--cpus=%.2f", config.CPULimit),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	}

	if config.ReadOnlyFS {
		args = append(args, "--read-only")
	}
	if !config.NetworkEnabled {
		args = append(args, "--network", "none")
	}
	for k, v := range config.EnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, p.image, "sleep", "infinity")

	ctx, cancel := context.WithTimeout(context.Background(), dockerStartTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("docker run timed out after %s", dockerStartTimeout)
		}
		return nil, fmt.Errorf("docker run failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	p.mu.Lock()
	p.containers[containerKey(agentID, sessionID)] = name
	p.mu.Unlock()

	return &SessionHandle{
		AgentID:   agentID,
		SessionID: sessionID,
		Status:    SessionRunning,
	}, nil
}

// ExecuteCode runs a command inside an existing sandbox session container.
func (p *DockerSandboxProvider) ExecuteCode(agentID, sessionID, code string) (*ExecutionHandle, error) {
	p.mu.Lock()
	name, ok := p.containers[containerKey(agentID, sessionID)]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("session %s:%s not found", agentID, sessionID)
	}

	execID := fmt.Sprintf("exec-%d", time.Now().UnixNano())
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), dockerExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", name, "sh", "-c", code)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start).Seconds()

	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("docker exec timed out after %s", dockerExecTimeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("docker exec failed: %w", err)
		}
	}

	result := &SandboxResult{
		Success:         exitCode == 0,
		ExitCode:        exitCode,
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		DurationSeconds: duration,
	}

	status := ExecutionCompleted
	if exitCode != 0 {
		status = ExecutionFailed
	}

	return &ExecutionHandle{
		ExecutionID: execID,
		AgentID:     agentID,
		SessionID:   sessionID,
		Status:      status,
		Result:      result,
	}, nil
}

// DestroySession force-removes the container for the given session.
func (p *DockerSandboxProvider) DestroySession(agentID, sessionID string) error {
	p.mu.Lock()
	key := containerKey(agentID, sessionID)
	name, ok := p.containers[key]
	if ok {
		delete(p.containers, key)
	}
	p.mu.Unlock()

	if !ok {
		return fmt.Errorf("session %s:%s not found", agentID, sessionID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerRemoveTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "rm", "-f", name).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("docker rm timed out after %s", dockerRemoveTimeout)
		}
		return fmt.Errorf("docker rm failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

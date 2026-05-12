// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"strings"
	"testing"
	"time"
)

// Compile-time interface satisfaction check.
var _ SandboxProvider = (*DockerSandboxProvider)(nil)

func TestDefaultSandboxConfig(t *testing.T) {
	cfg := DefaultSandboxConfig()

	if cfg.TimeoutSeconds != 60 {
		t.Errorf("TimeoutSeconds = %v, want 60", cfg.TimeoutSeconds)
	}
	if cfg.MemoryMB != 512 {
		t.Errorf("MemoryMB = %v, want 512", cfg.MemoryMB)
	}
	if cfg.CPULimit != 1.0 {
		t.Errorf("CPULimit = %v, want 1.0", cfg.CPULimit)
	}
	if cfg.NetworkEnabled {
		t.Error("NetworkEnabled = true, want false")
	}
	if !cfg.ReadOnlyFS {
		t.Error("ReadOnlyFS = false, want true")
	}
	if cfg.EnvVars == nil {
		t.Error("EnvVars is nil, want initialized map")
	}
	if len(cfg.EnvVars) != 0 {
		t.Errorf("EnvVars length = %d, want 0", len(cfg.EnvVars))
	}
}

func TestDockerSandboxProviderNew(t *testing.T) {
	p := NewDockerSandboxProvider("alpine:latest")

	if p.image != "alpine:latest" {
		t.Errorf("image = %q, want %q", p.image, "alpine:latest")
	}
	if p.containers == nil {
		t.Error("containers map is nil, want initialized map")
	}
	// available may be true or false depending on the host; just verify no panic.
	t.Logf("Docker available: %v", p.IsAvailable())
}

func TestNewDockerSandboxProviderDoesNotProbeDocker(t *testing.T) {
	// The constructor must not block on `docker info`. Wall-clock time
	// is the most direct proxy for I/O having happened — a non-zero
	// dockerInfoTimeout would dominate the duration if the probe ran
	// here. The bound is intentionally loose (one tenth of the probe
	// timeout) so we don't false-fail on slow CI.
	start := time.Now()
	p := NewDockerSandboxProvider("alpine:latest")
	elapsed := time.Since(start)
	if p == nil {
		t.Fatal("NewDockerSandboxProvider returned nil")
	}
	if elapsed > dockerInfoTimeout/10 {
		t.Fatalf("constructor took %s (> %s); appears to be probing docker synchronously",
			elapsed, dockerInfoTimeout/10)
	}
}

func TestSandboxProviderInterface(t *testing.T) {
	// This test verifies that DockerSandboxProvider satisfies SandboxProvider at compile time.
	// The var _ declaration above is the actual check; this test ensures it is exercised.
	var provider SandboxProvider = NewDockerSandboxProvider("alpine:latest")
	if provider == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestCreateExecuteDestroy(t *testing.T) {
	p := NewDockerSandboxProvider("alpine:latest")
	if !p.IsAvailable() {
		t.Skip("Docker is not available, skipping integration test")
	}

	cfg := DefaultSandboxConfig()
	session, err := p.CreateSession("test-agent", cfg)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if session.AgentID != "test-agent" {
		t.Errorf("AgentID = %q, want %q", session.AgentID, "test-agent")
	}
	if session.Status != SessionRunning {
		t.Errorf("Status = %q, want %q", session.Status, SessionRunning)
	}

	handle, err := p.ExecuteCode("test-agent", session.SessionID, "echo hello")
	if err != nil {
		t.Fatalf("ExecuteCode failed: %v", err)
	}
	if !handle.Result.Success {
		t.Errorf("Success = false, want true; stderr: %s", handle.Result.Stderr)
	}
	if handle.Result.Stdout != "hello\n" {
		t.Errorf("Stdout = %q, want %q", handle.Result.Stdout, "hello\n")
	}
	if handle.Status != ExecutionCompleted {
		t.Errorf("Status = %q, want %q", handle.Status, ExecutionCompleted)
	}

	err = p.DestroySession("test-agent", session.SessionID)
	if err != nil {
		t.Fatalf("DestroySession failed: %v", err)
	}
}

func TestCreateSessionRejectsInvalidAgentID(t *testing.T) {
	p := &DockerSandboxProvider{available: true, image: "alpine"}
	cases := []string{
		"agent with space",
		"agent$(rm)",
		"agent'name",
		"agent;ls",
		"../etc",
		"",
		"agent\nname",
	}
	for _, agentID := range cases {
		_, err := p.CreateSession(agentID, nil)
		if err == nil {
			t.Errorf("expected error for agentID %q, got nil", agentID)
		}
	}
}

func TestCreateSessionAcceptsValidAgentID(t *testing.T) {
	// Confirms the regex is not over-restrictive on legitimate IDs.
	// If Docker is available the call may succeed; we only assert the
	// regex did not reject the agent ID.
	p := NewDockerSandboxProvider("alpine")
	session, err := p.CreateSession("agent-123_test.local", nil)
	if err != nil && strings.Contains(err.Error(), "invalid agentID") {
		t.Fatalf("regex rejected a valid agentID: %v", err)
	}
	// Clean up if a container was actually created.
	if err == nil && session != nil {
		_ = p.DestroySession(session.AgentID, session.SessionID)
	}
}

func TestRandomHexProducesUniqueValues(t *testing.T) {
	// 1000 consecutive calls must all be distinct. Two collisions from
	// crypto/rand at 16 hex characters (8 bytes) is astronomically
	// unlikely; if this fails, the entropy source is broken.
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		v := randomHex(8)
		if len(v) != 16 {
			t.Fatalf("randomHex(8) returned %d chars, want 16", len(v))
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("randomHex collided after %d iterations: %q", i, v)
		}
		seen[v] = struct{}{}
	}
}

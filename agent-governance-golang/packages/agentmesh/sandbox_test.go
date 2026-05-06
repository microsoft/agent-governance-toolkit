// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"testing"
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

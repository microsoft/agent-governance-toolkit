// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShadowDiscoveryScannerScanText(t *testing.T) {
	scanner := NewShadowDiscoveryScanner()
	findings := scanner.ScanText("sample.env", "OPENAI_API_KEY=secret\nfrom langchain import PromptTemplate")
	if len(findings) < 2 {
		t.Fatalf("findings = %d, want at least 2", len(findings))
	}
}

func TestShadowDiscoveryScannerScanProcesses(t *testing.T) {
	scanner := NewShadowDiscoveryScanner()
	result := scanner.ScanProcesses([]ProcessInfo{{
		PID:         42,
		CommandLine: "python -m langchain.agent --api_key=secret",
		Host:        "test-host",
	}})
	if len(result.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(result.Agents))
	}
	if got := result.Agents[0].AgentType; got != "langchain" {
		t.Fatalf("agent type = %q, want langchain", got)
	}
	if evidence := result.Agents[0].Evidence[0].RawData["cmdline_redacted"]; !strings.Contains(evidence.(string), "[REDACTED]") {
		t.Fatalf("expected redacted command line, got %v", evidence)
	}
}

func TestShadowDiscoveryScannerScanConfigPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agentmesh.yaml"), []byte("name: test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("langchain==1.0.0"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	scanner := NewShadowDiscoveryScanner()
	result := scanner.ScanConfigPaths([]string{dir}, 5)
	if len(result.Agents) < 2 {
		t.Fatalf("agents = %d, want at least 2", len(result.Agents))
	}
}

func TestShadowDiscoveryScannerScanGitHubRepositories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/octo/demo/contents/agentmesh.yaml":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content": base64.StdEncoding.EncodeToString([]byte("name: demo")),
			})
		case "/repos/octo/demo/contents/requirements.txt":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content": base64.StdEncoding.EncodeToString([]byte("langchain==1.0.0")),
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGitHubDiscoveryClient("")
	client.BaseURL = server.URL

	scanner := NewShadowDiscoveryScanner()
	result := scanner.ScanGitHubRepositories(client, []string{"octo/demo"})
	if len(result.Agents) < 2 {
		t.Fatalf("agents = %d, want at least 2", len(result.Agents))
	}
}

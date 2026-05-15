// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddEvidenceCombinesConfidenceViaNoisyOR(t *testing.T) {
	agent := &DiscoveredAgent{}
	agent.AddEvidence(DiscoveryEvidence{Confidence: 0.5, Timestamp: time.Unix(1, 0)})
	if math.Abs(agent.Confidence-0.5) > 1e-9 {
		t.Fatalf("after one 0.5 evidence: Confidence = %v, want 0.5", agent.Confidence)
	}
	agent.AddEvidence(DiscoveryEvidence{Confidence: 0.5, Timestamp: time.Unix(2, 0)})
	// 1 - (1 - 0.5) * (1 - 0.5) = 0.75
	if math.Abs(agent.Confidence-0.75) > 1e-9 {
		t.Fatalf("after two 0.5 evidences: Confidence = %v, want 0.75", agent.Confidence)
	}
	agent.AddEvidence(DiscoveryEvidence{Confidence: 0.5, Timestamp: time.Unix(3, 0)})
	// 1 - (1 - 0.75) * (1 - 0.5) = 0.875
	if math.Abs(agent.Confidence-0.875) > 1e-9 {
		t.Fatalf("after three 0.5 evidences: Confidence = %v, want 0.875", agent.Confidence)
	}
}

func TestAddEvidenceSaturatesAtOne(t *testing.T) {
	agent := &DiscoveredAgent{Confidence: 1.0}
	agent.AddEvidence(DiscoveryEvidence{Confidence: 0.9, Timestamp: time.Unix(1, 0)})
	if agent.Confidence != 1.0 {
		t.Fatalf("Confidence = %v after combining 1.0 with 0.9, want 1.0", agent.Confidence)
	}
}

func TestAddEvidenceClampsOutOfRangeInputs(t *testing.T) {
	// Negative confidence clamps to 0 — should not move the aggregate.
	agent := &DiscoveredAgent{Confidence: 0.5}
	agent.AddEvidence(DiscoveryEvidence{Confidence: -1.0, Timestamp: time.Unix(1, 0)})
	if agent.Confidence != 0.5 {
		t.Fatalf("Confidence = %v after combining 0.5 with -1.0 (clamps to 0), want 0.5", agent.Confidence)
	}
	// > 1 clamps to 1 — should saturate the aggregate.
	agent.AddEvidence(DiscoveryEvidence{Confidence: 5.0, Timestamp: time.Unix(2, 0)})
	if agent.Confidence != 1.0 {
		t.Fatalf("Confidence = %v after combining 0.5 with 5.0 (clamps to 1), want 1.0", agent.Confidence)
	}
}

func TestAddEvidenceLowConfidencesCorroborate(t *testing.T) {
	// The whole point of this change: ten 0.1 hits should aggregate
	// well above 0.1 (which the old max() implementation produced).
	agent := &DiscoveredAgent{}
	for i := 0; i < 10; i++ {
		agent.AddEvidence(DiscoveryEvidence{Confidence: 0.1, Timestamp: time.Unix(int64(i+1), 0)})
	}
	// 1 - 0.9^10 ≈ 0.6513
	if agent.Confidence < 0.6 || agent.Confidence > 0.7 {
		t.Fatalf("Confidence = %v after ten 0.1 evidences, want ~0.65", agent.Confidence)
	}
}

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


func TestBuildContentsAPIPath(t *testing.T) {
	cases := []struct {
		name    string
		repo    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "plain repo and path", repo: "octo/demo", path: "agentmesh.yaml", want: "/repos/octo/demo/contents/agentmesh.yaml"},
		{name: "nested path keeps separators", repo: "octo/demo", path: "src/config/agentmesh.yaml", want: "/repos/octo/demo/contents/src/config/agentmesh.yaml"},
		{name: "repo segment with slash blocked", repo: "octo/demo/extra", path: "a.yaml", want: "/repos/octo/demo%2Fextra/contents/a.yaml"},
		{name: "path segment with traversal escaped", repo: "octo/demo", path: "..%2F..%2Fevil", want: "/repos/octo/demo/contents/..%252F..%252Fevil"},
		{name: "query injection escaped", repo: "octo/demo", path: "file?ref=main", want: "/repos/octo/demo/contents/file%3Fref=main"},
		{name: "fragment injection escaped", repo: "octo/demo", path: "file#frag", want: "/repos/octo/demo/contents/file%23frag"},
		{name: "empty repo rejected", repo: "", path: "a", wantErr: true},
		{name: "single-segment repo rejected", repo: "justname", path: "a", wantErr: true},
		{name: "empty owner rejected", repo: "/name", path: "a", wantErr: true},
		{name: "empty name rejected", repo: "owner/", path: "a", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildContentsAPIPath(tc.repo, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

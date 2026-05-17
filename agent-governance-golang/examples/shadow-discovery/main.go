// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang/packages/agentmesh"
)

func main() {
	scanner := agentmesh.NewShadowDiscoveryScanner()

	// 1. ScanText: low-level pattern hits in arbitrary content.
	textFindings := scanner.ScanText("inline.py", "import langchain\nOPENAI_API_KEY=sk-test-not-real\n")
	fmt.Printf("ScanText: %d findings\n", len(textFindings))
	for _, f := range textFindings {
		fmt.Printf("  [%s/%s] %s:%d %s\n", f.Category, f.Severity, f.Source, f.Line, f.Evidence)
	}

	// 2. ScanProcessCommands: scan a slice of supplied command lines.
	commands := []string{
		"/usr/bin/python -m crewai.run",
		"node /opt/agent/mcp-server.js",
		"/bin/bash -lc echo hi",
	}
	procFindings := scanner.ScanProcessCommands(commands)
	fmt.Printf("\nScanProcessCommands: %d findings\n", len(procFindings))
	for _, f := range procFindings {
		fmt.Printf("  [%s/%s] %s %s\n", f.Category, f.Severity, f.Source, f.Evidence)
	}

	// 3. ScanConfigPaths: walk a real directory tree. We build a small
	// fixture in a temp dir so the example is self-contained.
	root := buildFixture()
	defer os.RemoveAll(root)

	result := scanner.ScanConfigPaths([]string{root}, 5)
	fmt.Printf("\nScanConfigPaths: scanner=%s scanned=%d agents=%d errors=%d\n",
		result.ScannerName, result.ScannedTargets, len(result.Agents), len(result.Errors))
	for _, agent := range result.Agents {
		fmt.Printf("  %-25s type=%-12s confidence=%.2f evidence=%d\n",
			agent.Name, agent.AgentType, agent.Confidence, len(agent.Evidence))
	}
}

func buildFixture() string {
	root, err := os.MkdirTemp("", "agentmesh-discovery-*")
	if err != nil {
		log.Fatalf("creating fixture: %v", err)
	}
	files := map[string]string{
		"agentmesh.yaml": "agent_id: did:agentmesh:demo\n",
		"src/handler.py": "from langchain import agents\n",
		"mcp.json":       `{"server": "demo-mcp"}`,
	}
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatalf("creating fixture dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			log.Fatalf("writing fixture file: %v", err)
		}
	}
	return root
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Generator
 * 
 * Generates agent code from natural language descriptions.
 * Supports Python, TypeScript, and Go output.
 */

import { logger } from './logger';

export interface AgentSpec {
    name: string;
    description: string;
    tasks: string[];
    dataSources: string[];
    outputs: string[];
    schedule?: string;
    policies: PolicyRecommendation[];
}

export interface PolicyRecommendation {
    name: string;
    type: string;
    description: string;
    required: boolean;
    config?: Record<string, any>;
}

export interface GeneratedAgent {
    spec: AgentSpec;
    code: {
        python?: string;
        typescript?: string;
        go?: string;
    };
    policies: string;
    workflowYaml?: string;
    tests?: string;
}

export type SupportedLanguage = 'python' | 'typescript' | 'go';

export class AgentGenerator {
    
    /**
     * Parse natural language task description into structured agent spec
     */
    parseTaskDescription(description: string): AgentSpec {
        const words = description.toLowerCase();
        
        // Extract agent name from description
        const name = this.extractAgentName(description);
        
        // Detect data sources
        const dataSources = this.detectDataSources(words);
        
        // Detect output targets
        const outputs = this.detectOutputs(words);
        
        // Detect schedule requirements
        const schedule = this.detectSchedule(words);
        
        // Decompose into tasks
        const tasks = this.decomposeIntoTasks(description, dataSources, outputs);
        
        // Recommend policies based on detected features
        const policies = this.recommendPolicies(dataSources, outputs, words);
        
        return {
            name,
            description,
            tasks,
            dataSources,
            outputs,
            schedule,
            policies
        };
    }

    /**
     * Generate agent code from spec
     */
    async generateAgent(
        spec: AgentSpec,
        language: SupportedLanguage = 'python'
    ): Promise<GeneratedAgent> {
        logger.info('Generating agent', { name: spec.name, language });

        const code: GeneratedAgent['code'] = {};
        
        switch (language) {
            case 'python':
                code.python = this.generatePythonAgent(spec);
                break;
            case 'typescript':
                code.typescript = this.generateTypeScriptAgent(spec);
                break;
            case 'go':
                code.go = this.generateGoAgent(spec);
                break;
        }

        const policies = this.generatePolicyYaml(spec.policies);
        const workflowYaml = spec.schedule ? this.generateGitHubActionsWorkflow(spec) : undefined;
        const tests = this.generateTests(spec, language);

        return {
            spec,
            code,
            policies,
            workflowYaml,
            tests
        };
    }

    /**
     * Generate clarifying questions for incomplete specs
     */
    generateClarifyingQuestions(description: string): string[] {
        const questions: string[] = [];
        const words = description.toLowerCase();

        // Data source questions
        if (!this.detectDataSources(words).length) {
            questions.push('What data sources should this agent read from? (e.g., API, database, file)');
        }

        // Output questions
        if (!this.detectOutputs(words).length) {
            questions.push('Where should the agent send results? (e.g., Slack, email, database)');
        }

        // Schedule questions
        if (!this.detectSchedule(words)) {
            questions.push('How often should this agent run? (e.g., every hour, daily, on-demand)');
        }

        // Authentication questions
        if (words.includes('api') || words.includes('slack') || words.includes('github')) {
            questions.push('Do you have the required API tokens/credentials configured?');
        }

        return questions;
    }

    private extractAgentName(description: string): string {
        // Extract key nouns to form agent name
        const words = description.split(' ');
        const keywords = words.filter(w => 
            w.length > 3 && 
            !['for', 'the', 'that', 'with', 'from', 'this', 'agent'].includes(w.toLowerCase())
        ).slice(0, 3);
        
        return keywords.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
            .join('') + 'Agent';
    }

    private detectDataSources(text: string): string[] {
        const sources: string[] = [];
        
        const sourcePatterns: Record<string, string> = {
            'slack': 'Slack API',
            'github': 'GitHub API',
            'jira': 'Jira API',
            'email': 'Email/IMAP',
            'database': 'Database',
            'sql': 'SQL Database',
            'postgres': 'PostgreSQL',
            'mysql': 'MySQL',
            'mongo': 'MongoDB',
            'api': 'REST API',
            'webhook': 'Webhook',
            'file': 'File System',
            'csv': 'CSV File',
            'excel': 'Excel File',
            's3': 'AWS S3',
            'gcs': 'Google Cloud Storage',
            'azure blob': 'Azure Blob Storage',
            'twitter': 'Twitter API',
            'reddit': 'Reddit API',
            'rss': 'RSS Feed',
            'calendar': 'Calendar API',
        };

        for (const [pattern, source] of Object.entries(sourcePatterns)) {
            if (text.includes(pattern)) {
                sources.push(source);
            }
        }

        return sources;
    }

    private detectOutputs(text: string): string[] {
        const outputs: string[] = [];
        
        const outputPatterns: Record<string, string> = {
            'slack': 'Slack',
            'email': 'Email',
            'database': 'Database',
            'store': 'Database',
            'save': 'Storage',
            'report': 'Report',
            'dashboard': 'Dashboard',
            'notify': 'Notification',
            'alert': 'Alert',
            'webhook': 'Webhook',
            'api': 'API Endpoint',
            'file': 'File',
            'log': 'Logs',
        };

        for (const [pattern, output] of Object.entries(outputPatterns)) {
            if (text.includes(pattern)) {
                outputs.push(output);
            }
        }

        return outputs;
    }

    private detectSchedule(text: string): string | undefined {
        const schedulePatterns: Record<string, string> = {
            'every minute': '* * * * *',
            'every 5 minutes': '*/5 * * * *',
            'every 15 minutes': '*/15 * * * *',
            'every 30 minutes': '*/30 * * * *',
            'hourly': '0 * * * *',
            'every hour': '0 * * * *',
            'every 4 hours': '0 */4 * * *',
            'daily': '0 9 * * *',
            'every day': '0 9 * * *',
            'weekly': '0 9 * * 1',
            'every week': '0 9 * * 1',
            'monthly': '0 9 1 * *',
            'every month': '0 9 1 * *',
            'standup': '0 9 * * 1-5',
            'business hours': '0 9-17 * * 1-5',
        };

        for (const [pattern, cron] of Object.entries(schedulePatterns)) {
            if (text.includes(pattern)) {
                return cron;
            }
        }

        return undefined;
    }

    private decomposeIntoTasks(description: string, dataSources: string[], outputs: string[]): string[] {
        const tasks: string[] = [];

        // Input tasks
        for (const source of dataSources) {
            tasks.push(`Read data from ${source}`);
        }

        // Processing tasks based on keywords
        const text = description.toLowerCase();
        if (text.includes('analyze') || text.includes('sentiment')) {
            tasks.push('Analyze and process data');
        }
        if (text.includes('summarize') || text.includes('summary')) {
            tasks.push('Generate summary');
        }
        if (text.includes('filter') || text.includes('select')) {
            tasks.push('Filter relevant items');
        }
        if (text.includes('transform') || text.includes('convert')) {
            tasks.push('Transform data format');
        }
        if (text.includes('validate') || text.includes('check')) {
            tasks.push('Validate data');
        }

        // Output tasks
        for (const output of outputs) {
            tasks.push(`Send results to ${output}`);
        }

        // Default if no specific tasks detected
        if (tasks.length === 0) {
            tasks.push('Process input');
            tasks.push('Generate output');
        }

        return tasks;
    }

    private recommendPolicies(dataSources: string[], outputs: string[], text: string): PolicyRecommendation[] {
        const policies: PolicyRecommendation[] = [];

        // Rate limiting for API sources
        if (dataSources.some(s => s.includes('API'))) {
            policies.push({
                name: 'API Rate Limiting',
                type: 'rate_limit',
                description: 'Limits API calls to prevent quota exhaustion',
                required: true,
                config: { requests_per_minute: 60 }
            });
        }

        // Data privacy for sensitive data
        if (text.includes('customer') || text.includes('user') || text.includes('personal')) {
            policies.push({
                name: 'PII Protection',
                type: 'data_privacy',
                description: 'Redacts personally identifiable information',
                required: true,
                config: { redact_pii: true }
            });
        }

        // Authentication requirement
        if (dataSources.some(s => ['Slack API', 'GitHub API', 'Jira API'].includes(s))) {
            policies.push({
                name: 'Authentication Required',
                type: 'auth',
                description: 'Requires valid API token',
                required: true
            });
        }

        // Retry policy for external services
        if (dataSources.length > 0 || outputs.length > 0) {
            policies.push({
                name: 'Retry with Backoff',
                type: 'retry',
                description: 'Retries failed operations with exponential backoff',
                required: false,
                config: { max_retries: 3, backoff_multiplier: 2 }
            });
        }

        // Logging policy
        policies.push({
            name: 'Audit Logging',
            type: 'logging',
            description: 'Logs all agent actions for audit trail',
            required: true
        });

        return policies;
    }

    private generatePythonAgent(spec: AgentSpec): string {
        const envVars = this.getRequiredEnvVars(spec);
        
        return `"""
${spec.name}

${spec.description}

Generated by AgentOS for GitHub Copilot
"""

import os
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

from agent_os import KernelSpace
from agent_os.integrations import create_safe_toolkit

# Initialize kernel with safety policies
kernel = KernelSpace(policy="strict")
toolkit = create_safe_toolkit("standard")

${envVars.map(v => `${v} = os.environ.get("${v}")`).join('\n')}


@kernel.register
async def ${this.toSnakeCase(spec.name)}(task: str) -> Dict[str, Any]:
    """
    Main agent function.
    
    Tasks:
${spec.tasks.map(t => `    - ${t}`).join('\n')}
    """
    results = {
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": []
    }
    
    try:
        # Step 1: Fetch data from sources
${spec.dataSources.map((s, i) => `        data_${i} = await fetch_from_${this.toSnakeCase(s)}()`).join('\n')}
        
        # Step 2: Process data
        processed = await process_data(${spec.dataSources.map((_, i) => `data_${i}`).join(', ')})
        
        # Step 3: Send to outputs
${spec.outputs.map(o => `        await send_to_${this.toSnakeCase(o)}(processed)`).join('\n')}
        
        results["data"] = processed
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
        kernel.logger.error(f"Agent failed: {e}")
    
    return results


${spec.dataSources.map(s => `
async def fetch_from_${this.toSnakeCase(s)}() -> List[Dict]:
    """Fetch data from ${s}."""
    # TODO: Implement ${s} data fetching
    http = toolkit["http"]
    # Example: response = await http.get("https://api.example.com/data")
    return []
`).join('\n')}

${spec.outputs.map(o => `
async def send_to_${this.toSnakeCase(o)}(data: List[Dict]) -> None:
    """Send results to ${o}."""
    # TODO: Implement ${o} output
    pass
`).join('\n')}

async def process_data(*data_sources) -> List[Dict]:
    """Process and transform data."""
    # TODO: Implement data processing logic
    combined = []
    for source in data_sources:
        combined.extend(source)
    return combined


if __name__ == "__main__":
    # Run the agent
    result = asyncio.run(kernel.execute(${this.toSnakeCase(spec.name)}, "run"))
    print(f"Agent completed: {result}")
`;
    }

    private generateTypeScriptAgent(spec: AgentSpec): string {
        const envVars = this.getRequiredEnvVars(spec);
        
        return `/**
 * ${spec.name}
 * 
 * ${spec.description}
 * 
 * Generated by AgentOS for GitHub Copilot
 */

import { KernelSpace, SafeToolkit } from '@agent-os/core';

// Initialize kernel with safety policies
const kernel = new KernelSpace({ policy: 'strict' });
const toolkit = SafeToolkit.create('standard');

${envVars.map(v => `const ${this.toCamelCase(v)} = process.env.${v};`).join('\n')}

interface AgentResult {
    status: 'success' | 'error';
    timestamp: string;
    data: any[];
    error?: string;
}

/**
 * Main agent function.
 * 
 * Tasks:
${spec.tasks.map(t => ` * - ${t}`).join('\n')}
 */
export async function ${this.toCamelCase(spec.name)}(task: string): Promise<AgentResult> {
    const results: AgentResult = {
        status: 'success',
        timestamp: new Date().toISOString(),
        data: []
    };

    try {
        // Step 1: Fetch data from sources
${spec.dataSources.map((s, i) => `        const data${i} = await fetchFrom${this.toPascalCase(s)}();`).join('\n')}

        // Step 2: Process data
        const processed = await processData(${spec.dataSources.map((_, i) => `data${i}`).join(', ')});

        // Step 3: Send to outputs
${spec.outputs.map(o => `        await sendTo${this.toPascalCase(o)}(processed);`).join('\n')}

        results.data = processed;

    } catch (error) {
        results.status = 'error';
        results.error = error instanceof Error ? error.message : String(error);
        console.error(\`Agent failed: \${results.error}\`);
    }

    return results;
}

${spec.dataSources.map(s => `
async function fetchFrom${this.toPascalCase(s)}(): Promise<any[]> {
    // TODO: Implement ${s} data fetching
    const http = toolkit.get('http');
    // Example: const response = await http.get('https://api.example.com/data');
    return [];
}
`).join('\n')}

${spec.outputs.map(o => `
async function sendTo${this.toPascalCase(o)}(data: any[]): Promise<void> {
    // TODO: Implement ${o} output
}
`).join('\n')}

async function processData(...dataSources: any[][]): Promise<any[]> {
    // TODO: Implement data processing logic
    return dataSources.flat();
}

// Register with kernel
kernel.register(${this.toCamelCase(spec.name)});

// Run if executed directly
if (require.main === module) {
    kernel.execute(${this.toCamelCase(spec.name)}, 'run')
        .then(result => console.log('Agent completed:', result))
        .catch(error => console.error('Agent failed:', error));
}
`;
    }

    private generateGoAgent(spec: AgentSpec): string {
        return `// ${spec.name}
//
// ${spec.description}
//
// Generated by AgentOS for GitHub Copilot

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/microsoft/agent-governance-toolkit/go/kernel"
)

type AgentResult struct {
	Status    string      \`json:"status"\`
	Timestamp string      \`json:"timestamp"\`
	Data      []any       \`json:"data"\`
	Error     string      \`json:"error,omitempty"\`
}

func main() {
	// Initialize kernel with safety policies
	k := kernel.New(kernel.WithPolicy("strict"))
	
	// Register agent
	k.Register("${spec.name}", run${this.toPascalCase(spec.name)})
	
	// Execute
	result, err := k.Execute(context.Background(), "${spec.name}", "run")
	if err != nil {
		fmt.Printf("Agent failed: %v\\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Agent completed: %+v\\n", result)
}

// run${this.toPascalCase(spec.name)} is the main agent function.
//
// Tasks:
${spec.tasks.map(t => `//   - ${t}`).join('\n')}
func run${this.toPascalCase(spec.name)}(ctx context.Context, task string) (*AgentResult, error) {
	result := &AgentResult{
		Status:    "success",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      make([]any, 0),
	}

	// Step 1: Fetch data from sources
${spec.dataSources.map((s, i) => `	data${i}, err := fetchFrom${this.toPascalCase(s)}(ctx)
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result, err
	}`).join('\n\n')}

	// Step 2: Process data
	processed, err := processData(${spec.dataSources.map((_, i) => `data${i}`).join(', ')})
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result, err
	}

	// Step 3: Send to outputs
${spec.outputs.map(o => `	if err := sendTo${this.toPascalCase(o)}(ctx, processed); err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result, err
	}`).join('\n\n')}

	result.Data = processed
	return result, nil
}

${spec.dataSources.map(s => `
func fetchFrom${this.toPascalCase(s)}(ctx context.Context) ([]any, error) {
	// TODO: Implement ${s} data fetching
	return nil, nil
}
`).join('\n')}

${spec.outputs.map(o => `
func sendTo${this.toPascalCase(o)}(ctx context.Context, data []any) error {
	// TODO: Implement ${o} output
	return nil
}
`).join('\n')}

func processData(dataSources ...[]any) ([]any, error) {
	// TODO: Implement data processing logic
	var combined []any
	for _, source := range dataSources {
		combined = append(combined, source...)
	}
	return combined, nil
}
`;
    }

    private generatePolicyYaml(policies: PolicyRecommendation[]): string {
        let yaml = `# Agent OS Policy Configuration
# Generated by AgentOS for GitHub Copilot

policies:
`;
        for (const policy of policies) {
            yaml += `  - name: "${policy.name}"
    type: ${policy.type}
    description: "${policy.description}"
    required: ${policy.required}
`;
            if (policy.config) {
                yaml += `    config:
`;
                for (const [key, value] of Object.entries(policy.config)) {
                    yaml += `      ${key}: ${JSON.stringify(value)}
`;
                }
            }
            yaml += '\n';
        }
        return yaml;
    }

    private generateGitHubActionsWorkflow(spec: AgentSpec): string {
        const envVars = this.getRequiredEnvVars(spec);
        
        return `# ${spec.name} - GitHub Actions Workflow
# Generated by AgentOS for GitHub Copilot

name: ${spec.name}

on:
  schedule:
    - cron: '${spec.schedule}'
  workflow_dispatch:  # Allow manual trigger

jobs:
  run-agent:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install agent-os-kernel
          pip install -r requirements.txt
      
      - name: Run Agent
        uses: agentos/run-agent@v1
        with:
          agent: ${this.toSnakeCase(spec.name)}
          policy: production-safe
        env:
${envVars.map(v => `          ${v}: \${{ secrets.${v} }}`).join('\n')}
      
      - name: Upload logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-logs
          path: logs/
          retention-days: 7
`;
    }

    private generateTests(spec: AgentSpec, language: SupportedLanguage): string {
        if (language === 'python') {
            return `"""
Tests for ${spec.name}

Generated by AgentOS for GitHub Copilot
"""

import pytest
from unittest.mock import AsyncMock, patch

from ${this.toSnakeCase(spec.name)} import ${this.toSnakeCase(spec.name)}


@pytest.mark.asyncio
async def test_agent_success():
    """Test agent completes successfully."""
    result = await ${this.toSnakeCase(spec.name)}("test")
    assert result["status"] in ["success", "error"]
    assert "timestamp" in result


@pytest.mark.asyncio
async def test_agent_handles_errors():
    """Test agent handles errors gracefully."""
    with patch('${this.toSnakeCase(spec.name)}.fetch_from_slack_api', side_effect=Exception("API Error")):
        result = await ${this.toSnakeCase(spec.name)}("test")
        assert result["status"] == "error"
        assert "error" in result


@pytest.mark.asyncio
async def test_agent_respects_rate_limits():
    """Test agent respects rate limiting policy."""
    # TODO: Implement rate limit test
    pass


@pytest.mark.asyncio
async def test_agent_redacts_pii():
    """Test agent redacts PII when configured."""
    # TODO: Implement PII redaction test
    pass
`;
        }
        return '';
    }

    private getRequiredEnvVars(spec: AgentSpec): string[] {
        const envVars: string[] = [];
        
        for (const source of spec.dataSources) {
            if (source.includes('Slack')) envVars.push('SLACK_TOKEN');
            if (source.includes('GitHub')) envVars.push('GITHUB_TOKEN');
            if (source.includes('Jira')) envVars.push('JIRA_TOKEN');
            if (source.includes('Database') || source.includes('SQL')) envVars.push('DATABASE_URL');
        }
        
        for (const output of spec.outputs) {
            if (output === 'Slack') envVars.push('SLACK_WEBHOOK_URL');
            if (output === 'Email') envVars.push('SMTP_HOST', 'SMTP_USER', 'SMTP_PASSWORD');
        }
        
        return [...new Set(envVars)];
    }

    private toSnakeCase(str: string): string {
        return str
            .replace(/([A-Z])/g, '_$1')
            .toLowerCase()
            .replace(/^_/, '')
            .replace(/[^a-z0-9_]/g, '_')
            .replace(/_+/g, '_');
    }

    private toCamelCase(str: string): string {
        return str
            .replace(/[^a-zA-Z0-9]/g, ' ')
            .split(' ')
            .map((word, i) => i === 0 ? word.toLowerCase() : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join('');
    }

    private toPascalCase(str: string): string {
        return str
            .replace(/[^a-zA-Z0-9]/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join('');
    }
}

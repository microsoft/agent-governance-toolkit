// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Debug Helper
 * 
 * Provides debugging and troubleshooting capabilities for agents,
 * including error diagnosis, execution trace analysis, and fix suggestions.
 */

import { logger } from './logger';

export interface ErrorDiagnosis {
    errorType: ErrorType;
    summary: string;
    rootCause: string;
    affectedComponent: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    suggestions: FixSuggestion[];
    relatedDocs?: string[];
}

export type ErrorType = 
    | 'policy_violation'
    | 'authentication'
    | 'authorization'
    | 'network'
    | 'timeout'
    | 'rate_limit'
    | 'data_validation'
    | 'resource_exhaustion'
    | 'configuration'
    | 'runtime'
    | 'unknown';

export interface FixSuggestion {
    title: string;
    description: string;
    code?: string;
    confidence: 'high' | 'medium' | 'low';
    effort: 'minimal' | 'moderate' | 'significant';
    automated: boolean;
}

export interface ExecutionTrace {
    id: string;
    timestamp: string;
    agentName: string;
    status: 'success' | 'failure' | 'partial';
    duration: number;
    steps: TraceStep[];
    policyChecks: PolicyCheckResult[];
    resourceUsage: ResourceUsage;
}

export interface TraceStep {
    name: string;
    startTime: string;
    endTime: string;
    duration: number;
    status: 'success' | 'failure' | 'skipped';
    input?: any;
    output?: any;
    error?: string;
}

export interface PolicyCheckResult {
    policyName: string;
    passed: boolean;
    timestamp: string;
    details?: string;
}

export interface ResourceUsage {
    memoryMB: number;
    cpuPercent: number;
    networkCalls: number;
    diskReadMB: number;
    diskWriteMB: number;
}

export interface PerformanceIssue {
    type: 'slow_execution' | 'high_memory' | 'excessive_api_calls' | 'inefficient_loop';
    description: string;
    impact: string;
    location?: string;
    suggestion: string;
}

export class DebugHelper {
    
    /**
     * Diagnose an error from error message/stack
     */
    diagnoseError(error: string | Error, context?: Record<string, any>): ErrorDiagnosis {
        const errorStr = typeof error === 'string' ? error : error.message;
        const stack = typeof error === 'object' && error.stack ? error.stack : '';
        
        // Detect error type
        const errorType = this.detectErrorType(errorStr, stack);
        
        // Generate diagnosis based on type
        const diagnosis = this.generateDiagnosis(errorType, errorStr, context);
        
        logger.info('Error diagnosed', { type: errorType, summary: diagnosis.summary });
        
        return diagnosis;
    }

    /**
     * Explain an execution trace
     */
    explainTrace(trace: ExecutionTrace): string {
        let explanation = `## 📊 Execution Trace Analysis\n\n`;
        explanation += `**Agent:** ${trace.agentName}\n`;
        explanation += `**Status:** ${this.statusEmoji(trace.status)} ${trace.status}\n`;
        explanation += `**Duration:** ${trace.duration}ms\n`;
        explanation += `**Time:** ${trace.timestamp}\n\n`;

        // Steps timeline
        explanation += `### Execution Steps\n\n`;
        explanation += `| Step | Duration | Status |\n`;
        explanation += `|------|----------|--------|\n`;
        
        for (const step of trace.steps) {
            const status = this.statusEmoji(step.status);
            explanation += `| ${step.name} | ${step.duration}ms | ${status} |\n`;
        }

        // Failed steps detail
        const failedSteps = trace.steps.filter(s => s.status === 'failure');
        if (failedSteps.length > 0) {
            explanation += `\n### ❌ Failed Steps\n\n`;
            for (const step of failedSteps) {
                explanation += `**${step.name}**\n`;
                explanation += `- Error: ${step.error}\n`;
                if (step.input) {
                    explanation += `- Input: \`${JSON.stringify(step.input).substring(0, 100)}\`\n`;
                }
                explanation += '\n';
            }
        }

        // Policy checks
        if (trace.policyChecks.length > 0) {
            explanation += `### 🛡️ Policy Checks\n\n`;
            const failedChecks = trace.policyChecks.filter(p => !p.passed);
            if (failedChecks.length > 0) {
                for (const check of failedChecks) {
                    explanation += `- ❌ **${check.policyName}**: ${check.details}\n`;
                }
            } else {
                explanation += `✅ All ${trace.policyChecks.length} policy checks passed\n`;
            }
        }

        // Resource usage
        explanation += `\n### 📈 Resource Usage\n\n`;
        explanation += `| Metric | Value |\n`;
        explanation += `|--------|-------|\n`;
        explanation += `| Memory | ${trace.resourceUsage.memoryMB}MB |\n`;
        explanation += `| CPU | ${trace.resourceUsage.cpuPercent}% |\n`;
        explanation += `| Network Calls | ${trace.resourceUsage.networkCalls} |\n`;
        explanation += `| Disk I/O | ${trace.resourceUsage.diskReadMB + trace.resourceUsage.diskWriteMB}MB |\n`;

        return explanation;
    }

    /**
     * Detect performance issues in code
     */
    detectPerformanceIssues(code: string, language: string): PerformanceIssue[] {
        const issues: PerformanceIssue[] = [];

        // N+1 query pattern
        if (/for.*in.*:\s*\n.*\.query\(|forEach.*=>\s*{[^}]*fetch/i.test(code)) {
            issues.push({
                type: 'excessive_api_calls',
                description: 'Potential N+1 query/API pattern detected',
                impact: 'Multiplies API calls by number of items, causing slow execution',
                suggestion: 'Batch API calls or use bulk fetch operations'
            });
        }

        // Synchronous in loop
        if (/for\s+.*await|\.forEach\(async/i.test(code)) {
            issues.push({
                type: 'slow_execution',
                description: 'Sequential async operations in loop',
                impact: 'Each iteration waits for previous to complete',
                suggestion: 'Use Promise.all() for parallel execution'
            });
        }

        // Large data in memory
        if (/\.readFile\(|json\.load\(|\.fetchAll\(/i.test(code) && !/stream|chunk|batch/i.test(code)) {
            issues.push({
                type: 'high_memory',
                description: 'Loading entire file/dataset into memory',
                impact: 'May cause out-of-memory errors with large data',
                suggestion: 'Use streaming or pagination for large datasets'
            });
        }

        // String concatenation in loop
        if (/for.*:\s*\n.*\+=/i.test(code) && !/\[\]|list|array/i.test(code)) {
            issues.push({
                type: 'inefficient_loop',
                description: 'String concatenation in loop',
                impact: 'Creates new string objects on each iteration',
                suggestion: 'Use list/array and join at the end'
            });
        }

        // No caching
        if (/fetch\(|\.get\(|\.query\(/i.test(code) && !/cache|memo|lru/i.test(code)) {
            issues.push({
                type: 'excessive_api_calls',
                description: 'No caching detected for external calls',
                impact: 'Repeated identical requests increase latency and costs',
                suggestion: 'Add caching for frequently accessed data'
            });
        }

        return issues;
    }

    /**
     * Suggest optimizations for agent code
     */
    suggestOptimizations(code: string, language: string): string {
        const issues = this.detectPerformanceIssues(code, language);
        
        if (issues.length === 0) {
            return `## ✅ No Performance Issues Detected

Your agent code looks well-optimized! Here are some general best practices:

- Use connection pooling for database connections
- Implement retry with exponential backoff
- Add timeout handling for external calls
- Consider adding metrics for monitoring
`;
        }

        let output = `## 🔧 Performance Optimization Suggestions\n\n`;
        output += `Found ${issues.length} potential issue(s):\n\n`;

        for (let i = 0; i < issues.length; i++) {
            const issue = issues[i];
            output += `### ${i + 1}. ${issue.description}\n\n`;
            output += `**Impact:** ${issue.impact}\n\n`;
            output += `**Suggestion:** ${issue.suggestion}\n\n`;
            
            if (issue.location) {
                output += `**Location:** ${issue.location}\n\n`;
            }

            // Add code example for fix
            output += this.getOptimizationExample(issue.type, language);
            output += '\n---\n\n';
        }

        return output;
    }

    /**
     * Generate common error fixes
     */
    getCommonFixes(errorType: ErrorType): FixSuggestion[] {
        const fixMap: Record<ErrorType, FixSuggestion[]> = {
            'policy_violation': [
                {
                    title: 'Request Policy Exception',
                    description: 'Request a one-time exception for this operation',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: true
                },
                {
                    title: 'Modify Code to Comply',
                    description: 'Update the code to follow policy guidelines',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: false
                },
                {
                    title: 'Update Policy Rules',
                    description: 'Adjust policy rules if current ones are too restrictive',
                    confidence: 'medium',
                    effort: 'moderate',
                    automated: false
                }
            ],
            'authentication': [
                {
                    title: 'Verify Credentials',
                    description: 'Check that API keys/tokens are correctly configured',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: false,
                    code: `# Check environment variables
import os
token = os.environ.get('API_TOKEN')
if not token:
    raise ValueError("API_TOKEN not configured")`
                },
                {
                    title: 'Refresh Token',
                    description: 'The token may have expired - generate a new one',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: false
                },
                {
                    title: 'Check Secret Configuration',
                    description: 'Verify secrets are properly set in GitHub Actions',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: false
                }
            ],
            'authorization': [
                {
                    title: 'Check Permissions',
                    description: 'Verify the token has required permissions/scopes',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: false
                },
                {
                    title: 'Request Access',
                    description: 'Request access to the required resource',
                    confidence: 'medium',
                    effort: 'moderate',
                    automated: false
                }
            ],
            'network': [
                {
                    title: 'Add Retry Logic',
                    description: 'Implement retry with exponential backoff',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: true,
                    code: `import time
import random

def retry_with_backoff(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            wait = (2 ** attempt) + random.random()
            time.sleep(wait)`
                },
                {
                    title: 'Check Network Connectivity',
                    description: 'Verify the target endpoint is reachable',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: false
                }
            ],
            'timeout': [
                {
                    title: 'Increase Timeout',
                    description: 'Increase the timeout value for the operation',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: true,
                    code: `# Increase timeout
import httpx
client = httpx.Client(timeout=60.0)  # 60 second timeout`
                },
                {
                    title: 'Add Circuit Breaker',
                    description: 'Implement circuit breaker pattern for failing services',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: false
                }
            ],
            'rate_limit': [
                {
                    title: 'Add Rate Limiting',
                    description: 'Implement client-side rate limiting',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: true,
                    code: `import time
from functools import wraps

def rate_limit(calls_per_minute):
    min_interval = 60.0 / calls_per_minute
    last_call = [0]
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_call[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            result = func(*args, **kwargs)
            last_call[0] = time.time()
            return result
        return wrapper
    return decorator`
                },
                {
                    title: 'Wait and Retry',
                    description: 'Parse Retry-After header and wait',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: true
                }
            ],
            'data_validation': [
                {
                    title: 'Add Input Validation',
                    description: 'Validate input data before processing',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: false,
                    code: `from pydantic import BaseModel, validator

class InputData(BaseModel):
    id: int
    name: str
    
    @validator('name')
    def name_not_empty(cls, v):
        if not v.strip():
            raise ValueError('name cannot be empty')
        return v`
                },
                {
                    title: 'Handle Missing Fields',
                    description: 'Add default values or error handling for missing data',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: false
                }
            ],
            'resource_exhaustion': [
                {
                    title: 'Add Resource Limits',
                    description: 'Set memory and time limits for the agent',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: true
                },
                {
                    title: 'Use Streaming',
                    description: 'Process data in chunks instead of loading all at once',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: false
                }
            ],
            'configuration': [
                {
                    title: 'Verify Configuration',
                    description: 'Check all required configuration values are set',
                    confidence: 'high',
                    effort: 'minimal',
                    automated: false
                },
                {
                    title: 'Add Configuration Validation',
                    description: 'Validate configuration on startup',
                    confidence: 'medium',
                    effort: 'moderate',
                    automated: true
                }
            ],
            'runtime': [
                {
                    title: 'Add Error Handling',
                    description: 'Wrap risky operations in try/catch',
                    confidence: 'high',
                    effort: 'moderate',
                    automated: false
                },
                {
                    title: 'Add Logging',
                    description: 'Add detailed logging for debugging',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: true
                }
            ],
            'unknown': [
                {
                    title: 'Enable Debug Logging',
                    description: 'Turn on verbose logging to get more details',
                    confidence: 'medium',
                    effort: 'minimal',
                    automated: true
                },
                {
                    title: 'Contact Support',
                    description: 'Reach out to AgentOS support for assistance',
                    confidence: 'low',
                    effort: 'minimal',
                    automated: false
                }
            ]
        };

        return fixMap[errorType] || fixMap['unknown'];
    }

    /**
     * Format error diagnosis for chat
     */
    formatDiagnosis(diagnosis: ErrorDiagnosis): string {
        const severityEmoji = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🟢'
        };

        let output = `## 🔍 Error Diagnosis\n\n`;
        output += `**Severity:** ${severityEmoji[diagnosis.severity]} ${diagnosis.severity}\n`;
        output += `**Type:** ${diagnosis.errorType.replace(/_/g, ' ')}\n`;
        output += `**Component:** ${diagnosis.affectedComponent}\n\n`;
        
        output += `### Summary\n${diagnosis.summary}\n\n`;
        output += `### Root Cause\n${diagnosis.rootCause}\n\n`;

        output += `### Suggested Fixes\n\n`;
        for (const suggestion of diagnosis.suggestions) {
            const confidenceEmoji = { high: '✅', medium: '⚠️', low: '❓' };
            output += `#### ${confidenceEmoji[suggestion.confidence]} ${suggestion.title}\n`;
            output += `${suggestion.description}\n\n`;
            output += `- **Effort:** ${suggestion.effort}\n`;
            output += `- **Automated:** ${suggestion.automated ? 'Yes' : 'No'}\n`;
            
            if (suggestion.code) {
                output += `\n\`\`\`python\n${suggestion.code}\n\`\`\`\n`;
            }
            output += '\n';
        }

        if (diagnosis.relatedDocs && diagnosis.relatedDocs.length > 0) {
            output += `### Related Documentation\n`;
            for (const doc of diagnosis.relatedDocs) {
                output += `- ${doc}\n`;
            }
        }

        return output;
    }

    // Private helper methods

    private detectErrorType(error: string, stack: string): ErrorType {
        const errorLower = error.toLowerCase();
        const stackLower = stack.toLowerCase();
        const combined = errorLower + ' ' + stackLower;

        if (combined.includes('policy') || combined.includes('violation') || combined.includes('blocked')) {
            return 'policy_violation';
        }
        if (combined.includes('401') || combined.includes('unauthorized') || combined.includes('invalid token')) {
            return 'authentication';
        }
        if (combined.includes('403') || combined.includes('forbidden') || combined.includes('permission denied')) {
            return 'authorization';
        }
        if (combined.includes('connection') || combined.includes('network') || combined.includes('econnrefused')) {
            return 'network';
        }
        if (combined.includes('timeout') || combined.includes('timed out')) {
            return 'timeout';
        }
        if (combined.includes('rate limit') || combined.includes('429') || combined.includes('too many requests')) {
            return 'rate_limit';
        }
        if (combined.includes('validation') || combined.includes('invalid') || combined.includes('schema')) {
            return 'data_validation';
        }
        if (combined.includes('memory') || combined.includes('oom') || combined.includes('heap')) {
            return 'resource_exhaustion';
        }
        if (combined.includes('config') || combined.includes('environment') || combined.includes('missing')) {
            return 'configuration';
        }

        return 'unknown';
    }

    private generateDiagnosis(
        errorType: ErrorType,
        errorMessage: string,
        context?: Record<string, any>
    ): ErrorDiagnosis {
        const diagnosisMap: Record<ErrorType, Partial<ErrorDiagnosis>> = {
            'policy_violation': {
                summary: 'The agent attempted an action that violates configured safety policies.',
                rootCause: 'The operation was blocked by the AgentOS policy engine because it matches a prohibited pattern.',
                affectedComponent: 'Policy Engine',
                severity: 'high',
                relatedDocs: ['Policy Configuration Guide', 'Safety Policies Reference']
            },
            'authentication': {
                summary: 'The agent could not authenticate with an external service.',
                rootCause: 'API credentials are invalid, expired, or not configured correctly.',
                affectedComponent: 'External Service Authentication',
                severity: 'high',
                relatedDocs: ['Secrets Configuration', 'Authentication Setup']
            },
            'authorization': {
                summary: 'The agent lacks permission to access a resource.',
                rootCause: 'The API token or service account does not have required permissions.',
                affectedComponent: 'Access Control',
                severity: 'medium',
                relatedDocs: ['Permissions Guide', 'Token Scopes']
            },
            'network': {
                summary: 'The agent could not connect to an external service.',
                rootCause: 'Network connectivity issue or service unavailable.',
                affectedComponent: 'Network Layer',
                severity: 'medium',
                relatedDocs: ['Network Troubleshooting', 'Retry Configuration']
            },
            'timeout': {
                summary: 'An operation took too long and was terminated.',
                rootCause: 'External service slow response or operation complexity.',
                affectedComponent: 'Execution Runtime',
                severity: 'medium',
                relatedDocs: ['Timeout Configuration', 'Performance Tuning']
            },
            'rate_limit': {
                summary: 'The agent exceeded API rate limits.',
                rootCause: 'Too many API calls in a short time period.',
                affectedComponent: 'API Client',
                severity: 'medium',
                relatedDocs: ['Rate Limiting Guide', 'Backoff Strategies']
            },
            'data_validation': {
                summary: 'Input data failed validation checks.',
                rootCause: 'Data format or content does not match expected schema.',
                affectedComponent: 'Data Processing',
                severity: 'low',
                relatedDocs: ['Data Validation', 'Schema Reference']
            },
            'resource_exhaustion': {
                summary: 'The agent ran out of memory or other resources.',
                rootCause: 'Processing too much data or memory leak.',
                affectedComponent: 'Resource Management',
                severity: 'high',
                relatedDocs: ['Resource Limits', 'Memory Management']
            },
            'configuration': {
                summary: 'Required configuration is missing or invalid.',
                rootCause: 'Environment variables or config files not set correctly.',
                affectedComponent: 'Configuration',
                severity: 'medium',
                relatedDocs: ['Configuration Guide', 'Environment Setup']
            },
            'runtime': {
                summary: 'An unexpected error occurred during execution.',
                rootCause: 'Bug in agent code or unexpected input.',
                affectedComponent: 'Agent Code',
                severity: 'medium',
                relatedDocs: ['Debugging Guide', 'Error Handling']
            },
            'unknown': {
                summary: 'An unrecognized error occurred.',
                rootCause: 'Unable to determine the specific cause.',
                affectedComponent: 'Unknown',
                severity: 'medium',
                relatedDocs: ['General Troubleshooting', 'Support']
            }
        };

        const baseDiagnosis = diagnosisMap[errorType];
        const suggestions = this.getCommonFixes(errorType);

        return {
            errorType,
            summary: baseDiagnosis.summary || errorMessage,
            rootCause: baseDiagnosis.rootCause || 'Unknown',
            affectedComponent: baseDiagnosis.affectedComponent || 'Unknown',
            severity: baseDiagnosis.severity || 'medium',
            suggestions,
            relatedDocs: baseDiagnosis.relatedDocs
        };
    }

    private statusEmoji(status: string): string {
        switch (status) {
            case 'success': return '✅';
            case 'failure': return '❌';
            case 'partial': return '⚠️';
            case 'skipped': return '⏭️';
            default: return '❓';
        }
    }

    private getOptimizationExample(issueType: PerformanceIssue['type'], language: string): string {
        const examples: Record<PerformanceIssue['type'], string> = {
            'slow_execution': `
**Before (Sequential):**
\`\`\`python
results = []
for item in items:
    result = await fetch_data(item)
    results.append(result)
\`\`\`

**After (Parallel):**
\`\`\`python
results = await asyncio.gather(*[
    fetch_data(item) for item in items
])
\`\`\`
`,
            'high_memory': `
**Before (Load All):**
\`\`\`python
data = json.load(open('large_file.json'))
process(data)
\`\`\`

**After (Streaming):**
\`\`\`python
import ijson
with open('large_file.json') as f:
    for item in ijson.items(f, 'items.item'):
        process(item)
\`\`\`
`,
            'excessive_api_calls': `
**Before (N+1):**
\`\`\`python
for user_id in user_ids:
    user = api.get_user(user_id)
    results.append(user)
\`\`\`

**After (Batch):**
\`\`\`python
users = api.get_users(user_ids)  # Single batch request
\`\`\`
`,
            'inefficient_loop': `
**Before:**
\`\`\`python
result = ""
for item in items:
    result += str(item) + ","
\`\`\`

**After:**
\`\`\`python
result = ",".join(str(item) for item in items)
\`\`\`
`
        };

        return examples[issueType] || '';
    }
}

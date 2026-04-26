// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Test Simulator
 * 
 * Provides testing and simulation capabilities for agents,
 * including scenario-based testing and edge case detection.
 */

import { AgentSpec, GeneratedAgent } from './agentGenerator';
import { logger } from './logger';

export interface TestScenario {
    id: string;
    name: string;
    description: string;
    type: 'success' | 'failure' | 'edge-case' | 'security' | 'performance';
    inputs: Record<string, any>;
    expectedOutputs?: Record<string, any>;
    assertions: TestAssertion[];
    timeout?: number;
}

export interface TestAssertion {
    type: 'equals' | 'contains' | 'matches' | 'throws' | 'not-throws' | 'type' | 'range';
    field: string;
    expected?: any;
    message: string;
}

export interface TestResult {
    scenario: TestScenario;
    passed: boolean;
    duration: number;
    outputs?: Record<string, any>;
    error?: string;
    assertions: AssertionResult[];
}

export interface AssertionResult {
    assertion: TestAssertion;
    passed: boolean;
    actual?: any;
    message: string;
}

export interface SimulationConfig {
    iterations: number;
    concurrency: number;
    randomSeed?: number;
    injectFailures: boolean;
    failureRate?: number;
    mockExternalApis: boolean;
}

export interface SimulationResult {
    totalIterations: number;
    successRate: number;
    averageDuration: number;
    maxDuration: number;
    minDuration: number;
    errors: { type: string; count: number; message: string }[];
    resourceUsage: ResourceMetrics;
    recommendations: string[];
}

export interface ResourceMetrics {
    peakMemoryMB: number;
    avgMemoryMB: number;
    cpuPercent: number;
    networkCallsPerIteration: number;
    diskIoMB: number;
}

export interface EdgeCase {
    name: string;
    description: string;
    category: 'input' | 'network' | 'timing' | 'resource' | 'security';
    severity: 'low' | 'medium' | 'high' | 'critical';
    scenario: TestScenario;
    recommendation: string;
}

export interface SecurityAuditResult {
    passed: boolean;
    score: number;  // 0-100
    vulnerabilities: SecurityVulnerability[];
    recommendations: string[];
    timestamp: string;
}

export interface SecurityVulnerability {
    id: string;
    name: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    location?: string;
    remediation: string;
    cwe?: string;  // Common Weakness Enumeration
}

export class TestSimulator {
    
    /**
     * Generate test scenarios for an agent
     */
    generateTestScenarios(spec: AgentSpec): TestScenario[] {
        const scenarios: TestScenario[] = [];
        
        // Happy path scenario
        scenarios.push(this.generateHappyPathScenario(spec));
        
        // Error handling scenarios
        scenarios.push(...this.generateErrorScenarios(spec));
        
        // Edge case scenarios
        scenarios.push(...this.generateEdgeCaseScenarios(spec));
        
        // Security scenarios
        scenarios.push(...this.generateSecurityScenarios(spec));
        
        // Performance scenarios
        scenarios.push(this.generatePerformanceScenario(spec));
        
        return scenarios;
    }

    /**
     * Run test scenarios (simulated for the extension)
     */
    async runTests(
        scenarios: TestScenario[],
        agent?: GeneratedAgent
    ): Promise<TestResult[]> {
        const results: TestResult[] = [];
        
        for (const scenario of scenarios) {
            logger.info('Running test scenario', { name: scenario.name });
            
            const startTime = Date.now();
            const result: TestResult = {
                scenario,
                passed: true,
                duration: 0,
                assertions: []
            };
            
            try {
                // Simulate test execution
                const outputs = await this.simulateExecution(scenario);
                result.outputs = outputs;
                
                // Run assertions
                for (const assertion of scenario.assertions) {
                    const assertionResult = this.checkAssertion(assertion, outputs);
                    result.assertions.push(assertionResult);
                    if (!assertionResult.passed) {
                        result.passed = false;
                    }
                }
            } catch (error) {
                result.passed = false;
                result.error = error instanceof Error ? error.message : String(error);
            }
            
            result.duration = Date.now() - startTime;
            results.push(result);
        }
        
        return results;
    }

    /**
     * Detect potential edge cases for an agent
     */
    detectEdgeCases(spec: AgentSpec): EdgeCase[] {
        const edgeCases: EdgeCase[] = [];
        
        // Input edge cases
        edgeCases.push({
            name: 'Empty Input',
            description: 'Agent receives no input data',
            category: 'input',
            severity: 'medium',
            scenario: {
                id: 'edge-empty-input',
                name: 'Empty Input Test',
                description: 'Test behavior with empty input',
                type: 'edge-case',
                inputs: {},
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should handle empty input gracefully' }
                ]
            },
            recommendation: 'Add validation for empty/null inputs'
        });
        
        edgeCases.push({
            name: 'Malformed Input',
            description: 'Agent receives invalid/malformed data',
            category: 'input',
            severity: 'high',
            scenario: {
                id: 'edge-malformed-input',
                name: 'Malformed Input Test',
                description: 'Test behavior with malformed data',
                type: 'edge-case',
                inputs: { data: '<<<INVALID>>>' },
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should handle malformed input' }
                ]
            },
            recommendation: 'Add input validation and sanitization'
        });
        
        // Network edge cases
        if (spec.dataSources.some(s => s.includes('API'))) {
            edgeCases.push({
                name: 'API Timeout',
                description: 'External API takes too long to respond',
                category: 'network',
                severity: 'high',
                scenario: {
                    id: 'edge-api-timeout',
                    name: 'API Timeout Test',
                    description: 'Test behavior when API times out',
                    type: 'edge-case',
                    inputs: { simulateTimeout: true },
                    assertions: [
                        { type: 'not-throws', field: 'execution', message: 'Should handle timeout' }
                    ],
                    timeout: 30000
                },
                recommendation: 'Implement timeout handling and retry logic'
            });
            
            edgeCases.push({
                name: 'Rate Limited',
                description: 'External API returns rate limit error',
                category: 'network',
                severity: 'medium',
                scenario: {
                    id: 'edge-rate-limit',
                    name: 'Rate Limit Test',
                    description: 'Test behavior when rate limited',
                    type: 'edge-case',
                    inputs: { simulateRateLimit: true },
                    assertions: [
                        { type: 'not-throws', field: 'execution', message: 'Should handle rate limiting' }
                    ]
                },
                recommendation: 'Implement exponential backoff and rate limit handling'
            });
        }
        
        // Resource edge cases
        edgeCases.push({
            name: 'Large Dataset',
            description: 'Agent processes unusually large dataset',
            category: 'resource',
            severity: 'medium',
            scenario: {
                id: 'edge-large-data',
                name: 'Large Dataset Test',
                description: 'Test behavior with large input',
                type: 'edge-case',
                inputs: { dataSize: 1000000 },
                assertions: [
                    { type: 'range', field: 'duration', expected: { max: 60000 }, message: 'Should complete within time limit' }
                ]
            },
            recommendation: 'Implement pagination and streaming for large datasets'
        });
        
        // Timing edge cases
        edgeCases.push({
            name: 'Concurrent Execution',
            description: 'Multiple agent instances run simultaneously',
            category: 'timing',
            severity: 'medium',
            scenario: {
                id: 'edge-concurrent',
                name: 'Concurrent Execution Test',
                description: 'Test behavior under concurrent load',
                type: 'edge-case',
                inputs: { concurrency: 10 },
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should handle concurrent execution' }
                ]
            },
            recommendation: 'Implement proper locking or idempotency'
        });
        
        return edgeCases;
    }

    /**
     * Run security audit on agent code
     */
    runSecurityAudit(code: string, language: string): SecurityAuditResult {
        const vulnerabilities: SecurityVulnerability[] = [];
        
        // Check for common vulnerabilities
        
        // SQL Injection
        if (/f["'].*\{.*\}.*SELECT|query\(.*\+.*\)/i.test(code)) {
            vulnerabilities.push({
                id: 'sqli',
                name: 'SQL Injection',
                severity: 'critical',
                description: 'Potential SQL injection vulnerability detected',
                remediation: 'Use parameterized queries or ORM',
                cwe: 'CWE-89'
            });
        }
        
        // Command Injection
        if (/exec\(|system\(|subprocess.*shell\s*=\s*True/i.test(code)) {
            vulnerabilities.push({
                id: 'cmdi',
                name: 'Command Injection',
                severity: 'critical',
                description: 'Potential command injection vulnerability',
                remediation: 'Avoid shell execution or sanitize inputs',
                cwe: 'CWE-78'
            });
        }
        
        // Hardcoded Secrets
        if (/(api[_-]?key|password|secret)\s*=\s*["'][^"']+["']/i.test(code)) {
            vulnerabilities.push({
                id: 'secrets',
                name: 'Hardcoded Secrets',
                severity: 'high',
                description: 'Hardcoded credentials or API keys detected',
                remediation: 'Use environment variables or secret management',
                cwe: 'CWE-798'
            });
        }
        
        // Insecure Deserialization
        if (/pickle\.load|yaml\.load\((?!.*Loader)/i.test(code)) {
            vulnerabilities.push({
                id: 'deserial',
                name: 'Insecure Deserialization',
                severity: 'high',
                description: 'Insecure deserialization detected',
                remediation: 'Use safe deserialization methods',
                cwe: 'CWE-502'
            });
        }
        
        // Missing Authentication
        if (/@app\.route|router\.(get|post)/i.test(code) && !/auth|token|permission/i.test(code)) {
            vulnerabilities.push({
                id: 'auth',
                name: 'Missing Authentication',
                severity: 'medium',
                description: 'API endpoint without apparent authentication',
                remediation: 'Add authentication middleware',
                cwe: 'CWE-306'
            });
        }
        
        // Insecure Random
        if (/random\.|Math\.random/i.test(code) && /secret|token|key|password/i.test(code)) {
            vulnerabilities.push({
                id: 'random',
                name: 'Insecure Random',
                severity: 'medium',
                description: 'Using weak random for security-sensitive values',
                remediation: 'Use cryptographically secure random (secrets module)',
                cwe: 'CWE-330'
            });
        }
        
        // Path Traversal
        if (/open\(.*\+|file.*=.*request/i.test(code)) {
            vulnerabilities.push({
                id: 'path',
                name: 'Path Traversal',
                severity: 'high',
                description: 'Potential path traversal vulnerability',
                remediation: 'Validate and sanitize file paths',
                cwe: 'CWE-22'
            });
        }
        
        // XSS (for web agents)
        if (/innerHTML|document\.write|dangerouslySetInnerHTML/i.test(code)) {
            vulnerabilities.push({
                id: 'xss',
                name: 'Cross-Site Scripting (XSS)',
                severity: 'medium',
                description: 'Potential XSS vulnerability',
                remediation: 'Sanitize user input before rendering',
                cwe: 'CWE-79'
            });
        }
        
        // Calculate score
        const severityWeights = { critical: 30, high: 20, medium: 10, low: 5 };
        const totalDeduction = vulnerabilities.reduce((sum, v) => sum + severityWeights[v.severity], 0);
        const score = Math.max(0, 100 - totalDeduction);
        
        // Generate recommendations
        const recommendations: string[] = [];
        if (vulnerabilities.some(v => v.severity === 'critical')) {
            recommendations.push('🚨 Address critical vulnerabilities before deployment');
        }
        if (!code.includes('try') && !code.includes('catch') && !code.includes('except')) {
            recommendations.push('Add proper error handling');
        }
        if (!code.includes('log')) {
            recommendations.push('Add security audit logging');
        }
        if (score < 80) {
            recommendations.push('Consider a professional security review');
        }
        
        return {
            passed: score >= 70 && !vulnerabilities.some(v => v.severity === 'critical'),
            score,
            vulnerabilities,
            recommendations,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Estimate cost for running agent
     */
    estimateCost(spec: AgentSpec, runsPerMonth: number = 100): CostEstimate {
        const costs: CostBreakdown = {
            compute: 0,
            apiCalls: 0,
            storage: 0,
            network: 0
        };
        
        // Estimate compute cost
        const avgDurationMinutes = 1;  // Assume 1 minute average
        const computeCostPerMinute = 0.0001;  // GitHub Actions is ~$0.008/min for linux
        costs.compute = runsPerMonth * avgDurationMinutes * computeCostPerMinute;
        
        // Estimate API call costs
        for (const source of spec.dataSources) {
            if (source.includes('API')) {
                costs.apiCalls += runsPerMonth * 0.001;  // Rough estimate per API call
            }
        }
        
        // Estimate storage
        const storageGBPerMonth = 0.1;  // Logs, artifacts
        costs.storage = storageGBPerMonth * 0.02;  // ~$0.02/GB
        
        // Estimate network
        costs.network = runsPerMonth * 0.001;  // Minimal
        
        const total = costs.compute + costs.apiCalls + costs.storage + costs.network;
        
        return {
            monthly: total,
            perRun: total / runsPerMonth,
            breakdown: costs,
            recommendations: this.getCostRecommendations(spec, costs)
        };
    }

    /**
     * Format test results for chat display
     */
    formatTestResults(results: TestResult[]): string {
        const passed = results.filter(r => r.passed).length;
        const failed = results.length - passed;
        const passRate = ((passed / results.length) * 100).toFixed(0);
        
        let output = `## 🧪 Test Results\n\n`;
        output += `**Summary:** ${passed}/${results.length} passed (${passRate}%)\n\n`;
        
        output += `| Scenario | Status | Duration |\n`;
        output += `|----------|--------|----------|\n`;
        
        for (const result of results) {
            const status = result.passed ? '✅ Pass' : '❌ Fail';
            output += `| ${result.scenario.name} | ${status} | ${result.duration}ms |\n`;
        }
        
        // Show failures
        const failures = results.filter(r => !r.passed);
        if (failures.length > 0) {
            output += `\n### ❌ Failed Tests\n\n`;
            for (const failure of failures) {
                output += `**${failure.scenario.name}**\n`;
                if (failure.error) {
                    output += `- Error: ${failure.error}\n`;
                }
                for (const assertion of failure.assertions.filter(a => !a.passed)) {
                    output += `- ${assertion.message}\n`;
                }
                output += '\n';
            }
        }
        
        return output;
    }

    /**
     * Format security audit for chat display
     */
    formatSecurityAudit(audit: SecurityAuditResult): string {
        const scoreEmoji = audit.score >= 80 ? '🟢' : audit.score >= 60 ? '🟡' : '🔴';
        
        let output = `## 🔒 Security Audit Results\n\n`;
        output += `**Score:** ${scoreEmoji} ${audit.score}/100\n`;
        output += `**Status:** ${audit.passed ? '✅ Passed' : '❌ Failed'}\n\n`;
        
        if (audit.vulnerabilities.length > 0) {
            output += `### Vulnerabilities Found (${audit.vulnerabilities.length})\n\n`;
            output += `| Severity | Issue | Description |\n`;
            output += `|----------|-------|-------------|\n`;
            
            for (const vuln of audit.vulnerabilities) {
                const severityEmoji = {
                    critical: '🔴',
                    high: '🟠',
                    medium: '🟡',
                    low: '🟢'
                }[vuln.severity];
                output += `| ${severityEmoji} ${vuln.severity} | ${vuln.name} | ${vuln.description} |\n`;
            }
            
            output += '\n### Remediations\n\n';
            for (const vuln of audit.vulnerabilities) {
                output += `- **${vuln.name}:** ${vuln.remediation}\n`;
            }
        } else {
            output += `✅ No vulnerabilities detected!\n`;
        }
        
        if (audit.recommendations.length > 0) {
            output += `\n### Recommendations\n\n`;
            for (const rec of audit.recommendations) {
                output += `- ${rec}\n`;
            }
        }
        
        return output;
    }

    // Private helper methods

    private generateHappyPathScenario(spec: AgentSpec): TestScenario {
        return {
            id: 'happy-path',
            name: 'Happy Path',
            description: 'Test normal successful execution',
            type: 'success',
            inputs: {
                data: [{ id: 1, value: 'test' }]
            },
            assertions: [
                { type: 'equals', field: 'status', expected: 'success', message: 'Should complete successfully' },
                { type: 'type', field: 'data', expected: 'array', message: 'Should return array of results' }
            ]
        };
    }

    private generateErrorScenarios(spec: AgentSpec): TestScenario[] {
        const scenarios: TestScenario[] = [];
        
        // Network error
        if (spec.dataSources?.some(s => s.includes('API'))) {
            scenarios.push({
                id: 'network-error',
                name: 'Network Error',
                description: 'Test behavior when network fails',
                type: 'failure',
                inputs: { simulateNetworkError: true },
                assertions: [
                    { type: 'equals', field: 'status', expected: 'error', message: 'Should return error status' },
                    { type: 'contains', field: 'error', expected: 'network', message: 'Should indicate network error' }
                ]
            });
        }
        
        // Auth error
        if (spec.policies?.some(p => p.type === 'auth')) {
            scenarios.push({
                id: 'auth-error',
                name: 'Authentication Error',
                description: 'Test behavior with invalid credentials',
                type: 'failure',
                inputs: { invalidAuth: true },
                assertions: [
                    { type: 'equals', field: 'status', expected: 'error', message: 'Should return error status' }
                ]
            });
        }
        
        return scenarios;
    }

    private generateEdgeCaseScenarios(spec: AgentSpec): TestScenario[] {
        return [
            {
                id: 'empty-response',
                name: 'Empty Response',
                description: 'Test handling of empty data',
                type: 'edge-case',
                inputs: { data: [] },
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should handle empty data' }
                ]
            },
            {
                id: 'special-characters',
                name: 'Special Characters',
                description: 'Test handling of special characters',
                type: 'edge-case',
                inputs: { data: [{ value: '<script>alert("xss")</script>' }] },
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should handle special characters' }
                ]
            }
        ];
    }

    private generateSecurityScenarios(spec: AgentSpec): TestScenario[] {
        return [
            {
                id: 'injection-attempt',
                name: 'Injection Attempt',
                description: 'Test resistance to injection attacks',
                type: 'security',
                inputs: { data: "'; DROP TABLE users; --" },
                assertions: [
                    { type: 'not-throws', field: 'execution', message: 'Should resist injection' }
                ]
            }
        ];
    }

    private generatePerformanceScenario(spec: AgentSpec): TestScenario {
        return {
            id: 'performance',
            name: 'Performance Test',
            description: 'Test execution performance',
            type: 'performance',
            inputs: { dataSize: 1000 },
            assertions: [
                { type: 'range', field: 'duration', expected: { max: 30000 }, message: 'Should complete within 30 seconds' }
            ]
        };
    }

    private async simulateExecution(scenario: TestScenario): Promise<Record<string, any>> {
        // Simulate execution with randomized results
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
        
        if (scenario.inputs.simulateNetworkError) {
            return { status: 'error', error: 'network connection failed' };
        }
        
        if (scenario.inputs.invalidAuth) {
            return { status: 'error', error: 'authentication failed' };
        }
        
        return {
            status: 'success',
            data: scenario.inputs.data || [],
            execution: 'completed'
        };
    }

    private checkAssertion(assertion: TestAssertion, outputs: Record<string, any>): AssertionResult {
        const actual = outputs[assertion.field];
        let passed = false;
        
        switch (assertion.type) {
            case 'equals':
                passed = actual === assertion.expected;
                break;
            case 'contains':
                passed = String(actual).includes(String(assertion.expected));
                break;
            case 'type':
                passed = Array.isArray(actual) ? assertion.expected === 'array' : typeof actual === assertion.expected;
                break;
            case 'range':
                if (assertion.expected?.max) {
                    passed = actual <= assertion.expected.max;
                }
                break;
            case 'not-throws':
                passed = outputs.error === undefined;
                break;
            default:
                passed = true;
        }
        
        return {
            assertion,
            passed,
            actual,
            message: passed ? assertion.message : `Failed: ${assertion.message} (got: ${actual})`
        };
    }

    private getCostRecommendations(spec: AgentSpec, costs: CostBreakdown): string[] {
        const recommendations: string[] = [];
        
        if (costs.apiCalls > costs.compute) {
            recommendations.push('Consider caching API responses to reduce costs');
        }
        
        if (spec.schedule && spec.schedule.includes('* * * * *')) {
            recommendations.push('Running every minute can be expensive - consider longer intervals');
        }
        
        return recommendations;
    }
}

interface CostEstimate {
    monthly: number;
    perRun: number;
    breakdown: CostBreakdown;
    recommendations: string[];
}

interface CostBreakdown {
    compute: number;
    apiCalls: number;
    storage: number;
    network: number;
}

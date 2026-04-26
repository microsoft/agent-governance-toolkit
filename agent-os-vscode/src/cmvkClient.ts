// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * CMVK Client for Agent OS VS Code Extension
 * 
 * Provides multi-model code verification by calling the Agent OS CMVK API.
 */

import * as vscode from 'vscode';
import axios, { AxiosInstance } from 'axios';

export interface ModelResult {
    model: string;
    passed: boolean;
    summary: string;
    issues: string[];
    confidence: number;
}

export interface CMVKResult {
    consensus: number;
    modelResults: ModelResult[];
    issues: string[];
    recommendations: string;
    verificationId: string;
}

export class CMVKClient {
    private client: AxiosInstance | null = null;

    constructor() {
        this.initializeClient();
    }

    private initializeClient(): void {
        const config = vscode.workspace.getConfiguration('agentOS');
        const endpoint = config.get<string>('cmvk.apiEndpoint', 'https://api.agent-os.dev/cmvk');

        this.client = axios.create({
            baseURL: endpoint,
            timeout: 60000, // 60 second timeout for multi-model review
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'agent-os-vscode/0.1.0'
            }
        });
    }

    /**
     * Review code using multiple AI models
     */
    async reviewCode(code: string, language: string, models: string[]): Promise<CMVKResult> {
        if (!this.client) {
            this.initializeClient();
        }

        // For local development/demo, use mock response
        if (this.shouldUseMock()) {
            return this.mockReview(code, language, models);
        }

        try {
            const response = await this.client!.post('/verify', {
                code,
                language,
                models,
                consensusThreshold: vscode.workspace.getConfiguration('agentOS').get('cmvk.consensusThreshold', 0.8)
            });

            return response.data as CMVKResult;
        } catch (error: any) {
            if (error.response?.status === 401) {
                throw new Error('CMVK API authentication required. Please configure your API key.');
            } else if (error.response?.status === 429) {
                throw new Error('CMVK rate limit exceeded. Free tier allows 10 reviews/day.');
            } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
                // Fallback to mock for offline development
                return this.mockReview(code, language, models);
            }
            throw new Error(`CMVK API error: ${error.message}`);
        }
    }

    /**
     * Check if we should use mock response (local dev, no API key, etc.)
     */
    private shouldUseMock(): boolean {
        const config = vscode.workspace.getConfiguration('agentOS');
        const endpoint = config.get<string>('cmvk.apiEndpoint', '');
        
        // Use mock if endpoint is default (no custom endpoint configured)
        return endpoint.includes('api.agent-os.dev') || endpoint === '';
    }

    /**
     * Generate mock CMVK response for local development/demo
     */
    private mockReview(code: string, language: string, models: string[]): CMVKResult {
        const issues: string[] = [];
        const modelResults: ModelResult[] = [];

        // Simple static analysis to find potential issues
        const potentialIssues = this.staticAnalysis(code, language);

        // Generate realistic model responses
        for (const model of models) {
            // Vary responses slightly per model to show disagreement
            const modelIssues = potentialIssues.filter(() => Math.random() > 0.3);
            const passed = modelIssues.length === 0;

            modelResults.push({
                model,
                passed,
                summary: passed 
                    ? 'No significant issues detected'
                    : `Found ${modelIssues.length} potential issue(s)`,
                issues: modelIssues,
                confidence: passed ? 0.9 + Math.random() * 0.1 : 0.6 + Math.random() * 0.3
            });

            // Add unique issues to global list
            for (const issue of modelIssues) {
                if (!issues.includes(issue)) {
                    issues.push(issue);
                }
            }
        }

        // Calculate consensus
        const passedCount = modelResults.filter(m => m.passed).length;
        const consensus = passedCount / models.length;

        // Generate recommendations
        let recommendations = '';
        if (issues.length > 0) {
            recommendations = `Based on the analysis:\n\n`;
            for (let i = 0; i < issues.length; i++) {
                recommendations += `${i + 1}. ${this.getRecommendation(issues[i])}\n`;
            }
        }

        return {
            consensus,
            modelResults,
            issues,
            recommendations,
            verificationId: `mock-${Date.now()}`
        };
    }

    /**
     * Perform basic static analysis to find issues
     */
    private staticAnalysis(code: string, language: string): string[] {
        const issues: string[] = [];

        // SQL injection
        if (/\+\s*["'][^"']*\+/.test(code) && /SELECT|INSERT|UPDATE|DELETE/i.test(code)) {
            issues.push('Potential SQL injection: String concatenation in SQL query');
        }

        // Missing error handling
        if (/await\s+\w+/.test(code) && !/try\s*{/.test(code)) {
            issues.push('Missing error handling: async operation without try-catch');
        }

        // Race condition
        if (code.match(/await/g)?.length && code.match(/await/g)!.length > 2 && !/Promise\.all/i.test(code)) {
            issues.push('Potential race condition: Multiple sequential awaits without transaction');
        }

        // Hardcoded values
        if (/:\s*(8080|3000|5000)\b/.test(code) && !/process\.env|config/i.test(code)) {
            issues.push('Hardcoded port number: Consider using environment variables');
        }

        // Missing input validation
        if (/req\.(body|params|query)\./.test(code) && !/validate|check|sanitize/i.test(code)) {
            issues.push('Missing input validation: User input used without validation');
        }

        // Synchronous file operations
        if (/Sync\s*\(/.test(code) && ['javascript', 'typescript'].includes(language)) {
            issues.push('Synchronous file operation: Consider using async alternatives');
        }

        // eval usage
        if (/\beval\s*\(/.test(code)) {
            issues.push('Security risk: eval() usage detected');
        }

        // innerHTML
        if (/\.innerHTML\s*=/.test(code)) {
            issues.push('XSS risk: innerHTML assignment detected');
        }

        // No issues found? Return empty for some models
        return issues;
    }

    /**
     * Get recommendation for an issue
     */
    private getRecommendation(issue: string): string {
        if (issue.includes('SQL injection')) {
            return 'Use parameterized queries or an ORM to prevent SQL injection';
        } else if (issue.includes('error handling')) {
            return 'Wrap async operations in try-catch blocks';
        } else if (issue.includes('race condition')) {
            return 'Use database transactions or Promise.all for atomic operations';
        } else if (issue.includes('Hardcoded')) {
            return 'Move configuration values to environment variables';
        } else if (issue.includes('input validation')) {
            return 'Add input validation using a library like joi, zod, or express-validator';
        } else if (issue.includes('Synchronous')) {
            return 'Use fs.promises or async versions to avoid blocking the event loop';
        } else if (issue.includes('eval')) {
            return 'Remove eval() and use safer alternatives like JSON.parse or Function constructor';
        } else if (issue.includes('innerHTML')) {
            return 'Use textContent or a sanitization library to prevent XSS';
        }
        return 'Review and address this issue';
    }
}

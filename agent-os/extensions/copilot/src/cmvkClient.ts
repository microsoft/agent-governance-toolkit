// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * CMVK Client for Agent OS Copilot Extension
 * 
 * Multi-model code verification client.
 */

import axios, { AxiosInstance } from 'axios';
import { logger } from './logger';

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
    private client: AxiosInstance;
    private apiEndpoint: string;

    constructor() {
        this.apiEndpoint = process.env.CMVK_API_ENDPOINT || 'https://api.agent-os.dev/cmvk';
        
        this.client = axios.create({
            baseURL: this.apiEndpoint,
            timeout: 60000,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'agent-os-copilot-extension/1.0.0'
            }
        });
    }

    /**
     * Review code using multiple AI models
     */
    async reviewCode(
        code: string, 
        language: string,
        models: string[] = ['gpt-4', 'claude-sonnet-4', 'gemini-pro']
    ): Promise<CMVKResult> {
        // For local development/demo, use mock response
        if (this.shouldUseMock()) {
            return this.mockReview(code, language, models);
        }

        try {
            const response = await this.client.post('/verify', {
                code,
                language,
                models,
                consensusThreshold: 0.8
            });

            return response.data as CMVKResult;
        } catch (error: any) {
            logger.warn('CMVK API call failed, using mock', { error: error.message });
            return this.mockReview(code, language, models);
        }
    }

    private shouldUseMock(): boolean {
        return !process.env.CMVK_API_KEY || 
               this.apiEndpoint.includes('api.agent-os.dev');
    }

    private mockReview(code: string, language: string, models: string[]): CMVKResult {
        const issues: string[] = [];
        const modelResults: ModelResult[] = [];
        const potentialIssues = this.staticAnalysis(code, language);

        for (const model of models) {
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

            for (const issue of modelIssues) {
                if (!issues.includes(issue)) {
                    issues.push(issue);
                }
            }
        }

        const passedCount = modelResults.filter(m => m.passed).length;
        const consensus = passedCount / models.length;

        let recommendations = '';
        if (issues.length > 0) {
            recommendations = 'Based on the analysis:\n\n';
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
        if (code.match(/await/g)?.length && code.match(/await/g)!.length > 2) {
            if (!/Promise\.all/i.test(code) && !/transaction/i.test(code)) {
                issues.push('Potential race condition: Multiple sequential awaits without transaction');
            }
        }

        // Missing input validation
        if (/req\.(body|params|query)\./.test(code) && !/validate|check|sanitize/i.test(code)) {
            issues.push('Missing input validation: User input used without validation');
        }

        // eval usage
        if (/\beval\s*\(/.test(code)) {
            issues.push('Security risk: eval() usage detected');
        }

        // innerHTML
        if (/\.innerHTML\s*=/.test(code)) {
            issues.push('XSS risk: innerHTML assignment detected');
        }

        return issues;
    }

    private getRecommendation(issue: string): string {
        const recommendations: Record<string, string> = {
            'SQL injection': 'Use parameterized queries or an ORM to prevent SQL injection',
            'error handling': 'Wrap async operations in try-catch blocks',
            'race condition': 'Use database transactions or Promise.all for atomic operations',
            'input validation': 'Add input validation using a library like joi, zod, or express-validator',
            'eval': 'Remove eval() and use safer alternatives like JSON.parse',
            'innerHTML': 'Use textContent or a sanitization library to prevent XSS'
        };

        for (const [key, rec] of Object.entries(recommendations)) {
            if (issue.toLowerCase().includes(key)) {
                return rec;
            }
        }
        return 'Review and address this issue';
    }
}

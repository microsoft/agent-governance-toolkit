// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Copilot Extension Handler
 * 
 * Main handler for GitHub Copilot Extension interactions.
 * Filters suggestions, handles chat commands, and provides annotations.
 * 
 * Supports commands:
 * - @agentos create agent for [task] - Generate agent from description
 * - @agentos design workflow to [goal] - Design multi-step workflow
 * - @agentos test this agent with [scenario] - Run test simulation
 * - @agentos why did this agent fail? - Debug agent failures
 * - @agentos what policies apply? - Policy recommendations
 * - @agentos review - Code review with CMVK
 * - @agentos policy - Show active policies
 * - @agentos audit - View audit log
 * - @agentos templates - Browse agent templates
 * - @agentos deploy - Deploy agent to GitHub Actions
 * - @agentos help - Show help
 */

import { PolicyEngine, AnalysisResult } from './policyEngine';
import { CMVKClient, CMVKResult } from './cmvkClient';
import { AuditLogger } from './auditLogger';
import { logger } from './logger';
import { AgentGenerator, GeneratedAgent, AgentSpec, SupportedLanguage } from './agentGenerator';
import { TemplateGallery, AgentTemplate, TemplateCategory } from './templateGallery';
import { PolicyLibrary, ComplianceFramework } from './policyLibrary';
import { TestSimulator, TestScenario, SecurityAuditResult } from './testSimulator';
import { GitHubIntegration, DeploymentConfig } from './githubIntegration';
import { DebugHelper, ErrorDiagnosis } from './debugHelper';

export interface CopilotSuggestion {
    id: string;
    code: string;
    language: string;
    confidence: number;
    metadata?: Record<string, any>;
}

export interface CopilotContext {
    file?: {
        path: string;
        language: string;
        content?: string;
    };
    selection?: {
        start: { line: number; column: number };
        end: { line: number; column: number };
        text: string;
    };
    user?: {
        id: string;
        organization?: string;
    };
    repository?: {
        name: string;
        owner: string;
    };
}

export interface FilteredSuggestion extends CopilotSuggestion {
    safetyStatus: 'safe' | 'warning' | 'blocked';
    safetyMessage?: string;
    annotations?: SafetyAnnotation[];
}

export interface SafetyAnnotation {
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    severity: 'error' | 'warning' | 'info';
    message: string;
    rule: string;
    suggestion?: string;
}

export interface ChatResponse {
    message: string;
    markdown: boolean;
    suggestions?: string[];
    actions?: ChatAction[];
}

export interface ChatAction {
    label: string;
    command: string;
    args?: any;
}

export class CopilotExtension {
    private agentGenerator: AgentGenerator;
    private templateGallery: TemplateGallery;
    private policyLibrary: PolicyLibrary;
    private testSimulator: TestSimulator;
    private githubIntegration: GitHubIntegration;
    private debugHelper: DebugHelper;
    
    // Store state for multi-turn conversations
    private pendingAgentSpec?: AgentSpec;
    private pendingLanguage: SupportedLanguage = 'python';

    constructor(
        private policyEngine: PolicyEngine,
        private cmvkClient: CMVKClient,
        private auditLogger: AuditLogger
    ) {
        this.agentGenerator = new AgentGenerator();
        this.templateGallery = new TemplateGallery();
        this.policyLibrary = new PolicyLibrary();
        this.testSimulator = new TestSimulator();
        this.githubIntegration = new GitHubIntegration();
        this.debugHelper = new DebugHelper();
    }

    /**
     * Filter Copilot suggestions for safety
     */
    async filterSuggestions(
        suggestions: CopilotSuggestion[],
        context: CopilotContext
    ): Promise<{ suggestions: FilteredSuggestion[]; summary: FilterSummary }> {
        const filteredSuggestions: FilteredSuggestion[] = [];
        let blocked = 0;
        let warnings = 0;
        let safe = 0;

        for (const suggestion of suggestions) {
            const language = suggestion.language || context.file?.language || 'unknown';
            const result = await this.policyEngine.analyzeCode(suggestion.code, language);

            const filtered: FilteredSuggestion = {
                ...suggestion,
                safetyStatus: 'safe',
                annotations: []
            };

            if (result.blocked) {
                filtered.safetyStatus = 'blocked';
                filtered.safetyMessage = result.reason;
                filtered.annotations = this.createAnnotations(suggestion.code, result);
                blocked++;

                // Log violation
                this.auditLogger.log({
                    type: 'blocked',
                    timestamp: new Date(),
                    file: context.file?.path,
                    language,
                    code: suggestion.code.substring(0, 200),
                    violation: result.violation,
                    reason: result.reason,
                    repository: context.repository ? 
                        `${context.repository.owner}/${context.repository.name}` : undefined
                });

            } else if (result.warnings.length > 0) {
                filtered.safetyStatus = 'warning';
                filtered.safetyMessage = result.warnings.join('; ');
                filtered.annotations = this.createWarningAnnotations(suggestion.code, result.warnings);
                warnings++;

            } else {
                safe++;
            }

            filteredSuggestions.push(filtered);
        }

        const summary: FilterSummary = {
            total: suggestions.length,
            safe,
            warnings,
            blocked,
            timestamp: new Date().toISOString()
        };

        logger.info('Suggestions filtered', summary);

        return { suggestions: filteredSuggestions, summary };
    }

    /**
     * Handle @agent-os chat commands
     */
    async handleChatMessage(
        message: string,
        context: CopilotContext,
        command?: string
    ): Promise<ChatResponse> {
        // Parse command from message if not provided
        if (!command && message.startsWith('@agent-os')) {
            const parts = message.replace('@agent-os', '').trim().split(' ');
            command = parts[0];
            message = parts.slice(1).join(' ');
        }
        
        // Also handle @agentos format
        if (!command && message.startsWith('@agentos')) {
            const parts = message.replace('@agentos', '').trim().split(' ');
            command = parts[0];
            message = parts.slice(1).join(' ');
        }

        switch (command?.toLowerCase()) {
            case 'create':
                return this.handleCreateCommand(message, context);
            
            case 'design':
                return this.handleDesignCommand(message, context);
                
            case 'test':
            case 'simulate':
                return this.handleTestCommand(message, context);
                
            case 'debug':
            case 'why':
                return this.handleDebugCommand(message, context);
                
            case 'templates':
            case 'template':
                return this.handleTemplatesCommand(message, context);
                
            case 'compliance':
            case 'framework':
                return this.handleComplianceCommand(message, context);
            
            case 'deploy':
                return this.handleDeployCommand(message, context);
            
            case 'review':
                return this.handleReviewCommand(message, context);
            
            case 'policy':
            case 'policies':
                return this.handlePolicyCommand(message, context);
            
            case 'audit':
                return this.handleAuditCommand(context);
                
            case 'security':
                return this.handleSecurityCommand(message, context);
                
            case 'optimize':
                return this.handleOptimizeCommand(message, context);
            
            case 'help':
            default:
                return this.handleHelpCommand();
        }
    }

    /**
     * @agent-os review - Review code with CMVK
     */
    private async handleReviewCommand(
        message: string,
        context: CopilotContext
    ): Promise<ChatResponse> {
        const code = context.selection?.text || message || context.file?.content;
        
        if (!code || code.trim().length === 0) {
            return {
                message: '⚠️ No code to review. Please select code or provide it in your message.',
                markdown: false
            };
        }

        const language = context.file?.language || 'unknown';

        // First, run local policy check
        const policyResult = await this.policyEngine.analyzeCode(code, language);
        
        // Then, run CMVK verification
        let cmvkResult: CMVKResult | null = null;
        try {
            cmvkResult = await this.cmvkClient.reviewCode(code, language);
        } catch (error) {
            logger.warn('CMVK review failed, using local analysis only', { error });
        }

        // Build response
        let response = '# 🛡️ Agent OS Code Review\n\n';

        // Policy results
        if (policyResult.blocked) {
            response += `## ❌ Policy Violation\n`;
            response += `**${policyResult.reason}**\n\n`;
            if (policyResult.suggestion) {
                response += `💡 **Suggestion:** ${policyResult.suggestion}\n\n`;
            }
        } else if (policyResult.warnings.length > 0) {
            response += `## ⚠️ Policy Warnings\n`;
            for (const warning of policyResult.warnings) {
                response += `- ${warning}\n`;
            }
            response += '\n';
        } else {
            response += `## ✅ Policy Check Passed\n\n`;
        }

        // CMVK results
        if (cmvkResult) {
            const consensusEmoji = cmvkResult.consensus >= 0.8 ? '✅' : 
                                   cmvkResult.consensus >= 0.5 ? '⚠️' : '❌';
            
            response += `## ${consensusEmoji} CMVK Multi-Model Review\n\n`;
            response += `**Consensus:** ${(cmvkResult.consensus * 100).toFixed(0)}%\n\n`;
            
            response += '| Model | Status | Assessment |\n';
            response += '|-------|--------|------------|\n';
            
            for (const result of cmvkResult.modelResults) {
                const status = result.passed ? '✅' : '⚠️';
                response += `| ${result.model} | ${status} | ${result.summary} |\n`;
            }
            response += '\n';

            if (cmvkResult.issues.length > 0) {
                response += `### Issues Found\n`;
                for (const issue of cmvkResult.issues) {
                    response += `- ${issue}\n`;
                }
                response += '\n';
            }

            if (cmvkResult.recommendations) {
                response += `### Recommendations\n${cmvkResult.recommendations}\n`;
            }
        }

        // Log review
        this.auditLogger.log({
            type: 'cmvk_review',
            timestamp: new Date(),
            file: context.file?.path,
            language,
            code: code.substring(0, 200),
            result: {
                policyBlocked: policyResult.blocked,
                cmvkConsensus: cmvkResult?.consensus
            }
        });

        return {
            message: response,
            markdown: true,
            actions: policyResult.blocked ? [
                { label: 'Show Policy', command: 'agent-os.policy' },
                { label: 'Allow Once', command: 'agent-os.allowOnce', args: { violation: policyResult.violation } }
            ] : undefined
        };
    }

    /**
     * @agent-os policy - Show or configure policies
     */
    private handlePolicyCommand(message: string, context: CopilotContext): ChatResponse {
        const policies = this.policyEngine.getActivePolicies();
        
        let response = '# 🛡️ Agent OS Active Policies\n\n';
        response += '| Policy | Status | Severity |\n';
        response += '|--------|--------|----------|\n';
        
        for (const policy of policies) {
            const status = policy.enabled ? '✅ Enabled' : '❌ Disabled';
            response += `| ${policy.name} | ${status} | ${policy.severity} |\n`;
        }

        response += '\n---\n';
        response += `📊 **Total Rules:** ${this.policyEngine.getRuleCount()}\n\n`;
        response += 'To configure policies, edit `.github/agent-os.json` or your repository settings.\n';

        return {
            message: response,
            markdown: true,
            suggestions: [
                '@agent-os review - Review selected code',
                '@agent-os audit - View recent audit log'
            ]
        };
    }

    /**
     * @agent-os audit - Show recent audit log
     */
    private handleAuditCommand(context: CopilotContext): ChatResponse {
        const logs = this.auditLogger.getRecent(10);
        const stats = this.auditLogger.getStats();
        
        let response = '# 📋 Agent OS Audit Log\n\n';
        
        response += '## Summary\n';
        response += `- **Blocked Today:** ${stats.blockedToday}\n`;
        response += `- **Blocked This Week:** ${stats.blockedThisWeek}\n`;
        response += `- **CMVK Reviews:** ${stats.cmvkReviewsToday}\n\n`;

        if (logs.length > 0) {
            response += '## Recent Activity\n\n';
            response += '| Time | Type | Details |\n';
            response += '|------|------|--------|\n';
            
            for (const log of logs) {
                const time = this.formatTime(log.timestamp);
                const type = log.type === 'blocked' ? '🚫 Blocked' : 
                            log.type === 'cmvk_review' ? '🔍 Review' : '⚠️ Warning';
                const details = log.violation || log.reason || 'N/A';
                response += `| ${time} | ${type} | ${details.substring(0, 30)}... |\n`;
            }
        } else {
            response += '*No recent activity*\n';
        }

        return {
            message: response,
            markdown: true
        };
    }

    /**
     * @agent-os help - Show help
     */
    private handleHelpCommand(): ChatResponse {
        const response = `# 🛡️ AgentOS for GitHub Copilot

**Build safe AI agents with natural language and 0% policy violations.**

## 🚀 Quick Start Commands

| Command | Description |
|---------|-------------|
| \`@agentos create agent for [task]\` | Create a new agent from description |
| \`@agentos design workflow to [goal]\` | Design a multi-step workflow |
| \`@agentos templates\` | Browse 50+ agent templates |

## 🛡️ Safety & Compliance

| Command | Description |
|---------|-------------|
| \`@agentos review\` | Review code with multi-model verification |
| \`@agentos policy\` | Show active safety policies |
| \`@agentos compliance [framework]\` | Check GDPR, HIPAA, SOC2, PCI DSS compliance |
| \`@agentos security\` | Run security audit on code |

## 🧪 Testing & Debugging

| Command | Description |
|---------|-------------|
| \`@agentos test [scenario]\` | Test agent with scenarios |
| \`@agentos why did this fail?\` | Debug agent failures |
| \`@agentos optimize\` | Get performance optimization suggestions |

## 🚢 Deployment

| Command | Description |
|---------|-------------|
| \`@agentos deploy\` | Deploy agent to GitHub Actions |
| \`@agentos audit\` | View recent activity log |

## Examples

\`\`\`
@agentos create agent for processing customer feedback from Slack
@agentos design workflow to generate daily standup reports
@agentos templates data-processing
@agentos compliance gdpr
\`\`\`

---
**Learn More:** [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
`;

        return {
            message: response,
            markdown: true,
            suggestions: [
                '@agentos create agent for',
                '@agentos templates',
                '@agentos review',
                '@agentos policy'
            ]
        };
    }

    /**
     * @agentos create agent for [task] - Generate agent from natural language
     */
    private async handleCreateCommand(message: string, context: CopilotContext): Promise<ChatResponse> {
        // Extract task description
        const taskMatch = message.match(/(?:agent\s+(?:for|to)\s+)?(.+)/i);
        const taskDescription = taskMatch ? taskMatch[1].trim() : message.trim();

        if (!taskDescription || taskDescription.length < 10) {
            return {
                message: `## 🤖 Create Agent

Please describe what you want your agent to do. For example:

\`\`\`
@agentos create agent for processing customer feedback from Slack
@agentos create agent to generate daily standup reports from GitHub and Jira
@agentos create agent for monitoring API uptime and alerting on failures
\`\`\`

Or browse templates: \`@agentos templates\`
`,
                markdown: true,
                suggestions: [
                    '@agentos create agent for processing data from API',
                    '@agentos create agent to send daily reports to Slack',
                    '@agentos templates'
                ]
            };
        }

        logger.info('Creating agent from description', { description: taskDescription.substring(0, 100) });

        // Parse the task description
        const spec = this.agentGenerator.parseTaskDescription(taskDescription);
        
        // Check if we need clarifying questions
        const questions = this.agentGenerator.generateClarifyingQuestions(taskDescription);
        
        // Store spec for potential follow-up
        this.pendingAgentSpec = spec;

        // Generate the agent
        const agent = await this.agentGenerator.generateAgent(spec, this.pendingLanguage);

        // Format response
        let response = `## 🤖 Agent Created: ${spec.name}\n\n`;
        response += `${spec.description}\n\n`;

        // Show decomposed tasks
        response += `### Tasks\n`;
        for (const task of spec.tasks) {
            response += `- ${task}\n`;
        }
        response += '\n';

        // Show policies
        response += `### 🛡️ Safety Policies Applied\n`;
        for (const policy of spec.policies) {
            const icon = policy.required ? '✅' : '💡';
            response += `${icon} **${policy.name}** (${policy.type}): ${policy.description}\n`;
        }
        response += '\n';

        // Show generated code
        const code = agent.code.python || agent.code.typescript || agent.code.go || '';
        response += `### Generated Code (Python)\n`;
        response += `\`\`\`python\n${code.substring(0, 2000)}${code.length > 2000 ? '\n# ... (truncated)' : ''}\n\`\`\`\n\n`;

        // Show clarifying questions if any
        if (questions.length > 0) {
            response += `### 💬 Would you like to refine?\n`;
            for (const q of questions) {
                response += `- ${q}\n`;
            }
            response += '\n';
        }

        // Log creation
        this.auditLogger.log({
            type: 'agent_created',
            timestamp: new Date(),
            agent: spec.name,
            description: taskDescription.substring(0, 200)
        });

        return {
            message: response,
            markdown: true,
            actions: [
                { label: '🚀 Deploy to GitHub Actions', command: 'agent-os.deploy' },
                { label: '🧪 Test Agent', command: 'agent-os.test' },
                { label: '📄 Show TypeScript', command: 'agent-os.showTs' },
                { label: '📋 Copy Code', command: 'agent-os.copy' }
            ],
            suggestions: [
                '@agentos test this agent',
                '@agentos deploy',
                '@agentos add rate limiting policy'
            ]
        };
    }

    /**
     * @agentos design workflow to [goal]
     */
    private async handleDesignCommand(message: string, context: CopilotContext): Promise<ChatResponse> {
        const goalMatch = message.match(/(?:workflow\s+(?:to|for)\s+)?(.+)/i);
        const goal = goalMatch ? goalMatch[1].trim() : message.trim();

        if (!goal || goal.length < 10) {
            return {
                message: `## 📐 Design Workflow

Please describe the goal for your workflow:

\`\`\`
@agentos design workflow to process orders and notify customers
@agentos design workflow for CI/CD pipeline with security checks
\`\`\`
`,
                markdown: true
            };
        }

        // Parse into multi-step workflow
        const spec = this.agentGenerator.parseTaskDescription(goal);

        let response = `## 📐 Workflow Design: ${spec.name}\n\n`;
        response += `**Goal:** ${goal}\n\n`;

        // Visual workflow
        response += `### Workflow Steps\n\n`;
        response += `\`\`\`\n`;
        for (let i = 0; i < spec.tasks.length; i++) {
            const task = spec.tasks[i];
            const connector = i < spec.tasks.length - 1 ? '    │\n    ▼' : '';
            response += `┌──────────────────────────────────┐\n`;
            response += `│ ${(i + 1)}. ${task.padEnd(30)} │\n`;
            response += `└──────────────────────────────────┘\n`;
            if (connector) response += connector + '\n';
        }
        response += `\`\`\`\n\n`;

        // Data flow
        response += `### Data Flow\n`;
        response += `- **Inputs:** ${spec.dataSources.join(', ') || 'None specified'}\n`;
        response += `- **Outputs:** ${spec.outputs.join(', ') || 'None specified'}\n`;
        if (spec.schedule) {
            response += `- **Schedule:** \`${spec.schedule}\`\n`;
        }
        response += '\n';

        // Safety considerations
        response += `### 🛡️ Safety Considerations\n`;
        for (const policy of spec.policies) {
            response += `- ${policy.name}: ${policy.description}\n`;
        }

        return {
            message: response,
            markdown: true,
            actions: [
                { label: 'Generate Code', command: 'agent-os.create' },
                { label: 'Add Step', command: 'agent-os.addStep' }
            ]
        };
    }

    /**
     * @agentos test/simulate - Test agent with scenarios
     */
    private async handleTestCommand(message: string, context: CopilotContext): Promise<ChatResponse> {
        const code = context.selection?.text || context.file?.content || '';
        
        if (!code && !this.pendingAgentSpec) {
            return {
                message: `## 🧪 Test Agent

Please select agent code or create an agent first:

\`\`\`
@agentos create agent for [task]
@agentos test this agent with [scenario]
\`\`\`
`,
                markdown: true
            };
        }

        // Generate test scenarios
        const spec = this.pendingAgentSpec || this.agentGenerator.parseTaskDescription('generic agent');
        const scenarios = this.testSimulator.generateTestScenarios(spec);
        
        // Run tests
        const results = await this.testSimulator.runTests(scenarios);
        
        // Detect edge cases
        const edgeCases = this.testSimulator.detectEdgeCases(spec);
        
        // Format results
        let response = this.testSimulator.formatTestResults(results);
        
        // Add edge cases
        if (edgeCases.length > 0) {
            response += `\n### ⚠️ Potential Edge Cases\n\n`;
            for (const edge of edgeCases.slice(0, 5)) {
                const severity = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };
                response += `${severity[edge.severity]} **${edge.name}**: ${edge.description}\n`;
                response += `   - Recommendation: ${edge.recommendation}\n\n`;
            }
        }

        // Cost estimate
        const cost = this.testSimulator.estimateCost(spec);
        response += `\n### 💰 Cost Estimate\n`;
        response += `- **Monthly:** $${cost.monthly.toFixed(2)}\n`;
        response += `- **Per Run:** $${cost.perRun.toFixed(4)}\n`;

        return {
            message: response,
            markdown: true,
            actions: [
                { label: 'Run Security Audit', command: 'agent-os.security' },
                { label: 'Deploy', command: 'agent-os.deploy' }
            ]
        };
    }

    /**
     * @agentos debug/why - Debug agent failures
     */
    private async handleDebugCommand(message: string, context: CopilotContext): Promise<ChatResponse> {
        // Look for error in message or context
        const errorMessage = message.replace(/^(why|debug)\s*/i, '').trim() || 
                            context.selection?.text || 
                            'Unknown error';

        const diagnosis = this.debugHelper.diagnoseError(errorMessage, {
            file: context.file?.path,
            language: context.file?.language
        });

        const response = this.debugHelper.formatDiagnosis(diagnosis);

        return {
            message: response,
            markdown: true,
            actions: diagnosis.suggestions.filter(s => s.automated).map(s => ({
                label: s.title,
                command: 'agent-os.applyFix',
                args: { fix: s }
            }))
        };
    }

    /**
     * @agentos templates - Browse agent templates
     */
    private handleTemplatesCommand(message: string, context: CopilotContext): ChatResponse {
        // Parse category if provided
        const categoryMatch = message.match(/(data|customer|devops|content|business|security|integration|automation)/i);
        const category = categoryMatch ? categoryMatch[1].toLowerCase() as TemplateCategory : undefined;
        
        // Search templates
        const searchQuery = message.replace(/(templates?|browse)/gi, '').trim();
        const results = this.templateGallery.search(searchQuery || undefined, category as TemplateCategory);

        let response = `## 📚 Agent Templates\n\n`;
        response += `Found **${results.totalCount}** templates`;
        if (category) response += ` in **${category}**`;
        response += '\n\n';

        // Show categories
        const categories = this.templateGallery.getCategories();
        response += `### Categories\n`;
        for (const cat of categories) {
            response += `- **${cat.category}** (${cat.count}): ${cat.description}\n`;
        }
        response += '\n';

        // Show templates
        response += `### Templates\n\n`;
        for (const template of results.templates.slice(0, 10)) {
            const complexity = { beginner: '🟢', intermediate: '🟡', advanced: '🔴' };
            response += `#### ${template.name}\n`;
            response += `${complexity[template.complexity]} ${template.complexity} | ⏱️ ${template.estimatedSetupTime}\n\n`;
            response += `${template.shortDescription}\n\n`;
        }

        if (results.totalCount > 10) {
            response += `\n*Showing 10 of ${results.totalCount}. Use \`@agentos templates [category]\` to filter.*\n`;
        }

        return {
            message: response,
            markdown: true,
            suggestions: [
                '@agentos templates devops',
                '@agentos templates data-processing',
                '@agentos templates customer-support'
            ]
        };
    }

    /**
     * @agentos compliance - Check compliance frameworks
     */
    private handleComplianceCommand(message: string, context: CopilotContext): ChatResponse {
        const code = context.selection?.text || context.file?.content || '';
        const language = context.file?.language || 'python';
        
        // Detect framework from message
        const frameworkMatch = message.match(/(gdpr|hipaa|soc2|pci-?dss|iso27001|ccpa)/i);
        
        if (!frameworkMatch) {
            // Show available frameworks
            const frameworks = this.policyLibrary.getFrameworks();
            
            let response = `## 📋 Compliance Frameworks\n\n`;
            response += `AgentOS supports the following compliance frameworks:\n\n`;
            
            for (const fw of frameworks) {
                response += `### ${fw.framework.toUpperCase()}\n`;
                response += `${fw.description}\n\n`;
            }
            
            response += `Use \`@agentos compliance [framework]\` to check compliance.\n`;
            response += `Example: \`@agentos compliance gdpr\`\n`;
            
            return {
                message: response,
                markdown: true,
                suggestions: frameworks.map(f => `@agentos compliance ${f.framework}`)
            };
        }

        const framework = frameworkMatch[1].toLowerCase().replace('-', '') as ComplianceFramework;
        const policyId = `${framework}-standard`;
        
        // Validate code against policy
        const result = this.policyLibrary.validateAgainstPolicy(code, language, policyId);
        
        // Format policy info
        let response = this.policyLibrary.formatPolicyForChat(policyId);
        
        // Add validation results
        const scoreEmoji = result.score >= 80 ? '🟢' : result.score >= 60 ? '🟡' : '🔴';
        response += `\n### Compliance Check\n`;
        response += `**Score:** ${scoreEmoji} ${result.score}/100\n`;
        response += `**Status:** ${result.compliant ? '✅ Compliant' : '❌ Non-Compliant'}\n\n`;
        
        if (result.violations.length > 0) {
            response += `### Violations (${result.violations.length})\n`;
            for (const v of result.violations) {
                response += `- ❌ **${v.controlName}**: ${v.description}\n`;
            }
            response += '\n';
        }
        
        if (result.recommendations.length > 0) {
            response += `### Recommendations\n`;
            for (const rec of result.recommendations) {
                response += `- ${rec}\n`;
            }
        }

        return {
            message: response,
            markdown: true,
            actions: [
                { label: 'Generate Policy YAML', command: 'agent-os.generatePolicy', args: { policyId } },
                { label: 'Fix Violations', command: 'agent-os.fixViolations' }
            ]
        };
    }

    /**
     * @agentos deploy - Deploy agent to GitHub Actions
     */
    private async handleDeployCommand(message: string, context: CopilotContext): Promise<ChatResponse> {
        if (!this.pendingAgentSpec) {
            return {
                message: `## 🚀 Deploy Agent

Please create an agent first:

\`\`\`
@agentos create agent for [task]
@agentos deploy
\`\`\`
`,
                markdown: true
            };
        }

        const spec = this.pendingAgentSpec;
        const config: DeploymentConfig = {
            environment: 'staging',
            secrets: [],
            schedule: spec.schedule
        };

        // Generate agent code
        const agent = await this.agentGenerator.generateAgent(spec, 'python');
        
        // Generate PR files
        const files = this.githubIntegration.generatePRFiles(agent, config);
        
        // Generate workflow
        const workflow = this.githubIntegration.generateWorkflowYaml(spec, config);
        
        // Generate secrets instructions
        const secrets = config.secrets.length > 0 ? 
            this.githubIntegration.generateSecretsInstructions(config.secrets) : '';

        let response = `## 🚀 Deploy ${spec.name}\n\n`;
        
        // Show files to create
        response += `### Files to Create\n\n`;
        for (const file of files.agentCode) {
            response += `- \`${file.path}\`\n`;
        }
        if (files.workflow) response += `- \`${files.workflow.path}\`\n`;
        if (files.policy) response += `- \`${files.policy.path}\`\n`;
        if (files.tests) response += `- \`${files.tests.path}\`\n`;
        response += '\n';

        // Show workflow
        response += `### GitHub Actions Workflow\n\n`;
        response += `\`\`\`yaml\n${workflow.substring(0, 1500)}${workflow.length > 1500 ? '\n# ...' : ''}\n\`\`\`\n\n`;

        // Schedule info
        if (spec.schedule) {
            response += `### Schedule\n`;
            response += `Agent will run on cron: \`${spec.schedule}\`\n\n`;
        }

        // Secrets
        if (secrets) {
            response += secrets;
        }

        // PR description
        response += `### Pull Request\n`;
        response += `Ready to create a PR with all files.\n`;

        return {
            message: response,
            markdown: true,
            actions: [
                { label: 'Create Pull Request', command: 'agent-os.createPR' },
                { label: 'Copy Files', command: 'agent-os.copyFiles' },
                { label: 'Configure Secrets', command: 'agent-os.secrets' }
            ]
        };
    }

    /**
     * @agentos security - Run security audit
     */
    private handleSecurityCommand(message: string, context: CopilotContext): ChatResponse {
        const code = context.selection?.text || context.file?.content || '';
        const language = context.file?.language || 'python';

        if (!code) {
            return {
                message: `## 🔒 Security Audit

Please select code to audit or have an open file.

\`\`\`
# Select code and run:
@agentos security
\`\`\`
`,
                markdown: true
            };
        }

        const audit = this.testSimulator.runSecurityAudit(code, language);
        const response = this.testSimulator.formatSecurityAudit(audit);

        return {
            message: response,
            markdown: true,
            actions: audit.vulnerabilities.map(v => ({
                label: `Fix: ${v.name}`,
                command: 'agent-os.fixVuln',
                args: { vuln: v }
            }))
        };
    }

    /**
     * @agentos optimize - Performance optimization suggestions
     */
    private handleOptimizeCommand(message: string, context: CopilotContext): ChatResponse {
        const code = context.selection?.text || context.file?.content || '';
        const language = context.file?.language || 'python';

        if (!code) {
            return {
                message: `## 🚀 Performance Optimization

Please select code to optimize.
`,
                markdown: true
            };
        }

        const response = this.debugHelper.suggestOptimizations(code, language);

        return {
            message: response,
            markdown: true
        };
    }

    /**
     * Annotate code with safety markers
     */
    async annotateCode(
        code: string,
        language: string,
        context: CopilotContext
    ): Promise<SafetyAnnotation[]> {
        const result = await this.policyEngine.analyzeCode(code, language);
        return this.createAnnotations(code, result);
    }

    /**
     * Create annotations from analysis result
     */
    private createAnnotations(code: string, result: AnalysisResult): SafetyAnnotation[] {
        const annotations: SafetyAnnotation[] = [];
        
        if (result.blocked) {
            // Find the line containing the violation (simple heuristic)
            const lines = code.split('\n');
            for (let i = 0; i < lines.length; i++) {
                // Match against common dangerous patterns
                if (this.lineMatchesViolation(lines[i], result.violation)) {
                    annotations.push({
                        line: i + 1,
                        column: 1,
                        severity: 'error',
                        message: result.reason,
                        rule: result.violation,
                        suggestion: result.suggestion
                    });
                    break;
                }
            }

            // If no specific line found, annotate first line
            if (annotations.length === 0) {
                annotations.push({
                    line: 1,
                    column: 1,
                    severity: 'error',
                    message: result.reason,
                    rule: result.violation,
                    suggestion: result.suggestion
                });
            }
        }

        return annotations;
    }

    /**
     * Create warning annotations
     */
    private createWarningAnnotations(code: string, warnings: string[]): SafetyAnnotation[] {
        return warnings.map((warning, index) => ({
            line: 1,
            column: 1,
            severity: 'warning' as const,
            message: warning,
            rule: `warning_${index}`
        }));
    }

    /**
     * Check if line matches violation pattern
     */
    private lineMatchesViolation(line: string, violation: string): boolean {
        const patterns: Record<string, RegExp> = {
            'drop_table': /DROP\s+TABLE/i,
            'delete_all': /DELETE\s+FROM/i,
            'rm_rf': /rm\s+-rf/i,
            'hardcoded_api_key': /api[_-]?key\s*=/i,
            'hardcoded_password': /password\s*=/i,
            'sudo': /sudo\s+/i,
            'chmod_777': /chmod\s+777/i
        };

        const pattern = patterns[violation];
        return pattern ? pattern.test(line) : false;
    }

    /**
     * Format timestamp for display
     */
    private formatTime(timestamp: Date): string {
        const now = new Date();
        const diff = now.getTime() - new Date(timestamp).getTime();
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);

        if (minutes < 1) return 'just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        return new Date(timestamp).toLocaleDateString();
    }
}

interface FilterSummary {
    total: number;
    safe: number;
    warnings: number;
    blocked: number;
    timestamp: string;
}

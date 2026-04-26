// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Template Gallery
 * 
 * Provides a searchable library of pre-built agent templates
 * organized by category for quick instantiation.
 */

import { AgentSpec, PolicyRecommendation } from './agentGenerator';
import { logger } from './logger';

export interface AgentTemplate {
    id: string;
    name: string;
    category: TemplateCategory;
    description: string;
    shortDescription: string;
    tags: string[];
    complexity: 'beginner' | 'intermediate' | 'advanced';
    estimatedSetupTime: string;
    spec: Partial<AgentSpec>;
    requiredSecrets: string[];
    documentation?: string;
    exampleUseCase?: string;
}

export type TemplateCategory = 
    | 'data-processing'
    | 'customer-support'
    | 'devops'
    | 'content-management'
    | 'business-intelligence'
    | 'security'
    | 'integration'
    | 'automation';

export interface TemplateSearchResult {
    templates: AgentTemplate[];
    totalCount: number;
    categories: Record<TemplateCategory, number>;
}

export class TemplateGallery {
    private templates: AgentTemplate[] = [];

    constructor() {
        this.loadTemplates();
    }

    /**
     * Search templates by query and filters
     */
    search(
        query?: string,
        category?: TemplateCategory,
        complexity?: AgentTemplate['complexity'],
        limit: number = 20
    ): TemplateSearchResult {
        let results = [...this.templates];

        // Filter by category
        if (category) {
            results = results.filter(t => t.category === category);
        }

        // Filter by complexity
        if (complexity) {
            results = results.filter(t => t.complexity === complexity);
        }

        // Search by query
        if (query) {
            const q = query.toLowerCase();
            results = results.filter(t =>
                t.name.toLowerCase().includes(q) ||
                t.description.toLowerCase().includes(q) ||
                t.tags.some(tag => tag.toLowerCase().includes(q))
            );
        }

        // Count by category
        const categories = this.templates.reduce((acc, t) => {
            acc[t.category] = (acc[t.category] || 0) + 1;
            return acc;
        }, {} as Record<TemplateCategory, number>);

        return {
            templates: results.slice(0, limit),
            totalCount: results.length,
            categories
        };
    }

    /**
     * Get template by ID
     */
    getById(id: string): AgentTemplate | undefined {
        return this.templates.find(t => t.id === id);
    }

    /**
     * Get templates by category
     */
    getByCategory(category: TemplateCategory): AgentTemplate[] {
        return this.templates.filter(t => t.category === category);
    }

    /**
     * Get recommended templates based on description
     */
    recommend(description: string, limit: number = 5): AgentTemplate[] {
        const words = description.toLowerCase().split(/\s+/);
        
        // Score templates by keyword matches
        const scored = this.templates.map(template => {
            let score = 0;
            const templateText = `${template.name} ${template.description} ${template.tags.join(' ')}`.toLowerCase();
            
            for (const word of words) {
                if (word.length > 2 && templateText.includes(word)) {
                    score += 1;
                }
            }
            
            return { template, score };
        });

        // Sort by score and return top matches
        return scored
            .filter(s => s.score > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, limit)
            .map(s => s.template);
    }

    /**
     * Get all categories with counts
     */
    getCategories(): { category: TemplateCategory; count: number; description: string }[] {
        const categoryInfo: Record<TemplateCategory, string> = {
            'data-processing': 'ETL, data cleaning, file processing',
            'customer-support': 'Ticket routing, sentiment analysis, FAQ automation',
            'devops': 'Deployment, monitoring, incident response',
            'content-management': 'Content moderation, SEO, social media',
            'business-intelligence': 'Dashboards, KPIs, anomaly detection',
            'security': 'Security scanning, compliance checks, access control',
            'integration': 'API connectors, data sync, webhooks',
            'automation': 'Workflow automation, scheduled tasks, notifications'
        };

        const counts = this.templates.reduce((acc, t) => {
            acc[t.category] = (acc[t.category] || 0) + 1;
            return acc;
        }, {} as Record<TemplateCategory, number>);

        return Object.entries(categoryInfo).map(([category, description]) => ({
            category: category as TemplateCategory,
            count: counts[category as TemplateCategory] || 0,
            description
        }));
    }

    /**
     * Format template for chat display
     */
    formatForChat(template: AgentTemplate): string {
        const complexityEmoji = {
            'beginner': '🟢',
            'intermediate': '🟡',
            'advanced': '🔴'
        };

        return `### ${template.name}

${template.description}

| Property | Value |
|----------|-------|
| Category | ${template.category} |
| Complexity | ${complexityEmoji[template.complexity]} ${template.complexity} |
| Setup Time | ${template.estimatedSetupTime} |
| Tags | ${template.tags.join(', ')} |

**Required Secrets:** ${template.requiredSecrets.length > 0 ? template.requiredSecrets.join(', ') : 'None'}

${template.exampleUseCase ? `**Example Use Case:** ${template.exampleUseCase}` : ''}
`;
    }

    /**
     * Load all templates
     */
    private loadTemplates(): void {
        this.templates = [
            // ===== DATA PROCESSING =====
            {
                id: 'csv-processor',
                name: 'CSV File Processor',
                category: 'data-processing',
                description: 'Processes CSV files with validation, transformation, and error handling. Supports large files with streaming.',
                shortDescription: 'Process and transform CSV files',
                tags: ['csv', 'etl', 'data', 'file', 'transform'],
                complexity: 'beginner',
                estimatedSetupTime: '5 minutes',
                spec: {
                    dataSources: ['CSV File'],
                    outputs: ['CSV File', 'Database'],
                    tasks: ['Read CSV file', 'Validate data', 'Transform columns', 'Write output'],
                    policies: [
                        { name: 'File Size Limit', type: 'resource', description: 'Limits file size to 100MB', required: true },
                        { name: 'Data Validation', type: 'validation', description: 'Validates data types and formats', required: true }
                    ]
                },
                requiredSecrets: [],
                exampleUseCase: 'Daily import of sales data from CSV exports'
            },
            {
                id: 'data-cleaner',
                name: 'Data Cleaning Agent',
                category: 'data-processing',
                description: 'Cleans and normalizes data by removing duplicates, fixing formats, and handling missing values.',
                shortDescription: 'Clean and normalize datasets',
                tags: ['cleaning', 'normalization', 'dedup', 'data quality'],
                complexity: 'intermediate',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['Database', 'CSV File'],
                    outputs: ['Database'],
                    tasks: ['Fetch raw data', 'Remove duplicates', 'Normalize formats', 'Handle missing values', 'Write clean data'],
                    policies: [
                        { name: 'Data Backup', type: 'safety', description: 'Creates backup before cleaning', required: true }
                    ]
                },
                requiredSecrets: ['DATABASE_URL'],
                exampleUseCase: 'Weekly data quality maintenance'
            },
            {
                id: 'etl-pipeline',
                name: 'ETL Pipeline Agent',
                category: 'data-processing',
                description: 'Full Extract-Transform-Load pipeline with support for multiple sources and destinations.',
                shortDescription: 'Complete ETL pipeline',
                tags: ['etl', 'pipeline', 'warehouse', 'integration'],
                complexity: 'advanced',
                estimatedSetupTime: '30 minutes',
                spec: {
                    dataSources: ['REST API', 'Database', 'CSV File'],
                    outputs: ['Database', 'Data Warehouse'],
                    tasks: ['Extract from sources', 'Transform data', 'Load to destination', 'Validate results'],
                    policies: [
                        { name: 'Transaction Safety', type: 'safety', description: 'Uses transactions for data integrity', required: true },
                        { name: 'Retry Policy', type: 'retry', description: 'Retries failed operations', required: true }
                    ]
                },
                requiredSecrets: ['DATABASE_URL', 'WAREHOUSE_URL'],
                exampleUseCase: 'Nightly data warehouse refresh'
            },
            {
                id: 'report-generator',
                name: 'Report Generator',
                category: 'data-processing',
                description: 'Generates formatted reports from data sources with charts and summaries.',
                shortDescription: 'Generate data reports',
                tags: ['reports', 'pdf', 'charts', 'summary'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Database', 'REST API'],
                    outputs: ['Email', 'Storage'],
                    tasks: ['Fetch data', 'Calculate metrics', 'Generate charts', 'Format report', 'Distribute'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL', 'SMTP_HOST'],
                exampleUseCase: 'Weekly sales report generation'
            },
            {
                id: 'data-sync',
                name: 'Data Sync Agent',
                category: 'data-processing',
                description: 'Synchronizes data between two systems with conflict resolution and change tracking.',
                shortDescription: 'Sync data between systems',
                tags: ['sync', 'replication', 'bidirectional'],
                complexity: 'advanced',
                estimatedSetupTime: '25 minutes',
                spec: {
                    dataSources: ['Database', 'REST API'],
                    outputs: ['Database', 'REST API'],
                    tasks: ['Detect changes', 'Resolve conflicts', 'Apply updates', 'Log sync history'],
                    policies: [
                        { name: 'Conflict Resolution', type: 'safety', description: 'Handles sync conflicts gracefully', required: true }
                    ]
                },
                requiredSecrets: ['SOURCE_DB_URL', 'TARGET_API_KEY'],
                exampleUseCase: 'Real-time CRM to ERP sync'
            },

            // ===== CUSTOMER SUPPORT =====
            {
                id: 'ticket-router',
                name: 'Support Ticket Router',
                category: 'customer-support',
                description: 'Automatically routes support tickets to the right team based on content analysis.',
                shortDescription: 'Route tickets to teams',
                tags: ['tickets', 'routing', 'support', 'classification'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Jira API', 'Zendesk API'],
                    outputs: ['Jira API', 'Slack'],
                    tasks: ['Fetch new tickets', 'Analyze content', 'Classify priority', 'Route to team', 'Notify assignee'],
                    policies: [
                        { name: 'PII Protection', type: 'data_privacy', description: 'Protects customer PII', required: true }
                    ]
                },
                requiredSecrets: ['JIRA_TOKEN', 'SLACK_WEBHOOK_URL'],
                exampleUseCase: 'Auto-route incoming support requests'
            },
            {
                id: 'sentiment-analyzer',
                name: 'Sentiment Analysis Agent',
                category: 'customer-support',
                description: 'Analyzes customer feedback and messages to detect sentiment and escalate negative cases.',
                shortDescription: 'Analyze customer sentiment',
                tags: ['sentiment', 'nlp', 'feedback', 'escalation'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Slack API', 'Email'],
                    outputs: ['Database', 'Slack'],
                    tasks: ['Collect feedback', 'Analyze sentiment', 'Score messages', 'Alert on negative', 'Store results'],
                    policies: [
                        { name: 'PII Protection', type: 'data_privacy', description: 'Anonymizes personal data', required: true }
                    ]
                },
                requiredSecrets: ['SLACK_TOKEN', 'DATABASE_URL'],
                exampleUseCase: 'Monitor customer satisfaction in real-time'
            },
            {
                id: 'faq-bot',
                name: 'FAQ Automation Agent',
                category: 'customer-support',
                description: 'Automatically answers common questions from a knowledge base.',
                shortDescription: 'Auto-answer FAQs',
                tags: ['faq', 'chatbot', 'knowledge base', 'automation'],
                complexity: 'beginner',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['Knowledge Base'],
                    outputs: ['Slack', 'Email'],
                    tasks: ['Receive question', 'Search knowledge base', 'Generate response', 'Send answer'],
                    policies: []
                },
                requiredSecrets: ['SLACK_TOKEN'],
                exampleUseCase: 'Handle common customer questions automatically'
            },
            {
                id: 'escalation-agent',
                name: 'Escalation Routing Agent',
                category: 'customer-support',
                description: 'Monitors support channels and escalates critical issues to managers.',
                shortDescription: 'Escalate critical issues',
                tags: ['escalation', 'priority', 'alert', 'management'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Jira API', 'Slack API'],
                    outputs: ['Slack', 'Email', 'PagerDuty'],
                    tasks: ['Monitor tickets', 'Detect critical issues', 'Notify managers', 'Track resolution'],
                    policies: []
                },
                requiredSecrets: ['JIRA_TOKEN', 'PAGERDUTY_KEY'],
                exampleUseCase: 'Auto-escalate VIP customer issues'
            },
            {
                id: 'support-analytics',
                name: 'Support Analytics Agent',
                category: 'customer-support',
                description: 'Generates analytics and insights from support ticket data.',
                shortDescription: 'Analyze support metrics',
                tags: ['analytics', 'metrics', 'reporting', 'insights'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Jira API', 'Database'],
                    outputs: ['Dashboard', 'Slack'],
                    tasks: ['Collect ticket data', 'Calculate metrics', 'Identify trends', 'Generate report'],
                    policies: []
                },
                requiredSecrets: ['JIRA_TOKEN', 'DATABASE_URL'],
                exampleUseCase: 'Weekly support team performance report'
            },

            // ===== DEVOPS =====
            {
                id: 'deployment-agent',
                name: 'Deployment Automation Agent',
                category: 'devops',
                description: 'Automates deployment workflows with rollback capabilities and notifications.',
                shortDescription: 'Automate deployments',
                tags: ['deployment', 'ci/cd', 'rollback', 'automation'],
                complexity: 'advanced',
                estimatedSetupTime: '30 minutes',
                spec: {
                    dataSources: ['GitHub API'],
                    outputs: ['Slack', 'GitHub Actions'],
                    tasks: ['Trigger deployment', 'Run health checks', 'Notify team', 'Rollback on failure'],
                    policies: [
                        { name: 'Deployment Window', type: 'schedule', description: 'Only deploy during allowed hours', required: true },
                        { name: 'Approval Gate', type: 'approval', description: 'Requires approval for production', required: true }
                    ]
                },
                requiredSecrets: ['GITHUB_TOKEN', 'SLACK_WEBHOOK_URL'],
                exampleUseCase: 'Automated staging deployments on PR merge'
            },
            {
                id: 'uptime-monitor',
                name: 'Uptime Monitoring Agent',
                category: 'devops',
                description: 'Monitors API endpoints and websites for uptime with alerting.',
                shortDescription: 'Monitor service uptime',
                tags: ['monitoring', 'uptime', 'alerting', 'health check'],
                complexity: 'beginner',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['HTTP Endpoints'],
                    outputs: ['Slack', 'PagerDuty'],
                    tasks: ['Check endpoints', 'Record response times', 'Detect outages', 'Send alerts'],
                    policies: [
                        { name: 'Rate Limiting', type: 'rate_limit', description: 'Limits check frequency', required: true }
                    ]
                },
                requiredSecrets: ['SLACK_WEBHOOK_URL'],
                exampleUseCase: 'Monitor production APIs every 5 minutes'
            },
            {
                id: 'log-analyzer',
                name: 'Log Analysis Agent',
                category: 'devops',
                description: 'Analyzes application logs to detect errors, anomalies, and patterns.',
                shortDescription: 'Analyze application logs',
                tags: ['logs', 'analysis', 'errors', 'anomaly detection'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Log Files', 'Elasticsearch'],
                    outputs: ['Slack', 'Dashboard'],
                    tasks: ['Fetch logs', 'Parse entries', 'Detect anomalies', 'Alert on errors'],
                    policies: []
                },
                requiredSecrets: ['ELASTICSEARCH_URL'],
                exampleUseCase: 'Real-time error detection in production logs'
            },
            {
                id: 'incident-responder',
                name: 'Incident Response Agent',
                category: 'devops',
                description: 'Coordinates incident response with automated runbooks and communication.',
                shortDescription: 'Coordinate incident response',
                tags: ['incident', 'response', 'runbook', 'oncall'],
                complexity: 'advanced',
                estimatedSetupTime: '30 minutes',
                spec: {
                    dataSources: ['PagerDuty', 'Monitoring APIs'],
                    outputs: ['Slack', 'Jira', 'PagerDuty'],
                    tasks: ['Detect incident', 'Page on-call', 'Create ticket', 'Run diagnostics', 'Post updates'],
                    policies: []
                },
                requiredSecrets: ['PAGERDUTY_KEY', 'JIRA_TOKEN'],
                exampleUseCase: 'Automated incident management workflow'
            },
            {
                id: 'security-scanner',
                name: 'Security Scanning Agent',
                category: 'devops',
                description: 'Scans code and dependencies for security vulnerabilities.',
                shortDescription: 'Scan for vulnerabilities',
                tags: ['security', 'scanning', 'vulnerabilities', 'dependencies'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['GitHub API'],
                    outputs: ['GitHub Issues', 'Slack'],
                    tasks: ['Scan repository', 'Check dependencies', 'Report vulnerabilities', 'Create issues'],
                    policies: []
                },
                requiredSecrets: ['GITHUB_TOKEN'],
                exampleUseCase: 'Daily security scan of all repositories'
            },

            // ===== CONTENT MANAGEMENT =====
            {
                id: 'content-moderator',
                name: 'Content Moderation Agent',
                category: 'content-management',
                description: 'Automatically moderates user-generated content for policy violations.',
                shortDescription: 'Moderate user content',
                tags: ['moderation', 'content', 'policy', 'safety'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Database', 'REST API'],
                    outputs: ['Database', 'Slack'],
                    tasks: ['Fetch new content', 'Analyze for violations', 'Flag or remove', 'Notify moderators'],
                    policies: [
                        { name: 'Content Policy', type: 'moderation', description: 'Enforces content guidelines', required: true }
                    ]
                },
                requiredSecrets: ['DATABASE_URL'],
                exampleUseCase: 'Moderate forum posts and comments'
            },
            {
                id: 'seo-optimizer',
                name: 'SEO Optimization Agent',
                category: 'content-management',
                description: 'Analyzes content for SEO and suggests improvements.',
                shortDescription: 'Optimize content for SEO',
                tags: ['seo', 'optimization', 'content', 'marketing'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['CMS API', 'Google Search Console'],
                    outputs: ['CMS API', 'Report'],
                    tasks: ['Analyze content', 'Check keywords', 'Suggest improvements', 'Track rankings'],
                    policies: []
                },
                requiredSecrets: ['CMS_API_KEY', 'GOOGLE_API_KEY'],
                exampleUseCase: 'Weekly SEO audit of blog posts'
            },
            {
                id: 'social-poster',
                name: 'Social Media Posting Agent',
                category: 'content-management',
                description: 'Schedules and posts content across social media platforms.',
                shortDescription: 'Post to social media',
                tags: ['social', 'posting', 'scheduling', 'marketing'],
                complexity: 'beginner',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['Content Queue'],
                    outputs: ['Twitter API', 'LinkedIn API'],
                    tasks: ['Fetch scheduled posts', 'Format for platform', 'Post content', 'Track engagement'],
                    policies: [
                        { name: 'Rate Limiting', type: 'rate_limit', description: 'Limits posts per day', required: true }
                    ]
                },
                requiredSecrets: ['TWITTER_API_KEY', 'LINKEDIN_TOKEN'],
                exampleUseCase: 'Schedule and post marketing content'
            },
            {
                id: 'newsletter-generator',
                name: 'Newsletter Generation Agent',
                category: 'content-management',
                description: 'Automatically generates newsletters from curated content.',
                shortDescription: 'Generate newsletters',
                tags: ['newsletter', 'email', 'content', 'curation'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['RSS Feed', 'CMS API'],
                    outputs: ['Email'],
                    tasks: ['Fetch recent content', 'Curate highlights', 'Format newsletter', 'Send to subscribers'],
                    policies: []
                },
                requiredSecrets: ['SMTP_HOST', 'SMTP_USER'],
                exampleUseCase: 'Weekly company newsletter'
            },
            {
                id: 'translation-agent',
                name: 'Content Translation Agent',
                category: 'content-management',
                description: 'Translates content to multiple languages with quality checks.',
                shortDescription: 'Translate content',
                tags: ['translation', 'localization', 'i18n', 'languages'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['CMS API'],
                    outputs: ['CMS API'],
                    tasks: ['Fetch content', 'Translate text', 'Quality check', 'Publish translations'],
                    policies: []
                },
                requiredSecrets: ['TRANSLATION_API_KEY'],
                exampleUseCase: 'Translate product pages to multiple languages'
            },

            // ===== BUSINESS INTELLIGENCE =====
            {
                id: 'dashboard-updater',
                name: 'Dashboard Update Agent',
                category: 'business-intelligence',
                description: 'Automatically updates dashboards with latest metrics and data.',
                shortDescription: 'Update dashboards',
                tags: ['dashboard', 'metrics', 'kpi', 'visualization'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Database', 'REST API'],
                    outputs: ['Dashboard'],
                    tasks: ['Fetch metrics', 'Calculate KPIs', 'Update visualizations', 'Cache results'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL', 'DASHBOARD_API_KEY'],
                exampleUseCase: 'Hourly sales dashboard refresh'
            },
            {
                id: 'kpi-tracker',
                name: 'KPI Tracking Agent',
                category: 'business-intelligence',
                description: 'Tracks key performance indicators and alerts on thresholds.',
                shortDescription: 'Track KPIs',
                tags: ['kpi', 'tracking', 'alerts', 'metrics'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Database'],
                    outputs: ['Slack', 'Email'],
                    tasks: ['Calculate KPIs', 'Compare to targets', 'Alert on thresholds', 'Generate reports'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL', 'SLACK_WEBHOOK_URL'],
                exampleUseCase: 'Daily KPI monitoring for sales team'
            },
            {
                id: 'anomaly-detector',
                name: 'Anomaly Detection Agent',
                category: 'business-intelligence',
                description: 'Detects unusual patterns in business metrics and data.',
                shortDescription: 'Detect anomalies',
                tags: ['anomaly', 'detection', 'ml', 'monitoring'],
                complexity: 'advanced',
                estimatedSetupTime: '25 minutes',
                spec: {
                    dataSources: ['Database', 'Time Series DB'],
                    outputs: ['Slack', 'Dashboard'],
                    tasks: ['Fetch data', 'Calculate baselines', 'Detect anomalies', 'Alert on deviations'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL'],
                exampleUseCase: 'Detect unusual transaction patterns'
            },
            {
                id: 'trend-analyzer',
                name: 'Trend Analysis Agent',
                category: 'business-intelligence',
                description: 'Analyzes historical data to identify trends and patterns.',
                shortDescription: 'Analyze trends',
                tags: ['trends', 'analysis', 'forecasting', 'patterns'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Database'],
                    outputs: ['Report', 'Dashboard'],
                    tasks: ['Fetch historical data', 'Calculate trends', 'Generate insights', 'Create visualizations'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL'],
                exampleUseCase: 'Monthly trend analysis for product metrics'
            },
            {
                id: 'forecasting-agent',
                name: 'Forecasting Agent',
                category: 'business-intelligence',
                description: 'Generates forecasts and predictions from historical data.',
                shortDescription: 'Generate forecasts',
                tags: ['forecasting', 'prediction', 'ml', 'planning'],
                complexity: 'advanced',
                estimatedSetupTime: '30 minutes',
                spec: {
                    dataSources: ['Database'],
                    outputs: ['Dashboard', 'Report'],
                    tasks: ['Fetch historical data', 'Train model', 'Generate forecast', 'Validate predictions'],
                    policies: []
                },
                requiredSecrets: ['DATABASE_URL'],
                exampleUseCase: 'Quarterly revenue forecasting'
            },

            // ===== SECURITY =====
            {
                id: 'access-auditor',
                name: 'Access Audit Agent',
                category: 'security',
                description: 'Audits user access and permissions across systems.',
                shortDescription: 'Audit access permissions',
                tags: ['audit', 'access', 'permissions', 'compliance'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Identity Provider API', 'Cloud APIs'],
                    outputs: ['Report', 'Slack'],
                    tasks: ['Fetch access data', 'Analyze permissions', 'Detect over-privileged', 'Generate report'],
                    policies: [
                        { name: 'Audit Logging', type: 'logging', description: 'Logs all access checks', required: true }
                    ]
                },
                requiredSecrets: ['IDENTITY_API_KEY'],
                exampleUseCase: 'Weekly access review for compliance'
            },
            {
                id: 'compliance-checker',
                name: 'Compliance Check Agent',
                category: 'security',
                description: 'Checks systems against compliance frameworks (SOC2, GDPR, etc.).',
                shortDescription: 'Check compliance status',
                tags: ['compliance', 'soc2', 'gdpr', 'audit'],
                complexity: 'advanced',
                estimatedSetupTime: '30 minutes',
                spec: {
                    dataSources: ['Cloud APIs', 'Configuration APIs'],
                    outputs: ['Report', 'Jira'],
                    tasks: ['Scan configurations', 'Check against framework', 'Identify gaps', 'Create remediation tasks'],
                    policies: []
                },
                requiredSecrets: ['CLOUD_API_KEY'],
                exampleUseCase: 'Monthly SOC2 compliance scan'
            },
            {
                id: 'secret-scanner',
                name: 'Secret Scanning Agent',
                category: 'security',
                description: 'Scans repositories and systems for exposed secrets.',
                shortDescription: 'Scan for exposed secrets',
                tags: ['secrets', 'scanning', 'security', 'leaks'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['GitHub API', 'File System'],
                    outputs: ['Slack', 'GitHub Issues'],
                    tasks: ['Scan repositories', 'Detect secrets', 'Alert security team', 'Create issues'],
                    policies: []
                },
                requiredSecrets: ['GITHUB_TOKEN'],
                exampleUseCase: 'Continuous secret scanning across repos'
            },

            // ===== INTEGRATION =====
            {
                id: 'api-connector',
                name: 'API Integration Agent',
                category: 'integration',
                description: 'Connects and syncs data between APIs with transformation.',
                shortDescription: 'Connect APIs',
                tags: ['api', 'integration', 'sync', 'connector'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['REST API'],
                    outputs: ['REST API'],
                    tasks: ['Fetch from source', 'Transform data', 'Push to destination', 'Handle errors'],
                    policies: [
                        { name: 'Retry Policy', type: 'retry', description: 'Retries failed requests', required: true }
                    ]
                },
                requiredSecrets: ['SOURCE_API_KEY', 'DEST_API_KEY'],
                exampleUseCase: 'Sync Salesforce contacts to HubSpot'
            },
            {
                id: 'webhook-handler',
                name: 'Webhook Handler Agent',
                category: 'integration',
                description: 'Processes incoming webhooks and triggers actions.',
                shortDescription: 'Handle webhooks',
                tags: ['webhook', 'events', 'trigger', 'automation'],
                complexity: 'beginner',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['Webhook'],
                    outputs: ['Database', 'Slack'],
                    tasks: ['Receive webhook', 'Validate payload', 'Process event', 'Trigger actions'],
                    policies: [
                        { name: 'Signature Validation', type: 'security', description: 'Validates webhook signatures', required: true }
                    ]
                },
                requiredSecrets: ['WEBHOOK_SECRET'],
                exampleUseCase: 'Process GitHub webhooks for CI/CD'
            },

            // ===== AUTOMATION =====
            {
                id: 'standup-reporter',
                name: 'Standup Report Agent',
                category: 'automation',
                description: 'Generates daily standup reports from GitHub, Jira, and calendar.',
                shortDescription: 'Generate standup reports',
                tags: ['standup', 'report', 'daily', 'team'],
                complexity: 'beginner',
                estimatedSetupTime: '10 minutes',
                spec: {
                    dataSources: ['GitHub API', 'Jira API', 'Calendar API'],
                    outputs: ['Slack'],
                    tasks: ['Fetch commits', 'Fetch tickets', 'Fetch meetings', 'Format report', 'Post to Slack'],
                    policies: []
                },
                requiredSecrets: ['GITHUB_TOKEN', 'JIRA_TOKEN', 'SLACK_WEBHOOK_URL'],
                exampleUseCase: 'Daily 9am standup report to #team channel'
            },
            {
                id: 'notification-agent',
                name: 'Smart Notification Agent',
                category: 'automation',
                description: 'Sends intelligent notifications based on events and preferences.',
                shortDescription: 'Send smart notifications',
                tags: ['notifications', 'alerts', 'smart', 'routing'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Event Queue'],
                    outputs: ['Slack', 'Email', 'SMS'],
                    tasks: ['Receive events', 'Check preferences', 'Format message', 'Send notification'],
                    policies: [
                        { name: 'Rate Limiting', type: 'rate_limit', description: 'Prevents notification spam', required: true }
                    ]
                },
                requiredSecrets: ['SLACK_TOKEN', 'TWILIO_KEY'],
                exampleUseCase: 'Route alerts to the right channel'
            },
            {
                id: 'cleanup-agent',
                name: 'Resource Cleanup Agent',
                category: 'automation',
                description: 'Automatically cleans up unused resources and old data.',
                shortDescription: 'Clean up resources',
                tags: ['cleanup', 'maintenance', 'resources', 'cost'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Cloud APIs', 'Database'],
                    outputs: ['Report', 'Slack'],
                    tasks: ['Identify unused resources', 'Calculate savings', 'Clean up safely', 'Report results'],
                    policies: [
                        { name: 'Safety Check', type: 'safety', description: 'Prevents accidental deletions', required: true }
                    ]
                },
                requiredSecrets: ['CLOUD_API_KEY'],
                exampleUseCase: 'Weekly cleanup of unused cloud resources'
            },
            {
                id: 'backup-agent',
                name: 'Backup Automation Agent',
                category: 'automation',
                description: 'Automates backup creation and verification.',
                shortDescription: 'Automate backups',
                tags: ['backup', 'disaster recovery', 'automation'],
                complexity: 'intermediate',
                estimatedSetupTime: '20 minutes',
                spec: {
                    dataSources: ['Database', 'File System'],
                    outputs: ['Cloud Storage', 'Slack'],
                    tasks: ['Create backup', 'Verify integrity', 'Upload to storage', 'Notify on completion'],
                    policies: [
                        { name: 'Encryption', type: 'security', description: 'Encrypts backups at rest', required: true }
                    ]
                },
                requiredSecrets: ['DATABASE_URL', 'STORAGE_KEY'],
                exampleUseCase: 'Daily database backups to S3'
            },
            {
                id: 'expense-tracker',
                name: 'Expense Tracking Agent',
                category: 'automation',
                description: 'Tracks and categorizes expenses from receipts and transactions.',
                shortDescription: 'Track expenses',
                tags: ['expenses', 'finance', 'tracking', 'receipts'],
                complexity: 'intermediate',
                estimatedSetupTime: '15 minutes',
                spec: {
                    dataSources: ['Email', 'Bank API'],
                    outputs: ['Database', 'Report'],
                    tasks: ['Fetch transactions', 'Categorize expenses', 'Extract receipt data', 'Generate report'],
                    policies: [
                        { name: 'PII Protection', type: 'data_privacy', description: 'Protects financial data', required: true }
                    ]
                },
                requiredSecrets: ['BANK_API_KEY'],
                exampleUseCase: 'Monthly expense report generation'
            }
        ];

        logger.info(`Loaded ${this.templates.length} agent templates`);
    }
}

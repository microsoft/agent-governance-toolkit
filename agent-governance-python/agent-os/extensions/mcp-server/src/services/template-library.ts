// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Template Library Service
 * 
 * Provides pre-built agent and policy templates for common use cases.
 */

import { AgentTemplate, PolicyTemplate, Policy } from '../types/index.js';

// =============================================================================
// Agent Templates
// =============================================================================

const AGENT_TEMPLATES: AgentTemplate[] = [
  {
    id: 'data-processor',
    name: 'Data Processor',
    description: 'Processes and transforms data files on a schedule',
    category: 'data',
    tags: ['etl', 'automation', 'files'],
    difficulty: 'beginner',
    defaultPolicies: ['rate-limiting', 'cost-control'],
    config: {
      name: 'data-processor',
      task: 'Process data files from input directory, transform, and save to output',
      language: 'python',
      policies: ['rate-limiting', 'cost-control'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that processes CSV files daily',
      'Build a data pipeline that transforms JSON to Parquet',
      'Set up automated data cleaning for my analytics folder',
    ],
  },
  {
    id: 'email-assistant',
    name: 'Email Assistant',
    description: 'Monitors and processes emails with AI-powered responses',
    category: 'communication',
    tags: ['email', 'automation', 'ai'],
    difficulty: 'intermediate',
    defaultPolicies: ['pii-protection', 'human-review'],
    config: {
      name: 'email-assistant',
      task: 'Monitor inbox, categorize emails, and draft responses',
      language: 'python',
      policies: ['pii-protection', 'human-review'],
      approvalRequired: true,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that summarizes my daily emails',
      'Build an email responder for customer support',
      'Set up automatic email categorization and prioritization',
    ],
  },
  {
    id: 'database-analyst',
    name: 'Database Analyst',
    description: 'Queries databases and generates reports',
    category: 'analytics',
    tags: ['sql', 'database', 'reporting'],
    difficulty: 'intermediate',
    defaultPolicies: ['data-deletion', 'pii-protection', 'rate-limiting'],
    config: {
      name: 'database-analyst',
      task: 'Query databases, analyze data, and generate reports',
      language: 'python',
      policies: ['data-deletion', 'pii-protection', 'rate-limiting'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that generates weekly sales reports',
      'Build a dashboard data refresher',
      'Set up automated KPI tracking from our database',
    ],
  },
  {
    id: 'file-organizer',
    name: 'File Organizer',
    description: 'Organizes files based on rules and patterns',
    category: 'productivity',
    tags: ['files', 'organization', 'automation'],
    difficulty: 'beginner',
    defaultPolicies: ['data-deletion'],
    config: {
      name: 'file-organizer',
      task: 'Organize files into folders based on type, date, or content',
      language: 'python',
      policies: ['data-deletion'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that organizes my Downloads folder',
      'Build a photo organizer by date and location',
      'Set up automatic document filing by project',
    ],
  },
  {
    id: 'backup-agent',
    name: 'Backup Agent',
    description: 'Backs up files to cloud storage on schedule',
    category: 'infrastructure',
    tags: ['backup', 'cloud', 'automation'],
    difficulty: 'beginner',
    defaultPolicies: ['cost-control'],
    config: {
      name: 'backup-agent',
      task: 'Backup specified directories to cloud storage',
      language: 'python',
      policies: ['cost-control'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that backs up my Documents to Google Drive',
      'Build a database backup agent for AWS S3',
      'Set up incremental backups of my project folders',
    ],
  },
  {
    id: 'web-scraper',
    name: 'Web Scraper',
    description: 'Scrapes websites for data collection',
    category: 'data',
    tags: ['web', 'scraping', 'data-collection'],
    difficulty: 'intermediate',
    defaultPolicies: ['rate-limiting', 'cost-control'],
    config: {
      name: 'web-scraper',
      task: 'Scrape websites for specified data and save results',
      language: 'python',
      policies: ['rate-limiting', 'cost-control'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that monitors competitor prices',
      'Build a news aggregator from multiple sources',
      'Set up job listing monitoring from career sites',
    ],
  },
  {
    id: 'slack-bot',
    name: 'Slack Bot',
    description: 'Automated Slack notifications and responses',
    category: 'communication',
    tags: ['slack', 'notifications', 'automation'],
    difficulty: 'intermediate',
    defaultPolicies: ['human-review', 'rate-limiting'],
    config: {
      name: 'slack-bot',
      task: 'Send notifications and respond to Slack messages',
      language: 'typescript',
      policies: ['human-review', 'rate-limiting'],
      approvalRequired: true,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that posts daily standup summaries',
      'Build a Slack bot for on-call alerts',
      'Set up automated deployment notifications',
    ],
  },
  {
    id: 'api-monitor',
    name: 'API Monitor',
    description: 'Monitors API health and performance',
    category: 'infrastructure',
    tags: ['api', 'monitoring', 'alerts'],
    difficulty: 'intermediate',
    defaultPolicies: ['rate-limiting'],
    config: {
      name: 'api-monitor',
      task: 'Monitor API endpoints and alert on issues',
      language: 'python',
      policies: ['rate-limiting'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that monitors our API uptime',
      'Build a performance tracker for critical endpoints',
      'Set up automatic incident detection for our services',
    ],
  },
  {
    id: 'report-generator',
    name: 'Report Generator',
    description: 'Generates periodic reports from multiple data sources',
    category: 'analytics',
    tags: ['reports', 'automation', 'analytics'],
    difficulty: 'advanced',
    defaultPolicies: ['pii-protection', 'rate-limiting'],
    config: {
      name: 'report-generator',
      task: 'Aggregate data from multiple sources and generate reports',
      language: 'python',
      policies: ['pii-protection', 'rate-limiting'],
      approvalRequired: false,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that generates executive summaries weekly',
      'Build a financial report automation pipeline',
      'Set up automated compliance reporting',
    ],
  },
  {
    id: 'content-moderator',
    name: 'Content Moderator',
    description: 'Moderates user-generated content with AI',
    category: 'moderation',
    tags: ['ai', 'moderation', 'content'],
    difficulty: 'advanced',
    defaultPolicies: ['human-review', 'pii-protection'],
    config: {
      name: 'content-moderator',
      task: 'Review and moderate user-generated content',
      language: 'python',
      policies: ['human-review', 'pii-protection'],
      approvalRequired: true,
      status: 'draft',
    },
    examplePrompts: [
      'Create an agent that flags inappropriate comments',
      'Build a content review pipeline for submissions',
      'Set up automated spam detection for our forum',
    ],
  },
];

// =============================================================================
// Policy Templates
// =============================================================================

const POLICY_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'gdpr-compliance',
    name: 'GDPR Data Protection',
    description: 'EU General Data Protection Regulation compliance',
    category: 'compliance',
    framework: 'GDPR',
    tags: ['privacy', 'eu', 'data-protection'],
    policy: {
      name: 'GDPR Data Protection',
      description: 'Enforces GDPR requirements for data handling',
      version: '1.0.0',
      category: 'compliance',
      framework: 'GDPR',
      rules: [
        {
          name: 'pii_identification',
          description: 'Identify and flag PII fields',
          condition: 'field.type in ["email", "phone", "ssn", "address", "name"]',
          action: 'transform',
          severity: 'high',
          message: 'PII detected - applying protection measures',
        },
        {
          name: 'right_to_erasure',
          description: 'Support right to be forgotten requests',
          condition: 'action.type == "deletion_request" && data.personal == true',
          action: 'require_approval',
          severity: 'high',
          message: 'Data deletion request requires verification',
        },
        {
          name: 'data_minimization',
          description: 'Collect only necessary data',
          condition: 'action.type == "data_collection" && !data.purpose',
          action: 'deny',
          severity: 'high',
          message: 'Data collection requires specified purpose',
        },
        {
          name: 'consent_verification',
          description: 'Verify consent before processing',
          condition: 'action.involves_personal_data && !context.consent_verified',
          action: 'deny',
          severity: 'critical',
          message: 'Processing personal data requires verified consent',
        },
      ],
      enabled: true,
    },
  },
  {
    id: 'soc2-security',
    name: 'SOC 2 Security Controls',
    description: 'SOC 2 Type II security compliance controls',
    category: 'compliance',
    framework: 'SOC2',
    tags: ['security', 'audit', 'enterprise'],
    policy: {
      name: 'SOC 2 Security Controls',
      description: 'Enforces SOC 2 Type II security requirements',
      version: '1.0.0',
      category: 'compliance',
      framework: 'SOC2',
      rules: [
        {
          name: 'access_logging',
          description: 'Log all data access',
          condition: 'action.type in ["read", "write", "delete", "update"]',
          action: 'log',
          severity: 'info',
          message: 'Data access logged for audit trail',
        },
        {
          name: 'change_management',
          description: 'Require approval for configuration changes',
          condition: 'action.type == "config_change"',
          action: 'require_approval',
          severity: 'high',
          message: 'Configuration changes require approval',
        },
        {
          name: 'encryption_required',
          description: 'Ensure data encryption',
          condition: 'data.sensitivity == "high" && !action.encrypted',
          action: 'deny',
          severity: 'critical',
          message: 'High sensitivity data must be encrypted',
        },
        {
          name: 'incident_detection',
          description: 'Detect and alert on security incidents',
          condition: 'action.failed_attempts > 3',
          action: 'log',
          severity: 'critical',
          message: 'Potential security incident detected',
        },
      ],
      enabled: true,
    },
  },
  {
    id: 'hipaa-healthcare',
    name: 'HIPAA Healthcare Privacy',
    description: 'Health Insurance Portability and Accountability Act compliance',
    category: 'compliance',
    framework: 'HIPAA',
    tags: ['healthcare', 'phi', 'privacy'],
    policy: {
      name: 'HIPAA Healthcare Privacy',
      description: 'Protects Protected Health Information (PHI)',
      version: '1.0.0',
      category: 'compliance',
      framework: 'HIPAA',
      rules: [
        {
          name: 'phi_protection',
          description: 'Protect Protected Health Information',
          condition: 'data.type == "phi" || field in ["diagnosis", "treatment", "medical_record"]',
          action: 'transform',
          severity: 'critical',
          message: 'PHI must be encrypted and access controlled',
        },
        {
          name: 'minimum_necessary',
          description: 'Apply minimum necessary standard',
          condition: 'action.type == "data_access" && data.type == "phi" && !action.justified',
          action: 'deny',
          severity: 'high',
          message: 'Access to PHI requires justification',
        },
        {
          name: 'audit_controls',
          description: 'Maintain comprehensive audit logs',
          condition: 'data.type == "phi"',
          action: 'log',
          severity: 'info',
          message: 'PHI access logged for HIPAA compliance',
        },
      ],
      enabled: true,
    },
  },
  {
    id: 'pci-dss-payments',
    name: 'PCI DSS Payment Security',
    description: 'Payment Card Industry Data Security Standard compliance',
    category: 'compliance',
    framework: 'PCI_DSS',
    tags: ['payments', 'credit-card', 'security'],
    policy: {
      name: 'PCI DSS Payment Security',
      description: 'Protects payment card data',
      version: '1.0.0',
      category: 'compliance',
      framework: 'PCI_DSS',
      rules: [
        {
          name: 'block_card_storage',
          description: 'Prevent storage of full card numbers',
          condition: 'data.matches(/\\d{13,16}/) && action.type == "store"',
          action: 'deny',
          severity: 'critical',
          message: 'Full card numbers cannot be stored',
          alternative: 'Use tokenization service instead',
        },
        {
          name: 'block_cvv_storage',
          description: 'Never store CVV/CVC codes',
          condition: 'field in ["cvv", "cvc", "security_code"]',
          action: 'deny',
          severity: 'critical',
          message: 'CVV/CVC codes cannot be stored',
        },
        {
          name: 'encrypt_transmission',
          description: 'Encrypt card data in transit',
          condition: 'data.contains_card_data && !action.encrypted',
          action: 'deny',
          severity: 'critical',
          message: 'Card data must be encrypted in transit',
        },
      ],
      enabled: true,
    },
  },
  {
    id: 'read-only-access',
    name: 'Read-Only Database Access',
    description: 'Restricts database operations to read-only',
    category: 'security',
    tags: ['database', 'read-only', 'safety'],
    policy: {
      name: 'Read-Only Database Access',
      description: 'Prevents write operations to database',
      version: '1.0.0',
      category: 'security',
      rules: [
        {
          name: 'block_insert',
          description: 'Block INSERT operations',
          condition: 'action.sql.matches(/INSERT\\s+INTO/i)',
          action: 'deny',
          severity: 'high',
          message: 'INSERT operations are not allowed',
        },
        {
          name: 'block_update',
          description: 'Block UPDATE operations',
          condition: 'action.sql.matches(/UPDATE\\s+.*\\s+SET/i)',
          action: 'deny',
          severity: 'high',
          message: 'UPDATE operations are not allowed',
        },
        {
          name: 'block_delete',
          description: 'Block DELETE operations',
          condition: 'action.sql.matches(/DELETE\\s+FROM/i)',
          action: 'deny',
          severity: 'high',
          message: 'DELETE operations are not allowed',
        },
        {
          name: 'block_ddl',
          description: 'Block DDL operations',
          condition: 'action.sql.matches(/(CREATE|ALTER|DROP|TRUNCATE)/i)',
          action: 'deny',
          severity: 'critical',
          message: 'DDL operations are not allowed',
        },
      ],
      enabled: true,
    },
  },
  {
    id: 'production-safety',
    name: 'Production Environment Safety',
    description: 'Extra safeguards for production environments',
    category: 'operational',
    tags: ['production', 'safety', 'approval'],
    policy: {
      name: 'Production Environment Safety',
      description: 'Requires approvals and extra checks for production',
      version: '1.0.0',
      category: 'operational',
      rules: [
        {
          name: 'require_deployment_approval',
          description: 'Require approval for production deployments',
          condition: 'action.type == "deploy" && environment == "production"',
          action: 'require_approval',
          severity: 'high',
          message: 'Production deployments require approval',
        },
        {
          name: 'block_direct_db_access',
          description: 'Block direct database modifications',
          condition: 'environment == "production" && action.type == "database_write"',
          action: 'require_approval',
          severity: 'critical',
          message: 'Direct production database writes require approval',
        },
        {
          name: 'require_rollback_plan',
          description: 'Ensure rollback plan exists',
          condition: 'action.type == "deploy" && !action.has_rollback',
          action: 'deny',
          severity: 'high',
          message: 'Deployments must have a rollback plan',
        },
      ],
      enabled: true,
    },
  },
];

export class TemplateLibrary {
  private agentTemplates: Map<string, AgentTemplate>;
  private policyTemplates: Map<string, PolicyTemplate>;
  
  constructor() {
    this.agentTemplates = new Map();
    this.policyTemplates = new Map();
    
    // Load built-in templates
    for (const template of AGENT_TEMPLATES) {
      this.agentTemplates.set(template.id, template);
    }
    for (const template of POLICY_TEMPLATES) {
      this.policyTemplates.set(template.id, template);
    }
  }
  
  /**
   * List all agent templates.
   */
  listAgentTemplates(options?: {
    category?: string;
    search?: string;
    tags?: string[];
  }): AgentTemplate[] {
    let templates = Array.from(this.agentTemplates.values());
    
    if (options?.category) {
      templates = templates.filter(t => t.category === options.category);
    }
    
    if (options?.search) {
      const search = options.search.toLowerCase();
      templates = templates.filter(t =>
        t.name.toLowerCase().includes(search) ||
        t.description.toLowerCase().includes(search) ||
        t.tags.some(tag => tag.includes(search))
      );
    }
    
    if (options?.tags?.length) {
      templates = templates.filter(t =>
        options.tags!.some(tag => t.tags.includes(tag))
      );
    }
    
    return templates;
  }
  
  /**
   * List all policy templates.
   */
  listPolicyTemplates(options?: {
    category?: string;
    framework?: string;
    search?: string;
  }): PolicyTemplate[] {
    let templates = Array.from(this.policyTemplates.values());
    
    if (options?.category) {
      templates = templates.filter(t => t.category === options.category);
    }
    
    if (options?.framework) {
      templates = templates.filter(t => t.framework === options.framework);
    }
    
    if (options?.search) {
      const search = options.search.toLowerCase();
      templates = templates.filter(t =>
        t.name.toLowerCase().includes(search) ||
        t.description.toLowerCase().includes(search) ||
        t.tags.some(tag => tag.includes(search))
      );
    }
    
    return templates;
  }
  
  /**
   * Get agent template by ID.
   */
  getAgentTemplate(id: string): AgentTemplate | undefined {
    return this.agentTemplates.get(id);
  }
  
  /**
   * Get policy template by ID.
   */
  getPolicyTemplate(id: string): PolicyTemplate | undefined {
    return this.policyTemplates.get(id);
  }
  
  /**
   * Get all available categories.
   */
  getCategories(): { agents: string[]; policies: string[] } {
    const agentCategories = new Set(
      Array.from(this.agentTemplates.values()).map(t => t.category)
    );
    const policyCategories = new Set(
      Array.from(this.policyTemplates.values()).map(t => t.category)
    );
    
    return {
      agents: Array.from(agentCategories),
      policies: Array.from(policyCategories),
    };
  }
  
  /**
   * Get all compliance frameworks.
   */
  getFrameworks(): string[] {
    const frameworks = new Set(
      Array.from(this.policyTemplates.values())
        .map(t => t.framework)
        .filter(Boolean) as string[]
    );
    return Array.from(frameworks);
  }
  
  /**
   * Suggest templates based on description.
   */
  suggestTemplates(description: string): {
    agents: AgentTemplate[];
    policies: PolicyTemplate[];
  } {
    const lowerDesc = description.toLowerCase();
    
    // Score templates based on keyword matches
    const scoreAgent = (t: AgentTemplate): number => {
      let score = 0;
      if (lowerDesc.includes(t.category)) score += 3;
      for (const tag of t.tags) {
        if (lowerDesc.includes(tag)) score += 2;
      }
      for (const prompt of t.examplePrompts) {
        const words = prompt.toLowerCase().split(' ');
        for (const word of words) {
          if (word.length > 3 && lowerDesc.includes(word)) score += 1;
        }
      }
      return score;
    };
    
    const scorePolicy = (t: PolicyTemplate): number => {
      let score = 0;
      if (lowerDesc.includes(t.category)) score += 3;
      if (t.framework && lowerDesc.includes(t.framework.toLowerCase())) score += 5;
      for (const tag of t.tags) {
        if (lowerDesc.includes(tag)) score += 2;
      }
      return score;
    };
    
    const agents = Array.from(this.agentTemplates.values())
      .map(t => ({ template: t, score: scoreAgent(t) }))
      .filter(x => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(x => x.template);
    
    const policies = Array.from(this.policyTemplates.values())
      .map(t => ({ template: t, score: scorePolicy(t) }))
      .filter(x => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map(x => x.template);
    
    return { agents, policies };
  }
}

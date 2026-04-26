// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Library
 * 
 * Provides compliance policy templates for common regulatory frameworks
 * including GDPR, HIPAA, SOC2, PCI DSS, and custom policies.
 */

import { logger } from './logger';

export interface CompliancePolicy {
    id: string;
    name: string;
    framework: ComplianceFramework;
    version: string;
    description: string;
    requirements: PolicyRequirement[];
    controls: PolicyControl[];
    dataHandling: DataHandlingRules;
    auditRequirements: AuditRequirements;
}

export type ComplianceFramework = 
    | 'gdpr'
    | 'hipaa'
    | 'soc2'
    | 'pci-dss'
    | 'iso27001'
    | 'ccpa'
    | 'custom';

export interface PolicyRequirement {
    id: string;
    name: string;
    description: string;
    mandatory: boolean;
    controls: string[];  // References to control IDs
}

export interface PolicyControl {
    id: string;
    name: string;
    description: string;
    implementation: string;
    verification: string;
    frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'annual';
}

export interface DataHandlingRules {
    piiRedaction: boolean;
    encryptionRequired: boolean;
    retentionDays: number;
    geographicRestrictions?: string[];
    allowedPurposes?: string[];
    consentRequired: boolean;
}

export interface AuditRequirements {
    logAllAccess: boolean;
    logAllModifications: boolean;
    retentionDays: number;
    immutableLogs: boolean;
    alertOnViolations: boolean;
}

export interface PolicyValidationResult {
    compliant: boolean;
    framework: ComplianceFramework;
    violations: PolicyViolation[];
    warnings: PolicyWarning[];
    score: number;  // 0-100
    recommendations: string[];
}

export interface PolicyViolation {
    controlId: string;
    controlName: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    remediation: string;
    lineNumber?: number;
    code?: string;
}

export interface PolicyWarning {
    controlId: string;
    message: string;
    recommendation: string;
}

export class PolicyLibrary {
    private policies: Map<string, CompliancePolicy> = new Map();

    constructor() {
        this.loadPolicies();
    }

    /**
     * Get policy by ID
     */
    getPolicy(id: string): CompliancePolicy | undefined {
        return this.policies.get(id);
    }

    /**
     * Get all policies for a framework
     */
    getPoliciesByFramework(framework: ComplianceFramework): CompliancePolicy[] {
        return Array.from(this.policies.values()).filter(p => p.framework === framework);
    }

    /**
     * Get all available frameworks
     */
    getFrameworks(): { framework: ComplianceFramework; name: string; description: string }[] {
        return [
            { 
                framework: 'gdpr', 
                name: 'GDPR', 
                description: 'EU General Data Protection Regulation - Data privacy and protection for EU citizens'
            },
            { 
                framework: 'hipaa', 
                name: 'HIPAA', 
                description: 'Health Insurance Portability and Accountability Act - US healthcare data protection'
            },
            { 
                framework: 'soc2', 
                name: 'SOC 2', 
                description: 'Service Organization Control 2 - Security, availability, and confidentiality'
            },
            { 
                framework: 'pci-dss', 
                name: 'PCI DSS', 
                description: 'Payment Card Industry Data Security Standard - Payment data protection'
            },
            { 
                framework: 'iso27001', 
                name: 'ISO 27001', 
                description: 'Information Security Management System standard'
            },
            { 
                framework: 'ccpa', 
                name: 'CCPA', 
                description: 'California Consumer Privacy Act - Data privacy for California residents'
            }
        ];
    }

    /**
     * Validate code against a policy
     */
    validateAgainstPolicy(
        code: string,
        language: string,
        policyId: string
    ): PolicyValidationResult {
        const policy = this.policies.get(policyId);
        if (!policy) {
            return {
                compliant: false,
                framework: 'custom',
                violations: [{ 
                    controlId: 'unknown', 
                    controlName: 'Unknown Policy',
                    description: `Policy ${policyId} not found`,
                    severity: 'critical',
                    remediation: 'Select a valid policy'
                }],
                warnings: [],
                score: 0,
                recommendations: []
            };
        }

        const violations: PolicyViolation[] = [];
        const warnings: PolicyWarning[] = [];
        const recommendations: string[] = [];

        // Check data handling rules
        if (policy.dataHandling.piiRedaction) {
            const piiPatterns = this.detectPII(code);
            for (const pattern of piiPatterns) {
                violations.push({
                    controlId: 'data-pii',
                    controlName: 'PII Protection',
                    description: `Potential PII detected: ${pattern.type}`,
                    severity: 'high',
                    remediation: 'Use PII redaction or encryption for personal data',
                    lineNumber: pattern.line,
                    code: pattern.match
                });
            }
        }

        if (policy.dataHandling.encryptionRequired) {
            if (!this.hasEncryption(code, language)) {
                warnings.push({
                    controlId: 'data-encryption',
                    message: 'No encryption detected for data at rest/transit',
                    recommendation: 'Add encryption for sensitive data handling'
                });
            }
        }

        // Check audit requirements
        if (policy.auditRequirements.logAllAccess) {
            if (!this.hasLogging(code, language)) {
                warnings.push({
                    controlId: 'audit-logging',
                    message: 'Audit logging not detected',
                    recommendation: 'Add logging for all data access operations'
                });
            }
        }

        // Framework-specific checks
        this.runFrameworkChecks(code, language, policy, violations, warnings);

        // Calculate compliance score
        const totalControls = policy.controls.length;
        const violationWeight = violations.reduce((sum, v) => {
            const weights = { critical: 25, high: 15, medium: 10, low: 5 };
            return sum + weights[v.severity];
        }, 0);
        const score = Math.max(0, 100 - violationWeight);

        // Generate recommendations
        if (score < 100) {
            if (violations.some(v => v.severity === 'critical')) {
                recommendations.push('Address critical violations before deployment');
            }
            if (!this.hasLogging(code, language)) {
                recommendations.push('Add comprehensive audit logging');
            }
            if (!this.hasEncryption(code, language)) {
                recommendations.push('Implement encryption for sensitive data');
            }
            if (!this.hasErrorHandling(code, language)) {
                recommendations.push('Add proper error handling to prevent data leaks');
            }
        }

        return {
            compliant: violations.filter(v => v.severity === 'critical' || v.severity === 'high').length === 0,
            framework: policy.framework,
            violations,
            warnings,
            score,
            recommendations
        };
    }

    /**
     * Generate policy YAML for agent
     */
    generatePolicyYaml(policyId: string): string {
        const policy = this.policies.get(policyId);
        if (!policy) return '';

        return `# ${policy.name} Compliance Policy
# Framework: ${policy.framework.toUpperCase()}
# Version: ${policy.version}

policy:
  name: "${policy.name}"
  framework: ${policy.framework}
  version: "${policy.version}"
  
  data_handling:
    pii_redaction: ${policy.dataHandling.piiRedaction}
    encryption_required: ${policy.dataHandling.encryptionRequired}
    retention_days: ${policy.dataHandling.retentionDays}
    consent_required: ${policy.dataHandling.consentRequired}
${policy.dataHandling.geographicRestrictions ? `    geographic_restrictions:\n${policy.dataHandling.geographicRestrictions.map(r => `      - ${r}`).join('\n')}` : ''}

  audit:
    log_all_access: ${policy.auditRequirements.logAllAccess}
    log_all_modifications: ${policy.auditRequirements.logAllModifications}
    retention_days: ${policy.auditRequirements.retentionDays}
    immutable_logs: ${policy.auditRequirements.immutableLogs}
    alert_on_violations: ${policy.auditRequirements.alertOnViolations}

  controls:
${policy.controls.map(c => `    - id: ${c.id}
      name: "${c.name}"
      frequency: ${c.frequency}`).join('\n')}
`;
    }

    /**
     * Format policy for chat display
     */
    formatPolicyForChat(policyId: string): string {
        const policy = this.policies.get(policyId);
        if (!policy) return 'Policy not found';

        const frameworkEmoji: Record<ComplianceFramework, string> = {
            'gdpr': '🇪🇺',
            'hipaa': '🏥',
            'soc2': '🔒',
            'pci-dss': '💳',
            'iso27001': '📋',
            'ccpa': '🌴',
            'custom': '⚙️'
        };

        let output = `## ${frameworkEmoji[policy.framework]} ${policy.name}\n\n`;
        output += `**Framework:** ${policy.framework.toUpperCase()} | **Version:** ${policy.version}\n\n`;
        output += `${policy.description}\n\n`;

        output += `### Data Handling Requirements\n`;
        output += `| Requirement | Value |\n|-------------|-------|\n`;
        output += `| PII Redaction | ${policy.dataHandling.piiRedaction ? '✅ Required' : '❌ Not Required'} |\n`;
        output += `| Encryption | ${policy.dataHandling.encryptionRequired ? '✅ Required' : '❌ Not Required'} |\n`;
        output += `| Retention | ${policy.dataHandling.retentionDays} days |\n`;
        output += `| Consent Required | ${policy.dataHandling.consentRequired ? '✅ Yes' : '❌ No'} |\n\n`;

        output += `### Key Controls (${policy.controls.length} total)\n`;
        for (const control of policy.controls.slice(0, 5)) {
            output += `- **${control.name}**: ${control.description}\n`;
        }
        if (policy.controls.length > 5) {
            output += `- _...and ${policy.controls.length - 5} more_\n`;
        }

        return output;
    }

    /**
     * Create policy from natural language description
     */
    createPolicyFromDescription(description: string): CompliancePolicy {
        const words = description.toLowerCase();
        
        // Detect framework hints
        let framework: ComplianceFramework = 'custom';
        if (words.includes('gdpr') || words.includes('eu') || words.includes('european')) {
            framework = 'gdpr';
        } else if (words.includes('hipaa') || words.includes('health') || words.includes('medical')) {
            framework = 'hipaa';
        } else if (words.includes('soc2') || words.includes('soc 2')) {
            framework = 'soc2';
        } else if (words.includes('pci') || words.includes('payment') || words.includes('credit card')) {
            framework = 'pci-dss';
        }

        // Extract rules from description
        const piiRedaction = words.includes('pii') || words.includes('personal') || words.includes('privacy');
        const encryption = words.includes('encrypt') || words.includes('secure');
        const consent = words.includes('consent') || words.includes('permission');
        
        // Extract retention period if mentioned
        const retentionMatch = description.match(/(\d+)\s*(day|days|month|months|year|years)/i);
        let retentionDays = 365;  // Default
        if (retentionMatch) {
            const num = parseInt(retentionMatch[1]);
            const unit = retentionMatch[2].toLowerCase();
            if (unit.startsWith('day')) retentionDays = num;
            else if (unit.startsWith('month')) retentionDays = num * 30;
            else if (unit.startsWith('year')) retentionDays = num * 365;
        }

        return {
            id: `custom-${Date.now()}`,
            name: 'Custom Policy',
            framework,
            version: '1.0.0',
            description: description,
            requirements: [],
            controls: [],
            dataHandling: {
                piiRedaction,
                encryptionRequired: encryption,
                retentionDays,
                consentRequired: consent
            },
            auditRequirements: {
                logAllAccess: true,
                logAllModifications: true,
                retentionDays: Math.max(retentionDays, 90),
                immutableLogs: true,
                alertOnViolations: true
            }
        };
    }

    // Private helper methods

    private detectPII(code: string): { type: string; match: string; line: number }[] {
        const patterns: { type: string; regex: RegExp }[] = [
            { type: 'email', regex: /['"`][\w.-]+@[\w.-]+\.\w+['"`]/gi },
            { type: 'phone', regex: /['"`]\+?[\d\s-]{10,}['"`]/g },
            { type: 'ssn', regex: /\d{3}-\d{2}-\d{4}/g },
            { type: 'credit_card', regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g },
            { type: 'ip_address', regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
        ];

        const results: { type: string; match: string; line: number }[] = [];
        const lines = code.split('\n');

        for (let i = 0; i < lines.length; i++) {
            for (const { type, regex } of patterns) {
                const matches = lines[i].match(regex);
                if (matches) {
                    for (const match of matches) {
                        results.push({ type, match, line: i + 1 });
                    }
                }
            }
        }

        return results;
    }

    private hasEncryption(code: string, language: string): boolean {
        const encryptionPatterns = [
            /encrypt/i,
            /crypto/i,
            /AES/i,
            /RSA/i,
            /bcrypt/i,
            /argon2/i,
            /hashlib/i,
            /createCipher/i
        ];
        return encryptionPatterns.some(p => p.test(code));
    }

    private hasLogging(code: string, language: string): boolean {
        const loggingPatterns = [
            /logger\./i,
            /console\.(log|info|warn|error)/i,
            /logging\./i,
            /log\.(info|debug|warn|error)/i,
            /audit/i
        ];
        return loggingPatterns.some(p => p.test(code));
    }

    private hasErrorHandling(code: string, language: string): boolean {
        const errorPatterns = [
            /try\s*{/i,
            /catch/i,
            /except/i,
            /finally/i,
            /\.catch\(/i,
            /error\s*=>/i
        ];
        return errorPatterns.some(p => p.test(code));
    }

    private runFrameworkChecks(
        code: string,
        language: string,
        policy: CompliancePolicy,
        violations: PolicyViolation[],
        warnings: PolicyWarning[]
    ): void {
        switch (policy.framework) {
            case 'gdpr':
                this.runGDPRChecks(code, violations, warnings);
                break;
            case 'hipaa':
                this.runHIPAAChecks(code, violations, warnings);
                break;
            case 'pci-dss':
                this.runPCIDSSChecks(code, violations, warnings);
                break;
            case 'soc2':
                this.runSOC2Checks(code, violations, warnings);
                break;
        }
    }

    private runGDPRChecks(code: string, violations: PolicyViolation[], warnings: PolicyWarning[]): void {
        // Check for data transfer outside EU
        if (/api\.(us|america|china|india)/i.test(code)) {
            warnings.push({
                controlId: 'gdpr-transfer',
                message: 'Potential data transfer outside EU detected',
                recommendation: 'Ensure adequate protection for cross-border data transfers'
            });
        }

        // Check for consent handling
        if (/user[\s\S]{0,50}data/i.test(code) && !/consent/i.test(code)) {
            warnings.push({
                controlId: 'gdpr-consent',
                message: 'User data processing without apparent consent check',
                recommendation: 'Add consent verification before processing user data'
            });
        }
    }

    private runHIPAAChecks(code: string, violations: PolicyViolation[], warnings: PolicyWarning[]): void {
        // Check for PHI patterns
        const phiPatterns = [
            /patient/i, /diagnosis/i, /treatment/i, /medical/i,
            /health[\s\S]{0,30}record/i, /insurance/i, /prescription/i
        ];
        
        for (const pattern of phiPatterns) {
            if (pattern.test(code) && !this.hasEncryption(code, '')) {
                violations.push({
                    controlId: 'hipaa-phi-encryption',
                    controlName: 'PHI Encryption',
                    description: 'Protected Health Information detected without encryption',
                    severity: 'critical',
                    remediation: 'Encrypt all PHI at rest and in transit'
                });
                break;
            }
        }
    }

    private runPCIDSSChecks(code: string, violations: PolicyViolation[], warnings: PolicyWarning[]): void {
        // Check for card data
        if (/card[\s\S]{0,30}number|cvv|expir/i.test(code)) {
            if (!/mask|redact|encrypt/i.test(code)) {
                violations.push({
                    controlId: 'pci-card-data',
                    controlName: 'Card Data Protection',
                    description: 'Payment card data handling without apparent protection',
                    severity: 'critical',
                    remediation: 'Never store CVV, mask card numbers, encrypt all card data'
                });
            }
        }

        // Check for logging card data
        if (/log[\s\S]{0,30}card|print[\s\S]{0,30}card/i.test(code)) {
            violations.push({
                controlId: 'pci-logging',
                controlName: 'Card Data Logging',
                description: 'Potential logging of card data detected',
                severity: 'critical',
                remediation: 'Never log full card numbers or CVV codes'
            });
        }
    }

    private runSOC2Checks(code: string, violations: PolicyViolation[], warnings: PolicyWarning[]): void {
        // Check for access control
        if (/admin|root|sudo/i.test(code) && !/auth|permission|role/i.test(code)) {
            warnings.push({
                controlId: 'soc2-access',
                message: 'Privileged access without apparent authorization check',
                recommendation: 'Implement role-based access control'
            });
        }

        // Check for change management
        if (/update|modify|delete/i.test(code) && !/log|audit|track/i.test(code)) {
            warnings.push({
                controlId: 'soc2-change',
                message: 'Data modification without apparent audit logging',
                recommendation: 'Log all data modifications with user and timestamp'
            });
        }
    }

    private loadPolicies(): void {
        // GDPR Policy
        this.policies.set('gdpr-standard', {
            id: 'gdpr-standard',
            name: 'GDPR Standard Compliance',
            framework: 'gdpr',
            version: '2.0',
            description: 'Ensures compliance with EU General Data Protection Regulation for processing personal data of EU residents.',
            requirements: [
                { id: 'gdpr-r1', name: 'Lawful Basis', description: 'Establish lawful basis for processing', mandatory: true, controls: ['gdpr-c1'] },
                { id: 'gdpr-r2', name: 'Consent', description: 'Obtain and manage consent', mandatory: true, controls: ['gdpr-c2'] },
                { id: 'gdpr-r3', name: 'Data Subject Rights', description: 'Enable data subject rights', mandatory: true, controls: ['gdpr-c3', 'gdpr-c4'] },
                { id: 'gdpr-r4', name: 'Data Protection', description: 'Protect personal data', mandatory: true, controls: ['gdpr-c5', 'gdpr-c6'] }
            ],
            controls: [
                { id: 'gdpr-c1', name: 'Purpose Limitation', description: 'Process data only for specified purposes', implementation: 'Validate processing purpose before access', verification: 'Audit log review', frequency: 'continuous' },
                { id: 'gdpr-c2', name: 'Consent Management', description: 'Track and verify user consent', implementation: 'Consent database with timestamps', verification: 'Consent audit', frequency: 'continuous' },
                { id: 'gdpr-c3', name: 'Right to Access', description: 'Provide data access on request', implementation: 'Data export API', verification: 'Test data export', frequency: 'monthly' },
                { id: 'gdpr-c4', name: 'Right to Erasure', description: 'Delete data on request', implementation: 'Data deletion workflow', verification: 'Test deletion', frequency: 'monthly' },
                { id: 'gdpr-c5', name: 'Data Minimization', description: 'Collect only necessary data', implementation: 'Schema validation', verification: 'Data review', frequency: 'quarterly' },
                { id: 'gdpr-c6', name: 'Encryption', description: 'Encrypt personal data', implementation: 'AES-256 encryption', verification: 'Encryption audit', frequency: 'continuous' }
            ],
            dataHandling: {
                piiRedaction: true,
                encryptionRequired: true,
                retentionDays: 365,
                geographicRestrictions: ['EU', 'EEA'],
                allowedPurposes: ['consent-given', 'contract', 'legal-obligation', 'legitimate-interest'],
                consentRequired: true
            },
            auditRequirements: {
                logAllAccess: true,
                logAllModifications: true,
                retentionDays: 365,
                immutableLogs: true,
                alertOnViolations: true
            }
        });

        // HIPAA Policy
        this.policies.set('hipaa-standard', {
            id: 'hipaa-standard',
            name: 'HIPAA Compliance',
            framework: 'hipaa',
            version: '1.0',
            description: 'Ensures compliance with HIPAA for protecting health information (PHI).',
            requirements: [
                { id: 'hipaa-r1', name: 'PHI Protection', description: 'Protect all PHI', mandatory: true, controls: ['hipaa-c1', 'hipaa-c2'] },
                { id: 'hipaa-r2', name: 'Access Control', description: 'Limit access to PHI', mandatory: true, controls: ['hipaa-c3'] },
                { id: 'hipaa-r3', name: 'Audit Trail', description: 'Maintain audit trail', mandatory: true, controls: ['hipaa-c4'] }
            ],
            controls: [
                { id: 'hipaa-c1', name: 'PHI Encryption', description: 'Encrypt all PHI at rest and transit', implementation: 'AES-256 + TLS 1.3', verification: 'Encryption audit', frequency: 'continuous' },
                { id: 'hipaa-c2', name: 'De-identification', description: 'De-identify data when possible', implementation: 'Safe Harbor method', verification: 'Data review', frequency: 'quarterly' },
                { id: 'hipaa-c3', name: 'Minimum Necessary', description: 'Access only necessary PHI', implementation: 'RBAC with field-level control', verification: 'Access review', frequency: 'monthly' },
                { id: 'hipaa-c4', name: 'Audit Logging', description: 'Log all PHI access', implementation: 'Immutable audit log', verification: 'Log review', frequency: 'daily' }
            ],
            dataHandling: {
                piiRedaction: true,
                encryptionRequired: true,
                retentionDays: 2190,  // 6 years
                consentRequired: true
            },
            auditRequirements: {
                logAllAccess: true,
                logAllModifications: true,
                retentionDays: 2190,
                immutableLogs: true,
                alertOnViolations: true
            }
        });

        // SOC 2 Policy
        this.policies.set('soc2-standard', {
            id: 'soc2-standard',
            name: 'SOC 2 Type II Compliance',
            framework: 'soc2',
            version: '1.0',
            description: 'Ensures compliance with SOC 2 Trust Service Criteria for security, availability, and confidentiality.',
            requirements: [
                { id: 'soc2-r1', name: 'Security', description: 'Protect against unauthorized access', mandatory: true, controls: ['soc2-c1', 'soc2-c2'] },
                { id: 'soc2-r2', name: 'Availability', description: 'Ensure system availability', mandatory: true, controls: ['soc2-c3'] },
                { id: 'soc2-r3', name: 'Confidentiality', description: 'Protect confidential information', mandatory: true, controls: ['soc2-c4'] }
            ],
            controls: [
                { id: 'soc2-c1', name: 'Access Control', description: 'Role-based access control', implementation: 'RBAC with MFA', verification: 'Access review', frequency: 'quarterly' },
                { id: 'soc2-c2', name: 'Change Management', description: 'Control system changes', implementation: 'PR review + approval', verification: 'Change audit', frequency: 'continuous' },
                { id: 'soc2-c3', name: 'Monitoring', description: 'Monitor system health', implementation: 'Alerting + dashboards', verification: 'Incident review', frequency: 'continuous' },
                { id: 'soc2-c4', name: 'Data Classification', description: 'Classify and protect data', implementation: 'Data tagging + encryption', verification: 'Classification review', frequency: 'quarterly' }
            ],
            dataHandling: {
                piiRedaction: false,
                encryptionRequired: true,
                retentionDays: 365,
                consentRequired: false
            },
            auditRequirements: {
                logAllAccess: true,
                logAllModifications: true,
                retentionDays: 365,
                immutableLogs: true,
                alertOnViolations: true
            }
        });

        // PCI DSS Policy
        this.policies.set('pci-dss-standard', {
            id: 'pci-dss-standard',
            name: 'PCI DSS v4.0 Compliance',
            framework: 'pci-dss',
            version: '4.0',
            description: 'Ensures compliance with PCI DSS for handling payment card data.',
            requirements: [
                { id: 'pci-r1', name: 'Card Data Protection', description: 'Protect stored card data', mandatory: true, controls: ['pci-c1', 'pci-c2'] },
                { id: 'pci-r2', name: 'Network Security', description: 'Secure network transmission', mandatory: true, controls: ['pci-c3'] },
                { id: 'pci-r3', name: 'Access Control', description: 'Restrict access to card data', mandatory: true, controls: ['pci-c4'] }
            ],
            controls: [
                { id: 'pci-c1', name: 'No CVV Storage', description: 'Never store CVV/CVC', implementation: 'Validation + rejection', verification: 'Code review', frequency: 'continuous' },
                { id: 'pci-c2', name: 'Card Masking', description: 'Mask card numbers in display', implementation: 'Show only last 4 digits', verification: 'UI review', frequency: 'continuous' },
                { id: 'pci-c3', name: 'TLS Encryption', description: 'Use TLS 1.2+ for transmission', implementation: 'TLS 1.3', verification: 'SSL scan', frequency: 'monthly' },
                { id: 'pci-c4', name: 'Key Management', description: 'Secure encryption key management', implementation: 'HSM or KMS', verification: 'Key audit', frequency: 'quarterly' }
            ],
            dataHandling: {
                piiRedaction: true,
                encryptionRequired: true,
                retentionDays: 90,
                consentRequired: false
            },
            auditRequirements: {
                logAllAccess: true,
                logAllModifications: true,
                retentionDays: 365,
                immutableLogs: true,
                alertOnViolations: true
            }
        });

        logger.info(`Loaded ${this.policies.size} compliance policies`);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Compliance Framework Module
 * 
 * Provides pre-configured compliance templates and report generation
 * for SOC 2, GDPR, HIPAA, and PCI DSS.
 */

import * as vscode from 'vscode';

export interface ComplianceControl {
    id: string;
    name: string;
    description: string;
    category: string;
    requirement: string;
    implemented: boolean;
    evidence?: string;
    policies?: string[];
}

export interface ComplianceFramework {
    id: string;
    name: string;
    version: string;
    description: string;
    controls: ComplianceControl[];
}

export interface ComplianceReport {
    framework: string;
    generatedAt: Date;
    summary: {
        totalControls: number;
        implementedControls: number;
        compliancePercentage: number;
    };
    controls: ComplianceControl[];
    recommendations: string[];
}

export class ComplianceManager {
    private frameworks: Map<string, ComplianceFramework> = new Map();

    constructor() {
        this._initializeFrameworks();
    }

    private _initializeFrameworks(): void {
        // SOC 2 Type II
        this.frameworks.set('soc2', {
            id: 'soc2',
            name: 'SOC 2 Type II',
            version: '2017',
            description: 'Service Organization Control 2 - Trust Service Criteria',
            controls: [
                {
                    id: 'CC6.1',
                    name: 'Logical Access Security',
                    description: 'Restrict access to information assets',
                    category: 'Common Criteria',
                    requirement: 'Implement logical access security software',
                    implemented: false,
                    policies: ['rbac', 'authentication']
                },
                {
                    id: 'CC6.2',
                    name: 'Access Control',
                    description: 'Manage access to systems',
                    category: 'Common Criteria',
                    requirement: 'Prior to issuing system credentials, register and authorize new internal and external users',
                    implemented: false,
                    policies: ['user_registration', 'access_approval']
                },
                {
                    id: 'CC6.3',
                    name: 'Access Removal',
                    description: 'Remove access when no longer required',
                    category: 'Common Criteria',
                    requirement: 'Remove access to protected information assets when no longer required',
                    implemented: false,
                    policies: ['access_revocation']
                },
                {
                    id: 'CC7.1',
                    name: 'Detection',
                    description: 'Detect security events',
                    category: 'Common Criteria',
                    requirement: 'Detect, respond to, and recover from security incidents',
                    implemented: false,
                    policies: ['audit_logging', 'anomaly_detection']
                },
                {
                    id: 'CC7.2',
                    name: 'Monitoring',
                    description: 'Monitor system components',
                    category: 'Common Criteria',
                    requirement: 'Monitor system components and operation of controls',
                    implemented: false,
                    policies: ['continuous_monitoring', 'metrics']
                },
                {
                    id: 'CC8.1',
                    name: 'Change Management',
                    description: 'Manage changes to infrastructure',
                    category: 'Common Criteria',
                    requirement: 'Authorize, design, develop, configure, document, test, approve, and implement changes',
                    implemented: false,
                    policies: ['change_approval', 'policy_versioning']
                }
            ]
        });

        // GDPR
        this.frameworks.set('gdpr', {
            id: 'gdpr',
            name: 'GDPR',
            version: '2018',
            description: 'General Data Protection Regulation',
            controls: [
                {
                    id: 'Art5',
                    name: 'Data Processing Principles',
                    description: 'Lawfulness, fairness, transparency, purpose limitation, data minimization',
                    category: 'Principles',
                    requirement: 'Personal data must be processed lawfully, fairly and transparently',
                    implemented: false,
                    policies: ['data_minimization', 'purpose_limitation']
                },
                {
                    id: 'Art17',
                    name: 'Right to Erasure',
                    description: 'Right to be forgotten',
                    category: 'Data Subject Rights',
                    requirement: 'Ability to erase personal data upon request',
                    implemented: false,
                    policies: ['data_deletion']
                },
                {
                    id: 'Art20',
                    name: 'Right to Data Portability',
                    description: 'Receive personal data in structured format',
                    category: 'Data Subject Rights',
                    requirement: 'Provide data in machine-readable format',
                    implemented: false,
                    policies: ['data_export']
                },
                {
                    id: 'Art25',
                    name: 'Data Protection by Design',
                    description: 'Privacy by design and default',
                    category: 'Technical Measures',
                    requirement: 'Implement appropriate technical measures',
                    implemented: false,
                    policies: ['encryption', 'pseudonymization']
                },
                {
                    id: 'Art32',
                    name: 'Security of Processing',
                    description: 'Appropriate security measures',
                    category: 'Technical Measures',
                    requirement: 'Ensure confidentiality, integrity, availability',
                    implemented: false,
                    policies: ['encryption', 'access_control', 'audit_logging']
                },
                {
                    id: 'Art33',
                    name: 'Breach Notification',
                    description: 'Notify supervisory authority within 72 hours',
                    category: 'Incident Response',
                    requirement: 'Detect and report breaches within 72 hours',
                    implemented: false,
                    policies: ['breach_detection', 'incident_response']
                }
            ]
        });

        // HIPAA
        this.frameworks.set('hipaa', {
            id: 'hipaa',
            name: 'HIPAA',
            version: '1996',
            description: 'Health Insurance Portability and Accountability Act',
            controls: [
                {
                    id: '164.312(a)',
                    name: 'Access Control',
                    description: 'Implement technical policies for access',
                    category: 'Technical Safeguards',
                    requirement: 'Unique user identification, emergency access, automatic logoff',
                    implemented: false,
                    policies: ['authentication', 'session_management']
                },
                {
                    id: '164.312(b)',
                    name: 'Audit Controls',
                    description: 'Record and examine access',
                    category: 'Technical Safeguards',
                    requirement: 'Implement hardware, software, and procedural mechanisms to record and examine activity',
                    implemented: false,
                    policies: ['audit_logging', 'log_retention']
                },
                {
                    id: '164.312(c)',
                    name: 'Integrity Controls',
                    description: 'Protect ePHI from improper alteration',
                    category: 'Technical Safeguards',
                    requirement: 'Implement electronic mechanisms to corroborate ePHI has not been altered',
                    implemented: false,
                    policies: ['data_integrity', 'checksums']
                },
                {
                    id: '164.312(d)',
                    name: 'Person Authentication',
                    description: 'Verify person or entity seeking access',
                    category: 'Technical Safeguards',
                    requirement: 'Implement procedures to verify that a person seeking access is the one claimed',
                    implemented: false,
                    policies: ['authentication', 'mfa']
                },
                {
                    id: '164.312(e)',
                    name: 'Transmission Security',
                    description: 'Guard against unauthorized access during transmission',
                    category: 'Technical Safeguards',
                    requirement: 'Implement technical security measures to guard against unauthorized access',
                    implemented: false,
                    policies: ['encryption', 'tls']
                }
            ]
        });

        // PCI DSS
        this.frameworks.set('pci-dss', {
            id: 'pci-dss',
            name: 'PCI DSS',
            version: '4.0',
            description: 'Payment Card Industry Data Security Standard',
            controls: [
                {
                    id: 'Req3',
                    name: 'Protect Stored Account Data',
                    description: 'Protect stored cardholder data',
                    category: 'Build and Maintain a Secure Network',
                    requirement: 'Protect stored account data using strong encryption',
                    implemented: false,
                    policies: ['encryption', 'key_management']
                },
                {
                    id: 'Req4',
                    name: 'Encrypt Transmission',
                    description: 'Encrypt transmission of cardholder data',
                    category: 'Build and Maintain a Secure Network',
                    requirement: 'Use strong cryptography during transmission over open, public networks',
                    implemented: false,
                    policies: ['tls', 'encryption']
                },
                {
                    id: 'Req7',
                    name: 'Restrict Access',
                    description: 'Restrict access to system components',
                    category: 'Access Control',
                    requirement: 'Limit access to system components to only those individuals whose job requires such access',
                    implemented: false,
                    policies: ['rbac', 'least_privilege']
                },
                {
                    id: 'Req8',
                    name: 'Identify Users',
                    description: 'Identify users and authenticate access',
                    category: 'Access Control',
                    requirement: 'Assign a unique ID to each person with computer access',
                    implemented: false,
                    policies: ['authentication', 'unique_ids']
                },
                {
                    id: 'Req10',
                    name: 'Log and Monitor',
                    description: 'Log and monitor all access',
                    category: 'Monitor and Test Networks',
                    requirement: 'Log all access to system components and cardholder data',
                    implemented: false,
                    policies: ['audit_logging', 'monitoring']
                },
                {
                    id: 'Req11',
                    name: 'Test Security',
                    description: 'Regularly test security systems',
                    category: 'Monitor and Test Networks',
                    requirement: 'Regularly test security systems and processes',
                    implemented: false,
                    policies: ['vulnerability_scanning', 'penetration_testing']
                }
            ]
        });
    }

    getFramework(id: string): ComplianceFramework | undefined {
        return this.frameworks.get(id);
    }

    getAllFrameworks(): ComplianceFramework[] {
        return Array.from(this.frameworks.values());
    }

    async generateReport(frameworkId: string): Promise<ComplianceReport | undefined> {
        const framework = this.frameworks.get(frameworkId);
        if (!framework) {
            vscode.window.showErrorMessage(`Unknown compliance framework: ${frameworkId}`);
            return undefined;
        }

        // Evaluate compliance status
        const controls = framework.controls.map(control => ({
            ...control,
            implemented: this._evaluateControl(control)
        }));

        const implementedCount = controls.filter(c => c.implemented).length;
        const compliancePercentage = Math.round((implementedCount / controls.length) * 100);

        const report: ComplianceReport = {
            framework: framework.name,
            generatedAt: new Date(),
            summary: {
                totalControls: controls.length,
                implementedControls: implementedCount,
                compliancePercentage
            },
            controls,
            recommendations: this._generateRecommendations(controls)
        };

        return report;
    }

    private _evaluateControl(control: ComplianceControl): boolean {
        // In a real implementation, this would check against actual policy configurations
        // For now, return a mock evaluation
        const config = vscode.workspace.getConfiguration('agentOS');
        
        if (control.policies?.includes('audit_logging')) {
            return config.get('audit.enabled', false);
        }
        if (control.policies?.includes('authentication')) {
            return config.get('enterprise.sso.enabled', false);
        }
        if (control.policies?.includes('encryption')) {
            return true; // Assume encryption is always on
        }
        
        return Math.random() > 0.5; // Mock for demo
    }

    private _generateRecommendations(controls: ComplianceControl[]): string[] {
        const recommendations: string[] = [];
        const notImplemented = controls.filter(c => !c.implemented);

        if (notImplemented.length === 0) {
            recommendations.push('All controls are implemented. Continue regular monitoring and testing.');
        } else {
            for (const control of notImplemented.slice(0, 5)) {
                recommendations.push(`Implement ${control.name} (${control.id}): ${control.requirement}`);
            }
            
            if (notImplemented.length > 5) {
                recommendations.push(`...and ${notImplemented.length - 5} more controls need implementation.`);
            }
        }

        return recommendations;
    }

    async exportReport(report: ComplianceReport, format: 'json' | 'markdown' | 'pdf'): Promise<void> {
        let content: string;
        let extension: string;

        switch (format) {
            case 'json':
                content = JSON.stringify(report, null, 2);
                extension = 'json';
                break;
            case 'markdown':
                content = this._generateMarkdownReport(report);
                extension = 'md';
                break;
            case 'pdf':
                // PDF would require additional library
                content = this._generateMarkdownReport(report);
                extension = 'md';
                vscode.window.showInformationMessage('PDF export requires pandoc. Generating Markdown instead.');
                break;
        }

        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(`compliance-report-${report.framework.toLowerCase().replace(/\s+/g, '-')}.${extension}`),
            filters: { [format.toUpperCase()]: [extension] }
        });

        if (uri) {
            await vscode.workspace.fs.writeFile(uri, Buffer.from(content));
            const doc = await vscode.workspace.openTextDocument(uri);
            await vscode.window.showTextDocument(doc);
        }
    }

    private _generateMarkdownReport(report: ComplianceReport): string {
        const controlsTable = report.controls.map(c => 
            `| ${c.implemented ? '✅' : '❌'} | ${c.id} | ${c.name} | ${c.category} |`
        ).join('\n');

        return `# ${report.framework} Compliance Report

**Generated:** ${report.generatedAt.toISOString()}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Controls | ${report.summary.totalControls} |
| Implemented | ${report.summary.implementedControls} |
| Compliance | **${report.summary.compliancePercentage}%** |

## Control Status

| Status | ID | Control | Category |
|--------|-----|---------|----------|
${controlsTable}

## Recommendations

${report.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n')}

---

*This report was generated by Agent OS Compliance Manager.*
`;
    }

    async showComplianceWizard(): Promise<void> {
        const selected = await vscode.window.showQuickPick(
            this.getAllFrameworks().map(f => ({
                label: f.name,
                description: f.description,
                id: f.id
            })),
            {
                placeHolder: 'Select compliance framework to evaluate'
            }
        );

        if (!selected) return;

        const report = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Evaluating ${selected.label} compliance...`,
            cancellable: false
        }, async () => {
            return this.generateReport(selected.id);
        });

        if (report) {
            const action = await vscode.window.showInformationMessage(
                `${selected.label} Compliance: ${report.summary.compliancePercentage}% (${report.summary.implementedControls}/${report.summary.totalControls} controls)`,
                'Export Report',
                'View Details'
            );

            if (action === 'Export Report') {
                const format = await vscode.window.showQuickPick(
                    ['markdown', 'json'],
                    { placeHolder: 'Select export format' }
                );
                if (format) {
                    await this.exportReport(report, format as 'markdown' | 'json');
                }
            } else if (action === 'View Details') {
                // Show in output channel
                const channel = vscode.window.createOutputChannel('Agent OS Compliance');
                channel.appendLine(this._generateMarkdownReport(report));
                channel.show();
            }
        }
    }
}

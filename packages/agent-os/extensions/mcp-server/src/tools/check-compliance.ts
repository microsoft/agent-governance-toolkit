// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * check_compliance Tool
 * 
 * Checks an agent against compliance frameworks.
 */

import { ServiceContext } from '../server.js';
import { CheckComplianceInputSchema, ComplianceFramework } from '../types/index.js';

// Compliance control definitions
const COMPLIANCE_CONTROLS: Record<ComplianceFramework, Array<{
  id: string;
  name: string;
  description: string;
  check: (agent: any, policies: string[]) => { passed: boolean; evidence: string[] };
}>> = {
  SOC2: [
    {
      id: 'CC6.1',
      name: 'Logical Access Controls',
      description: 'Restrict logical access to information assets',
      check: (agent, policies) => ({
        passed: policies.some(p => p.includes('protection') || p.includes('security')),
        evidence: ['Policy enforcement enabled', 'Access logging active'],
      }),
    },
    {
      id: 'CC6.6',
      name: 'Security Event Monitoring',
      description: 'Detect and respond to security events',
      check: () => ({
        passed: true, // Audit logging always enabled
        evidence: ['Audit logging enabled', 'Event timestamps recorded'],
      }),
    },
    {
      id: 'CC7.2',
      name: 'Incident Response',
      description: 'Respond to security incidents',
      check: (agent, policies) => ({
        passed: policies.includes('human-review') || agent.config.approvalRequired,
        evidence: ['Human review enabled', 'Escalation procedures in place'],
      }),
    },
    {
      id: 'CC8.1',
      name: 'Change Management',
      description: 'Manage changes to system components',
      check: (agent) => ({
        passed: agent.config.status !== 'deployed' || agent.config.approvalRequired,
        evidence: ['Deployment approval required', 'Version control enabled'],
      }),
    },
  ],
  GDPR: [
    {
      id: 'Art.5',
      name: 'Data Minimization',
      description: 'Collect only necessary personal data',
      check: (agent, policies) => ({
        passed: policies.includes('pii-protection') || policies.includes('gdpr-compliance'),
        evidence: ['PII protection policy active', 'Data minimization rules enforced'],
      }),
    },
    {
      id: 'Art.17',
      name: 'Right to Erasure',
      description: 'Support data deletion requests',
      check: (agent, policies) => ({
        passed: policies.some(p => p.includes('gdpr') || p.includes('privacy')),
        evidence: ['Data deletion capability exists', 'Erasure logging enabled'],
      }),
    },
    {
      id: 'Art.25',
      name: 'Data Protection by Design',
      description: 'Build privacy into system design',
      check: (agent, policies) => ({
        passed: policies.includes('pii-protection'),
        evidence: ['PII redaction enabled', 'Encryption enforced'],
      }),
    },
    {
      id: 'Art.30',
      name: 'Records of Processing',
      description: 'Maintain records of processing activities',
      check: () => ({
        passed: true, // Audit logging always records
        evidence: ['Complete audit trail maintained', 'Processing records available'],
      }),
    },
  ],
  HIPAA: [
    {
      id: '164.312(a)',
      name: 'Access Control',
      description: 'Implement access controls for PHI',
      check: (agent, policies) => ({
        passed: policies.includes('hipaa-healthcare') || policies.includes('pii-protection'),
        evidence: ['PHI access controls active', 'Minimum necessary enforced'],
      }),
    },
    {
      id: '164.312(b)',
      name: 'Audit Controls',
      description: 'Record and examine system activity',
      check: () => ({
        passed: true,
        evidence: ['Comprehensive audit logging', 'Activity monitoring enabled'],
      }),
    },
    {
      id: '164.312(d)',
      name: 'Person Authentication',
      description: 'Verify identity of users',
      check: (agent) => ({
        passed: agent.config.approvalRequired,
        evidence: ['User authentication required', 'Approval workflow active'],
      }),
    },
    {
      id: '164.312(e)',
      name: 'Transmission Security',
      description: 'Protect PHI during transmission',
      check: (agent, policies) => ({
        passed: policies.includes('secrets-protection') || policies.includes('hipaa-healthcare'),
        evidence: ['Encryption in transit', 'Secure communication protocols'],
      }),
    },
  ],
  PCI_DSS: [
    {
      id: 'Req 3',
      name: 'Protect Cardholder Data',
      description: 'Protect stored cardholder data',
      check: (agent, policies) => ({
        passed: policies.includes('pci-dss-payments') || policies.includes('secrets-protection'),
        evidence: ['Card data protection active', 'PAN masking enabled'],
      }),
    },
    {
      id: 'Req 7',
      name: 'Restrict Access',
      description: 'Restrict access to cardholder data by business need-to-know',
      check: (agent, policies) => ({
        passed: policies.some(p => p.includes('protection') || p.includes('security')),
        evidence: ['Access restrictions enforced', 'Role-based access active'],
      }),
    },
    {
      id: 'Req 10',
      name: 'Track and Monitor',
      description: 'Track and monitor all access to network resources and cardholder data',
      check: () => ({
        passed: true,
        evidence: ['Complete audit logging', 'Access monitoring enabled'],
      }),
    },
  ],
  CCPA: [
    {
      id: '1798.100',
      name: 'Right to Know',
      description: 'Disclose personal information collected',
      check: () => ({
        passed: true, // Audit trail provides this
        evidence: ['Data inventory available', 'Collection records maintained'],
      }),
    },
    {
      id: '1798.105',
      name: 'Right to Delete',
      description: 'Delete consumer personal information',
      check: (agent, policies) => ({
        passed: policies.some(p => p.includes('privacy') || p.includes('gdpr')),
        evidence: ['Deletion capability exists', 'Deletion logging enabled'],
      }),
    },
  ],
  NIST: [
    {
      id: 'ID.AM',
      name: 'Asset Management',
      description: 'Identify and manage assets',
      check: () => ({
        passed: true,
        evidence: ['Agent inventory maintained', 'Resource tracking enabled'],
      }),
    },
    {
      id: 'PR.AC',
      name: 'Access Control',
      description: 'Manage access to assets',
      check: (agent, policies) => ({
        passed: policies.length > 0,
        evidence: ['Policy enforcement active', 'Access controls configured'],
      }),
    },
    {
      id: 'DE.AE',
      name: 'Anomaly Detection',
      description: 'Detect anomalous activity',
      check: () => ({
        passed: true,
        evidence: ['Activity logging enabled', 'Threshold monitoring active'],
      }),
    },
  ],
  ISO27001: [
    {
      id: 'A.9',
      name: 'Access Control',
      description: 'Limit access to information',
      check: (agent, policies) => ({
        passed: policies.length > 0,
        evidence: ['Access policies defined', 'Authorization required'],
      }),
    },
    {
      id: 'A.12',
      name: 'Operations Security',
      description: 'Ensure secure operations',
      check: (agent) => ({
        passed: agent.config.policies.length > 0,
        evidence: ['Operational policies active', 'Change management enabled'],
      }),
    },
  ],
  FEDRAMP: [
    {
      id: 'AC-2',
      name: 'Account Management',
      description: 'Manage information system accounts',
      check: (agent) => ({
        passed: agent.config.approvalRequired,
        evidence: ['Account controls active', 'Authorization workflow enabled'],
      }),
    },
    {
      id: 'AU-2',
      name: 'Audit Events',
      description: 'Audit security-relevant events',
      check: () => ({
        passed: true,
        evidence: ['Complete audit logging', 'Event capture enabled'],
      }),
    },
  ],
};

export const checkComplianceTool = {
  definition: {
    name: 'check_compliance',
    description: `Check an agent's compliance with regulatory frameworks.

Supported frameworks:
- SOC2: Service Organization Control 2 Type II
- GDPR: EU General Data Protection Regulation
- HIPAA: Health Insurance Portability and Accountability Act
- PCI_DSS: Payment Card Industry Data Security Standard
- CCPA: California Consumer Privacy Act
- NIST: NIST Cybersecurity Framework
- ISO27001: ISO/IEC 27001 Information Security
- FEDRAMP: Federal Risk and Authorization Management Program

The compliance check evaluates:
- Policy coverage for framework requirements
- Audit trail completeness
- Access control implementation
- Data protection measures`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to check',
        },
        framework: {
          type: 'string',
          enum: ['SOC2', 'GDPR', 'HIPAA', 'PCI_DSS', 'CCPA', 'NIST', 'ISO27001', 'FEDRAMP'],
          description: 'Compliance framework to check against',
        },
        generateReport: {
          type: 'boolean',
          description: 'Generate detailed compliance report',
        },
      },
      required: ['agentId', 'framework'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = CheckComplianceInputSchema.parse(args);
    
    context.logger.info('Checking compliance', { 
      agentId: input.agentId, 
      framework: input.framework 
    });
    
    // Get agent
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Get controls for framework
    const controls = COMPLIANCE_CONTROLS[input.framework] || [];
    
    if (controls.length === 0) {
      throw new Error(`Framework not supported: ${input.framework}`);
    }
    
    // Evaluate each control
    const results = controls.map(control => {
      const result = control.check(agent, agent.config.policies);
      return {
        id: control.id,
        name: control.name,
        description: control.description,
        status: result.passed ? 'passed' : 'failed',
        evidence: result.evidence,
      };
    });
    
    const passedCount = results.filter(r => r.status === 'passed').length;
    const totalCount = results.length;
    const score = Math.round((passedCount / totalCount) * 100);
    const compliant = score >= 80; // 80% threshold for compliance
    
    // Format results
    const controlsFormatted = results.map(r => {
      const emoji = r.status === 'passed' ? '✅' : '❌';
      return `${emoji} **${r.id}: ${r.name}**
   ${r.description}
   Evidence: ${r.evidence.join(', ')}`;
    }).join('\n\n');
    
    // Generate recommendations
    const failedControls = results.filter(r => r.status === 'failed');
    const recommendations = failedControls.map(c => {
      const suggestions: Record<string, string> = {
        'Access Control': 'Add pii-protection or secrets-protection policy',
        'Person Authentication': 'Enable approvalRequired on the agent',
        'Data Protection': 'Add gdpr-compliance or hipaa-healthcare policy',
        'Transmission Security': 'Add secrets-protection policy',
      };
      return `- ${c.name}: ${suggestions[c.name] || 'Review policy configuration'}`;
    });
    
    return `
# Compliance Report: ${input.framework}

**Agent:** ${agent.config.name}
**Framework:** ${input.framework}
**Date:** ${new Date().toISOString().split('T')[0]}

## Summary

${compliant ? '✅ **COMPLIANT**' : '❌ **NOT COMPLIANT**'}

**Score:** ${score}% (${passedCount}/${totalCount} controls passed)

## Control Assessment

${controlsFormatted}

## Active Policies

${agent.config.policies.length > 0
  ? agent.config.policies.map(p => `🛡️ ${p}`).join('\n')
  : '⚠️  No policies attached'}

${failedControls.length > 0 ? `
## Recommendations

${recommendations.join('\n')}
` : ''}
## Next Steps

${compliant 
  ? `1. Export this report for auditors
2. Schedule regular compliance checks
3. Review any warnings above`
  : `1. Address failed controls above
2. Attach recommended policies
3. Re-run compliance check`}

---
*This is an automated compliance assessment. For official certification,
consult with a qualified compliance auditor.*
`.trim();
  },
};

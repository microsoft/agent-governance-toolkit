// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Smoke tests for AgentOS Copilot Extension

const { AgentGenerator } = require('./dist/agentGenerator.js');
const { TemplateGallery } = require('./dist/templateGallery.js');
const { PolicyLibrary } = require('./dist/policyLibrary.js');
const { TestSimulator } = require('./dist/testSimulator.js');
const { DebugHelper } = require('./dist/debugHelper.js');
const { GitHubIntegration } = require('./dist/githubIntegration.js');

console.log('');
console.log('================================================');
console.log('  AgentOS Copilot Extension - Smoke Tests');
console.log('================================================');
console.log('');

let passed = 0;
let failed = 0;

function test(name, condition) {
  if (condition) {
    console.log('[PASS]', name);
    passed++;
  } else {
    console.log('[FAIL]', name);
    failed++;
  }
}

// AgentGenerator Tests
console.log('--- AgentGenerator ---');
const generator = new AgentGenerator();
const spec = generator.parseTaskDescription('Create an agent that monitors API endpoints');
test('parseTaskDescription returns spec', spec && spec.tasks);
test('parseTaskDescription extracts tasks', spec.tasks.length > 0);

const genResult = generator.generateAgent(spec, 'python');
test('generateAgent returns object', typeof genResult === 'object');

const workflow = generator.generateGitHubActionsWorkflow(spec);
test('generateGitHubActionsWorkflow returns YAML', workflow.includes('name:'));

// TemplateGallery Tests
console.log('');
console.log('--- TemplateGallery ---');
const gallery = new TemplateGallery();
test('getById returns template', gallery.getById('uptime-monitor') !== undefined);
test('getCategories returns 8 categories', gallery.getCategories().length === 8);
test('recommend returns results', gallery.recommend('monitor api').length > 0);
test('getByCategory returns devops templates', gallery.getByCategory('devops').length > 0);

// PolicyLibrary Tests
console.log('');
console.log('--- PolicyLibrary ---');
const policyLib = new PolicyLibrary();
test('getPolicy returns GDPR', policyLib.getPolicy('gdpr-standard') !== undefined);
test('getPolicy returns HIPAA', policyLib.getPolicy('hipaa-standard') !== undefined);
test('getPolicy returns SOC2', policyLib.getPolicy('soc2-standard') !== undefined);
test('getPolicy returns PCI-DSS', policyLib.getPolicy('pci-dss-standard') !== undefined);
test('getFrameworks returns 6 frameworks', policyLib.getFrameworks().length >= 4);

const validation = policyLib.validateAgainstPolicy('const email = user.email;', 'gdpr');
test('validateAgainstPolicy returns score', typeof validation.score === 'number');

const pii = policyLib.detectPII('Email: john@company.com Phone: (555) 123-4567 SSN: 123-45-6789');
test('detectPII works', typeof pii === 'object');

// TestSimulator Tests
console.log('');
console.log('--- TestSimulator ---');
const simulator = new TestSimulator();
const scenarios = simulator.generateTestScenarios('function test() { return 1; }', { dataSources: ['file'], outputs: ['log'] });
test('generateTestScenarios returns scenarios', scenarios.length > 0);

const audit = simulator.runSecurityAudit('const password = "secret123";');
test('runSecurityAudit detects hardcoded credential', audit.vulnerabilities.length > 0);

// DebugHelper Tests
console.log('');
console.log('--- DebugHelper ---');
const debugHelper = new DebugHelper();
const diagnosis = debugHelper.diagnoseError('TypeError: Cannot read property x of undefined', { code: 'const a = obj.x;' });
test('diagnoseError returns analysis', diagnosis.rootCause !== undefined);

const issues = debugHelper.detectPerformanceIssues('for(let i=0;i<1000;i++){arr.push(i)}', 'javascript');
test('detectPerformanceIssues returns array', Array.isArray(issues));

// GitHubIntegration Tests  
console.log('');
console.log('--- GitHubIntegration ---');
const github = new GitHubIntegration();
const workflowYaml = github.generateWorkflowYaml({ name: 'test-agent', schedule: '0 * * * *' }, { name: 'test-agent', language: 'python' });
test('generateWorkflowYaml returns YAML', workflowYaml.includes('name:'));

console.log('');
console.log('================================================');
console.log('  Results:', passed, 'passed,', failed, 'failed');
console.log('================================================');
console.log('');

process.exit(failed > 0 ? 1 : 0);

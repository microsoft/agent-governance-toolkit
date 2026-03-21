// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * CI/CD Integration Module
 * 
 * Provides integration with CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins)
 * for automated policy validation and deployment.
 */

import * as vscode from 'vscode';

export interface CICDProvider {
    id: string;
    name: string;
    configFile: string;
    template: string;
}

export interface ValidationResult {
    passed: boolean;
    violations: {
        file: string;
        line: number;
        rule: string;
        message: string;
        severity: 'error' | 'warning';
    }[];
    summary: {
        filesScanned: number;
        errorsFound: number;
        warningsFound: number;
    };
}

export class CICDIntegration {
    private readonly providers: CICDProvider[] = [
        {
            id: 'github-actions',
            name: 'GitHub Actions',
            configFile: '.github/workflows/agent-os.yml',
            template: `name: Agent OS Security Check

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    name: Agent OS Policy Validation
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install Agent OS
        run: pip install agent-os-kernel
        
      - name: Run Policy Validation
        run: |
          agentos check --format sarif --output results.sarif
        continue-on-error: true
        
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          
      - name: Check for violations
        run: |
          agentos check --fail-on-violation
`
        },
        {
            id: 'gitlab-ci',
            name: 'GitLab CI',
            configFile: '.gitlab-ci.yml',
            template: `stages:
  - security

agent-os-check:
  stage: security
  image: python:3.11
  before_script:
    - pip install agent-os-kernel
  script:
    - agentos check --format json --output agent-os-report.json
    - agentos check --fail-on-violation
  artifacts:
    reports:
      codequality: agent-os-report.json
    when: always
  rules:
    - if: \$CI_PIPELINE_SOURCE == "merge_request_event"
    - if: \$CI_COMMIT_BRANCH == "main"
`
        },
        {
            id: 'azure-pipelines',
            name: 'Azure Pipelines',
            configFile: 'azure-pipelines.yml',
            template: `trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
      
  - script: |
      pip install agent-os-kernel
    displayName: 'Install Agent OS'
    
  - script: |
      agentos check --format sarif --output $(Build.ArtifactStagingDirectory)/agent-os.sarif
    displayName: 'Run Agent OS Check'
    continueOnError: true
    
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'SecurityReports'
      
  - script: |
      agentos check --fail-on-violation
    displayName: 'Validate No Violations'
`
        },
        {
            id: 'jenkins',
            name: 'Jenkins',
            configFile: 'Jenkinsfile',
            template: `pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install agent-os-kernel'
            }
        }
        
        stage('Agent OS Security Check') {
            steps {
                sh 'agentos check --format json --output agent-os-report.json'
                archiveArtifacts artifacts: 'agent-os-report.json', allowEmptyArchive: true
            }
        }
        
        stage('Validate') {
            steps {
                sh 'agentos check --fail-on-violation'
            }
        }
    }
    
    post {
        always {
            recordIssues(
                tools: [checkStyle(pattern: 'agent-os-report.json')]
            )
        }
    }
}
`
        },
        {
            id: 'circleci',
            name: 'CircleCI',
            configFile: '.circleci/config.yml',
            template: `version: 2.1

jobs:
  agent-os-check:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run:
          name: Install Agent OS
          command: pip install agent-os-kernel
      - run:
          name: Run Security Check
          command: |
            agentos check --format junit --output test-results/agent-os.xml
      - store_test_results:
          path: test-results
      - run:
          name: Fail on Violations
          command: agentos check --fail-on-violation

workflows:
  security:
    jobs:
      - agent-os-check
`
        }
    ];

    getProvider(id: string): CICDProvider | undefined {
        return this.providers.find(p => p.id === id);
    }

    getAllProviders(): CICDProvider[] {
        return this.providers;
    }

    async generateConfig(providerId: string): Promise<void> {
        const provider = this.getProvider(providerId);
        if (!provider) {
            vscode.window.showErrorMessage(`Unknown CI/CD provider: ${providerId}`);
            return;
        }

        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const configUri = vscode.Uri.joinPath(workspaceFolder.uri, provider.configFile);

        // Check if file exists
        try {
            await vscode.workspace.fs.stat(configUri);
            const overwrite = await vscode.window.showWarningMessage(
                `${provider.configFile} already exists. Overwrite?`,
                'Overwrite',
                'Cancel'
            );
            if (overwrite !== 'Overwrite') {
                return;
            }
        } catch {
            // File doesn't exist, create directories
            const dir = vscode.Uri.joinPath(configUri, '..');
            try {
                await vscode.workspace.fs.createDirectory(dir);
            } catch {
                // Directory might already exist
            }
        }

        await vscode.workspace.fs.writeFile(configUri, Buffer.from(provider.template));
        
        const doc = await vscode.workspace.openTextDocument(configUri);
        await vscode.window.showTextDocument(doc);
        
        vscode.window.showInformationMessage(
            `Created ${provider.name} configuration: ${provider.configFile}`
        );
    }

    async showConfigWizard(): Promise<void> {
        const selected = await vscode.window.showQuickPick(
            this.providers.map(p => ({
                label: p.name,
                description: p.configFile,
                id: p.id
            })),
            {
                placeHolder: 'Select CI/CD provider'
            }
        );

        if (selected) {
            await this.generateConfig(selected.id);
        }
    }

    async validatePreCommit(): Promise<ValidationResult> {
        // Run validation on staged files
        const result: ValidationResult = {
            passed: true,
            violations: [],
            summary: {
                filesScanned: 0,
                errorsFound: 0,
                warningsFound: 0
            }
        };

        // This would integrate with the policy engine
        // For now, return a mock result
        return result;
    }

    async installPreCommitHook(): Promise<void> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const hookScript = `#!/bin/sh
# Agent OS pre-commit hook
# Validates code against security policies before committing

echo "🛡️ Running Agent OS security check..."

# Run Agent OS check on staged files
agentos check --staged --fail-on-violation

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Agent OS found policy violations. Commit blocked."
    echo "Run 'agentos check --staged' to see details."
    exit 1
fi

echo "✅ Agent OS check passed"
exit 0
`;

        const hookPath = vscode.Uri.joinPath(workspaceFolder.uri, '.git', 'hooks', 'pre-commit');
        
        try {
            await vscode.workspace.fs.writeFile(hookPath, Buffer.from(hookScript));
            
            // Make executable (on Unix-like systems)
            const terminal = vscode.window.createTerminal('Agent OS');
            terminal.sendText(`chmod +x "${hookPath.fsPath}"`);
            terminal.dispose();
            
            vscode.window.showInformationMessage(
                'Pre-commit hook installed! Agent OS will check code before each commit.'
            );
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to install pre-commit hook: ${error}`);
        }
    }
}

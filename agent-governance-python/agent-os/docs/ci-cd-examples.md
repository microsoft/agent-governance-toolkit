# CI/CD Pipeline Examples

Integrate Agent-OS governance checks into your continuous integration and
delivery pipelines. The examples below cover GitHub Actions, GitLab CI, and
Azure DevOps.

---

## Environment Variables

All pipelines use two common environment variables:

| Variable | Description | Default |
|---|---|---|
| `AGENTOS_CONFIG` | Path to the Agent-OS configuration file | `agentos.yaml` |
| `AGENTOS_LOG_LEVEL` | Logging verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`) | `INFO` |

---

## GitHub Actions

```yaml
# .github/workflows/agentos-ci.yml
name: Agent-OS CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

env:
  AGENTOS_CONFIG: agentos.yaml
  AGENTOS_LOG_LEVEL: INFO

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      # Cache pip dependencies to speed up builds
      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-

      - name: Install dependencies
        run: pip install -r requirements.txt

      # Run the test suite on every PR
      - name: Run tests
        run: pytest tests/ -v

  policy-validation:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-

      - name: Install dependencies
        run: pip install -r requirements.txt

      # Validate governance policies before merging
      - name: Validate policies
        run: agentos validate --json > policy-validation.json

  security-check:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-

      - name: Install dependencies
        run: pip install -r requirements.txt

      # Run security checks against known vulnerability databases
      - name: Security check
        run: agentos check --json > security-report.json

  audit:
    runs-on: ubuntu-latest
    needs: [policy-validation, security-check]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-

      - name: Install dependencies
        run: pip install -r requirements.txt

      # Collect audit logs and upload as a build artifact
      - name: Collect audit logs
        run: agentos audit --format json > audit-report.json

      - name: Upload audit report
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml
variables:
  AGENTOS_CONFIG: agentos.yaml
  AGENTOS_LOG_LEVEL: INFO
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip-cache"

# Cache pip dependencies across jobs
cache:
  paths:
    - .pip-cache/

stages:
  - test
  - validate
  - audit

# Run the test suite
test:
  stage: test
  image: python:3.11-slim
  script:
    - pip install -r requirements.txt
    - pytest tests/ -v

# Validate governance policies
policy-validation:
  stage: validate
  image: python:3.11-slim
  needs: [test]
  script:
    - pip install -r requirements.txt
    - agentos validate

# Run security checks
security-check:
  stage: validate
  image: python:3.11-slim
  needs: [test]
  script:
    - pip install -r requirements.txt
    - agentos check

# Collect audit logs and store as an artifact
audit:
  stage: audit
  image: python:3.11-slim
  needs: [policy-validation, security-check]
  script:
    - pip install -r requirements.txt
    - agentos audit --format json > audit-report.json
  artifacts:
    paths:
      - audit-report.json
    expire_in: 30 days
```

---

## Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

variables:
  AGENTOS_CONFIG: agentos.yaml
  AGENTOS_LOG_LEVEL: INFO

pool:
  vmImage: "ubuntu-latest"

stages:
  - stage: Test
    displayName: "Run Tests"
    jobs:
      - job: RunTests
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: "3.11"

          # Cache pip dependencies
          - task: Cache@2
            inputs:
              key: pip | "$(Agent.OS)" | requirements.txt
              path: $(PIP_CACHE_DIR)
            displayName: "Cache pip packages"

          - script: pip install -r requirements.txt
            displayName: "Install dependencies"

          - script: pytest tests/ -v
            displayName: "Run tests"

  - stage: Validate
    displayName: "Governance Checks"
    dependsOn: Test
    jobs:
      - job: PolicyValidation
        displayName: "Validate Policies"
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: "3.11"

          - script: pip install -r requirements.txt
            displayName: "Install dependencies"

          # Validate governance policies
          - script: agentos validate
            displayName: "Policy validation"

      - job: SecurityCheck
        displayName: "Security Check"
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: "3.11"

          - script: pip install -r requirements.txt
            displayName: "Install dependencies"

          # Run security checks
          - script: agentos check
            displayName: "Security check"

  - stage: Audit
    displayName: "Audit Collection"
    dependsOn: Validate
    jobs:
      - job: CollectAudit
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: "3.11"

          - script: pip install -r requirements.txt
            displayName: "Install dependencies"

          # Collect audit logs
          - script: agentos audit --format json > $(Build.ArtifactStagingDirectory)/audit-report.json
            displayName: "Collect audit logs"

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: "$(Build.ArtifactStagingDirectory)/audit-report.json"
              artifactName: "audit-report"
            displayName: "Publish audit report"
```

---

## README Badges

Add status badges to your `README.md` to show pipeline health at a glance.

### GitHub Actions

```markdown
![Agent-OS CI](https://github.com/<owner>/<repo>/actions/workflows/agentos-ci.yml/badge.svg)
```

### GitLab CI

```markdown
![pipeline status](https://gitlab.com/<namespace>/<project>/badges/main/pipeline.svg)
```

### Azure DevOps

```markdown
![Build Status](https://dev.azure.com/<org>/<project>/_apis/build/status/<definition>?branchName=main)
```

# Governance Attestation GitHub Action

Automated validation of PR governance attestation checklists using the Agent Governance Toolkit.

Ensures PRs contain properly filled governance attestations with exactly one checkbox marked per required section.

## Quick Start

```yaml
- uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
```

This validates the current PR's description against the standard 7-section governance attestation.

## Usage Examples

### Basic validation (default sections)

```yaml
- name: Governance Attestation
  uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
```

### Custom sections

```yaml
- name: Governance Attestation
  uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
  with:
    required-sections: |
      Security review
      Privacy review
      CELA review
```

### Validate specific PR body

```yaml
- name: Governance Attestation
  uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
  with:
    pr-body: ${{ github.event.pull_request.body }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `pr-body` | PR body text to validate | No | (current PR from context) |
| `required-sections` | YAML list of section titles (one per line) | No | Standard 7 sections |
| `min-body-length` | Minimum PR body length | No | `40` |
| `python-version` | Python version to use | No | `3.12` |
| `toolkit-version` | Toolkit version to install | No | (latest) |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `pass` or `fail` |
| `errors` | Newline-separated list of errors |
| `sections-found` | JSON mapping sections to checkbox counts |
| `message` | Formatted validation message |

## Default Required Sections

1. Security review
2. Privacy review
3. CELA review
4. Responsible AI review
5. Accessibility review
6. Release Readiness / Safe Deployment
7. Org-specific Launch Gates

Each section must have **exactly one** checkbox marked:
- ✅ `[x] Yes`
- ✅ `[x] No`
- ✅ `[x] Not needed (explain below)`

## PR Template Format

Your `.github/pull_request_template.md` should follow this structure:

> **GitHub Issue Forms compatibility:** GitHub Issue Forms with `type: checkboxes` automatically render checkbox group labels as `###` (h3) headings. Both `##` (h2) and `###` (h3) heading levels are accepted, so Issue Form–generated bodies and hand-written PR templates work without any extra configuration.

```markdown
# Governance Attestations (required)

## 1) Security review
- [ ] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

## 2) Privacy review
- [ ] ✅ Yes
- [ ] ❌ No
- [ ] ⚠️ Not needed (explain below)

<!-- ... more sections ... -->

---

# Notes / Links

Provide justifications for N/A selections:

- 
```

## Complete Workflow Example

```yaml
name: Governance Attestation

on:
  pull_request:
    types: [opened, edited, reopened, synchronize]

permissions:
  pull-requests: read

jobs:
  verify-attestation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Verify PR governance attestation
        uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
        id: attestation
      
      - name: Comment on PR (on failure)
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const errors = `${{ steps.attestation.outputs.errors }}`.split('\n');
            const body = `❌ **Governance attestation validation failed:**\n\n${errors.map(e => `- ${e}`).join('\n')}`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

## Validation Rules

### ✅ Valid Example
```markdown
## 1) Security review
- [ ] ✅ Yes
- [x] ⚠️ Not needed (explain below)
- [ ] ❌ No
```
**Exactly one** checkbox marked.

### ❌ Invalid Examples

**No checkbox marked:**
```markdown
## 1) Security review
- [ ] ✅ Yes
- [ ] ⚠️ Not needed (explain below)
- [ ] ❌ No
```

**Multiple checkboxes marked:**
```markdown
## 1) Security review
- [x] ✅ Yes
- [x] ⚠️ Not needed (explain below)
- [ ] ❌ No
```

**Section missing:**
```markdown
# Governance Attestations

(Security review section not found)
```

## Error Messages

| Error | Meaning | Fix |
|-------|---------|-----|
| `Missing section: "X"` | Required section not found | Add section to PR description |
| `Section "X" must have exactly ONE checked box, found 0` | No checkbox marked | Mark exactly one checkbox |
| `Section "X" must have exactly ONE checked box, found 2` | Multiple checkboxes marked | Uncheck all but one |
| `PR description is too short` | Template not used | Use governance attestation template |

## Customization

### Organization-Specific Sections

Override default sections for your organization:

```yaml
- uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
  with:
    required-sections: |
      Security review
      Privacy review
      Legal review
      Compliance review
      Architecture review
      Product review
```

### Lenient Mode (Warnings Only)

Use `continue-on-error` to treat failures as warnings:

```yaml
- name: Governance Attestation
  uses: microsoft/agent-governance-toolkit/action/governance-attestation@v2
  continue-on-error: true
```

## License

MIT License - see [LICENSE](../../LICENSE) for details.

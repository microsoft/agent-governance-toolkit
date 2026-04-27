<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 46: Contributor Governance

> **Time**: 30 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 45 (Shift-Left Governance)

Detect coordinated inauthentic behavior, product placement campaigns, and
credibility farming before untrusted code or content enters your repository.
This tutorial covers AGT's full contributor governance toolchain: from running
a single check against a GitHub username to deploying automated CI workflows
that screen every PR and issue author.

> **Scope:** contributor reputation analysis, coordination detection, cross-project scanning
> **Tools:** contributor_check.py, credential_audit.py, cluster_detect.py, GitHub Actions
> **Audience:** OSS maintainers, security teams, DevRel teams managing open-source projects

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Why Contributor Governance?](#why-contributor-governance) | The problem of inauthentic contributions in AI/agent repos |
| [Quick Start](#quick-start) | Run your first contributor check in 60 seconds |
| [Understanding Signals](#understanding-signals) | All 12 detection signals explained with real examples |
| [The Three Scripts](#the-three-scripts) | contributor_check.py, credential_audit.py, cluster_detect.py |
| [CI Integration](#ci-integration) | Deploy the contributor-check GitHub Action |
| [Cross-Project Scanning](#cross-project-scanning) | Scan issue authors across entire ecosystems |
| [Tuning and False Positives](#tuning-and-false-positives) | Adjusting thresholds, handling legitimate contributors |
| [Case Studies](#case-studies) | Real-world detection examples from AGT, A2A, and MCP Servers |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Why Contributor Governance?

Open-source AI agent projects face a unique attack surface: contributors who
use the project's credibility to promote their own products. Unlike traditional
supply chain attacks (malicious code in dependencies), these attacks operate
through **social engineering of trust**:

1. **Product placement**: Filing PRs or issues that embed links, integrations,
   or references to the contributor's own unrelated project
2. **Credibility farming**: Forking popular awesome-lists and curated
   repositories to manufacture a profile that appears legitimate
3. **Credential laundering**: Getting a small PR merged, then citing that merge
   as a credential in issues filed across dozens of other repos
4. **Feature cloning**: Creating a near-copy of an existing project, then
   filing issues in related repos to promote the clone
5. **Coordinated networks**: Multiple accounts working together to cross-promote
   products, share forks, and amplify each other's issues

These patterns are especially prevalent in the AI agent governance space, where
projects are new, standards bodies are forming, and there is strong incentive to
position products as "the standard."

---

## Quick Start

### Prerequisites

- Python 3.10+
- A GitHub personal access token (or `gh` CLI authenticated)

### Your First Check

```bash
# Set your GitHub token
export GITHUB_TOKEN="ghp_your_token_here"

# Or use gh CLI authentication (no token needed)
gh auth login

# Run a contributor check
cd agent-governance-toolkit
python scripts/contributor_check.py --username <github-handle>
```

Example output for a clean contributor:

```
Reputation Report: clean-developer
Risk: LOW
No signals detected.
```

Example output for a suspicious account:

```
Reputation Report: suspicious-account
Risk: HIGH

Signals:
  [HIGH] recent_repo_burst: 41 repos created in last 90 days
  [HIGH] cross_repo_spray: Issues filed in 72 repos within 7 days
  [HIGH] self_promotion_spray: 15 issues promoting own repos across 12 orgs
  [HIGH] thin_credibility: Repo 'my-project' (22d old, 0 stars) promoted across 28 orgs
  [HIGH] coordinated_promotion: 8 thin repos promoted to overlapping org set
```

### JSON Output

For programmatic use, add `--json`:

```bash
python scripts/contributor_check.py --username <handle> --json
```

### Target Repository Context

Add `--repo` to enable feature overlap detection and credential spray checks:

```bash
python scripts/contributor_check.py \
  --username <handle> \
  --repo microsoft/agent-governance-toolkit
```

This enables three additional signals: `feature_overlap`, `credential_citation`/
`credential_laundering`, and provides richer context for `thin_credibility`.

---

## Understanding Signals

AGT's contributor check evaluates accounts across 12 behavioral signals,
grouped into four categories.

### Account Shape Signals

These signals analyze the GitHub profile itself, without fetching repos or issues.

| Signal | Severity | Triggers When |
|--------|----------|---------------|
| `repo_velocity` | MEDIUM/HIGH | More than 0.2 repos/day with 10+ repos (MEDIUM) or 0.5/day with 15+ (HIGH) |
| `new_account_burst` | MEDIUM/HIGH | Account < 90 days old with 20+ repos (HIGH) or < 180 days with 30+ (MEDIUM) |
| `following_farming` | MEDIUM/HIGH | Following:follower ratio > 5:1 with 100+ following (MEDIUM) or > 20:1 (HIGH) |
| `zero_followers` | MEDIUM | 0 followers despite 5+ public repos |

**Example:** An account created 33 days ago with 27 repos and zero followers
triggers `new_account_burst` (HIGH), `repo_velocity` (HIGH), and
`zero_followers` (MEDIUM).

### Repository Pattern Signals

These signals analyze the user's repositories for suspicious creation patterns.

| Signal | Severity | Triggers When |
|--------|----------|---------------|
| `governance_theme_concentration` | MEDIUM | > 50% of repos are governance/security themed (with 5+ total repos) |
| `recent_repo_burst` | HIGH | 15+ repos created in the last 90 days |
| `awesome_fork_burst` | HIGH | 3+ awesome-list forks within 72 hours |
| `fork_burst` | MEDIUM | 5+ general forks within 72 hours |
| `batch_repo_naming` | MEDIUM/HIGH | 3+ repos with the same suffix (e.g., `*-mcp`) created within 48 hours, all with < 10 stars |
| `feature_overlap` | MEDIUM/HIGH | A non-fork repo matches 3+ (MEDIUM) or 4+ (HIGH) of 6 AGT feature buckets |

**Awesome fork burst explained:** Credibility farming accounts fork curated
"awesome" lists to pad their profile with seemingly relevant repos. A burst of
3+ awesome-list forks in 72 hours is a strong signal because legitimate
developers rarely fork multiple curated lists in rapid succession.

**Feature overlap explained:** AGT defines six feature buckets that together
characterize its unique capability set:

```
1. mcp_security    - MCP scanner, tool poisoning, rug pull detection
2. policy_engine   - Policy evaluation, Cedar/YAML policies, deny-by-default
3. identity_crypto - Ed25519 agent identity, zero-trust identity, agent DID
4. runtime_controls - Execution sandbox, kill switch, circuit breaker
5. audit_trust     - Audit trail, trust scoring, hash-chain logs
6. compliance      - OWASP Agentic, EU AI Act, NIST AI RMF
```

A repo matching 4+ of these 6 categories is likely a concept clone, especially
if it is young and has few stars.

**Batch repo naming explained:** Accounts that mass-create repos with templated
names (e.g., `agent-workflow-mcp`, `agent-security-mcp`, `agent-guard-mcp` all
in one day) are likely producing thin placeholder projects for spam promotion.
The check only flags low-star repos (< 10 stars) to avoid false-positiving on
legitimate ecosystems.

### Issue Spray Signals

These signals analyze the user's issue-filing patterns across GitHub.

| Signal | Severity | Triggers When |
|--------|----------|---------------|
| `cross_repo_spray` | HIGH | Issues filed in 5+ distinct repos within 7 days |
| `cross_repo_spread` | MEDIUM | Issues filed across 8+ distinct repos total |
| `self_promotion_spray` | MEDIUM/HIGH | 3+ issues promoting the author's own repos across 2+ orgs (MEDIUM) or 5+ issues across 3+ orgs (HIGH) |
| `credential_citation` | MEDIUM | Citing a target repo's merges in issues across 1+ other repos |
| `credential_laundering` | HIGH | Citing a target repo's merges in issues across 3+ other repos |

**Self-promotion spray explained:** This is the key signal that separates
legitimate protocol contributors from product placement accounts. Both may file
issues across many repos (triggering `cross_repo_spray`), but only spammers'
issues reference their own repos.

The check uses strong matching:
- Full `owner/repo` references
- `github.com/owner/repo` URLs
- Distinctive repo names (4+ chars, excluding generic words like `app`, `api`, `web`)

Forked repos are excluded from the author's repo list to prevent false matches.

### Credibility Signals

These signals analyze the user's project promotion patterns.

| Signal | Severity | Triggers When |
|--------|----------|---------------|
| `thin_credibility` | MEDIUM/HIGH | A repo < 60 days old with < 5 stars is mentioned in issues filed in 1 org (MEDIUM) or 2+ orgs (HIGH) |
| `coordinated_promotion` | HIGH | 3+ thin repos promoted to overlapping org sets (Jaccard similarity >= 0.6 on 50%+ of pairs) |

**Coordinated promotion explained:** When an account creates multiple thin
repos and promotes them all to the same set of target organizations, it
indicates automated or systematic spam. The check computes pairwise Jaccard
similarity between the promoted-org sets and flags when the overlap pattern
is systematic.

---

## The Three Scripts

AGT provides three complementary contributor governance scripts.

### contributor_check.py

The primary tool. Runs all signal checks and produces a risk assessment.

```bash
# Basic profile check
python scripts/contributor_check.py --username <handle>

# With target repo context (enables feature_overlap + credential checks)
python scripts/contributor_check.py --username <handle> --repo <owner/repo>

# JSON output for programmatic use
python scripts/contributor_check.py --username <handle> --json
```

**Exit codes:**
- `0` = LOW risk
- `1` = MEDIUM risk
- `2` = HIGH risk

**Risk computation:** 2+ HIGH severity signals = HIGH risk. 1 HIGH or 3+
MEDIUM signals = MEDIUM risk. Otherwise LOW.

### credential_audit.py

Deep-dive tool for investigating credential laundering. Checks if a user has
merged PRs in one repo and cites those merges in issues filed against other
repos.

```bash
python scripts/credential_audit.py --username <handle> --repo <target-repo>
```

Use this for manual investigation of HIGH-risk accounts detected by
contributor_check.py.

### cluster_detect.py

Network analysis tool for mapping coordination between accounts. Starting from
a seed account, it maps shared forks, co-comments, and synchronized filing
patterns.

```bash
python scripts/cluster_detect.py --seed <handle>
```

> **Note:** cluster_detect.py is API-heavy and may hit GitHub's secondary rate
> limits when analyzing large networks. Use it for targeted investigation, not
> bulk scanning.

---

## CI Integration

### The Contributor Check GitHub Action

Deploy automated screening on every PR and issue:

```yaml
# .github/workflows/contributor-check.yml
name: Contributor Reputation Check

on:
  pull_request_target:
    types: [opened]
  issues:
    types: [opened]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  check:
    runs-on: ubuntu-latest
    if: github.actor != 'dependabot[bot]'
    steps:
      - name: Checkout AGT action
        uses: actions/checkout@v4
        with:
          repository: microsoft/agent-governance-toolkit
          sparse-checkout: |
            scripts
            .github/actions/contributor-check
          path: agt

      - name: Run contributor check
        uses: ./agt/.github/actions/contributor-check
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          checks: profile,credential
          risk-threshold: MEDIUM
```

### What the Action Does

1. Extracts the PR/issue author's username
2. Runs contributor_check.py with `--repo` set to the current repository
3. Optionally runs credential_audit.py for deeper analysis
4. Posts a collapsible comment with findings (MEDIUM or higher)
5. Adds risk labels (`needs-review:MEDIUM` or `needs-review:HIGH`)
6. Comments are idempotent: re-runs update instead of duplicating

### Security Note

Use `pull_request_target` (not `pull_request`) so the action has write
permissions to comment and label on fork PRs. Do not run untrusted PR code
before this action in the same workflow.

---

## Cross-Project Scanning

For maintainers responsible for ecosystem health, contributor_check.py can
scan all issue authors across a project:

### Step 1: Extract Issue Authors

```bash
# Using gh CLI to list issue authors
gh issue list --repo <owner/repo> --state all --json author --limit 100 \
  | jq -r '.[].author.login' | sort -u > authors.txt
```

### Step 2: Batch Scan

```bash
# Scan each author with target repo context
while IFS= read -r author; do
  echo "=== $author ==="
  python scripts/contributor_check.py \
    --username "$author" \
    --repo <owner/repo> \
    --json
done < authors.txt > scan_results.jsonl
```

### Step 3: Filter HIGH Risk

```bash
# Extract HIGH risk accounts
cat scan_results.jsonl | \
  python -c "
import sys, json
for line in sys.stdin:
    if line.startswith('{'):
        d = json.loads(line)
        if d['risk'] == 'HIGH':
            print(f\"{d['username']}: {len(d['signals'])} signals\")
"
```

### Cross-Ecosystem Scanning

For scanning across multiple repositories (as we did with AAIF, A2A, and MCP
Servers), maintain a list of target repos and deduplicate authors:

```bash
repos=("aaif/project-proposals" "google/A2A" "modelcontextprotocol/servers")
for repo in "${repos[@]}"; do
  gh issue list --repo "$repo" --state all --json author --limit 100 \
    | jq -r '.[].author.login'
done | sort -u > all_authors.txt
```

This approach revealed shared bad actors across ecosystems. For example, the
same accounts were found filing product placement issues in AAIF, Google A2A,
and MCP Servers simultaneously.

---

## Tuning and False Positives

### Common False Positive: Protocol/Spec Contributors

Legitimate protocol contributors (e.g., people working on HTTP specs, A2A
protocol, MCP standards) file issues across many repos as part of their work.
This triggers `cross_repo_spray` but should not flag as suspicious.

**How AGT handles this:** The `self_promotion_spray` signal differentiates
between "filing issues about protocol topics" and "promoting your own repos."
A spec contributor filing HTTP/3 tracking issues across 15 repos will trigger
`cross_repo_spray` (MEDIUM overall) but not `self_promotion_spray`, keeping
them at MEDIUM rather than HIGH.

### Common False Positive: Active Open-Source Contributors

Developers who genuinely contribute across many repos may trigger
`cross_repo_spray`. Without self-promotion or thin-credibility signals, they
remain at MEDIUM.

### Adjusting the Risk Threshold

In the GitHub Action, set `risk-threshold` to control when comments are posted:

- `risk-threshold: HIGH` - Only flag the most suspicious accounts (fewer false positives, may miss some bad actors)
- `risk-threshold: MEDIUM` - Flag anything suspicious (more false positives, catches more bad actors)

### Excluding Known Accounts

For known legitimate contributors who trigger false positives, add them to an
allow list in the workflow:

```yaml
- name: Run contributor check
  if: >
    github.actor != 'dependabot[bot]' &&
    github.actor != 'known-legit-contributor'
  uses: ./agt/.github/actions/contributor-check
```

---

## Case Studies

### Case Study 1: Credibility Farming Network

**Detected:** A network of 5 linked accounts operating across AAIF, Google A2A,
and AGT. The primary account created 46 repos, sprayed issues across 72 repos
in 7 days, and promoted thin-credibility projects across 28 organizations.

**Signals fired:**
- `recent_repo_burst` (41 repos in 90 days)
- `cross_repo_spray` (72 repos in 7 days)
- `self_promotion_spray` (promoting own repos across 12+ orgs)
- `thin_credibility` (multiple 0-star repos promoted across 28 orgs)
- `coordinated_promotion` (8 thin repos targeting overlapping org sets)
- `credential_citation` (citing AGT merges as credentials elsewhere)

**Action taken:** 33 files and 5,544 lines of product placement content removed
from AGT. Tracking issues created for legitimate feature gaps identified
during cleanup.

### Case Study 2: Quiet Feature Clone

**Detected:** An account that cloned AGT's entire feature set into a 22-day-old
repo with 1 star, then filed a project proposal in AAIF.

**Why existing checks missed it:** No spray pattern (only 1 issue), no
following farming, no unusual account age. Traditional signals were clean.

**New signals that caught it:**
- `awesome_fork_burst` (5 awesome-list forks in 72 hours)
- `feature_overlap` (6/6 AGT feature buckets matched)
- `thin_credibility` (22-day-old, 1-star repo promoted in aaif)

This case drove the development of the feature_overlap and fork_burst signals.

### Case Study 3: MCP Server Spam Ring

**Detected:** Two accounts mass-creating thin MCP server repos (0 stars,
< 5 days old) and promoting them identically across modelcontextprotocol,
punkpeye, aimcp, and chatmcp organizations.

**Signals fired:**
- `batch_repo_naming` (22 repos ending in `-mcp` created in one batch)
- `thin_credibility` (22 thin repos promoted across 3-4 orgs each)
- `coordinated_promotion` (all repos targeting the same org set)
- `new_account_burst` (141-day account with 35 repos, 0 followers)

This case drove the development of the batch_repo_naming and
coordinated_promotion signals.

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Shift-left governance overview | [Tutorial 45 -- Shift-Left Governance](45-shift-left-governance.md) |
| CI/CD security tooling | [Tutorial 25 -- Security Hardening](25-security-hardening.md) |
| Trust and identity fundamentals | [Tutorial 02 -- Trust & Identity](02-trust-and-identity.md) |
| Advanced trust and behavior | [Tutorial 17 -- Advanced Trust](17-advanced-trust-and-behavior.md) |
| Plugin marketplace governance | [Tutorial 10 -- Plugin Marketplace](10-plugin-marketplace.md) |
| SBOM and supply chain | [Tutorial 26 -- SBOM & Signing](26-sbom-and-signing.md) |

---

## Source Files

| Component | Location |
|-----------|----------|
| Contributor check script | `scripts/contributor_check.py` |
| Credential audit script | `scripts/credential_audit.py` |
| Cluster detection script | `scripts/cluster_detect.py` |
| Contributor check tests | `scripts/tests/test_contributor_check.py` |
| GitHub Action workflow | `.github/workflows/contributor-check.yml` |
| Composite action | `.github/actions/contributor-check/` |

---

## Next Steps

- **Deploy the contributor-check action** to your repository using the
  workflow template in [CI Integration](#ci-integration)
- **Run a baseline scan** of your existing contributors to identify any
  historical product placement content
- **Set up periodic re-scans** as new accounts and patterns emerge
- **Read Tutorial 45** ([Shift-Left Governance](45-shift-left-governance.md))
  for the complete shift-left pipeline that contributor governance fits into
- **Read Tutorial 17** ([Advanced Trust](17-advanced-trust-and-behavior.md))
  for runtime trust scoring that complements build-time contributor checks

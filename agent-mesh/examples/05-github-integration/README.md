# GitHub PR Review Agent

An agent that reviews pull requests with governance, preventing malicious code suggestions and security vulnerabilities.

## What This Example Shows

- **Real-world GitHub integration** via GitHub API
- **Output sanitization policies** to prevent credential leakage
- **Shadow mode** for testing policies before enforcement
- **Trust score decay** on bad suggestions or policy violations

## Use Case

A code review agent that:
- Analyzes pull requests for security issues
- Suggests improvements
- **Never suggests** code with hardcoded secrets
- Blocks suggestions that violate security policies
- Tracks trust score based on suggestion quality

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│              GitHub PR Review Agent                        │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │ AgentMesh Governance                                 │ │
│  │ • Output sanitization (no secrets in suggestions)   │ │
│  │ • Shadow mode testing                                │ │
│  │ • Trust score tracking                               │ │
│  └──────────────────────────────────────────────────────┘ │
│                         │                                  │
│  ┌──────────┬──────────┴──────────┬──────────────────┐   │
│  │ GitHub   │ LLM Code            │  Security        │   │
│  │ API      │ Analysis            │  Scanners        │   │
│  └──────────┴─────────────────────┴──────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Set GitHub token
export GITHUB_TOKEN="your_token_here"

# Install dependencies
pip install -r requirements.txt

# Run the agent
python main.py --repo owner/repo --pr 123
```

## Key Features

### 1. Output Sanitization

Prevents agent from suggesting code with secrets:

```python
# This would be blocked by policy
suggestion = "API_KEY = 'sk-abc123...'"  # ✗ Blocked

# This would be allowed
suggestion = "API_KEY = os.getenv('API_KEY')"  # ✓ Allowed
```

### 2. Shadow Mode

Test policies without blocking:

```yaml
governance:
  shadow_mode: true  # Log violations but don't block
```

### 3. Trust Score Tracking

Agent's trust score changes based on:
- Quality of suggestions (upvoted/downvoted)
- Policy compliance
- Security issues found vs. false positives

## Security Policies

- **No hardcoded secrets** in suggestions
- **No SQL injection** patterns
- **No XSS vulnerabilities** in web code
- **No path traversal** vulnerabilities

## Example Output

```
🔍 Reviewing PR #123: Add user authentication

✓ Scanned 5 files
✓ Found 2 security issues
  • Hardcoded API key in config.py (critical)
  • Missing input validation in auth.py (medium)

💡 Suggestions:
  1. Use environment variables for API keys
  2. Add input validation with regex

📋 Policy checks: All passed
⭐ Trust score: 847/1000
```

## Integration with GitHub Actions

```yaml
# .github/workflows/pr-review.yml
name: AgentMesh PR Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: pip install agentmesh-platform
      - run: python pr-agent.py --pr ${{ github.event.pull_request.number }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Learn More

- [GitHub API Documentation](https://docs.github.com/en/rest)
- [AgentMesh Shadow Mode](../../docs/shadow-mode.md)

---

**Note:** This example uses simulated GitHub API calls. For production, integrate with actual GitHub API.

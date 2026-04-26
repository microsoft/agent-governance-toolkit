# Publishing AgentOS MCP Server to npm

This guide walks you through publishing the AgentOS MCP Server to npm for distribution via `npx`.

## Prerequisites

Before publishing, ensure you have:
- [x] A working MCP server (code in `agent-governance-python/agent-os/extensions/mcp-server/`)
- [x] npm account with publish access
- [ ] MCP server tested with Claude Desktop
- [ ] All TypeScript compiled successfully

---

## Pre-Flight Checklist

```
[x] TypeScript compiles without errors (`npm run build`)
[x] Version set in package.json (currently: 1.0.0)
[x] README.md complete with usage instructions
[x] CHANGELOG.md updated
[x] LICENSE file present (MIT)
[x] All 10 tools implemented and tested
[x] 6 built-in policies configured
[x] 10 agent templates available
[x] 6 policy templates available
[x] 6 MCP prompts defined
[ ] Tested with Claude Desktop locally
```

---

## Step 1: Test Locally with Claude Desktop

Before publishing, verify the server works with Claude Desktop:

### 1.1 Build the Package

```powershell
cd agent-governance-python/agent-os/extensions/mcp-server
npm run build
```

### 1.2 Configure Claude Desktop for Local Testing

Edit `claude_desktop_config.json`:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "agentos-dev": {
      "command": "node",
      "args": ["<your-path>", "--stdio"],
      "env": {
        "AGENTOS_POLICY_MODE": "strict",
        "AGENTOS_LOG_LEVEL": "debug"
      }
    }
  }
}
```

### 1.3 Restart Claude Desktop and Test

1. Restart Claude Desktop
2. Try: "Create an agent that backs up my documents daily"
3. Verify all tools work correctly

---

## Step 2: Prepare for Publishing

### 2.1 Update Version (if needed)

```powershell
# For patch release (1.0.0 → 1.0.1)
npm version patch

# For minor release (1.0.0 → 1.1.0)
npm version minor

# For major release (1.0.0 → 2.0.0)
npm version major
```

### 2.2 Verify Package Contents

```powershell
# See what will be published
npm pack --dry-run
```

Expected output:
```
npm notice 📦  @agentos/mcp-server@1.0.0
npm notice Tarball Contents
npm notice 15.2kB dist/cli.js
npm notice 12.8kB dist/server.js
npm notice ...
npm notice Tarball Details
npm notice name:          @agentos/mcp-server
npm notice version:       1.0.0
npm notice package size:  45.2 kB
npm notice total files:   30
```

### 2.3 Verify package.json

Ensure these fields are set:

```json
{
  "name": "@agentos/mcp-server",
  "version": "1.0.0",
  "description": "AgentOS MCP Server for Claude Desktop - Build, deploy, and manage policy-compliant autonomous agents",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "bin": {
    "agentos-mcp": "dist/cli.js"
  },
  "files": [
    "dist",
    "src/templates"
  ],
  "repository": {
    "type": "git",
    "url": "https://github.com/microsoft/agent-governance-toolkit"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "agent-os",
    "claude-desktop",
    "ai-agents",
    "agent-safety",
    "anthropic"
  ]
}
```

---

## Step 3: Create npm Organization (First Time Only)

If publishing under `@agentos` scope for the first time:

### 3.1 Create npm Account

1. Go to [npmjs.com](https://www.npmjs.com/)
2. Sign up or log in

### 3.2 Create Organization

1. Go to your npm profile
2. Click **"Add Organization"**
3. Organization name: `agentos`
4. Choose free plan

### 3.3 Login via CLI

```powershell
npm login
# Enter username, password, and email
# Enter OTP if 2FA enabled
```

---

## Step 4: Publish to npm

### 4.1 Publish Public Package

```powershell
cd agent-governance-python/agent-os/extensions/mcp-server

# For scoped packages, must explicitly set public access
npm publish --access public
```

### 4.2 Verify Publication

1. Wait 1-2 minutes for npm to process
2. Visit: https://www.npmjs.com/package/@agentos/mcp-server
3. Verify all information appears correctly

### 4.3 Test Installation

```powershell
# Test with npx (how users will run it)
npx -y @agentos/mcp-server --help

# Or install globally
npm install -g @agentos/mcp-server
agentos-mcp --help
```

---

## Step 5: Update Claude Desktop Configuration

After publishing, users can configure with:

```json
{
  "mcpServers": {
    "agentos": {
      "command": "npx",
      "args": ["-y", "@agentos/mcp-server"],
      "env": {
        "AGENTOS_POLICY_MODE": "strict"
      }
    }
  }
}
```

---

## Updating the Package

### Version Bump and Publish

```powershell
# Update version and publish in one command
npm version patch && npm publish --access public

# Or for minor/major releases
npm version minor && npm publish --access public
npm version major && npm publish --access public
```

### Pre-release Versions

```powershell
# Publish beta version (1.0.0-beta.1)
npm version prerelease --preid=beta
npm publish --access public --tag beta

# Users can install beta with:
# npx @agentos/mcp-server@beta
```

---

## npm Badges

Add these to README.md after publishing:

```markdown
[![npm version](https://badge.fury.io/js/@agentos%2Fmcp-server.svg)](https://www.npmjs.com/package/@agentos/mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@agentos/mcp-server)](https://www.npmjs.com/package/@agentos/mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

---

## Troubleshooting

### "You do not have permission to publish"

```powershell
# Verify you're logged in
npm whoami

# Check organization membership
npm team ls @agentos:developers
```

### "Package name too similar to existing package"

- npm may block names similar to existing packages
- Try a different package name or scope

### "Missing required field"

Ensure package.json has:
- `name`
- `version`
- `description`
- `main`
- `repository`

### "Cannot publish over existing version"

You cannot republish the same version. Bump the version:
```powershell
npm version patch
```

### "Tarball too large"

Check `.npmignore` or `files` in package.json to exclude:
- `node_modules/`
- `tests/`
- `.git/`
- Development files

---

## CI/CD Integration (Optional)

Add to `.github/workflows/publish.yml`:

```yaml
name: Publish to npm
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      
      - name: Install dependencies
        run: npm ci
        working-directory: agent-governance-python/agent-os/extensions/mcp-server
      
      - name: Build
        run: npm run build
        working-directory: agent-governance-python/agent-os/extensions/mcp-server
      
      - name: Publish
        run: npm publish --access public
        working-directory: agent-governance-python/agent-os/extensions/mcp-server
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Set `NPM_TOKEN` in repository secrets (from npm → Access Tokens → Generate New Token → Automation).

---

## Anthropic MCP Server Directory (Future)

When Anthropic launches their official MCP server directory:

1. Submit AgentOS MCP Server for inclusion
2. Provide:
   - Package name: `@agentos/mcp-server`
   - Description: Safety layer for autonomous AI agents
   - Category: Agent Safety / Governance
   - Documentation link
3. Wait for Anthropic review and approval

---

## Support & Resources

- [npm Documentation](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
- [MCP Specification](https://modelcontextprotocol.io)
- [Claude Desktop MCP Guide](https://www.anthropic.com/news/model-context-protocol)
- [AgentOS GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)

---

**Package Status**: Ready for npm publish  
**Version**: 1.0.0  
**Package Size**: ~50 KB (estimated)

# Publishing AgentOS VS Code Extension to Marketplace

## Pre-Flight Checklist

Before publishing, ensure these items are complete:

- [x] Extension compiles without errors (`npm run compile`)
- [x] Extension packaged successfully (`npm run package`)
- [x] Version updated in package.json (currently: `1.0.0`)
- [x] Icon added (`images/icon.png` - 128x128px)
- [x] README.md updated with features
- [x] CHANGELOG.md updated
- [x] LICENSE file present (MIT)
- [x] All 18 commands registered and functional
- [x] 14 snippets registered
- [x] VS Code walkthrough configured

## Publishing Steps

### Step 1: Create a Publisher Account

1. Go to [Visual Studio Marketplace Publisher Management](https://marketplace.visualstudio.com/manage)
2. Sign in with your Microsoft account (or create one)
3. Create a publisher:
   - **Publisher ID**: `agent-os` (must match `package.json`)
   - **Display Name**: `Agent OS Team`
   - **Description**: Safety-first kernel for AI coding assistants
4. Verify your email address

### Step 2: Create a Personal Access Token (PAT)

1. Go to [Azure DevOps](https://dev.azure.com/)
2. Sign in (create account if needed - can use same Microsoft account)
3. Create organization if you don't have one
4. Click your profile icon → **Personal access tokens**
5. Click **+ New Token**
6. Configure:
   - **Name**: `vscode-marketplace-publish`
   - **Organization**: `All accessible organizations`
   - **Expiration**: Set to 1 year (maximum)
   - **Scopes**: Click "Custom defined" → **Marketplace** → Check **Manage**
7. Click **Create** and **copy the token immediately** (won't be shown again)

### Step 3: Login with VSCE

```powershell
# If not installed globally
npm install -g @vscode/vsce

# Login (will prompt for PAT)
vsce login agent-os
# Paste your Personal Access Token when prompted
```

### Step 4: Publish the Extension

```powershell
cd <your-path>

# Publish directly (recommended)
vsce publish

# OR publish a specific VSIX file
vsce publish --packagePath agent-os-vscode-1.0.0.vsix
```

### Step 5: Verify Publication

1. Wait 5-10 minutes for processing
2. Visit: https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode
3. Verify all information appears correctly
4. Test install from marketplace

## Updating the Extension

### Version Bump Options

```powershell
# Auto-increment patch (1.0.0 → 1.0.1)
vsce publish patch

# Auto-increment minor (1.0.0 → 1.1.0)
vsce publish minor

# Auto-increment major (1.0.0 → 2.0.0)
vsce publish major

# Or manually update version in package.json, then:
vsce publish
```

### Pre-release Versions

```powershell
# Publish as pre-release (for beta testing)
vsce publish --pre-release
```

## Marketplace Badges

Add these to README.md after publishing:

```markdown
[![Version](https://img.shields.io/visual-studio-marketplace/v/agent-os.agent-os-vscode)](https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/agent-os.agent-os-vscode)](https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode)
[![Rating](https://img.shields.io/visual-studio-marketplace/r/agent-os.agent-os-vscode)](https://marketplace.visualstudio.com/items?itemName=agent-os.agent-os-vscode)
```

## Troubleshooting

### "Publisher 'agent-os' is not verified"

New publishers need to build reputation. Consider:
- Adding a verified GitHub repository link
- Building download/rating history
- Applying for verified publisher status after 1000+ installs

### "Personal Access Token expired"

Create a new PAT with same steps, then:
```powershell
vsce logout agent-os
vsce login agent-os
```

### "Icon not showing"

- Ensure `icon.png` is 128x128 pixels minimum
- Icon must be PNG format (not SVG in VSIX)
- Check `.vscodeignore` doesn't exclude `images/`

### "Extension not appearing in search"

- Wait up to 24 hours for indexing
- Ensure keywords in package.json are relevant
- Categories should be accurate

## CI/CD Integration (Optional)

Add to `.github/workflows/publish.yml`:

```yaml
name: Publish Extension
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
      - run: npm install
        working-directory: extensions/vscode
      - run: npm run package
        working-directory: extensions/vscode
      - name: Publish
        run: npx vsce publish -p ${{ secrets.VSCE_PAT }}
        working-directory: extensions/vscode
```

Set `VSCE_PAT` in repository secrets.

## Support & Resources

- [VSCE Documentation](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
- [Marketplace Publisher Portal](https://marketplace.visualstudio.com/manage)
- [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)
- [AgentOS GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)

---

**Extension Status**: Ready for GA Release  
**Version**: 1.0.0  
**Package Size**: ~960 KB

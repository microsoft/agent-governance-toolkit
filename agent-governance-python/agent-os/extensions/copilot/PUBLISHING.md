# Publishing AgentOS to GitHub Marketplace

This guide walks you through publishing the AgentOS Copilot Extension to the GitHub Marketplace.

## Prerequisites

Before publishing, ensure you have:
- [x] A working Copilot Extension (we have the code in `extensions/copilot/`)
- [ ] A GitHub App configured for the extension
- [ ] A deployed backend server (the extension needs to be running somewhere)
- [ ] Organization account (required for Marketplace listing)

---

## Step 1: Deploy the Backend Server

The Copilot Extension needs a publicly accessible backend. Options:

### Option A: Deploy to Azure (Recommended)
```bash
# From extensions/copilot directory
az webapp up --name agentos-copilot --runtime "NODE:18-lts" --sku B1
```

### Option B: Deploy to Vercel
```bash
npm i -g vercel
vercel --prod
```

### Option C: Deploy to Railway/Render/Fly.io
Follow their respective deployment guides for Node.js apps.

**After deployment, note your URL:** `https://agentos-copilot.azurewebsites.net` (example)

---

## Step 2: Create a GitHub App

1. Go to **GitHub** → **Settings** → **Developer settings** → **GitHub Apps**
2. Click **"New GitHub App"**

### Basic Information
| Field | Value |
|-------|-------|
| **GitHub App name** | `AgentOS` |
| **Description** | Build safe AI agents with natural language. 50+ templates, compliance frameworks, and 0% policy violations. |
| **Homepage URL** | `https://github.com/microsoft/agent-governance-toolkit/tree/main/docs` |

### Identifying and authorizing users
| Field | Value |
|-------|-------|
| **Callback URL** | `https://your-backend-url.com/auth/callback` |
| **Request user authorization during installation** | ✅ Checked |

### Post installation
| Field | Value |
|-------|-------|
| **Setup URL** | `https://your-backend-url.com/setup` (optional) |

### Webhook
| Field | Value |
|-------|-------|
| **Active** | ✅ Checked |
| **Webhook URL** | `https://your-backend-url.com/api/webhook` |
| **Webhook secret** | Generate a secure random string |

### Permissions

#### Repository permissions:
| Permission | Access |
|------------|--------|
| Contents | Read & write |
| Pull requests | Read & write |
| Workflows | Read & write |
| Actions | Read |
| Metadata | Read |

#### Account permissions:
| Permission | Access |
|------------|--------|
| Copilot Chat | Read-only |

### Copilot Extension Settings
| Field | Value |
|-------|-------|
| **App Type** | Agent |
| **URL** | `https://your-backend-url.com/api/copilot` |
| **Inference description** | AgentOS helps you build safe AI agents using natural language. Get templates, compliance validation, testing, and deployment to GitHub Actions. |

3. Click **"Create GitHub App"**
4. Note your **App ID** and generate a **Private Key**

---

## Step 3: Configure Environment Variables

Create `.env` in your deployed backend:

```env
# GitHub App Configuration
GITHUB_APP_ID=your_app_id
GITHUB_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
GITHUB_WEBHOOK_SECRET=your_webhook_secret
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret

# Server Configuration
PORT=3000
NODE_ENV=production

# Optional: Telemetry
APPLICATIONINSIGHTS_CONNECTION_STRING=your_connection_string
```

---

## Step 4: Create Marketplace Listing

1. Go to your GitHub App settings
2. In the left sidebar, click **"Marketplace listing"**
3. Click **"Create draft listing"**

### Listing Details

#### Product name and description
| Field | Value |
|-------|-------|
| **Listing name** | AgentOS |
| **Primary category** | Code quality |
| **Secondary category** | Security |
| **Short description** | Build safe AI agents with natural language, 50+ templates, and enterprise compliance |

#### Full description (Markdown):
```markdown
## 🤖 AgentOS - Safe AI Agents Made Simple

Build production-ready AI agents directly in GitHub Copilot Chat with natural language.

### Features

- **🗣️ Natural Language Creation** - Describe what you want, get working code
- **📚 50+ Templates** - Pre-built agents for DevOps, data processing, support, and more
- **🛡️ Compliance Built-in** - GDPR, HIPAA, SOC2, PCI-DSS policy validation
- **🧪 Testing & Simulation** - Sandbox testing before deployment
- **🚀 One-Click Deploy** - GitHub Actions workflows generated automatically
- **🔬 CMVK Review** - Multi-model verification for safety

### Quick Start

Type `@agentos help` in GitHub Copilot Chat to get started!

### Example Commands

- `@agentos create an agent that monitors my API endpoints`
- `@agentos templates devops`
- `@agentos compliance gdpr`
- `@agentos test this agent`
- `@agentos deploy`

### Enterprise Ready

- ✅ 0% policy violations
- ✅ Complete audit logging
- ✅ Role-based access control
- ✅ SOC2 Type II compliant infrastructure

### Documentation

Visit our [documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docstutorials/copilot-extension/) for tutorials and guides.
```

### Pricing and plans
| Plan | Price | Features |
|------|-------|----------|
| **Free** | $0/month | All features, unlimited agents |

(Start with free to get traction, can add paid tiers later)

### Links
| Field | Value |
|-------|-------|
| **Privacy policy URL** | `https://github.com/microsoft/agent-governance-toolkit/tree/main/docsprivacy/` |
| **Terms of service URL** | `https://github.com/microsoft/agent-governance-toolkit/tree/main/docsterms/` |
| **Support URL** | `https://github.com/microsoft/agent-governance-toolkit/issues` |
| **Documentation URL** | `https://github.com/microsoft/agent-governance-toolkit/tree/main/docstutorials/copilot-extension/` |

### Visual assets

#### Logo requirements:
- **Size**: 256x256 pixels minimum
- **Format**: PNG or JPG
- **Background**: Transparent or solid color

#### Feature card (for Marketplace browse):
- **Size**: 1200x628 pixels
- **Format**: PNG or JPG

#### Screenshots (3-5 required):
1. Agent creation with natural language
2. Template gallery
3. Compliance validation
4. Test results
5. Deployment to GitHub Actions

---

## Step 5: Make App Public

1. Go to GitHub App settings → **General**
2. Scroll to **"Make this GitHub App public"**
3. Click **"Make public"**

⚠️ **Warning**: Once public, anyone can install your app.

---

## Step 6: Submit for Review

1. Go to your Marketplace draft listing
2. Click **"Overview"** in the left sidebar
3. Review all sections are complete (green checkmarks)
4. Click **"Request publish"**

### What happens next:
- GitHub's onboarding team will review your listing
- They may request changes or additional information
- Review typically takes 1-2 weeks
- You'll be notified via email when approved/rejected

---

## Step 7: Post-Publication

After your app is approved:

### Monitor usage
```bash
# View installation metrics in GitHub App settings
# Insights → Installations
```

### Handle support
- Monitor GitHub Issues for bug reports
- Respond to user feedback quickly
- Keep documentation updated

### Iterate
- Release updates with semantic versioning
- Announce new features to users
- Gather feedback for improvements

---

## Required Files to Create

Before submitting, you need these additional files:

### 1. Privacy Policy (`privacy.html`)
```html
<!-- Create at: github.com/microsoft/agent-governance-toolkit/tree/main/docsprivacy/index.html -->
```

### 2. Terms of Service (`terms.html`)
```html
<!-- Create at: github.com/microsoft/agent-governance-toolkit/tree/main/docsterms/index.html -->
```

### 3. Logo and Screenshots
- Create 256x256 logo
- Create 1200x628 feature card
- Take 3-5 screenshots of the extension in action

---

## Checklist

```
[ ] Backend deployed and accessible
[ ] GitHub App created
[ ] Copilot Extension settings configured
[ ] Environment variables set
[ ] Privacy policy page created
[ ] Terms of service page created
[ ] Logo created (256x256)
[ ] Feature card created (1200x628)
[ ] 3-5 screenshots captured
[ ] Marketplace listing drafted
[ ] App made public
[ ] Listing submitted for review
```

---

## Troubleshooting

### "Copilot Extension settings not available"
- Ensure you've enabled Copilot Extensions in your GitHub settings
- Your organization may need to enable this feature

### "Webhook delivery failed"
- Check your backend is running and accessible
- Verify the webhook URL is correct
- Check the webhook secret matches

### "Installation fails"
- Verify all required permissions are set
- Check the callback URL is correct
- Review GitHub App logs for errors

---

## Resources

- [GitHub Copilot Extensions Documentation](https://docs.github.com/en/copilot/building-copilot-extensions)
- [GitHub Marketplace Requirements](https://docs.github.com/en/apps/github-marketplace/creating-apps-for-github-marketplace/requirements-for-listing-an-app)
- [GitHub App Webhooks](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/using-webhooks-with-github-apps)

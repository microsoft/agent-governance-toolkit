#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS Copilot Extension - Deployment Script
 * 
 * Usage:
 *   node deploy.js vercel     - Deploy to Vercel
 *   node deploy.js azure      - Deploy to Azure
 *   node deploy.js docker     - Build Docker image
 *   node deploy.js check      - Check deployment readiness
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

function log(color, message) {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

function exec(cmd, options = {}) {
    try {
        return execSync(cmd, { stdio: 'inherit', ...options });
    } catch (error) {
        if (!options.ignoreError) {
            throw error;
        }
    }
}

function checkFile(filePath, description) {
    const exists = fs.existsSync(filePath);
    if (exists) {
        log('green', `✅ ${description}`);
    } else {
        log('red', `❌ ${description} - Missing: ${filePath}`);
    }
    return exists;
}

function checkEnv(varName, required = true) {
    const exists = !!process.env[varName];
    if (exists) {
        log('green', `✅ ${varName} is set`);
    } else if (required) {
        log('red', `❌ ${varName} is not set (required)`);
    } else {
        log('yellow', `⚠️  ${varName} is not set (optional)`);
    }
    return exists;
}

async function checkDeploymentReadiness() {
    log('blue', '\n🔍 Checking deployment readiness...\n');
    
    let ready = true;

    // Check required files
    log('blue', '📁 Required Files:');
    ready &= checkFile('dist/index.js', 'Built JavaScript');
    ready &= checkFile('package.json', 'Package manifest');
    ready &= checkFile('.env.example', 'Environment template');
    
    // Check optional files
    log('blue', '\n📁 Deployment Configs:');
    checkFile('vercel.json', 'Vercel config');
    checkFile('Dockerfile', 'Docker config');
    checkFile('github-app-manifest.json', 'GitHub App manifest');
    
    // Check assets
    log('blue', '\n🎨 Visual Assets:');
    checkFile('assets/logo.svg', 'Logo (SVG)');
    checkFile('assets/feature-card.svg', 'Feature card (SVG)');
    
    // Check environment
    log('blue', '\n🔐 Environment Variables:');
    
    // Load .env if exists
    if (fs.existsSync('.env')) {
        require('dotenv').config();
    }
    
    const hasGitHubAppId = checkEnv('GITHUB_APP_ID');
    const hasGitHubClientId = checkEnv('GITHUB_CLIENT_ID');
    const hasGitHubClientSecret = checkEnv('GITHUB_CLIENT_SECRET');
    const hasWebhookSecret = checkEnv('GITHUB_WEBHOOK_SECRET');
    
    checkEnv('GITHUB_PRIVATE_KEY', false);
    checkEnv('SERVER_URL', false);
    
    if (!hasGitHubAppId || !hasGitHubClientId) {
        log('yellow', '\n⚠️  GitHub App not configured. Create one at:');
        log('yellow', '   https://github.com/settings/apps/new');
    }
    
    // Summary
    log('blue', '\n📊 Summary:');
    if (ready) {
        log('green', '✅ Basic deployment requirements met');
    } else {
        log('red', '❌ Missing required files - run `npm run build` first');
    }
    
    return ready;
}

async function deployVercel() {
    log('blue', '\n🚀 Deploying to Vercel...\n');
    
    // Check if vercel CLI is installed
    try {
        execSync('vercel --version', { stdio: 'pipe' });
    } catch {
        log('yellow', 'Installing Vercel CLI...');
        exec('npm install -g vercel');
    }
    
    // Deploy
    log('blue', 'Deploying (this will prompt for login if needed)...\n');
    exec('vercel --prod');
    
    log('green', '\n✅ Deployment complete!');
    log('blue', '\nNext steps:');
    log('blue', '1. Note your deployment URL');
    log('blue', '2. Update your GitHub App settings with the URL');
    log('blue', '3. Set environment variables in Vercel dashboard');
}

async function deployAzure() {
    log('blue', '\n🚀 Deploying to Azure...\n');
    
    // Check if Azure CLI is installed
    try {
        execSync('az --version', { stdio: 'pipe' });
    } catch {
        log('red', '❌ Azure CLI not installed');
        log('blue', 'Install from: https://docs.microsoft.com/cli/azure/install-azure-cli');
        process.exit(1);
    }
    
    const appName = process.env.AZURE_APP_NAME || 'agentos-copilot';
    
    log('blue', `Deploying to Azure App Service: ${appName}\n`);
    exec(`az webapp up --name ${appName} --runtime "NODE:20-lts" --sku B1`);
    
    log('green', '\n✅ Deployment complete!');
    log('blue', `\nYour app URL: https://${appName}.azurewebsites.net`);
}

async function buildDocker() {
    log('blue', '\n🐳 Building Docker image...\n');
    
    const imageName = 'agentos-copilot';
    const tag = process.env.DOCKER_TAG || 'latest';
    
    exec(`docker build -t ${imageName}:${tag} .`);
    
    log('green', '\n✅ Docker image built!');
    log('blue', `\nImage: ${imageName}:${tag}`);
    log('blue', '\nTo run locally:');
    log('blue', `  docker run -p 3000:3000 --env-file .env ${imageName}:${tag}`);
    log('blue', '\nTo push to registry:');
    log('blue', `  docker tag ${imageName}:${tag} your-registry/${imageName}:${tag}`);
    log('blue', `  docker push your-registry/${imageName}:${tag}`);
}

async function main() {
    const command = process.argv[2] || 'check';
    
    log('blue', '═══════════════════════════════════════════════');
    log('blue', '  AgentOS Copilot Extension - Deployment Tool');
    log('blue', '═══════════════════════════════════════════════');
    
    switch (command) {
        case 'check':
            await checkDeploymentReadiness();
            break;
        case 'vercel':
            await checkDeploymentReadiness();
            await deployVercel();
            break;
        case 'azure':
            await checkDeploymentReadiness();
            await deployAzure();
            break;
        case 'docker':
            await checkDeploymentReadiness();
            await buildDocker();
            break;
        default:
            log('yellow', `Unknown command: ${command}`);
            log('blue', '\nUsage:');
            log('blue', '  node deploy.js check   - Check deployment readiness');
            log('blue', '  node deploy.js vercel  - Deploy to Vercel');
            log('blue', '  node deploy.js azure   - Deploy to Azure');
            log('blue', '  node deploy.js docker  - Build Docker image');
    }
}

main().catch(error => {
    log('red', `\n❌ Error: ${error.message}`);
    process.exit(1);
});

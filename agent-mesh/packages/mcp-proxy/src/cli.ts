#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * AgentMesh MCP Proxy CLI
 * 
 * Wrap any MCP server with security controls.
 * 
 * Usage:
 *   agentmesh protect [options] <mcp-command> [args...]
 *   agentmesh audit <logfile>
 *   agentmesh policy validate <file>
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { MCPProxy } from './proxy.js';
import { loadPolicy, BUILTIN_POLICIES } from './policy.js';
import { AuditLogger } from './audit.js';
import { readFileSync } from 'fs';

const pkg = { version: '1.0.0' };

const program = new Command();

program
  .name('agentmesh')
  .description('🛡️ Security proxy for MCP servers - The Firewall for AI Agents')
  .version(pkg.version);

// ==================== PROTECT COMMAND ====================

program
  .command('protect')
  .description('Wrap an MCP server with security controls')
  .argument('<mcp-command>', 'MCP server command to wrap')
  .argument('[args...]', 'Arguments to pass to the MCP server')
  .option('-p, --policy <name|file>', 'Policy to apply', 'standard')
  .option('-m, --mode <mode>', 'enforce | shadow', 'enforce')
  .option('-l, --log <path>', 'Audit log file path')
  .option('--log-format <format>', 'json | cloudevents', 'cloudevents')
  .option('--rate-limit <spec>', 'Global rate limit (e.g., 100/minute)')
  .option('--no-sanitize', 'Disable input sanitization')
  .option('-v, --verbose', 'Verbose logging')
  .action(async (mcpCommand: string, args: string[], options) => {
    console.error(chalk.blue('🛡️ AgentMesh MCP Proxy'));
    console.error(chalk.dim(`   Protecting: ${mcpCommand} ${args.join(' ')}`));
    console.error(chalk.dim(`   Policy: ${options.policy} (${options.mode} mode)`));
    console.error();

    try {
      // Load policy
      const policy = await loadPolicy(options.policy);
      
      // Create audit logger
      const auditLogger = new AuditLogger({
        path: options.log,
        format: options.logFormat,
      });

      // Parse rate limit
      let rateLimit = undefined;
      if (options.rateLimit) {
        const [requests, per] = options.rateLimit.split('/');
        rateLimit = { requests: parseInt(requests), per };
      }

      // Create and start proxy
      const proxy = new MCPProxy({
        command: mcpCommand,
        args: args,
        policy: policy,
        mode: options.mode as 'enforce' | 'shadow',
        auditLogger: auditLogger,
        rateLimit: rateLimit,
        sanitize: options.sanitize !== false,
        verbose: options.verbose,
      });

      await proxy.start();
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ==================== AUDIT COMMAND ====================

program
  .command('audit')
  .description('Analyze audit logs')
  .argument('<logfile>', 'Path to audit log file')
  .option('--violations-only', 'Show only policy violations')
  .option('--format <fmt>', 'Output format: table | json | csv', 'table')
  .option('--since <time>', 'Filter by time (e.g., 1h, 24h, 7d)')
  .action(async (logfile: string, options) => {
    try {
      const content = readFileSync(logfile, 'utf-8');
      const lines = content.trim().split('\n');
      const events = lines.map(line => JSON.parse(line));

      let filtered = events;

      // Filter violations only
      if (options.violationsOnly) {
        filtered = filtered.filter((e: any) => 
          e.type?.includes('violation') || e.data?.decision === 'deny'
        );
      }

      // Time filter
      if (options.since) {
        const since = parseTimespec(options.since);
        filtered = filtered.filter((e: any) => 
          new Date(e.time).getTime() > since
        );
      }

      // Output
      if (options.format === 'json') {
        console.log(JSON.stringify(filtered, null, 2));
      } else if (options.format === 'csv') {
        console.log('time,type,tool,decision,reason');
        for (const e of filtered) {
          console.log(`${e.time},${e.type},${e.data?.tool || ''},${e.data?.decision || ''},${e.data?.reason || ''}`);
        }
      } else {
        // Table format
        console.log(chalk.bold('Audit Log Analysis'));
        console.log(chalk.dim(`File: ${logfile}`));
        console.log(chalk.dim(`Events: ${filtered.length}`));
        console.log();

        for (const e of filtered.slice(-20)) {
          const decision = e.data?.decision;
          const icon = decision === 'deny' ? '🚫' : decision === 'allow' ? '✅' : '📝';
          const color = decision === 'deny' ? chalk.red : decision === 'allow' ? chalk.green : chalk.dim;
          console.log(`${icon} ${color(e.time)} ${e.data?.tool || e.type}`);
          if (e.data?.reason) {
            console.log(chalk.dim(`   └─ ${e.data.reason}`));
          }
        }
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ==================== POLICY COMMAND ====================

const policyCmd = program
  .command('policy')
  .description('Manage policies');

policyCmd
  .command('list')
  .description('List built-in policies')
  .action(() => {
    console.log(chalk.bold('Built-in Policies'));
    console.log();
    for (const [name, desc] of Object.entries(BUILTIN_POLICIES)) {
      console.log(`  ${chalk.cyan(name.padEnd(15))} ${desc}`);
    }
  });

policyCmd
  .command('validate')
  .description('Validate a policy file')
  .argument('<file>', 'Policy file to validate')
  .action(async (file: string) => {
    try {
      const policy = await loadPolicy(file);
      console.log(chalk.green('✅ Policy is valid'));
      console.log(chalk.dim(`   Rules: ${policy.rules.length}`));
      console.log(chalk.dim(`   Mode: ${policy.mode}`));
    } catch (error) {
      console.error(chalk.red('❌ Policy validation failed:'), (error as Error).message);
      process.exit(1);
    }
  });

policyCmd
  .command('generate')
  .description('Generate policy from audit log')
  .argument('<logfile>', 'Audit log to analyze')
  .option('--strictness <level>', 'low | medium | high', 'medium')
  .action(async (logfile: string, options) => {
    try {
      const content = readFileSync(logfile, 'utf-8');
      const lines = content.trim().split('\n');
      const events = lines.map(line => JSON.parse(line));

      // Extract unique tools
      const tools = new Set<string>();
      for (const e of events) {
        if (e.data?.tool) {
          tools.add(e.data.tool);
        }
      }

      // Generate policy
      console.log('# Auto-generated policy from audit log');
      console.log(`# Generated: ${new Date().toISOString()}`);
      console.log(`# Strictness: ${options.strictness}`);
      console.log();
      console.log('version: "1.0"');
      console.log(`mode: ${options.strictness === 'high' ? 'enforce' : 'shadow'}`);
      console.log();
      console.log('rules:');

      for (const tool of tools) {
        console.log(`  - tool: "${tool}"`);
        console.log(`    action: allow`);
        console.log();
      }

      if (options.strictness === 'high') {
        console.log('  # Deny all other tools');
        console.log('  - tool: "*"');
        console.log('    action: deny');
        console.log('    reason: "Tool not in allowlist"');
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ==================== HELPERS ====================

function parseTimespec(spec: string): number {
  const match = spec.match(/^(\d+)([hmd])$/);
  if (!match) {
    throw new Error(`Invalid time spec: ${spec}. Use format like 1h, 24h, 7d`);
  }
  const [, num, unit] = match;
  const multipliers: Record<string, number> = {
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
    m: 60 * 1000,
  };
  return Date.now() - parseInt(num) * multipliers[unit];
}

// ==================== MAIN ====================

program.parse();

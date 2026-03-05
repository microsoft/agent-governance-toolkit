// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#!/usr/bin/env node
/**
 * AgentOS MCP Server - CLI Entry Point
 */

import { AgentOSMCPServer, ServerConfig } from './server.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  const config: ServerConfig = {
    policyMode: (process.env.AGENTOS_POLICY_MODE as 'strict' | 'permissive') || 'strict',
    apiKey: process.env.AGENTOS_API_KEY,
    dataDir: process.env.AGENTOS_DATA_DIR || '.agentos',
    logLevel: (process.env.AGENTOS_LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || 'info',
  };
  
  const server = new AgentOSMCPServer(config);
  
  if (args.includes('--stdio') || args.length === 0) {
    // Default: stdio mode for Claude Desktop
    await server.runStdio();
  } else if (args.includes('--http')) {
    const portIndex = args.indexOf('--port');
    const port = portIndex !== -1 ? parseInt(args[portIndex + 1], 10) : 8080;
    await server.runHttp(port);
  } else if (args.includes('--help') || args.includes('-h')) {
    printHelp();
  } else if (args.includes('--version') || args.includes('-v')) {
    console.log('AgentOS MCP Server v1.0.0');
  } else {
    console.error('Unknown command. Use --help for usage.');
    process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
AgentOS MCP Server - AI Agent Safety Framework for Claude Desktop

USAGE:
  agentos-mcp [OPTIONS]

OPTIONS:
  --stdio         Run in stdio mode (default, for Claude Desktop)
  --http          Run in HTTP mode (for development)
  --port <PORT>   HTTP port (default: 8080)
  --help, -h      Show this help message
  --version, -v   Show version

ENVIRONMENT VARIABLES:
  AGENTOS_API_KEY       API key for cloud features (optional)
  AGENTOS_POLICY_MODE   Policy mode: 'strict' (default) or 'permissive'
  AGENTOS_DATA_DIR      Data directory (default: .agentos)
  AGENTOS_LOG_LEVEL     Log level: debug, info (default), warn, error

CLAUDE DESKTOP CONFIGURATION:
  Add to claude_desktop_config.json:
  
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

EXAMPLES:
  # Run for Claude Desktop (stdio mode)
  agentos-mcp
  
  # Run HTTP server for development
  agentos-mcp --http --port 3000

For more information: https://github.com/microsoft/agent-governance-toolkit
`);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

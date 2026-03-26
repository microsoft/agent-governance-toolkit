# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CLI for MCP Kernel Server.

Usage:
    # For Claude Desktop (stdio transport)
    mcp-kernel-server --stdio

    # For development (HTTP transport)
    mcp-kernel-server --http --port 8080

Claude Desktop Integration:
    Add to ~/Library/Application Support/Claude/claude_desktop_config.json:

    {
      "mcpServers": {
        "agent-os": {
          "command": "mcp-kernel-server",
          "args": ["--stdio"]
        }
      }
    }
"""

import argparse
import asyncio
import logging
import sys

from mcp_kernel_server.server import KernelMCPServer, ServerConfig

# Configure logging to stderr (stdout is for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="MCP Kernel Server - Agent OS primitives via Model Context Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # For Claude Desktop integration
    mcp-kernel-server --stdio

    # For development/testing
    mcp-kernel-server --http --port 8080

    # With custom policy mode
    mcp-kernel-server --stdio --policy-mode permissive

Claude Desktop Setup:
    Add to claude_desktop_config.json:
    {
      "mcpServers": {
        "agent-os": {
          "command": "mcp-kernel-server",
          "args": ["--stdio"]
        }
      }
    }
""",
    )
    parser.add_argument(
        "--stdio", action="store_true", help="Use stdio transport (for Claude Desktop)"
    )
    parser.add_argument("--http", action="store_true", help="Use HTTP transport (for development)")
    parser.add_argument(
        "--port", "-p", type=int, default=8080, help="Port for HTTP transport (default: 8080)"
    )
    parser.add_argument(
        "--host",
        "-H",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--policy-mode",
        choices=["strict", "permissive", "audit"],
        default="strict",
        help="Policy enforcement mode (default: strict)",
    )
    parser.add_argument(
        "--cmvk-threshold",
        type=float,
        default=0.85,
        help="CMVK verification threshold (default: 0.85)",
    )
    parser.add_argument("--version", "-v", action="store_true", help="Show version and exit")
    parser.add_argument("--list-tools", action="store_true", help="List available tools and exit")
    parser.add_argument(
        "--list-prompts", action="store_true", help="List available prompts and exit"
    )

    return parser.parse_args()


def print_tools():
    """Print available tools."""
    print("Available MCP Tools:")
    print()
    print("  cmvk_verify")
    print("    Verify claims across multiple AI models to detect hallucinations")
    print("    Arguments: claim (required), context, models, threshold")
    print()
    print("  kernel_execute")
    print("    Execute actions through the Agent OS kernel with policy enforcement")
    print("    Arguments: action (required), params, agent_id (required), policies, context")
    print()
    print("  iatp_sign")
    print("    Create a trust attestation for inter-agent communication")
    print("    Arguments: attester_id (required), subject_id (required), trust_level, claims")
    print()
    print("  iatp_verify")
    print("    Verify trust relationship before agent-to-agent communication")
    print(
        "    Arguments: source_agent (required), target_agent (required), action, data_classification"
    )
    print()
    print("  iatp_reputation")
    print("    Query or modify agent reputation across the trust network")
    print("    Arguments: agent_id (required), action (required), reason")


def print_prompts():
    """Print available prompts."""
    print("Available MCP Prompts:")
    print()
    print("  governed_agent")
    print("    Instructions for operating as a governed agent under Agent OS")
    print("    Arguments: agent_id (required), policies")
    print()
    print("  verify_claim")
    print("    Instructions for verifying a claim using CMVK")
    print("    Arguments: claim (required)")
    print()
    print("  safe_execution")
    print("    Template for executing actions safely through the kernel")
    print("    Arguments: action (required), params (required)")


def main():
    """Main entry point."""
    args = parse_args()

    if args.version:
        from mcp_kernel_server import __version__

        print(f"mcp-kernel-server {__version__}")
        print("Agent OS MCP Server for kernel-level AI agent governance")
        return 0

    if args.list_tools:
        print_tools()
        return 0

    if args.list_prompts:
        print_prompts()
        return 0

    # Default to stdio if neither specified
    if not args.stdio and not args.http:
        args.stdio = True

    # Build config
    config = ServerConfig(
        host=args.host,
        port=args.port,
        policy_mode=args.policy_mode,
        cmvk_threshold=args.cmvk_threshold,
    )

    # Create server
    server = KernelMCPServer(config)

    # Run
    if args.stdio:
        logger.info("Starting MCP Kernel Server with stdio transport")
        logger.info(f"Policy mode: {args.policy_mode}")
        logger.info("Tools: cmvk_verify, kernel_execute, iatp_sign, iatp_verify, iatp_reputation")
        logger.info("Prompts: governed_agent, verify_claim, safe_execution")

        try:
            asyncio.run(server.run_stdio())
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception:
            logger.exception("Server error")
            return 1
    else:
        # HTTP transport
        logger.info(f"Starting MCP Kernel Server on http://{args.host}:{args.port}")
        logger.info(f"Policy mode: {args.policy_mode}")
        logger.info("Tools: cmvk_verify, kernel_execute, iatp_sign, iatp_verify, iatp_reputation")
        logger.info("Prompts: governed_agent, verify_claim, safe_execution")
        logger.info("Press Ctrl+C to stop")

        try:
            asyncio.run(server.start())
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

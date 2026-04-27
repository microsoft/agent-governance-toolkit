# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Fuzz target for the MCP security scanner."""

import sys
import atheris


def test_one_input(data: bytes) -> None:
    """Fuzz the MCP security scanner with arbitrary tool definitions."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        from agent_os.mcp_security import MCPSecurityScanner

        scanner = MCPSecurityScanner()

        # Fuzz tool description scanning
        tool_def = {
            "name": text[:50] if len(text) > 50 else text,
            "description": text,
            "inputSchema": {"type": "object", "properties": {}},
        }
        scanner.scan_tool(tool_def)
    except (ValueError, TypeError, KeyError, AttributeError):
        pass
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

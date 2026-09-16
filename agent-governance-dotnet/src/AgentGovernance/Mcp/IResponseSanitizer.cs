// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Mcp;

/// <summary>
/// Scans and sanitizes MCP tool output before it reaches an LLM. Implemented by
/// <see cref="McpResponseSanitizer"/> and resolved from DI so consumers can replace or extend
/// response sanitization with their own implementation.
/// </summary>
public interface IResponseSanitizer
{
    /// <summary>Scans text for threats and returns a sanitized version.</summary>
    McpSanitizedResponse ScanText(string text);
}

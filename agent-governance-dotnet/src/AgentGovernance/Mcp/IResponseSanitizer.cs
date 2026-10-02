// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Mcp;

/// <summary>
/// Scans and sanitizes MCP tool output before it reaches an LLM. Implemented by
/// <see cref="McpResponseSanitizer"/> and resolved from DI so consumers can replace or extend
/// response sanitization with their own implementation. A replacement implementation takes over
/// all of the default redaction (prompt-injection, credential, and exfiltration checks), so
/// implementers should wrap or call <see cref="McpResponseSanitizer"/> unless they deliberately
/// intend to drop those checks.
/// </summary>
public interface IResponseSanitizer
{
    /// <summary>Scans text for threats and returns a sanitized version.</summary>
    McpSanitizedResponse ScanText(string text);
}

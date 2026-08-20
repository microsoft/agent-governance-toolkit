// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { isIP } from "node:net";

import {
  evaluateDirectResourceAccess,
  loadPolicy as loadBasePolicy,
} from "./policy.mjs";

export * from "./policy.mjs";

const DEFAULT_ALLOWLIST_EFFECT = "allow";
const COMMAND_ARGUMENT_KEYS = ["command", "bash", "powershell", "script", "cmd"];
const COMMAND_TOOL_NAME_PATTERN =
  /(?:^|[._:/-])(?:bash|shell|sh|zsh|fish|powershell|pwsh|cmd|terminal|exec|execute|command)(?:$|[._:/-])/i;

/**
 * Load the existing OpenCode policy and attach positive command/URL allowlists.
 *
 * The base policy remains the source for deny/review rules. This layer only
 * adds a deny result when an explicitly enabled positive allowlist does not
 * match. PolicyEngine resolves backend decisions with deny precedence, so an
 * existing deny rule can never be overridden by an allowlist match.
 */
export async function loadPolicy(options = {}) {
  const state = await loadBasePolicy(options);

  try {
    const positiveAllowlists = compilePositiveAllowlistPolicy(state.policy.raw);
    state.policy.positiveAllowlists = positiveAllowlists;
    state.policyEngine.registerBackend(
      createPositiveAllowlistBackend(positiveAllowlists, state.policy),
    );
  } catch (error) {
    const policyError = error instanceof Error ? error : new Error(String(error));
    state.policy.positiveAllowlists = emptyPositiveAllowlistPolicy();

    // Preserve the package's existing policy-error contract. In enforce mode,
    // the normal evaluator path will fail closed before executing a tool. In
    // advisory mode the invalid extension is ignored and surfaced as a policy
    // warning instead of silently becoming an active allowlist.
    if (state.source === "bundled-default") {
      state.bundledDefaultError ??= policyError;
    } else {
      state.configuredPolicyError ??= policyError;
    }
  }

  return state;
}

function compilePositiveAllowlistPolicy(raw) {
  const commandPatterns = compileRegexPatterns(
    raw?.toolPolicies?.allowedCommandPatterns,
    "toolPolicies.allowedCommandPatterns",
  );
  const urlPatterns = compileRegexPatterns(
    raw?.directResourcePolicies?.allowedUrlPatterns,
    "directResourcePolicies.allowedUrlPatterns",
  );

  return {
    commands: {
      defaultEffect: compileDefaultEffect(
        raw?.toolPolicies?.commandDefaultEffect,
        "toolPolicies.commandDefaultEffect",
      ),
      patterns: commandPatterns,
    },
    urls: {
      defaultEffect: compileDefaultEffect(
        raw?.directResourcePolicies?.urlDefaultEffect,
        "directResourcePolicies.urlDefaultEffect",
      ),
      domains: compileAllowedDomains(raw?.directResourcePolicies?.allowedDomains),
      patterns: urlPatterns,
    },
  };
}

function emptyPositiveAllowlistPolicy() {
  return {
    commands: { defaultEffect: DEFAULT_ALLOWLIST_EFFECT, patterns: [] },
    urls: { defaultEffect: DEFAULT_ALLOWLIST_EFFECT, domains: [], patterns: [] },
  };
}

function compileDefaultEffect(value, label) {
  if (value === undefined || value === null || value === "") {
    return DEFAULT_ALLOWLIST_EFFECT;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized !== "allow" && normalized !== "deny") {
    throw new Error(`${label} must be either "allow" or "deny".`);
  }
  return normalized;
}

function compileRegexPatterns(value, label) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array of regex pattern objects.`);
  }

  return value.map((pattern, index) => {
    if (!pattern || typeof pattern !== "object") {
      throw new Error(`${label}[${index}] must be a regex pattern object.`);
    }
    if (typeof pattern.source !== "string" || !pattern.source.trim()) {
      throw new Error(`${label}[${index}] is missing a non-empty regex source.`);
    }

    const flags = pattern.flags === undefined ? "" : pattern.flags;
    if (typeof flags !== "string") {
      throw new Error(`${label}[${index}].flags must be a string.`);
    }
    // Stateful and line/dot mode regexes can make security-sensitive matching
    // history-dependent or allow an anchored pattern to match only one line of
    // a multi-command string.
    if (/[gyms]/.test(flags)) {
      throw new Error(`${label}[${index}] must not use g/y/m/s regex flags.`);
    }

    let regex;
    try {
      regex = new RegExp(pattern.source, flags);
    } catch (error) {
      throw new Error(
        `${label}[${index}] contains an invalid regular expression: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    return {
      flags,
      regex,
      source: pattern.source,
    };
  });
}

function compileAllowedDomains(value) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error("directResourcePolicies.allowedDomains must be an array of domain strings.");
  }

  return value.map((entry, index) => compileAllowedDomain(entry, index));
}

function compileAllowedDomain(entry, index) {
  if (typeof entry !== "string" || !entry.trim()) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] must be a non-empty domain string.`,
    );
  }

  const source = entry.trim().toLowerCase();
  if (source.includes("://") || /[\s/@?#\\]/.test(source)) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] must contain only a host and optional port.`,
    );
  }

  const wildcard = source.startsWith("*.");
  const hostPort = wildcard ? source.slice(2) : source;
  if (!hostPort || hostPort.includes("*")) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] has an invalid wildcard domain.`,
    );
  }

  const port = extractExplicitPort(hostPort, index);
  let parsed;
  try {
    parsed = new URL(`https://${hostPort}`);
  } catch (error) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] is not a valid host/port: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    throw new Error(`directResourcePolicies.allowedDomains[${index}] has no hostname.`);
  }
  if (wildcard && isIP(stripIpv6Brackets(hostname))) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] cannot apply a wildcard to an IP address.`,
    );
  }

  return {
    hostname,
    port,
    source,
    wildcard,
  };
}

function extractExplicitPort(hostPort, index) {
  if (hostPort.startsWith("[")) {
    const match = /^\[[^\]]+\](?::(\d+))?$/.exec(hostPort);
    if (!match) {
      throw new Error(
        `directResourcePolicies.allowedDomains[${index}] has an invalid IPv6 host/port.`,
      );
    }
    return normalizePort(match[1], index);
  }

  const firstColon = hostPort.indexOf(":");
  const lastColon = hostPort.lastIndexOf(":");
  if (firstColon !== lastColon) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] must bracket IPv6 addresses.`,
    );
  }
  if (lastColon < 0) {
    return "";
  }

  const portText = hostPort.slice(lastColon + 1);
  if (!/^\d+$/.test(portText)) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] has a non-numeric port.`,
    );
  }
  return normalizePort(portText, index);
}

function normalizePort(portText, index) {
  if (portText === undefined) {
    return "";
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `directResourcePolicies.allowedDomains[${index}] has a port outside 1-65535.`,
    );
  }
  return String(port);
}

function stripIpv6Brackets(hostname) {
  return hostname.replace(/^\[/, "").replace(/\]$/, "");
}

function createPositiveAllowlistBackend(positivePolicy, basePolicy) {
  return {
    name: "agt-positive-allowlists",
    evaluateAction(action, context) {
      if (!String(action).startsWith("tool.")) {
        return "allow";
      }

      const commandDecision = evaluateCommandAllowlist(positivePolicy.commands, context);
      if (commandDecision) {
        return commandDecision;
      }

      const urlDecision = evaluateUrlAllowlist(positivePolicy.urls, basePolicy, context);
      if (urlDecision) {
        return urlDecision;
      }

      return "allow";
    },
  };
}

function evaluateCommandAllowlist(commandPolicy, context) {
  if (commandPolicy.defaultEffect !== "deny") {
    return null;
  }

  const toolName = String(context.toolName ?? "unknown");
  const commandResult = collectAllowlistedCommands(context);
  if (commandResult.invalid) {
    return {
      backend: "agt-positive-allowlists",
      decision: "deny",
      reason: `Command allowlist denied malformed command arguments for tool '${toolName}'.`,
    };
  }
  if (commandResult.commands.length === 0) {
    return null;
  }

  for (const command of commandResult.commands) {
    if (commandPolicy.patterns.some((pattern) => pattern.regex.test(command))) {
      continue;
    }
    return {
      backend: "agt-positive-allowlists",
      decision: "deny",
      reason: `Command allowlist denied an unapproved command for tool '${toolName}'.`,
    };
  }

  return null;
}

function collectAllowlistedCommands(context) {
  const args = context.rawToolArgs;
  const commands = [];
  let sawCommandKey = false;

  if (args && typeof args === "object" && !Array.isArray(args)) {
    for (const key of COMMAND_ARGUMENT_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(args, key)) {
        continue;
      }
      sawCommandKey = true;
      const value = args[key];
      if (typeof value !== "string" || !value.trim()) {
        return { commands: [], invalid: true };
      }
      commands.push(normalizeCommandText(value));
    }
  }

  if (sawCommandKey) {
    return { commands, invalid: false };
  }

  const toolName = String(context.toolName ?? "").trim();
  if (!COMMAND_TOOL_NAME_PATTERN.test(toolName)) {
    return { commands: [], invalid: false };
  }

  const fallbackCommand = normalizeCommandText(context.commandText);
  return {
    commands: fallbackCommand ? [fallbackCommand] : [],
    invalid: false,
  };
}

function normalizeCommandText(value) {
  return String(value ?? "").replace(/\r\n?/g, "\n").trim();
}

function evaluateUrlAllowlist(urlPolicy, basePolicy, context) {
  const enforcePositiveAllowlist = urlPolicy.defaultEffect === "deny";
  const candidates = collectHttpUrlCandidates(context.rawToolArgs);
  let reviewDecision;

  for (const candidate of candidates) {
    if (!candidate.valid) {
      const denyAmbiguousAuthority = candidate.invalidReason === "ambiguous-authority-backslash";
      if (!enforcePositiveAllowlist && !denyAmbiguousAuthority) {
        continue;
      }
      return {
        backend: "agt-positive-allowlists",
        decision: "deny",
        reason: denyAmbiguousAuthority
          ? "URL governance denied an ambiguous HTTP(S) authority containing a backslash."
          : "URL allowlist denied a malformed HTTP(S) URL in tool arguments.",
      };
    }

    const existingDecision = evaluateDirectResourceAccess(basePolicy, {
      cwd: context.cwd,
      rawToolArgs: { url: candidate.normalizedUrl },
      toolName: context.toolName,
    });
    if (existingDecision?.effect === "deny") {
      return {
        backend: "agt-positive-allowlists",
        decision: "deny",
        reason: existingDecision.reason,
      };
    }
    if (existingDecision?.effect === "review") {
      reviewDecision ??= {
        backend: "agt-positive-allowlists",
        decision: "review",
        reason: existingDecision.reason,
      };
    }

    if (!enforcePositiveAllowlist || isAllowedUrlCandidate(candidate, urlPolicy)) {
      continue;
    }

    return {
      backend: "agt-positive-allowlists",
      decision: "deny",
      reason: `URL allowlist denied unapproved origin ${candidate.origin}.`,
    };
  }

  return reviewDecision ?? null;
}

function collectHttpUrlCandidates(value) {
  const candidates = [];
  const stack = [value];
  const seenObjects = new WeakSet();
  const seenUrls = new Set();

  while (stack.length) {
    const current = stack.pop();
    if (typeof current === "string") {
      const raw = current.trim();
      if (!/^https?:/i.test(raw)) {
        continue;
      }

      let candidate;
      if (hasAmbiguousHttpAuthorityBackslash(raw)) {
        candidate = {
          invalidReason: "ambiguous-authority-backslash",
          raw,
          valid: false,
        };
      } else {
        try {
          const url = new URL(raw);
          if (url.protocol !== "http:" && url.protocol !== "https:") {
            continue;
          }
          candidate = {
            normalizedUrl: url.toString(),
            origin: url.origin,
            url,
            valid: true,
          };
        } catch {
          candidate = { raw, valid: false };
        }
      }

      const key = candidate.valid ? candidate.normalizedUrl : `invalid:${raw}`;
      if (!seenUrls.has(key)) {
        seenUrls.add(key);
        candidates.push(candidate);
      }
      continue;
    }

    if (!current || typeof current !== "object") {
      continue;
    }
    if (seenObjects.has(current)) {
      continue;
    }
    seenObjects.add(current);

    if (Array.isArray(current)) {
      stack.push(...current);
    } else {
      stack.push(...Object.values(current));
    }
  }

  return candidates;
}

function hasAmbiguousHttpAuthorityBackslash(raw) {
  const scheme = /^https?:/i.exec(raw)?.[0];
  if (!scheme) {
    return false;
  }

  let remainder = raw.slice(scheme.length);
  if (remainder.startsWith("//")) {
    remainder = remainder.slice(2);
  }

  const boundaryIndexes = [remainder.indexOf("/"), remainder.indexOf("?"), remainder.indexOf("#")]
    .filter((index) => index >= 0);
  const authorityEnd = boundaryIndexes.length ? Math.min(...boundaryIndexes) : remainder.length;
  return remainder.slice(0, authorityEnd).includes("\\");
}

function isAllowedUrlCandidate(candidate, urlPolicy) {
  if (urlPolicy.patterns.some((pattern) => pattern.regex.test(candidate.normalizedUrl))) {
    return true;
  }
  return urlPolicy.domains.some((domain) => domainMatches(domain, candidate.url));
}

function domainMatches(domain, url) {
  const hostname = url.hostname.toLowerCase();
  const hostMatches = domain.wildcard
    ? hostname !== domain.hostname && hostname.endsWith(`.${domain.hostname}`)
    : hostname === domain.hostname;
  if (!hostMatches) {
    return false;
  }

  if (!domain.port) {
    return true;
  }
  return effectiveUrlPort(url) === domain.port;
}

function effectiveUrlPort(url) {
  if (url.port) {
    return url.port;
  }
  return url.protocol === "https:" ? "443" : "80";
}

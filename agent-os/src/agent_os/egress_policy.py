# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Network egress policy enforcement for MCP gateway.

Provides domain-level egress control so that agent tool calls can only
reach pre-approved external endpoints.  Wildcard domains are supported
(e.g. ``*.openai.com`` matches ``api.openai.com``).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class EgressRule:
    """A single egress control rule."""

    domain: str
    ports: list[int] = field(default_factory=lambda: [443])
    protocol: str = "tcp"
    action: str = "allow"

    def __post_init__(self) -> None:
        if self.action not in ("allow", "deny"):
            raise ValueError(f"action must be 'allow' or 'deny', got {self.action!r}")
        if self.protocol not in ("tcp", "udp"):
            raise ValueError(f"protocol must be 'tcp' or 'udp', got {self.protocol!r}")

    def matches(self, hostname: str, port: int, protocol: str) -> bool:
        """Return *True* if this rule matches the given endpoint."""
        if protocol != self.protocol:
            return False
        if port not in self.ports:
            return False
        return fnmatch.fnmatch(hostname.lower(), self.domain.lower())


@dataclass
class EgressDecision:
    """Result of an egress policy check."""

    allowed: bool
    matched_rule: Optional[EgressRule]
    reason: str


class EgressPolicy:
    """Network egress enforcement for agent tool calls.

    Rules are evaluated in insertion order; the first match wins.
    If no rule matches, ``default_action`` is applied.
    """

    def __init__(self, default_action: str = "deny") -> None:
        if default_action not in ("allow", "deny"):
            raise ValueError(
                f"default_action must be 'allow' or 'deny', got {default_action!r}"
            )
        self.rules: list[EgressRule] = []
        self.default_action = default_action

    def add_rule(
        self,
        domain: str,
        ports: list[int],
        protocol: str = "tcp",
        action: str = "allow",
    ) -> EgressRule:
        """Create and append an :class:`EgressRule`."""
        rule = EgressRule(
            domain=domain, ports=ports, protocol=protocol, action=action
        )
        self.rules.append(rule)
        return rule

    def load_from_yaml(self, yaml_str: str) -> None:
        """Parse a simple YAML-like egress policy and add rules.

        Supported format (stdlib-only, no PyYAML dependency)::

            rules:
              - domain: "*.openai.com"
                ports: [443]
                protocol: tcp
                action: allow
        """
        current: dict[str, str] = {}
        for raw_line in yaml_str.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line == "rules:" or line == "rules":
                continue
            if line.startswith("- domain:"):
                if current:
                    self._add_from_dict(current)
                    current = {}
                current["domain"] = self._unquote(line.split(":", 1)[1])
            elif line.startswith("domain:"):
                current["domain"] = self._unquote(line.split(":", 1)[1])
            elif line.startswith("ports:"):
                current["ports"] = line.split(":", 1)[1].strip()
            elif line.startswith("protocol:"):
                current["protocol"] = self._unquote(line.split(":", 1)[1])
            elif line.startswith("action:"):
                current["action"] = self._unquote(line.split(":", 1)[1])
        if current:
            self._add_from_dict(current)

    def check(
        self, hostname: str, port: int, protocol: str = "tcp"
    ) -> EgressDecision:
        """Check whether an outbound connection is permitted."""
        for rule in self.rules:
            if rule.matches(hostname, port, protocol):
                allowed = rule.action == "allow"
                return EgressDecision(
                    allowed=allowed,
                    matched_rule=rule,
                    reason=f"matched rule for {rule.domain} -> {rule.action}",
                )
        allowed = self.default_action == "allow"
        return EgressDecision(
            allowed=allowed,
            matched_rule=None,
            reason=f"no matching rule; default action is {self.default_action}",
        )

    def check_url(self, url: str) -> EgressDecision:
        """Convenience wrapper that extracts host/port from a URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return self.check(hostname, port)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unquote(value: str) -> str:
        return value.strip().strip("\"'")

    @staticmethod
    def _parse_ports(raw: str) -> list[int]:
        raw = raw.strip().strip("[]")
        return [int(p.strip()) for p in raw.split(",") if p.strip()]

    def _add_from_dict(self, d: dict[str, str]) -> None:
        domain = d.get("domain", "")
        ports = self._parse_ports(d.get("ports", "[443]"))
        protocol = d.get("protocol", "tcp")
        action = d.get("action", "allow")
        self.add_rule(domain, ports, protocol, action)

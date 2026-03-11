"""GovernancePolicyChecker component for Haystack pipelines.

Loads policies from YAML and enforces tool allowlists/blocklists,
content pattern filters, token limits, and rate limits.
"""

from __future__ import annotations

import fnmatch
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import yaml

try:
    from haystack import component
except ImportError:  # pragma: no cover
    # Lightweight shim so the class works without haystack-ai installed
    class _ComponentShim:
        def __call__(self, cls):
            return cls

        @staticmethod
        def input_types(**kwargs):
            def decorator(func):
                return func
            return decorator

        @staticmethod
        def output_types(**kwargs):
            def decorator(func):
                return func
            return decorator

    component = _ComponentShim()  # type: ignore[assignment]


@component
class GovernancePolicyChecker:
    """Checks agent actions against a governance policy loaded from YAML.

    Supports tool allowlist/blocklist, content pattern matching (substring,
    regex, glob), token limits, and per-agent rate limits.
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        policy_dict: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._policy: Dict[str, Any] = {}
        self._compiled_patterns: List[Tuple[str, str, "re.Pattern[str]"]] = []
        self._rate_tracker: Dict[str, List[float]] = {}

        if policy_path is not None:
            self.load_policy_file(policy_path)
        elif policy_dict is not None:
            self.load_policy(policy_dict)

    # ── Policy loading ────────────────────────────────────────────

    def load_policy_file(self, path: str) -> None:
        """Load a governance policy from a YAML file."""
        with open(path, "r") as fh:
            self.load_policy(yaml.safe_load(fh))

    def load_policy(self, data: Dict[str, Any]) -> None:
        """Load a governance policy from a dictionary."""
        self._policy = data
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._compiled_patterns = []
        for entry in self._policy.get("blocked_patterns", []):
            pattern = entry["pattern"]
            ptype = entry.get("type", "substring")
            if ptype == "regex":
                compiled = re.compile(pattern, re.IGNORECASE)
            elif ptype == "glob":
                compiled = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
            else:
                compiled = re.compile(re.escape(pattern), re.IGNORECASE)
            self._compiled_patterns.append((pattern, ptype, compiled))

    # ── Component interface ───────────────────────────────────────

    @component.input_types(
        action=str,
        params=Dict[str, Any],
        agent_id=Optional[str],
    )
    @component.output_types(decision=str, reason=str, passed=bool)
    def run(
        self,
        action: str,
        params: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate an action against the loaded governance policy.

        Returns a dict with ``decision`` ("allow" | "deny" | "audit"),
        ``reason``, and ``passed`` (bool).
        """
        if params is None:
            params = {}

        # 1. Tool allowlist / blocklist
        result = self._check_tool(action)
        if result is not None:
            return result

        # 2. Content pattern check
        result = self._check_content(action, params)
        if result is not None:
            return result

        # 3. Token limit
        result = self._check_token_limit(params)
        if result is not None:
            return result

        # 4. Rate limit
        result = self._check_rate_limit(agent_id)
        if result is not None:
            return result

        return {"decision": "allow", "reason": "All policy checks passed", "passed": True}

    # ── Individual checks ─────────────────────────────────────────

    def _check_tool(self, action: str) -> Optional[Dict[str, Any]]:
        blocklist: List[str] = self._policy.get("blocked_tools", [])
        if action in blocklist:
            return {
                "decision": "deny",
                "reason": f"Tool '{action}' is blocked by policy",
                "passed": False,
            }

        allowlist: List[str] = self._policy.get("allowed_tools", [])
        if allowlist and action not in allowlist:
            return {
                "decision": "deny",
                "reason": f"Tool '{action}' not in allowed list",
                "passed": False,
            }
        return None

    def _check_content(self, action: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        text = f"{action} {' '.join(str(v) for v in params.values())}"
        for pattern, ptype, compiled in self._compiled_patterns:
            if compiled.search(text):
                return {
                    "decision": "deny",
                    "reason": f"Blocked pattern matched: '{pattern}' ({ptype})",
                    "passed": False,
                }
        return None

    def _check_token_limit(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        max_tokens = self._policy.get("max_tokens", 0)
        if max_tokens <= 0:
            return None
        requested = params.get("tokens", 0)
        if requested > max_tokens:
            return {
                "decision": "deny",
                "reason": f"Token limit exceeded: {requested} > {max_tokens}",
                "passed": False,
            }
        return None

    def _check_rate_limit(self, agent_id: Optional[str]) -> Optional[Dict[str, Any]]:
        rate_limit = self._policy.get("rate_limit")
        if not rate_limit or not agent_id:
            return None

        max_calls = rate_limit.get("max_calls", 0)
        window_seconds = rate_limit.get("window_seconds", 60)
        if max_calls <= 0:
            return None

        now = time.time()
        calls = self._rate_tracker.setdefault(agent_id, [])
        # Prune expired entries
        calls[:] = [t for t in calls if now - t < window_seconds]
        if len(calls) >= max_calls:
            return {
                "decision": "audit",
                "reason": f"Rate limit: {len(calls)}/{max_calls} calls in {window_seconds}s window",
                "passed": False,
            }
        calls.append(now)
        return None

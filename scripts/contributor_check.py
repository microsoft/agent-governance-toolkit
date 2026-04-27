#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contributor reputation checker for OSS maintainers.

Evaluates a GitHub contributor's profile for signals of coordinated
inauthentic behavior (claw patterns): account-shape anomalies,
cross-repo spray, credential laundering, and network coordination.

Usage:
    python scripts/contributor_check.py --username <handle>
    python scripts/contributor_check.py --username <handle> --repo microsoft/agent-governance-toolkit
    python scripts/contributor_check.py --username <handle> --json

Requires: GITHUB_TOKEN environment variable (or gh CLI auth).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

_TOKEN: str | None = None


def _get_token() -> str:
    """Resolve a GitHub token from env or gh CLI."""
    global _TOKEN
    if _TOKEN:
        return _TOKEN

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not token:
        print("Error: set GITHUB_TOKEN or authenticate with `gh auth login`", file=sys.stderr)
        sys.exit(1)

    _TOKEN = token
    return token


def _api(path: str, params: dict[str, str] | None = None) -> Any:
    """Call the GitHub REST API and return parsed JSON."""
    url = f"https://api.github.com{path}"
    if params:
        qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
        url = f"{url}?{qs}"

    req = Request(url)
    req.add_header("Authorization", f"Bearer {_get_token()}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")

    for attempt in range(3):
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except HTTPError as exc:
            if exc.code == 403 and attempt < 2:
                wait = int(exc.headers.get("Retry-After", "10"))
                wait = min(max(wait, 5), 60)
                print(f"  Rate limited, waiting {wait}s...", file=sys.stderr)
                import time; time.sleep(wait)
                continue
            if exc.code == 404:
                return None
            raise


def _search_issues(query: str, per_page: int = 30) -> list[dict]:
    """Search GitHub issues/PRs."""
    data = _api("/search/issues", {"q": query, "per_page": str(per_page)})
    return data.get("items", []) if data else []


# ---------------------------------------------------------------------------
# Signal checkers
# ---------------------------------------------------------------------------

@dataclass
class Signal:
    """A single reputation signal."""
    name: str
    severity: str  # LOW, MEDIUM, HIGH
    detail: str
    value: Any = None


@dataclass
class ReputationReport:
    """Full reputation report for a contributor."""
    username: str
    risk: str = "LOW"
    signals: list[Signal] = field(default_factory=list)
    profile: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    @property
    def high_count(self) -> int:
        return sum(1 for s in self.signals if s.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for s in self.signals if s.severity == "MEDIUM")

    def compute_risk(self) -> str:
        if self.high_count >= 2:
            self.risk = "HIGH"
        elif self.high_count >= 1 or self.medium_count >= 3:
            self.risk = "MEDIUM"
        else:
            self.risk = "LOW"
        return self.risk


def check_account_shape(user: dict) -> list[Signal]:
    """Check account age, repo velocity, follower ratios."""
    signals: list[Signal] = []

    created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - created).days

    public_repos = user.get("public_repos", 0)
    followers = user.get("followers", 0)
    following = user.get("following", 0)

    # Repo velocity
    if age_days > 0:
        repos_per_day = public_repos / age_days
        if repos_per_day > 0.5 and public_repos > 15:
            signals.append(Signal(
                name="repo_velocity",
                severity="HIGH",
                detail=f"{public_repos} repos in {age_days} days ({repos_per_day:.2f}/day)",
                value=repos_per_day,
            ))
        elif repos_per_day > 0.2 and public_repos > 10:
            signals.append(Signal(
                name="repo_velocity",
                severity="MEDIUM",
                detail=f"{public_repos} repos in {age_days} days ({repos_per_day:.2f}/day)",
                value=repos_per_day,
            ))

    # Following farming
    if following > 100 and followers > 0:
        ratio = following / followers
        if ratio > 20:
            signals.append(Signal(
                name="following_farming",
                severity="HIGH",
                detail=f"{followers} followers / {following} following (ratio 1:{ratio:.0f})",
                value=ratio,
            ))
        elif ratio > 5:
            signals.append(Signal(
                name="following_farming",
                severity="MEDIUM",
                detail=f"{followers} followers / {following} following (ratio 1:{ratio:.0f})",
                value=ratio,
            ))

    # Very new account with high activity
    if age_days < 90 and public_repos > 20:
        signals.append(Signal(
            name="new_account_burst",
            severity="HIGH",
            detail=f"Account is {age_days} days old with {public_repos} repos",
        ))
    elif age_days < 180 and public_repos > 30:
        signals.append(Signal(
            name="new_account_burst",
            severity="MEDIUM",
            detail=f"Account is {age_days} days old with {public_repos} repos",
        ))

    # Zero followers with many repos
    if followers == 0 and public_repos > 5:
        signals.append(Signal(
            name="zero_followers",
            severity="MEDIUM",
            detail=f"0 followers despite {public_repos} public repos",
        ))

    return signals


def check_repo_themes(username: str) -> list[Signal]:
    """Check if repos are overwhelmingly governance/security themed."""
    signals: list[Signal] = []
    repos = _api(f"/users/{username}/repos", {"per_page": "100", "sort": "created"})
    if not repos:
        return signals

    governance_keywords = {
        "governance", "policy", "trust", "attestation", "identity",
        "passport", "delegation", "audit", "compliance", "zero-trust",
        "agent-governance", "mcp-secure", "agent-guard", "veil",
    }

    governance_count = 0
    recent_repos = []
    now = datetime.now(timezone.utc)

    for repo in repos:
        name_lower = repo.get("name", "").lower()
        desc_lower = (repo.get("description") or "").lower()
        topics = repo.get("topics", [])

        is_gov = False
        for kw in governance_keywords:
            if kw in name_lower or kw in desc_lower or kw in topics:
                is_gov = True
                break
        if is_gov:
            governance_count += 1

        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        if (now - created).days < 90:
            recent_repos.append(repo["name"])

    total = len(repos)
    if total > 5 and governance_count / total > 0.5:
        signals.append(Signal(
            name="governance_theme_concentration",
            severity="MEDIUM",
            detail=f"{governance_count}/{total} repos are governance/security themed",
            value=governance_count,
        ))

    if len(recent_repos) > 15:
        signals.append(Signal(
            name="recent_repo_burst",
            severity="HIGH",
            detail=f"{len(recent_repos)} repos created in last 90 days",
            value=len(recent_repos),
        ))

    return signals


def check_spray_pattern(username: str) -> list[Signal]:
    """Check if user filed similar issues across many repos."""
    signals: list[Signal] = []

    issues = _search_issues(f"author:{username} is:issue", per_page=100)
    if not issues:
        return signals

    # Group by repo
    repos_hit: dict[str, list[dict]] = {}
    for issue in issues:
        repo_url = issue.get("repository_url", "")
        repo_name = repo_url.replace("https://api.github.com/repos/", "")
        repos_hit.setdefault(repo_name, []).append(issue)

    # Check for spray: many repos with similar issue titles
    unique_repos = len(repos_hit)
    if unique_repos >= 5:
        # Check if issues were filed in a short window
        dates = []
        for issue in issues:
            created = datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
            dates.append(created)

        if dates:
            dates.sort()
            # Check if 5+ repos were hit within 7 days
            window_repos = set()
            for i, d in enumerate(dates):
                window_repos_local = {
                    issues[j].get("repository_url", "").replace("https://api.github.com/repos/", "")
                    for j, d2 in enumerate(dates)
                    if abs((d2 - d).days) <= 7
                }
                window_repos = max(window_repos, window_repos_local, key=len)

            if len(window_repos) >= 5:
                signals.append(Signal(
                    name="cross_repo_spray",
                    severity="HIGH",
                    detail=f"Issues filed in {len(window_repos)} repos within 7 days",
                    value=len(window_repos),
                ))
            elif unique_repos >= 8:
                signals.append(Signal(
                    name="cross_repo_spread",
                    severity="MEDIUM",
                    detail=f"Issues filed across {unique_repos} different repos",
                    value=unique_repos,
                ))

    return signals


def check_credential_spray(username: str, target_repo: str | None = None) -> list[Signal]:
    """Check if user cites merges from one repo in issues across other repos."""
    signals: list[Signal] = []

    issues = _search_issues(f"author:{username} is:issue", per_page=50)
    if not issues:
        return signals

    # Look for PR/merge references in issue bodies
    credential_citations = 0
    repos_with_citations = set()

    for issue in issues:
        body = (issue.get("body") or "").lower()
        repo_url = issue.get("repository_url", "")
        repo_name = repo_url.replace("https://api.github.com/repos/", "")

        # Skip issues in the target repo itself
        if target_repo and repo_name == target_repo:
            continue

        # Look for credential patterns
        credential_patterns = [
            "pr #", "pull/", "merged", "contributor",
            "already in production", "integration with",
        ]
        has_credential = any(pat in body for pat in credential_patterns)

        if has_credential and target_repo and target_repo.lower() in body:
            credential_citations += 1
            repos_with_citations.add(repo_name)

    if credential_citations >= 3:
        signals.append(Signal(
            name="credential_laundering",
            severity="HIGH",
            detail=f"Cites {target_repo} merges in issues across {len(repos_with_citations)} repos",
            value=credential_citations,
        ))
    elif credential_citations >= 1:
        signals.append(Signal(
            name="credential_citation",
            severity="MEDIUM",
            detail=f"Cites {target_repo} in issues across {len(repos_with_citations)} other repos",
            value=credential_citations,
        ))

    return signals


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def check_contributor(username: str, target_repo: str | None = None) -> ReputationReport:
    """Run all checks and produce a reputation report."""
    report = ReputationReport(username=username)

    # Fetch user profile
    user = _api(f"/users/{username}")
    if not user:
        report.risk = "UNKNOWN"
        report.signals.append(Signal(
            name="user_not_found",
            severity="HIGH",
            detail=f"GitHub user '{username}' does not exist",
        ))
        return report

    report.profile = {
        "name": user.get("name"),
        "bio": user.get("bio"),
        "company": user.get("company"),
        "created_at": user.get("created_at"),
        "public_repos": user.get("public_repos"),
        "followers": user.get("followers"),
        "following": user.get("following"),
    }

    created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - created).days
    report.stats = {
        "account_age_days": age_days,
        "repos_per_day": round(user.get("public_repos", 0) / max(age_days, 1), 3),
    }

    # Run checks
    for signal in check_account_shape(user):
        report.add(signal)

    for signal in check_repo_themes(username):
        report.add(signal)

    for signal in check_spray_pattern(username):
        report.add(signal)

    if target_repo:
        for signal in check_credential_spray(username, target_repo):
            report.add(signal)

    report.compute_risk()
    return report


def format_report(report: ReputationReport, as_json: bool = False) -> str:
    """Format a reputation report for display."""
    if as_json:
        return json.dumps({
            "username": report.username,
            "risk": report.risk,
            "profile": report.profile,
            "stats": report.stats,
            "signals": [
                {"name": s.name, "severity": s.severity, "detail": s.detail}
                for s in report.signals
            ],
        }, indent=2)

    risk_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "UNKNOWN": "⚪"}.get(report.risk, "⚪")
    lines = [
        f"Contributor Check: {report.username}",
        f"{'=' * 50}",
        f"Risk: {risk_icon} {report.risk}",
        "",
    ]

    if report.profile:
        p = report.profile
        lines.append("Profile:")
        if p.get("name"):
            lines.append(f"  Name:         {p['name']}")
        if p.get("bio"):
            lines.append(f"  Bio:          {p['bio'][:80]}")
        if p.get("company"):
            lines.append(f"  Company:      {p['company']}")
        lines.append(f"  Created:      {p.get('created_at', 'unknown')}")
        lines.append(f"  Public repos: {p.get('public_repos', 0)}")
        lines.append(f"  Followers:    {p.get('followers', 0)}")
        lines.append(f"  Following:    {p.get('following', 0)}")
        lines.append("")

    if report.stats:
        lines.append("Stats:")
        lines.append(f"  Account age:    {report.stats.get('account_age_days', 0)} days")
        lines.append(f"  Repos/day:      {report.stats.get('repos_per_day', 0)}")
        lines.append("")

    if report.signals:
        lines.append("Signals:")
        for s in report.signals:
            icon = {"LOW": "  ", "MEDIUM": "⚠️", "HIGH": "🚩"}.get(s.severity, "  ")
            lines.append(f"  {icon} [{s.severity}] {s.name}: {s.detail}")
        lines.append("")
    else:
        lines.append("No signals detected.")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a GitHub contributor's reputation for claw indicators.",
    )
    parser.add_argument("--username", "-u", required=True, help="GitHub username to check")
    parser.add_argument("--repo", "-r", default=None, help="Target repo (owner/repo) for credential audit")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    report = check_contributor(args.username, args.repo)
    print(format_report(report, as_json=args.as_json))

    # Exit code reflects risk
    if report.risk == "HIGH":
        return 2
    elif report.risk == "MEDIUM":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

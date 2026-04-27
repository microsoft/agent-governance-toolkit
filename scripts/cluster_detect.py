#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cluster detection: map coordination networks from a seed account.

Builds a graph of GitHub accounts connected by shared forks, thread
co-participation, and synchronized issue filing patterns.

Usage:
    python scripts/cluster_detect.py --seed <handle>
    python scripts/cluster_detect.py --seed <handle> --depth 2 --json

Requires: GITHUB_TOKEN environment variable (or gh CLI auth).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
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
    global _TOKEN
    if _TOKEN:
        return _TOKEN
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True, text=True, timeout=10,
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
            if exc.code in (404, 422):
                return None
            raise


def _search(endpoint: str, query: str, per_page: int = 30) -> list[dict]:
    data = _api(f"/search/{endpoint}", {"q": query, "per_page": str(per_page)})
    return data.get("items", []) if data else []


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Edge:
    """A connection between two accounts."""
    source: str
    target: str
    edge_type: str  # shared_fork, co_comment, sync_filing, same_repo_issue
    detail: str
    weight: float = 1.0


@dataclass
class AccountInfo:
    """Basic info about an account in the cluster."""
    username: str
    created_at: str = ""
    public_repos: int = 0
    followers: int = 0
    following: int = 0


@dataclass
class ClusterReport:
    """Full cluster detection report."""
    seed: str
    depth: int
    accounts: dict[str, AccountInfo] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    shared_forks: dict[str, list[str]] = field(default_factory=dict)

    @property
    def account_count(self) -> int:
        return len(self.accounts)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def risk_level(self) -> str:
        if self.account_count >= 5 and self.edge_count >= 8:
            return "HIGH"
        elif self.account_count >= 3 and self.edge_count >= 4:
            return "MEDIUM"
        elif self.account_count >= 2:
            return "LOW"
        return "NONE"


# ---------------------------------------------------------------------------
# Detection passes
# ---------------------------------------------------------------------------

def _get_user_info(username: str) -> AccountInfo | None:
    """Fetch basic user info."""
    user = _api(f"/users/{username}")
    if not user:
        return None
    return AccountInfo(
        username=username,
        created_at=user.get("created_at", ""),
        public_repos=user.get("public_repos", 0),
        followers=user.get("followers", 0),
        following=user.get("following", 0),
    )


def detect_shared_forks(seed: str, known_accounts: set[str]) -> tuple[list[Edge], dict[str, list[str]]]:
    """Find repos that the seed forked, then check if other accounts forked the same repos."""
    edges: list[Edge] = []
    shared_forks: dict[str, list[str]] = defaultdict(list)

    # Get seed's repos
    repos = _api(f"/users/{seed}/repos", {"per_page": "100", "type": "all"})
    if not repos:
        return edges, dict(shared_forks)

    forked_repos = []
    for repo in repos:
        if isinstance(repo, dict) and repo.get("fork"):
            parent = repo.get("parent", {})
            if parent:
                forked_repos.append(parent.get("full_name", ""))
            else:
                # Try to get parent via API
                detail = _api(f"/repos/{repo.get('full_name', '')}")
                if detail and detail.get("parent"):
                    forked_repos.append(detail["parent"]["full_name"])

    # Also check repos owned by seed (others may have forked them)
    owned_repos = [
        r for r in repos
        if isinstance(r, dict) and not r.get("fork") and r.get("stargazers_count", 0) < 10
    ]

    # For each owned low-star repo, check forks
    for repo in owned_repos[:10]:  # limit API calls
        repo_name = repo.get("full_name", "")
        if not repo_name:
            continue
        forks = _api(f"/repos/{repo_name}/forks", {"per_page": "30"})
        if not forks:
            continue
        forkers = [f["owner"]["login"] for f in forks if isinstance(f, dict)]
        if len(forkers) >= 1:
            shared_forks[repo_name] = forkers
            for forker in forkers:
                if forker != seed:
                    edges.append(Edge(
                        source=seed,
                        target=forker,
                        edge_type="shared_fork",
                        detail=f"Both connected via {repo_name}",
                        weight=2.0 if repo.get("stargazers_count", 0) < 5 else 1.0,
                    ))

    return edges, dict(shared_forks)


def detect_co_comments(seed: str, limit: int = 50) -> list[Edge]:
    """Find accounts that comment on the same issues as the seed."""
    edges: list[Edge] = []
    co_commenters: dict[str, int] = defaultdict(int)

    # Get issues authored by seed
    issues = _search("issues", f"author:{seed} is:issue", per_page=30)

    for issue in issues[:20]:  # limit API calls
        issue_url = issue.get("url", "")
        if not issue_url:
            continue

        # Fetch comments
        comments_url = issue.get("comments_url", "")
        if not comments_url:
            continue

        path = comments_url.replace("https://api.github.com", "")
        comments = _api(path, {"per_page": "50"})
        if not comments:
            continue

        for comment in comments:
            if not isinstance(comment, dict):
                continue
            commenter = comment.get("user", {}).get("login", "")
            if commenter and commenter != seed:
                co_commenters[commenter] += 1

    # Flag accounts that co-comment on 2+ threads
    for account, count in co_commenters.items():
        if count >= 2:
            edges.append(Edge(
                source=seed,
                target=account,
                edge_type="co_comment",
                detail=f"Co-commented on {count} of {seed}'s issues",
                weight=min(count, 5),
            ))

    return edges


def detect_sync_filing(seed: str) -> list[Edge]:
    """Find accounts that filed issues in the same repos within 48 hours of the seed."""
    edges: list[Edge] = []

    # Get seed's issues
    seed_issues = _search("issues", f"author:{seed} is:issue", per_page=50)
    if not seed_issues:
        return edges

    # Group by repo
    seed_repos: dict[str, list[dict]] = defaultdict(list)
    for issue in seed_issues:
        repo_url = issue.get("repository_url", "")
        repo = repo_url.replace("https://api.github.com/repos/", "")
        if repo:
            seed_repos[repo].append(issue)

    # For each repo, check for similar issues by other authors within 48h
    sync_accounts: dict[str, list[str]] = defaultdict(list)

    for repo, issues in list(seed_repos.items())[:10]:  # limit
        for issue in issues[:3]:  # limit
            created = issue.get("created_at", "")
            if not created:
                continue

            # Search for other governance-related issues in same repo around same time
            repo_issues = _search(
                "issues",
                f"repo:{repo} is:issue -author:{seed}",
                per_page=20,
            )

            seed_date = datetime.fromisoformat(created.replace("Z", "+00:00"))

            for other in repo_issues:
                other_date = datetime.fromisoformat(
                    other["created_at"].replace("Z", "+00:00")
                )
                delta_hours = abs((other_date - seed_date).total_seconds()) / 3600

                if delta_hours <= 48:
                    other_author = other.get("user", {}).get("login", "")
                    if other_author and other_author != seed:
                        sync_accounts[other_author].append(repo)

    # Flag accounts that appear in 2+ repos within the window
    for account, repos_list in sync_accounts.items():
        unique_repos = set(repos_list)
        if len(unique_repos) >= 2:
            edges.append(Edge(
                source=seed,
                target=account,
                edge_type="sync_filing",
                detail=f"Filed issues in {len(unique_repos)} same repos within 48h",
                weight=len(unique_repos),
            ))

    return edges


# ---------------------------------------------------------------------------
# Main detection
# ---------------------------------------------------------------------------

def detect_cluster(seed: str, depth: int = 1) -> ClusterReport:
    """Detect a coordination cluster starting from a seed account."""
    report = ClusterReport(seed=seed, depth=depth)

    # Get seed info
    seed_info = _get_user_info(seed)
    if not seed_info:
        return report
    report.accounts[seed] = seed_info

    visited = {seed}
    frontier = {seed}

    for current_depth in range(depth):
        next_frontier: set[str] = set()

        for account in frontier:
            # Pass 1: Shared forks
            fork_edges, shared = detect_shared_forks(account, visited)
            report.edges.extend(fork_edges)
            report.shared_forks.update(shared)

            # Pass 2: Co-comment analysis
            comment_edges = detect_co_comments(account)
            report.edges.extend(comment_edges)

            # Pass 3: Synchronized filing (only for seed, expensive)
            if current_depth == 0:
                sync_edges = detect_sync_filing(account)
                report.edges.extend(sync_edges)

            # Collect new accounts for next depth
            for edge in fork_edges + comment_edges:
                for target in (edge.source, edge.target):
                    if target not in visited:
                        next_frontier.add(target)
                        # Get info for new accounts
                        info = _get_user_info(target)
                        if info:
                            report.accounts[target] = info
                        visited.add(target)

        frontier = next_frontier
        if not frontier:
            break

    # Deduplicate edges
    seen_edges: set[tuple] = set()
    unique_edges = []
    for edge in report.edges:
        key = (
            min(edge.source, edge.target),
            max(edge.source, edge.target),
            edge.edge_type,
        )
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(edge)
    report.edges = unique_edges

    return report


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_report(report: ClusterReport, as_json: bool = False) -> str:
    if as_json:
        return json.dumps({
            "seed": report.seed,
            "depth": report.depth,
            "risk": report.risk_level(),
            "account_count": report.account_count,
            "edge_count": report.edge_count,
            "accounts": {
                name: {
                    "created_at": info.created_at,
                    "public_repos": info.public_repos,
                    "followers": info.followers,
                    "following": info.following,
                }
                for name, info in report.accounts.items()
            },
            "edges": [
                {"source": e.source, "target": e.target,
                 "type": e.edge_type, "detail": e.detail, "weight": e.weight}
                for e in report.edges
            ],
            "shared_forks": report.shared_forks,
        }, indent=2)

    risk = report.risk_level()
    risk_icon = {"NONE": "🟢", "LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴"}.get(risk, "⚪")

    lines = [
        f"Cluster Detection: seed={report.seed}, depth={report.depth}",
        f"{'=' * 60}",
        f"Risk: {risk_icon} {risk}",
        f"Accounts: {report.account_count}  |  Edges: {report.edge_count}",
        "",
    ]

    if report.accounts:
        lines.append("Accounts:")
        for name, info in sorted(report.accounts.items()):
            age = ""
            if info.created_at:
                created = datetime.fromisoformat(info.created_at.replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - created).days
                age = f"{days}d old"
            lines.append(
                f"  {name:.<30s} {info.public_repos:>3d} repos  "
                f"{info.followers:>4d} followers  {age}"
            )
        lines.append("")

    if report.edges:
        lines.append("Connections:")
        # Group by type
        by_type: dict[str, list[Edge]] = defaultdict(list)
        for edge in report.edges:
            by_type[edge.edge_type].append(edge)

        for edge_type, edges in sorted(by_type.items()):
            lines.append(f"  [{edge_type}]")
            for edge in edges:
                lines.append(f"    {edge.source} <-> {edge.target}")
                lines.append(f"      {edge.detail}")
            lines.append("")

    if report.shared_forks:
        lines.append("Shared Forks:")
        for repo, forkers in report.shared_forks.items():
            lines.append(f"  {repo}: {', '.join(forkers)}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect coordination clusters from a seed GitHub account.",
    )
    parser.add_argument("--seed", "-s", required=True, help="Seed GitHub username")
    parser.add_argument("--depth", "-d", type=int, default=1,
                        help="Search depth (1=direct connections, 2=friends-of-friends)")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    report = detect_cluster(args.seed, depth=args.depth)
    print(format_report(report, as_json=args.as_json))

    risk = report.risk_level()
    return {"NONE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(risk, 0)


if __name__ == "__main__":
    sys.exit(main())

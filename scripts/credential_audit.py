#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential audit: detect when merged PRs are used as spray credentials.

Checks whether a contributor cites merges from a target repo in issues
filed across other repos, a pattern called "credential laundering."

Usage:
    python scripts/credential_audit.py --username <handle> --repo org/repo
    python scripts/credential_audit.py --username <handle> --repo org/repo --json

Requires: GITHUB_TOKEN environment variable (or gh CLI auth).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# GitHub API helpers (shared pattern with contributor_check.py)
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


def _search(endpoint: str, query: str, per_page: int = 100) -> list[dict]:
    data = _api(f"/search/{endpoint}", {"q": query, "per_page": str(per_page)})
    return data.get("items", []) if data else []


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class MergeRecord:
    """A PR merged into the target repo by the subject user."""
    pr_number: int
    title: str
    merged_at: str
    additions: int
    url: str


@dataclass
class SprayCitation:
    """An issue in another repo that cites a merge from the target repo."""
    repo: str
    issue_number: int
    title: str
    created_at: str
    url: str
    citation_snippets: list[str] = field(default_factory=list)
    days_after_merge: int | None = None


@dataclass
class CredentialAuditReport:
    """Full credential audit report."""
    username: str
    target_repo: str
    risk: str = "LOW"
    merges: list[MergeRecord] = field(default_factory=list)
    citations: list[SprayCitation] = field(default_factory=list)
    spray_repos: set = field(default_factory=set)
    spray_window_hours: float | None = None

    def compute_risk(self) -> str:
        n_citations = len(self.citations)
        n_repos = len(self.spray_repos)

        if n_citations >= 3 and n_repos >= 3:
            self.risk = "HIGH"
        elif n_citations >= 2 or n_repos >= 2:
            self.risk = "MEDIUM"
        elif n_citations >= 1:
            self.risk = "LOW"
        else:
            self.risk = "NONE"
        return self.risk


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

# Patterns that indicate credential citation
_CREDENTIAL_PATTERNS = [
    r"(?:pr|pull)\s*#?\d+\s*(?:merged|accepted)",
    r"merged\s+(?:into|in)\s+",
    r"contributor\s+to\s+",
    r"already\s+in\s+production",
    r"integration\s+with\s+",
    r"(?:pr|pull request)\s+.*?merged",
]

_CREDENTIAL_RE = re.compile("|".join(_CREDENTIAL_PATTERNS), re.IGNORECASE)


def find_merges(username: str, target_repo: str) -> list[MergeRecord]:
    """Find PRs by username that were merged into target_repo."""
    owner, repo = target_repo.split("/")
    prs = _search("issues", f"author:{username} repo:{target_repo} is:pr is:merged", per_page=50)

    merges = []
    for pr in prs:
        pr_url = pr.get("html_url", "")
        pr_number = pr.get("number", 0)

        # Get merge details
        pr_detail = _api(f"/repos/{owner}/{repo}/pulls/{pr_number}")
        merged_at = ""
        additions = 0
        if pr_detail:
            merged_at = pr_detail.get("merged_at", "")
            additions = pr_detail.get("additions", 0)

        if merged_at:
            merges.append(MergeRecord(
                pr_number=pr_number,
                title=pr.get("title", ""),
                merged_at=merged_at,
                additions=additions,
                url=pr_url,
            ))

    merges.sort(key=lambda m: m.merged_at)
    return merges


def find_spray_citations(
    username: str,
    target_repo: str,
    merges: list[MergeRecord],
) -> list[SprayCitation]:
    """Find issues by username in OTHER repos that cite merges from target_repo."""
    issues = _search("issues", f"author:{username} is:issue", per_page=100)

    # Normalize target repo references to check for
    target_lower = target_repo.lower()
    owner, repo_name = target_repo.split("/")
    repo_name_lower = repo_name.lower()

    # Build PR number set for matching
    pr_numbers = {m.pr_number for m in merges}

    # Parse earliest merge date
    earliest_merge: datetime | None = None
    if merges:
        earliest_merge = datetime.fromisoformat(merges[0].merged_at.replace("Z", "+00:00"))

    citations: list[SprayCitation] = []

    for issue in issues:
        issue_repo_url = issue.get("repository_url", "")
        issue_repo = issue_repo_url.replace("https://api.github.com/repos/", "")

        # Skip issues in the target repo itself
        if issue_repo.lower() == target_lower:
            continue

        body = issue.get("body") or ""
        body_lower = body.lower()

        # Check for target repo mention
        if target_lower not in body_lower and repo_name_lower not in body_lower:
            continue

        # Check for credential-style citation
        snippets = []

        # Check for PR number references
        for pr_num in pr_numbers:
            patterns = [
                f"#{pr_num}",
                f"pull/{pr_num}",
                f"pr {pr_num}",
                f"pr #{pr_num}",
            ]
            for pat in patterns:
                if pat in body_lower:
                    # Extract surrounding context
                    idx = body_lower.index(pat)
                    start = max(0, idx - 40)
                    end = min(len(body), idx + len(pat) + 40)
                    snippets.append(body[start:end].strip())

        # Check for general credential patterns
        if _CREDENTIAL_RE.search(body) and (target_lower in body_lower):
            match = _CREDENTIAL_RE.search(body)
            if match:
                idx = match.start()
                start = max(0, idx - 20)
                end = min(len(body), match.end() + 40)
                snippets.append(body[start:end].strip())

        if snippets:
            # Calculate days after merge
            days_after = None
            if earliest_merge:
                issue_created = datetime.fromisoformat(
                    issue["created_at"].replace("Z", "+00:00")
                )
                days_after = (issue_created - earliest_merge).days

            citations.append(SprayCitation(
                repo=issue_repo,
                issue_number=issue.get("number", 0),
                title=issue.get("title", ""),
                created_at=issue.get("created_at", ""),
                url=issue.get("html_url", ""),
                citation_snippets=snippets[:3],  # cap at 3
                days_after_merge=days_after,
            ))

    citations.sort(key=lambda c: c.created_at)
    return citations


def audit_credentials(username: str, target_repo: str) -> CredentialAuditReport:
    """Run a full credential audit."""
    report = CredentialAuditReport(username=username, target_repo=target_repo)

    # Step 1: Find merges
    report.merges = find_merges(username, target_repo)
    if not report.merges:
        report.risk = "NONE"
        return report

    # Step 2: Find spray citations
    report.citations = find_spray_citations(username, target_repo, report.merges)
    report.spray_repos = {c.repo for c in report.citations}

    # Step 3: Calculate spray window
    if report.citations:
        dates = [
            datetime.fromisoformat(c.created_at.replace("Z", "+00:00"))
            for c in report.citations
        ]
        dates.sort()
        span = (dates[-1] - dates[0]).total_seconds() / 3600
        report.spray_window_hours = round(span, 1)

    report.compute_risk()
    return report


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_report(report: CredentialAuditReport, as_json: bool = False) -> str:
    if as_json:
        return json.dumps({
            "username": report.username,
            "target_repo": report.target_repo,
            "risk": report.risk,
            "merges": [
                {"pr": m.pr_number, "title": m.title, "merged_at": m.merged_at,
                 "additions": m.additions, "url": m.url}
                for m in report.merges
            ],
            "citations": [
                {"repo": c.repo, "issue": c.issue_number, "title": c.title,
                 "created_at": c.created_at, "url": c.url,
                 "snippets": c.citation_snippets,
                 "days_after_merge": c.days_after_merge}
                for c in report.citations
            ],
            "spray_repos_count": len(report.spray_repos),
            "spray_window_hours": report.spray_window_hours,
        }, indent=2)

    risk_icon = {"NONE": "🟢", "LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴"}.get(report.risk, "⚪")
    lines = [
        f"Credential Audit: {report.username} -> {report.target_repo}",
        f"{'=' * 60}",
        f"Risk: {risk_icon} {report.risk}",
        "",
    ]

    if report.merges:
        lines.append(f"Merged PRs ({len(report.merges)}):")
        for m in report.merges:
            lines.append(f"  PR #{m.pr_number}: {m.title}")
            lines.append(f"    Merged: {m.merged_at}  |  +{m.additions} lines")
        lines.append("")

    if report.citations:
        lines.append(f"Credential Citations ({len(report.citations)} across {len(report.spray_repos)} repos):")
        if report.spray_window_hours is not None:
            lines.append(f"  Spray window: {report.spray_window_hours} hours")
        lines.append("")
        for c in report.citations:
            days_str = f" ({c.days_after_merge}d after merge)" if c.days_after_merge is not None else ""
            lines.append(f"  {c.repo} #{c.issue_number}{days_str}")
            lines.append(f"    {c.title}")
            for snippet in c.citation_snippets[:2]:
                clean = snippet.replace("\n", " ")[:100]
                lines.append(f"    > {clean}")
            lines.append("")
    else:
        lines.append("No credential citations found in external issues.")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit whether a contributor uses merged PRs as spray credentials.",
    )
    parser.add_argument("--username", "-u", required=True, help="GitHub username to audit")
    parser.add_argument("--repo", "-r", required=True, help="Target repo (owner/repo)")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")

    args = parser.parse_args()
    report = audit_credentials(args.username, args.repo)
    print(format_report(report, as_json=args.as_json))

    return {"NONE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(report.risk, 0)


if __name__ == "__main__":
    sys.exit(main())

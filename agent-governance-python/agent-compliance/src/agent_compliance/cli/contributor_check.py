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
                import time
                time.sleep(wait)
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
    age_days = max((datetime.now(timezone.utc) - created).days, 0)

    # Future created_at (clock skew or tampered API response) is itself suspicious
    if age_days == 0 and created > datetime.now(timezone.utc):
        signals.append(Signal(
            name="future_account_timestamp",
            severity="HIGH",
            detail=f"Account created_at is in the future: {user['created_at']}",
        ))

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


def check_repo_themes(username: str, repos: list[dict] | None = None) -> list[Signal]:
    """Check if repos are overwhelmingly governance/security themed.

    Args:
        username: GitHub username.
        repos: Pre-fetched repos (avoids redundant API call).
    """
    signals: list[Signal] = []
    if repos is None:
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

    # Fork burst detection: many forks created in a short window
    fork_signals = _check_fork_burst(repos, username=username)
    signals.extend(fork_signals)

    # Batch naming detection: many repos with same suffix created together
    batch_signals = _check_batch_naming(repos)
    signals.extend(batch_signals)

    return signals


_fork_pr_cache: dict[str, bool] = {}


def _fork_has_outgoing_pr(username: str, fork_name: str) -> bool:
    """Check if a fork has at least one PR (open, merged, or closed) to its parent."""
    cache_key = f"{username}/{fork_name}"
    if cache_key in _fork_pr_cache:
        return _fork_pr_cache[cache_key]

    result = False
    try:
        prs = _api(f"/repos/{username}/{fork_name}/pulls", {
            "state": "all", "per_page": "1",
        })
        result = bool(prs)
    except Exception:
        pass
    _fork_pr_cache[cache_key] = result
    return result


def _check_fork_burst(repos: list[dict], *, username: str = "") -> list[Signal]:
    """Detect credibility-farming fork bursts (e.g., forking awesome lists).

    Forks that have at least one outgoing PR to their parent repo are
    excluded from the burst count, since those represent legitimate
    contributions rather than profile padding.
    """
    signals: list[Signal] = []
    now = datetime.now(timezone.utc)

    forks = []
    awesome_forks = []
    for repo in repos:
        if not repo.get("fork"):
            continue
        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        if (now - created).days > 90:
            continue
        forks.append({"name": repo["name"], "created": created})
        name_lower = repo.get("name", "").lower()
        if "awesome" in name_lower or "curated" in (repo.get("description") or "").lower():
            awesome_forks.append({"name": repo["name"], "created": created})

    if not forks:
        return signals

    # Exclude forks that have outgoing PRs (legitimate contributions)
    if username:
        awesome_forks = [
            f for f in awesome_forks
            if not _fork_has_outgoing_pr(username, f["name"])
        ]
        forks = [
            f for f in forks
            if not _fork_has_outgoing_pr(username, f["name"])
        ]

    forks.sort(key=lambda f: f["created"])
    max_window = 0
    for f in forks:
        window_count = sum(
            1 for f2 in forks
            if abs((f2["created"] - f["created"]).total_seconds()) <= 72 * 3600
        )
        max_window = max(max_window, window_count)

    awesome_window = 0
    if awesome_forks:
        awesome_forks.sort(key=lambda f: f["created"])
        for f in awesome_forks:
            count = sum(
                1 for f2 in awesome_forks
                if abs((f2["created"] - f["created"]).total_seconds()) <= 72 * 3600
            )
            awesome_window = max(awesome_window, count)

    if awesome_window >= 3:
        signals.append(Signal(
            name="awesome_fork_burst",
            severity="HIGH",
            detail=f"{awesome_window} awesome-list forks within 72 hours (credibility farming)",
            value=awesome_window,
        ))
    elif max_window >= 5:
        signals.append(Signal(
            name="fork_burst",
            severity="MEDIUM",
            detail=f"{max_window} forks within 72 hours",
            value=max_window,
        ))

    return signals


def _check_batch_naming(repos: list[dict]) -> list[Signal]:
    """Detect templated repo creation: many repos with same suffix in a short window."""
    signals: list[Signal] = []
    now = datetime.now(timezone.utc)

    # Only consider non-fork, recent, low-star repos
    recent: list[dict] = []
    for repo in repos:
        if repo.get("fork"):
            continue
        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        if (now - created).days > 90:
            continue
        stars = repo.get("stargazers_count", 0)
        if stars >= 10:
            continue
        recent.append({"name": repo["name"].lower(), "created": created})

    if len(recent) < 3:
        return signals

    # Extract common suffixes (last hyphenated segment, e.g., "-mcp", "-agent")
    suffix_groups: dict[str, list[dict]] = {}
    for r in recent:
        parts = r["name"].rsplit("-", 1)
        if len(parts) == 2 and len(parts[1]) >= 2:
            suffix_groups.setdefault(f"-{parts[1]}", []).append(r)

    for suffix, group in suffix_groups.items():
        if len(group) < 3:
            continue
        # Check if created within 48-hour windows
        group.sort(key=lambda g: g["created"])
        best_window = 0
        for g in group:
            count = sum(
                1 for g2 in group
                if abs((g2["created"] - g["created"]).total_seconds()) <= 48 * 3600
            )
            best_window = max(best_window, count)

        if best_window >= 5:
            signals.append(Signal(
                name="batch_repo_naming",
                severity="HIGH",
                detail=f"{best_window} repos with '{suffix}' suffix created within 48 hours",
                value=best_window,
            ))
        elif best_window >= 3:
            signals.append(Signal(
                name="batch_repo_naming",
                severity="MEDIUM",
                detail=f"{best_window} repos with '{suffix}' suffix created within 48 hours",
                value=best_window,
            ))

    return signals
_AGT_FEATURE_BUCKETS: dict[str, list[str]] = {
    "mcp_security": [
        "mcp scanner", "mcp security", "tool poisoning", "mcp gateway",
        "rug pull", "typosquat", "mcp tool scan",
    ],
    "policy_engine": [
        "policy engine", "policy evaluator", "policy enforcement",
        "cedar polic", "yaml polic", "deny-by-default",
    ],
    "identity_crypto": [
        "ed25519", "agent identity", "zero-trust identity",
        "cryptographic identity", "agent keypair", "agent did",
    ],
    "runtime_controls": [
        "execution sandbox", "kill switch", "circuit breaker",
        "permission level", "sandboxing", "emergency shutdown",
    ],
    "audit_trust": [
        "audit trail", "trust scor", "hash-chain", "tamper-proof log",
        "governance decision", "trust tier",
    ],
    "compliance": [
        "owasp agentic", "owasp agent", "compliance attestation",
        "eu ai act", "nist ai rmf",
    ],
}


def check_feature_overlap(username: str, target_repo: str | None = None) -> list[Signal]:
    """Detect repos that clone AGT's feature set using bucketed analysis."""
    signals: list[Signal] = []
    if not target_repo:
        return signals

    repos = _api(f"/users/{username}/repos", {"per_page": "100", "sort": "updated"})
    if not repos:
        return signals

    now = datetime.now(timezone.utc)

    for repo in repos:
        if repo.get("fork"):
            continue

        name = repo.get("name", "")
        desc = (repo.get("description") or "").lower()
        topics = " ".join(repo.get("topics", []))
        searchable = f"{name} {desc} {topics}".lower()

        # Quick scan: does this repo match at least 2 buckets?
        matched_buckets = set()
        for bucket, keywords in _AGT_FEATURE_BUCKETS.items():
            for kw in keywords:
                if kw in searchable:
                    matched_buckets.add(bucket)
                    break

        if len(matched_buckets) < 2:
            continue

        # Deep scan: fetch README for candidates
        readme_text = ""
        readme = _api(f"/repos/{username}/{name}/readme")
        if readme and readme.get("content"):
            try:
                import base64
                readme_text = base64.b64decode(readme["content"]).decode("utf-8", errors="replace").lower()
            except Exception:
                pass

        full_text = f"{searchable} {readme_text}"
        final_buckets = set()
        for bucket, keywords in _AGT_FEATURE_BUCKETS.items():
            for kw in keywords:
                if kw in full_text:
                    final_buckets.add(bucket)
                    break

        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        age_days = (now - created).days
        stars = repo.get("stargazers_count", 0)

        if len(final_buckets) >= 4:
            signals.append(Signal(
                name="feature_overlap",
                severity="HIGH",
                detail=(
                    f"Repo '{name}' matches {len(final_buckets)}/6 AGT feature buckets "
                    f"({', '.join(sorted(final_buckets))}), "
                    f"age={age_days}d, stars={stars}"
                ),
                value=len(final_buckets),
            ))
        elif len(final_buckets) >= 3:
            signals.append(Signal(
                name="feature_overlap",
                severity="MEDIUM",
                detail=(
                    f"Repo '{name}' matches {len(final_buckets)}/6 AGT feature buckets "
                    f"({', '.join(sorted(final_buckets))})"
                ),
                value=len(final_buckets),
            ))

    return signals


def check_thin_credibility(
    username: str,
    target_repo: str | None = None,
    repos: list[dict] | None = None,
    issues: list[dict] | None = None,
) -> list[Signal]:
    """Detect young, low-star projects promoted across multiple orgs.

    Args:
        username: GitHub username.
        target_repo: Optional target repo context (unused, kept for API compat).
        repos: Pre-fetched user repos (avoids redundant API call).
        issues: Pre-fetched issues (avoids redundant API call).
    """
    signals: list[Signal] = []

    if repos is None:
        repos = _api(f"/users/{username}/repos", {"per_page": "100", "sort": "created"})
    if not repos:
        return signals

    now = datetime.now(timezone.utc)

    thin_repos: list[dict] = []
    for repo in repos:
        if repo.get("fork"):
            continue
        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        age_days = (now - created).days
        stars = repo.get("stargazers_count", 0)

        if age_days <= 60 and stars < 5:
            thin_repos.append({
                "name": repo["name"],
                "full_name": repo.get("full_name", f"{username}/{repo['name']}"),
                "age_days": age_days,
                "stars": stars,
            })

    if not thin_repos:
        return signals

    if issues is None:
        issues = _search_issues(f"author:{username} is:issue", per_page=50)
    if not issues:
        return signals

    # Track per-repo promoting orgs for coordinated promotion detection
    repo_org_map: dict[str, set[str]] = {}

    for thin in thin_repos:
        repo_name = thin["name"].lower()
        full_name = thin["full_name"].lower()
        promoting_orgs: set[str] = set()

        for issue in issues:
            body = (issue.get("body") or "").lower()
            title = (issue.get("title") or "").lower()
            repo_url = issue.get("repository_url", "")
            issue_org = repo_url.replace("https://api.github.com/repos/", "").split("/")[0].lower()

            if repo_name in body or repo_name in title or full_name in body:
                if issue_org != username.lower():
                    promoting_orgs.add(issue_org)

        repo_org_map[thin["name"]] = promoting_orgs

        if len(promoting_orgs) >= 2:
            signals.append(Signal(
                name="thin_credibility",
                severity="HIGH",
                detail=(
                    f"Repo '{thin['name']}' ({thin['age_days']}d old, {thin['stars']} stars) "
                    f"promoted across {len(promoting_orgs)} orgs ({', '.join(sorted(promoting_orgs)[:5])})"
                ),
                value=len(promoting_orgs),
            ))
        elif len(promoting_orgs) >= 1:
            signals.append(Signal(
                name="thin_credibility",
                severity="MEDIUM",
                detail=(
                    f"Repo '{thin['name']}' ({thin['age_days']}d old, {thin['stars']} stars) "
                    f"promoted in {list(promoting_orgs)[0]}"
                ),
                value=len(promoting_orgs),
            ))

    # Coordinated promotion: multiple thin repos targeting the same org set
    promoted_repos = {k: v for k, v in repo_org_map.items() if len(v) >= 2}
    if len(promoted_repos) >= 3:
        # Check pairwise Jaccard overlap
        org_sets = list(promoted_repos.values())
        high_overlap_count = 0
        for i in range(len(org_sets)):
            for j in range(i + 1, len(org_sets)):
                intersection = len(org_sets[i] & org_sets[j])
                union = len(org_sets[i] | org_sets[j])
                if union > 0 and intersection / union >= 0.6:
                    high_overlap_count += 1

        total_pairs = len(org_sets) * (len(org_sets) - 1) // 2
        if total_pairs > 0 and high_overlap_count / total_pairs >= 0.5:
            all_orgs = set()
            for s in org_sets:
                all_orgs |= s
            signals.append(Signal(
                name="coordinated_promotion",
                severity="HIGH",
                detail=(
                    f"{len(promoted_repos)} thin repos promoted to overlapping org set "
                    f"({', '.join(sorted(all_orgs)[:5])}...)"
                ),
                value=len(promoted_repos),
            ))

    return signals


def check_spray_pattern(
    username: str,
    issues: list[dict] | None = None,
    user_repos: list[dict] | None = None,
) -> list[Signal]:
    """Check if user filed similar issues across many repos.

    Args:
        username: GitHub username.
        issues: Pre-fetched issues (avoids redundant API call).
        user_repos: Pre-fetched user repos for self-promotion detection.
    """
    signals: list[Signal] = []

    if issues is None:
        issues = _search_issues(f"author:{username} is:issue", per_page=100)
    if not issues:
        return signals

    # Build (created_at, repo_name) pairs keeping them aligned
    entries: list[tuple[datetime, str]] = []
    for issue in issues:
        created = datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
        repo_url = issue.get("repository_url", "")
        repo_name = repo_url.replace("https://api.github.com/repos/", "")
        entries.append((created, repo_name))

    unique_repos = {repo for _, repo in entries}
    if len(unique_repos) >= 5:
        entries.sort(key=lambda e: e[0])

        # Find the largest set of distinct repos hit within any 7-day window
        best_window_repos: set[str] = set()
        for i, (d, _) in enumerate(entries):
            window_repos = {
                repo for d2, repo in entries
                if abs((d2 - d).days) <= 7
            }
            if len(window_repos) > len(best_window_repos):
                best_window_repos = window_repos

        if len(best_window_repos) >= 5:
            signals.append(Signal(
                name="cross_repo_spray",
                severity="HIGH",
                detail=f"Issues filed in {len(best_window_repos)} repos within 7 days",
                value=len(best_window_repos),
            ))
        elif len(unique_repos) >= 8:
            signals.append(Signal(
                name="cross_repo_spread",
                severity="MEDIUM",
                detail=f"Issues filed across {len(unique_repos)} different repos",
                value=len(unique_repos),
            ))

    # Self-promotion: check if sprayed issues mention the author's own repos
    signals.extend(_check_self_promotion(username, issues, user_repos))

    return signals


def _check_self_promotion(
    username: str,
    issues: list[dict],
    user_repos: list[dict] | None = None,
) -> list[Signal]:
    """Detect issues that promote the author's own repos across other orgs."""
    signals: list[Signal] = []
    if not user_repos:
        return signals

    # Build lookup of user's non-fork repo identifiers
    own_repo_names: set[str] = set()
    own_repo_full: set[str] = set()
    for repo in user_repos:
        if repo.get("fork"):
            continue
        name = repo.get("name", "").lower()
        full = repo.get("full_name", f"{username}/{name}").lower()
        own_repo_names.add(name)
        own_repo_full.add(full)

    if not own_repo_names:
        return signals

    username_lower = username.lower()
    promo_orgs: set[str] = set()
    promo_issues = 0

    for issue in issues:
        repo_url = issue.get("repository_url", "")
        issue_org = repo_url.replace("https://api.github.com/repos/", "").split("/")[0].lower()

        # Skip issues in the user's own repos/org
        if issue_org == username_lower:
            continue

        body = (issue.get("body") or "").lower()
        title = (issue.get("title") or "").lower()
        text = f"{title} {body}"

        # Strong match: full_name or GitHub URL
        has_promo = False
        for full in own_repo_full:
            if full in text or f"github.com/{full}" in text:
                has_promo = True
                break

        if not has_promo:
            # Weaker match: repo name as a whole word, but only for
            # distinctive names (>= 4 chars, not generic)
            generic = {"app", "api", "cli", "web", "bot", "docs", "test", "demo", "core", "data", "main"}
            for name in own_repo_names:
                if len(name) >= 4 and name not in generic and name in text:
                    has_promo = True
                    break

        if has_promo:
            promo_issues += 1
            promo_orgs.add(issue_org)

    if promo_issues >= 5 and len(promo_orgs) >= 3:
        signals.append(Signal(
            name="self_promotion_spray",
            severity="HIGH",
            detail=(
                f"{promo_issues} issues promoting own repos across "
                f"{len(promo_orgs)} orgs ({', '.join(sorted(promo_orgs)[:5])})"
            ),
            value=promo_issues,
        ))
    elif promo_issues >= 3 and len(promo_orgs) >= 2:
        signals.append(Signal(
            name="self_promotion_spray",
            severity="MEDIUM",
            detail=(
                f"{promo_issues} issues promoting own repos across "
                f"{len(promo_orgs)} orgs"
            ),
            value=promo_issues,
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
    age_days = max((datetime.now(timezone.utc) - created).days, 0)
    report.stats = {
        "account_age_days": age_days,
        "repos_per_day": round(user.get("public_repos", 0) / max(age_days, 1), 3),
    }

    # Shared data fetches (avoids redundant API calls across checkers)
    repos = _api(f"/users/{username}/repos", {"per_page": "100", "sort": "created"}) or []
    issues = _search_issues(f"author:{username} is:issue", per_page=100)

    # Run checks with shared data
    for signal in check_account_shape(user):
        report.add(signal)

    for signal in check_repo_themes(username, repos=repos):
        report.add(signal)

    for signal in check_spray_pattern(username, issues=issues, user_repos=repos):
        report.add(signal)

    # thin_credibility runs regardless of target_repo
    for signal in check_thin_credibility(username, target_repo, repos=repos, issues=issues):
        report.add(signal)

    if target_repo:
        for signal in check_credential_spray(username, target_repo):
            report.add(signal)
        for signal in check_feature_overlap(username, target_repo):
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


def _entry() -> None:
    """Console-script entry point for pip-installed CLI."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())

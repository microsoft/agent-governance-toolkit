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
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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

        # A repo that is itself AGED + well-starred (>=1yr, >=10 stars) is a
        # domain specialist's own mature project, not a fresh clone. Skip it.
        # The age branch (not the bare 50-star branch) is required so a same-week
        # star-bought clone cannot suppress its own overlap signal; a young/thin
        # repo matching the same buckets still fires below.
        if _is_established_repo_aged(repo):
            continue

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


def _is_established_repo(repo: dict) -> bool:
    """Return True if a repo has enough traction to be considered established."""
    stars = repo.get("stargazers_count", 0)
    if stars >= 50:
        return True
    created = repo.get("created_at", "")
    if created:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(
                created.replace("Z", "+00:00")
            )).days
            if age >= 365 and stars >= 10:
                return True
        except (ValueError, TypeError):
            pass
    return False


def _check_self_promotion(
    username: str,
    issues: list[dict],
    user_repos: list[dict] | None = None,
) -> list[Signal]:
    """Detect issues that promote the author's own repos across other orgs.

    Distinguishes between thin-credibility spam and legitimate cross-ecosystem
    references to established projects (>50 stars, or >1yr with >10 stars).
    """
    signals: list[Signal] = []
    if not user_repos:
        return signals

    # Build lookup of user's non-fork repo identifiers and quality
    own_repo_names: set[str] = set()
    own_repo_full: set[str] = set()
    repo_quality: dict[str, bool] = {}  # full_name -> is_established
    for repo in user_repos:
        if repo.get("fork"):
            continue
        name = repo.get("name", "").lower()
        full = repo.get("full_name", f"{username}/{name}").lower()
        own_repo_names.add(name)
        own_repo_full.add(full)
        repo_quality[full] = _is_established_repo(repo)

    if not own_repo_names:
        return signals

    username_lower = username.lower()
    promo_orgs: set[str] = set()
    promo_issues = 0
    promoted_repos: set[str] = set()

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
        matched_repo: str | None = None
        for full in own_repo_full:
            if full in text or f"github.com/{full}" in text:
                matched_repo = full
                break

        if not matched_repo:
            # Weaker match: repo name in a URL or owner/repo format only.
            # Plain substring matching causes false positives for names that
            # are common domain terms (e.g., "agent-governance" matches any
            # governance discussion).
            for name in own_repo_names:
                if len(name) < 6:
                    continue
                url_form = f"github.com/{username_lower}/{name}"
                slash_form = f"{username_lower}/{name}"
                if url_form in text or slash_form in text:
                    matched_repo = f"{username_lower}/{name}"
                    break

        if matched_repo:
            promo_issues += 1
            promo_orgs.add(issue_org)
            promoted_repos.add(matched_repo)

    if promo_issues < 3 or len(promo_orgs) < 2:
        return signals

    # Split promotions by repo quality: only thin-repo promotions count
    # as spam. Referencing established projects is legitimate.
    thin_repos = {r for r in promoted_repos if not repo_quality.get(r, False)}
    established_refs = {r for r in promoted_repos if repo_quality.get(r, False)}

    # Count only issues that reference thin repos toward the spam score
    if thin_repos:
        # Re-count promotions that involve thin repos only
        thin_promo_issues = 0
        thin_promo_orgs: set[str] = set()

        for issue in issues:
            repo_url = issue.get("repository_url", "")
            issue_org = repo_url.replace("https://api.github.com/repos/", "").split("/")[0].lower()
            if issue_org == username_lower:
                continue

            body = (issue.get("body") or "").lower()
            title = (issue.get("title") or "").lower()
            text = f"{title} {body}"

            mentions_thin = False
            for full in thin_repos:
                if full in text or f"github.com/{full}" in text:
                    mentions_thin = True
                    break
            if not mentions_thin:
                for r in thin_repos:
                    name = r.split("/")[-1]
                    owner = r.split("/")[0] if "/" in r else username_lower
                    url_form = f"github.com/{owner}/{name}"
                    if len(name) >= 6 and (url_form in text or r in text):
                        mentions_thin = True
                        break

            if mentions_thin:
                thin_promo_issues += 1
                thin_promo_orgs.add(issue_org)

        if thin_promo_issues >= 5 and len(thin_promo_orgs) >= 3:
            signals.append(Signal(
                name="self_promotion_spray",
                severity="HIGH",
                detail=(
                    f"{thin_promo_issues} issues promoting thin repos across "
                    f"{len(thin_promo_orgs)} orgs ({', '.join(sorted(thin_promo_orgs)[:5])})"
                ),
                value=thin_promo_issues,
            ))
        elif thin_promo_issues >= 3 and len(thin_promo_orgs) >= 2:
            signals.append(Signal(
                name="self_promotion_spray",
                severity="MEDIUM",
                detail=(
                    f"{thin_promo_issues} issues promoting thin repos across "
                    f"{len(thin_promo_orgs)} orgs"
                ),
                value=thin_promo_issues,
            ))

    # Log established-project cross-references at LOW severity for
    # transparency (does not affect risk scoring)
    if established_refs:
        signals.append(Signal(
            name="established_project_reference",
            severity="LOW",
            detail=(
                f"{promo_issues} cross-ecosystem references to established repos "
                f"({len(established_refs)} repos with significant traction) across "
                f"{len(promo_orgs)} orgs ({', '.join(sorted(promo_orgs)[:5])})"
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
    age_days = (datetime.now(timezone.utc) - created).days
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

    # Org-aware + prior-interaction established credibility: a contributor who
    # CONTRIBUTED to an aged org repo, or already landed maintainer-merged PRs
    # here, earns credit even with a thin personal account. Fail-closed: any
    # error in these network paths abstains (credibility from personal signal
    # only) rather than crashing or granting credit.
    try:
        org_backed, _org_evidence = _org_owned_established(username)
        prior_interaction = _has_prior_target_contribution(username, target_repo)
    except Exception:
        org_backed, prior_interaction = False, False
    established, full_tier = _established_credibility(user, org_backed, prior_interaction)

    _dampen_for_established_accounts(report, user, established=established, full=full_tier)
    report.compute_risk()

    # Maintainer-curated allowlist: a final, auditable escape hatch. It only
    # SOFTENS the auto-flag (HIGH -> MEDIUM, still surfaced for human review);
    # it never sets LOW and never bypasses code review. Ships empty.
    allow_users, allow_orgs = _load_allowlist()
    if allow_users or allow_orgs:
        try:
            _orgs_resp = _api(f"/users/{username}/orgs", {"per_page": "100"})
        except Exception:
            _orgs_resp = []
        user_orgs = (
            [o.get("login", "") for o in _orgs_resp if isinstance(o, dict)]
            if isinstance(_orgs_resp, list)
            else []
        )
        if _is_allowlisted(username, user_orgs, (allow_users, allow_orgs)):
            _apply_allowlist(report)

    return report


def _apply_allowlist(report: ReputationReport) -> None:
    """Apply the maintainer allowlist to an already-matched contributor.

    The allowlist only SOFTENS the auto-flag (HIGH -> MEDIUM, still surfaced for
    human review); it never sets LOW and never bypasses code review. It does NOT
    apply -- and records the refusal -- when either hard guard that
    :func:`_dampen_for_established_accounts` enforces is present (SG: abuse
    cannot be whitewashed):

      * any of the four deliberate-abuse signals, or
      * a multi-repo split-clone (>=2 ``feature_overlap`` HIGH signals).
    """
    abuse = bool({s.name for s in report.signals} & _ABUSE_SIGNALS)
    split_clone = sum(
        1 for s in report.signals
        if s.name == "feature_overlap" and s.severity == "HIGH"
    ) >= 2
    if abuse or split_clone:
        report.add(Signal(
            name="allowlist_blocked",
            severity="HIGH",
            detail="maintainer allowlist NOT applied: "
                   + ("deliberate-abuse signal present" if abuse
                      else "multi-repo split-clone pattern present"),
        ))
    elif report.risk == "HIGH":
        report.risk = "MEDIUM"
        report.add(Signal(
            name="allowlisted",
            severity="MEDIUM",
            detail="maintainer allowlist: auto-flag softened HIGH→MEDIUM "
                   "(still surfaced; does not bypass code review)",
        ))


# ---------------------------------------------------------------------------
# Established-account dampening
# ---------------------------------------------------------------------------

# Signal names that indicate deliberate abuse patterns.  If any of these
# are present, the account's age/followers should NOT soften the verdict.
_ABUSE_SIGNALS = frozenset({
    "thin_credibility",
    "credential_laundering",
    "coordinated_promotion",
    "self_promotion_spray",
    # NOTE: feature_overlap is intentionally NOT an abuse signal. It measures
    # domain overlap with this project, which is expected for a domain
    # specialist and is not a deliberate-abuse pattern. It is dampening-eligible
    # (see _DAMPEN_RULES) and its own check skips repos that are themselves
    # established. The four signals above are deliberate abuse and still block
    # dampening entirely.
})

# Signals eligible for dampening and the maximum value at which dampening
# is applied.  Beyond the cap the signal keeps its original severity,
# guarding against compromised or purchased mature accounts.
_DAMPEN_RULES: dict[str, tuple[str, int | None]] = {
    # name -> (new_severity, max_value_for_dampening)
    "recent_repo_burst": ("LOW", 30),       # >30 repos in 90d stays HIGH
    "cross_repo_spray":  ("MEDIUM", 8),     # >8 repos in 7d stays HIGH
    "cross_repo_spread": ("LOW", None),     # always safe to lower
    "awesome_fork_burst": ("MEDIUM", 6),    # >6 awesome forks stays HIGH
    "feature_overlap": ("MEDIUM", 5),       # single established overlap; >=6/6 buckets stays HIGH
}

# Signals a PARTIAL credibility tier (org-backed / prior-interaction only, with a
# thin personal account) is allowed to dampen. Raw volume/velocity bursts are
# excluded: org/prior history does not vouch for a sudden personal repo/issue
# burst, so those stay at full severity for a thin-but-org-backed account.
#
# NOTE (reviewer-visible by design): for a partial-tier account, a single
# feature_overlap HIGH (-> MEDIUM) together with a cross_repo_spread MEDIUM
# (-> LOW) can net to overall LOW. That softening is intentional -- the partial
# tier exists to vouch for domain overlap -- and it is reachable only by an
# account that already EARNED the tier (contributor to an aged >=1yr/>=10-star
# org repo, or >=2 distinct-maintainer merges here), neither of which is cheaply
# forgeable. Two or more feature_overlap HIGH (a split clone) remain
# non-dampenable regardless (see _dampen_for_established_accounts).
_PARTIAL_DAMPEN_SIGNALS = frozenset({"feature_overlap", "cross_repo_spread"})


def _is_established(user: dict) -> bool:
    """Return True if the account shows strong organic credibility."""
    created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
    age_days = (datetime.now(timezone.utc) - created).days
    followers = user.get("followers", 0)
    public_repos = user.get("public_repos", 0)
    return age_days >= 366 and followers >= 50 and public_repos >= 20


def _is_established_repo_aged(repo: dict) -> bool:
    """Stricter establishment: only the AGE branch (>=1yr old AND >=10 stars).

    Used where star-count alone is too cheap to trust (org-credibility grant and
    the feature_overlap source-skip). A same-week star-bought repo cannot
    qualify -- only one that has existed >=1 year with sustained traction.
    """
    stars = repo.get("stargazers_count", 0)
    created = repo.get("created_at", "")
    if not created or stars < 10:
        return False
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(
            created.replace("Z", "+00:00")
        )).days
    except (ValueError, TypeError):
        return False
    return age >= 365


def _user_contributed_to(owner: str, repo_name: str, username: str) -> bool:
    """Return True if ``username`` appears in the repo's contributor list.

    Guards org-credibility against "member of an org that owns a repo I did not
    build" and mirror-a-popular-repo: org credit requires the user to actually
    be a contributor to the established repo. Fail-closed on error.
    """
    contributors = _api(f"/repos/{owner}/{repo_name}/contributors", {"per_page": "100"})
    if not isinstance(contributors, list):
        return False
    uname = username.lower()
    return any(
        isinstance(c, dict) and str(c.get("login", "")).lower() == uname
        for c in contributors
    )


def _org_owned_established(username: str) -> tuple[bool, str]:
    """Return (True, evidence) if the user is a CONTRIBUTOR to an AGED, well-starred
    repo owned by an org they publicly belong to.

    Hardened against cheap forgery (SG: star-buying / mirror-into-org): the repo
    must pass ``_is_established_repo_aged`` (>=1yr old AND >=10 stars, so same-week
    star-buying cannot qualify) AND the user must appear in that repo's
    contributors (so merely belonging to an org that owns someone else's repo, or
    mirroring a popular project, grants no credit). Only PUBLIC org memberships
    are visible; a concealed membership yields no credit (UNKNOWN, not negative).
    """
    orgs = _api(f"/users/{username}/orgs", {"per_page": "100"})
    if not isinstance(orgs, list):
        return False, ""
    for org in orgs[:10]:
        login = org.get("login")
        if not login:
            continue
        repos = _api(f"/orgs/{login}/repos", {"per_page": "100", "sort": "pushed"})
        if not isinstance(repos, list):
            continue
        for repo in repos[:50]:
            name = repo.get("name")
            if (not repo.get("fork") and name and _is_established_repo_aged(repo)
                    and _user_contributed_to(login, name, username)):
                stars = repo.get("stargazers_count", 0)
                return True, f"{login}/{name} ({stars} stars)"
    return False, ""


def _is_public_org_member(org: str, login: str) -> bool:
    """Return True if ``login`` is a PUBLIC member of ``org``.

    The public-members membership endpoint returns HTTP 204 for a member and 404
    otherwise, with no JSON body -- so it cannot go through ``_api`` (which parses
    JSON). Fail-closed: any error or non-204 status -> False.
    """
    if not org or not login:
        return False
    req = Request(f"https://api.github.com/orgs/{org}/public_members/{login}")
    req.add_header("Authorization", f"Bearer {_get_token()}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urlopen(req, timeout=15) as resp:
            return getattr(resp, "status", resp.getcode()) == 204
    except Exception:
        return False


# Seconds to wait between successive per-PR detail calls in the maintainer-merged
# lookup, to stay under GitHub's secondary rate limit. Tests set this to 0.
_MAINTAINER_LOOKUP_PACE_SECONDS = 0.5


def _has_prior_target_contribution(username: str, target_repo: str | None) -> bool:
    """Return True if the user has >=2 merged PRs in the target repo each merged by
    a DISTINCT maintainer (a public member of the target org), other than the author.

    Hardened against the 2-account merge ring (SG): "merged_by != author" is not
    enough -- the merger must be a public org member (a real maintainer), and the
    two qualifying merges must be by DISTINCT maintainers. A sock-puppet that
    merged a colluder's PR is not an org member, so the ring no longer
    manufactures credibility. Bare COLLABORATOR association is no longer a
    fast-path (it is grantable and the weakest role).
    """
    if not target_repo or "/" not in target_repo:
        return False
    target_org = target_repo.split("/")[0]
    prs = _search_issues(
        f"repo:{target_repo} author:{username} is:pr is:merged", per_page=10
    )
    if not prs:
        return False
    return _count_maintainer_merged(target_repo, target_org, username, prs, need=2) >= 2


def _count_maintainer_merged(
    target_repo: str, target_org: str, username: str, prs: list[dict], need: int
) -> int:
    """Count distinct maintainers (public org members != author) who merged the
    user's PRs. Capped at ten candidates, early-exit once ``need`` distinct
    maintainers are seen. Fail-closed: an unconfirmed merger, a self-merge, or a
    non-member merger does not count.

    Paces the per-PR detail calls by ``_MAINTAINER_LOOKUP_PACE_SECONDS`` to stay
    under GitHub's secondary rate limit when a candidate has many merged PRs but
    few distinct maintainer merges (the no-early-exit path).
    """
    maintainers: set[str] = set()
    made_api_call = False
    for pr in prs[:10]:
        number = pr.get("number")
        if not number:
            continue
        if made_api_call and _MAINTAINER_LOOKUP_PACE_SECONDS:
            time.sleep(_MAINTAINER_LOOKUP_PACE_SECONDS)
        made_api_call = True
        detail = _api(f"/repos/{target_repo}/pulls/{number}")
        merged_login = ((detail or {}).get("merged_by") or {}).get("login", "")
        if not merged_login or merged_login.lower() == username.lower():
            continue
        if merged_login.lower() in maintainers:
            continue
        if _is_public_org_member(target_org, merged_login):
            maintainers.add(merged_login.lower())
            if len(maintainers) >= need:
                break
    return len(maintainers)


def _established_credibility(
    user: dict, org_backed: bool = False, prior_interaction: bool = False
) -> tuple[bool, bool]:
    """Return ``(credible, full_tier)``.

    ``full_tier`` is True only for the personal ``_is_established`` signal, which
    vouches for the whole account. ``org_backed`` / ``prior_interaction`` are a
    PARTIAL tier: real but narrower credibility that dampens domain-overlap and
    spread signals but NOT raw volume/velocity bursts (which they do not speak
    to). ``credible`` is True if any signal holds.
    """
    full = _is_established(user)
    credible = full or org_backed or prior_interaction
    return credible, full


_ALLOWLIST_PATH = Path(__file__).resolve().parent / "contributor_check_allowlist.json"


def _load_allowlist(path: "Path | None" = None) -> tuple[set[str], set[str]]:
    """Load the maintainer-curated allowlist of trusted users and orgs.

    Returns ``(users, orgs)`` as lowercased sets. A missing or invalid file
    yields empty sets (fail-closed: an absent allowlist grants no exemption).
    The allowlist only downgrades the auto-flag; it never bypasses code review.
    """
    p = path or _ALLOWLIST_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set(), set()
    users = {str(u).lower() for u in data.get("users", []) if isinstance(u, str)}
    orgs = {str(o).lower() for o in data.get("orgs", []) if isinstance(o, str)}
    return users, orgs


def _is_allowlisted(
    username: str, user_orgs: list[str], allowlist: tuple[set[str], set[str]]
) -> bool:
    """Return True if the user, or one of their orgs, is on the allowlist."""
    users, orgs = allowlist
    if username.lower() in users:
        return True
    return any(o.lower() in orgs for o in user_orgs)


def _dampen_for_established_accounts(
    report: ReputationReport,
    user: dict,
    *,
    established: "bool | None" = None,
    full: bool = True,
) -> None:
    """Down-grade volume/activity signals for accounts with organic credibility.

    ``established`` lets the caller pass a richer org/prior-interaction-aware
    credibility verdict (see ``_established_credibility``). When omitted it
    falls back to the personal ``_is_established`` check, preserving the prior
    behavior and call signature (``full`` defaults to True).

    ``full=False`` selects the PARTIAL tier (org-backed / prior-interaction with
    a thin personal account): only ``_PARTIAL_DAMPEN_SIGNALS`` are eligible, so
    raw volume/velocity bursts stay at full severity.

    Two hard guards (SG: abuse cannot be whitewashed):
      * any of the four deliberate-abuse signals present -> dampen nothing;
      * two or more distinct ``feature_overlap`` HIGH signals (a split, multi-repo
        clone) -> ``feature_overlap`` is non-dampenable and stays HIGH.
    """
    if established is None:
        established = _is_established(user)
    if not established:
        return

    # If any abuse-pattern signal exists, skip dampening entirely
    signal_names = {s.name for s in report.signals}
    if signal_names & _ABUSE_SIGNALS:
        return

    # Multi-repo split-clone: two or more feature_overlap HIGH signals are treated
    # as abuse and are NOT dampened (a single overlap is the legit-specialist case).
    overlap_high = sum(
        1 for s in report.signals if s.name == "feature_overlap" and s.severity == "HIGH"
    )
    multi_overlap = overlap_high >= 2

    for signal in report.signals:
        rule = _DAMPEN_RULES.get(signal.name)
        if rule is None:
            continue
        if not full and signal.name not in _PARTIAL_DAMPEN_SIGNALS:
            continue  # partial tier does not vouch for volume/velocity bursts
        if signal.name == "feature_overlap" and multi_overlap:
            continue  # split-clone stays HIGH
        new_severity, max_value = rule
        if max_value is not None and signal.value is not None and signal.value > max_value:
            continue  # extreme value, keep original severity
        old = signal.severity
        if old != new_severity:
            signal.severity = new_severity
            signal.detail += f" [dampened {old}\u2192{new_severity}: established account]"


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

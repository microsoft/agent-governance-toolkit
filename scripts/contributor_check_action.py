#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Entrypoint for the contributor-check composite action.

Orchestrates profile analysis, credential audit, and cluster detection,
then posts a summary comment and applies labels on PRs/issues that meet
the risk threshold.

Usage (from the composite action):
    python scripts/contributor_check_action.py \
        --username <login> \
        --checks profile,credential \
        --target-repo owner/repo \
        --risk-threshold MEDIUM \
        --number 42 \
        --item-type pr
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

MARKER = "<!-- agt-contributor-check -->"
RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 0}


# ── Helpers ───────────────────────────────────────────────────────


def _api(token: str, method: str, path: str, data: dict | None = None) -> dict | None:
    """Minimal GitHub API helper (no third-party deps)."""
    url = f"https://api.github.com{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    req = Request(url, method=method, headers=headers)
    if data:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except HTTPError as exc:
        if exc.code == 422:
            return None
        raise


def _run_check(script: str, args: list[str], out_path: str) -> str:
    """Run a check script and return the risk level from its JSON output."""
    try:
        result = subprocess.run(
            [sys.executable, script, *args, "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        Path(out_path).write_text(result.stdout)
        data = json.loads(result.stdout)
        return data.get("risk", "UNKNOWN")
    except Exception:
        return "UNKNOWN"


def _aggregate_risk(*levels: str) -> str:
    """Return the highest risk level from a set of check results."""
    max_val = max(RISK_ORDER.get(r, 0) for r in levels)
    for label, val in RISK_ORDER.items():
        if val == max_val and label != "UNKNOWN":
            return label
    return "LOW"


def _set_output(name: str, value: str) -> None:
    """Write a value to $GITHUB_OUTPUT."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def _write_summary(text: str) -> None:
    """Append text to $GITHUB_STEP_SUMMARY."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(text)


# ── Comment / label helpers ───────────────────────────────────────


def _build_comment(username: str, overall: str, profile_risk: str,
                   cred_risk: str, cluster_risk: str) -> str:
    """Build a concise comment body with risk levels only."""
    icon = "\U0001f534" if overall == "HIGH" else "\U0001f7e1"

    lines = [
        MARKER,
        f"{icon} **Contributor Check: {overall}**",
        "",
        "| Check | Result |",
        "|-------|--------|",
    ]
    if profile_risk:
        lines.append(f"| Profile | {profile_risk} |")
    if cred_risk:
        lines.append(f"| Credential | {cred_risk} |")
    if cluster_risk:
        lines.append(f"| Cluster | {cluster_risk} |")
    lines.append(f"| **Overall** | **{overall}** |")
    lines.append("")
    lines.append(
        "*Automated check by "
        "[AGT Contributor Check]"
        "(https://github.com/microsoft/agent-governance-toolkit"
        "/tree/main/scripts#contributor-reputation-tools).*"
    )
    return "\n".join(lines)


def _post_comment(token: str, owner: str, repo: str, number: int,
                  body: str) -> None:
    """Create or update the contributor-check comment (idempotent)."""
    page = 1
    existing_id = None
    while True:
        comments = _api(
            token, "GET",
            f"/repos/{owner}/{repo}/issues/{number}/comments?per_page=100&page={page}",
        ) or []
        for c in comments:
            if MARKER in (c.get("body") or ""):
                existing_id = c["id"]
                break
        if existing_id or len(comments) < 100:
            break
        page += 1

    if existing_id:
        _api(token, "PATCH",
             f"/repos/{owner}/{repo}/issues/comments/{existing_id}",
             {"body": body})
    else:
        _api(token, "POST",
             f"/repos/{owner}/{repo}/issues/{number}/comments",
             {"body": body})


def _apply_label(token: str, owner: str, repo: str, number: int,
                 risk: str) -> None:
    """Ensure the correct needs-review label is applied."""
    color = "D93F0B" if risk == "HIGH" else "FFA500"
    try:
        _api(token, "POST", f"/repos/{owner}/{repo}/labels", {
            "name": f"needs-review:{risk}",
            "description": f"Contributor check flagged {risk} risk",
            "color": color,
        })
    except HTTPError:
        pass

    for level in ("LOW", "MEDIUM", "HIGH"):
        if level != risk:
            try:
                req = Request(
                    f"https://api.github.com/repos/{owner}/{repo}"
                    f"/issues/{number}/labels/needs-review:{level}",
                    method="DELETE",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                urlopen(req, timeout=15)
            except Exception:
                pass

    _api(token, "POST", f"/repos/{owner}/{repo}/issues/{number}/labels", {
        "labels": [f"needs-review:{risk}"],
    })


# ── Main ──────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Contributor check action entrypoint")
    parser.add_argument("--username", required=True)
    parser.add_argument("--checks", default="profile,credential")
    parser.add_argument("--target-repo", required=True)
    parser.add_argument("--risk-threshold", default="MEDIUM")
    parser.add_argument("--number", type=int, default=0)
    parser.add_argument("--item-type", default="manual",
                        choices=["pr", "issue", "manual"])
    args = parser.parse_args()

    if not args.username:
        print("No username provided, skipping.")
        _set_output("risk", "UNKNOWN")
        return

    token = os.environ.get("GITHUB_TOKEN", "")
    scripts_dir = Path(__file__).resolve().parent
    checks = [c.strip() for c in args.checks.split(",")]

    profile_risk = ""
    cred_risk = ""
    cluster_risk = ""

    if "profile" in checks:
        profile_risk = _run_check(
            str(scripts_dir / "contributor_check.py"),
            ["--username", args.username, "--repo", args.target_repo],
            "/tmp/agt-profile.json",
        )

    if "credential" in checks:
        cred_risk = _run_check(
            str(scripts_dir / "credential_audit.py"),
            ["--username", args.username, "--repo", args.target_repo],
            "/tmp/agt-cred.json",
        )

    if "cluster" in checks:
        cluster_risk = _run_check(
            str(scripts_dir / "cluster_detect.py"),
            ["--seed", args.username],
            "/tmp/agt-cluster.json",
        )

    overall = _aggregate_risk(
        profile_risk or "LOW",
        cred_risk or "LOW",
        cluster_risk or "LOW",
    )

    # Set action outputs
    _set_output("risk", overall)
    _set_output("profile-risk", profile_risk)
    _set_output("credential-risk", cred_risk)
    _set_output("cluster-risk", cluster_risk)

    print(f"Contributor check for {args.username}: {overall}")

    # Post comment and label for PR/issue if risk meets threshold
    threshold_val = RISK_ORDER.get(args.risk_threshold, 2)
    risk_val = RISK_ORDER.get(overall, 0)

    if args.item_type != "manual" and args.number > 0 and risk_val >= threshold_val:
        owner, repo = args.target_repo.split("/", 1)
        body = _build_comment(
            args.username, overall, profile_risk, cred_risk, cluster_risk,
        )
        _post_comment(token, owner, repo, args.number, body)
        _apply_label(token, owner, repo, args.number, overall)
        print(f"Posted comment and label on #{args.number}")

    # Job summary
    summary_lines = [
        f"## Contributor Check: `{args.username}`\n",
        "| Check | Result |",
        "|-------|--------|",
    ]
    if profile_risk:
        summary_lines.append(f"| Profile | {profile_risk} |")
    if cred_risk:
        summary_lines.append(f"| Credential | {cred_risk} |")
    if cluster_risk:
        summary_lines.append(f"| Cluster | {cluster_risk} |")
    summary_lines.append(f"| **Overall** | **{overall}** |")
    summary_lines.append("")
    _write_summary("\n".join(summary_lines))


if __name__ == "__main__":
    main()

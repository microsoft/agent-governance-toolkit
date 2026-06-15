#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end PoC scenarios for the org-aware contributor-reputation check.

Each scenario drives the FULL ``check_contributor`` pipeline (all signal
checkers + credibility + dampening + allowlist + compute_risk) against a
synthetic GitHub persona, patching only ``_api`` (which ``_search_issues`` calls
through), ``_is_public_org_member`` (a status-only call outside ``_api``), and,
where relevant, ``_load_allowlist``. They prove, end to end:

  S1  aged-repo + org-backed specialist        -> NOT HIGH  (mature repos source-skipped; org credit earned)
  S2  throwaway promoter                        -> HIGH      (true positive kept)
  S3  manufactured thin promo org               -> HIGH      (org credit needs an AGED, contributed repo)
  S4  self-merged-only PR history               -> HIGH      (self-merge grants no credibility)
  S5  maintainer-allowlisted split-clone         -> HIGH      (allowlist never whitewashes abuse)
  S6  established account + real abuse signal    -> HIGH      (abuse still blocks dampening)

The router raises on any unexpected path, so a missing mock can never fall
through to a live network call.
"""

# Synthetic GitHub usernames/org logins used only as test fixtures below.
# cspell:ignore myorg someoneelse freshorg selfmerge

from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contributor_check import check_contributor


@pytest.fixture(autouse=True)
def _no_api_pacing(monkeypatch):
    """Zero the maintainer-lookup API pacing so end-to-end tests do not sleep."""
    monkeypatch.setattr(
        "contributor_check._MAINTAINER_LOOKUP_PACE_SECONDS", 0, raising=False
    )


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# 4-bucket governance description (mcp_security, policy_engine, identity_crypto, runtime_controls)
_BUCKET_DESC = "mcp security policy engine ed25519 kill switch"


def _repo(name, *, stars, days, desc=_BUCKET_DESC, fork=False, owner="u"):
    return {
        "name": name,
        "full_name": f"{owner}/{name}",
        "description": desc,
        "topics": [],
        "fork": fork,
        "created_at": _iso(days),
        "stargazers_count": stars,
        "language": "Python",
    }


TARGET = "microsoft/agent-governance-toolkit"


class _FakeGitHub:
    """Path-routing fake for ``_api`` (covers ``_search_issues`` via /search/issues)."""

    def __init__(self, *, username, user, repos, orgs=None, org_repos=None,
                 contributors=None, issues=None, merged_prs=None, pull_details=None):
        self.username = username
        self.user = user
        self.repos = repos
        self.orgs = orgs or []
        self.org_repos = org_repos or {}
        self.contributors = contributors or {}   # "owner/name" -> [logins]
        self.issues = issues or []
        self.merged_prs = merged_prs or []
        self.pull_details = pull_details or {}

    def api(self, path, params=None):
        if path == "/search/issues":
            q = (params or {}).get("q", "")
            if "is:pr is:merged" in q:
                return {"items": self.merged_prs}
            if "is:issue" in q:
                return {"items": self.issues}
            return {"items": []}
        if path == f"/users/{self.username}":
            return self.user
        if path == f"/users/{self.username}/repos":
            return self.repos
        if path == f"/users/{self.username}/orgs":
            return self.orgs
        if path.startswith("/orgs/") and path.endswith("/repos"):
            return self.org_repos.get(path[len("/orgs/"):-len("/repos")], [])
        if path.startswith("/repos/") and path.endswith("/contributors"):
            slug = path[len("/repos/"):-len("/contributors")]
            return [{"login": x} for x in self.contributors.get(slug, [])]
        if path.startswith(f"/repos/{TARGET}/pulls/"):
            return self.pull_details.get(int(path.rsplit("/", 1)[1]))
        if path.endswith("/readme"):
            return None
        if path.startswith("/repos/") and path.endswith("/pulls"):
            return []
        raise AssertionError(f"unexpected API path in scenario: {path}")


def _run(fake: _FakeGitHub, *, org_members=(), allowlist=(frozenset(), frozenset())):
    members = {m.lower() for m in org_members}
    with patch("contributor_check._api", side_effect=fake.api), \
         patch("contributor_check._is_public_org_member",
               side_effect=lambda org, login: login.lower() in members), \
         patch("contributor_check._load_allowlist", return_value=allowlist):
        return check_contributor(fake.username, TARGET)


# ---------------------------------------------------------------------------
# Fixed false positives (NOT HIGH)
# ---------------------------------------------------------------------------

def test_s1_aged_repo_org_backed_specialist_not_high():
    """A domain specialist whose own repos are AGED + well-starred (source-skipped
    by feature_overlap) and who contributed to an aged repo in their org. No HIGH
    signals -> NOT HIGH. Exercises _is_established_repo_aged source-skip and
    _org_owned_established (aged repo + contributor)."""
    fake = _FakeGitHub(
        username="specialist",
        user={"login": "specialist", "created_at": _iso(800), "public_repos": 3,
              "followers": 11, "following": 20, "name": "Dev", "bio": "governance"},
        repos=[_repo("mature-gov", stars=40, days=600, owner="specialist")],
        orgs=[{"login": "myorg"}],
        org_repos={"myorg": [_repo("flagship", stars=80, days=700, owner="myorg")]},
        contributors={"myorg/flagship": ["someoneelse", "specialist"]},
        issues=[], merged_prs=[],
    )
    report = _run(fake)
    assert report.risk != "HIGH", [s.name + ":" + s.severity for s in report.signals]


def test_s5_allowlist_does_not_whitewash_split_clone():
    """A maintainer-allowlisted user who is ALSO a split-clone (>=2 feature_overlap
    HIGH) stays HIGH. The allowlist softens residual false-positives; it never
    whitewashes an abuse pattern, and it records the refusal for audit."""
    fake = _FakeGitHub(
        username="trusted",
        user={"login": "trusted", "created_at": _iso(40), "public_repos": 3,
              "followers": 0, "following": 0, "name": "", "bio": ""},
        repos=[_repo("clone-a", stars=0, days=10, owner="trusted"),
               _repo("clone-b", stars=0, days=8, owner="trusted")],
        orgs=[], issues=[], merged_prs=[],
    )
    report = _run(fake, allowlist=({"trusted"}, frozenset()))
    assert report.risk == "HIGH", [s.name + ":" + s.severity for s in report.signals]
    assert any(s.name == "allowlist_blocked" for s in report.signals)
    assert not any(s.name == "allowlisted" for s in report.signals)


# ---------------------------------------------------------------------------
# True positives / attacks that MUST stay HIGH
# ---------------------------------------------------------------------------

def test_s2_throwaway_promoter_still_high():
    """New account, no org, no prior PRs, two young bucket repos -> HIGH."""
    fake = _FakeGitHub(
        username="throwaway",
        user={"login": "throwaway", "created_at": _iso(20), "public_repos": 3,
              "followers": 0, "following": 0, "name": "", "bio": ""},
        repos=[_repo("clone-a", stars=0, days=10, owner="throwaway"),
               _repo("clone-b", stars=0, days=8, owner="throwaway")],
        orgs=[], issues=[], merged_prs=[],
    )
    report = _run(fake)
    assert report.risk == "HIGH", [s.name + ":" + s.severity for s in report.signals]


def test_s3_thin_promo_org_not_credited_still_high():
    """Org repos all thin/young -> NOT aged -> no org credit. Two young bucket
    repos (split clone) -> HIGH."""
    fake = _FakeGitHub(
        username="promo",
        user={"login": "promo", "created_at": _iso(800), "public_repos": 3,
              "followers": 11, "following": 20, "name": "P", "bio": "x"},
        repos=[_repo("clone-a", stars=0, days=15, owner="promo"),
               _repo("clone-b", stars=0, days=15, owner="promo")],
        orgs=[{"login": "freshorg"}],
        org_repos={"freshorg": [_repo("bought", stars=60, days=10, owner="freshorg")]},  # 60 stars but young -> not aged
        contributors={"freshorg/bought": ["promo"]},
        issues=[], merged_prs=[],
    )
    report = _run(fake)
    assert report.risk == "HIGH", [s.name + ":" + s.severity for s in report.signals]


def test_s4_self_merged_only_not_credited_still_high():
    """Two merged PRs but both self-merged -> prior-interaction NOT credited.
    Two young bucket repos -> HIGH."""
    fake = _FakeGitHub(
        username="selfmerge",
        user={"login": "selfmerge", "created_at": _iso(800), "public_repos": 3,
              "followers": 11, "following": 20, "name": "S", "bio": "x"},
        repos=[_repo("clone-a", stars=0, days=15, owner="selfmerge"),
               _repo("clone-b", stars=0, days=15, owner="selfmerge")],
        orgs=[], issues=[],
        merged_prs=[{"number": 1, "author_association": "CONTRIBUTOR"},
                    {"number": 2, "author_association": "CONTRIBUTOR"}],
        pull_details={1: {"merged_by": {"login": "selfmerge"}},
                      2: {"merged_by": {"login": "selfmerge"}}},
    )
    report = _run(fake, org_members={"selfmerge"})  # even if a member, self-merge does not count
    assert report.risk == "HIGH", [s.name + ":" + s.severity for s in report.signals]


def test_s6_established_but_real_abuse_still_high():
    """Established personal account, but a young thin repo is promoted across
    multiple orgs (thin_credibility, a real abuse signal) -> dampening blocked
    -> stays HIGH."""
    promoted = "scam-tool"
    fake = _FakeGitHub(
        username="vet",
        user={"login": "vet", "created_at": _iso(2000), "public_repos": 50,
              "followers": 200, "following": 30, "name": "Vet", "bio": "x"},
        repos=[_repo(promoted, stars=1, days=10, owner="vet", desc="a tool"),
               _repo("clone-a", stars=0, days=15, owner="vet"),
               _repo("clone-b", stars=0, days=15, owner="vet")],
        orgs=[],
        issues=[
            {"title": f"try {promoted}", "body": f"check out {promoted}",
             "repository_url": "https://api.github.com/repos/orgone/x",
             "created_at": _iso(5)},
            {"title": f"use {promoted}", "body": f"{promoted} is great",
             "repository_url": "https://api.github.com/repos/orgtwo/y",
             "created_at": _iso(4)},
        ],
        merged_prs=[],
    )
    report = _run(fake)
    names = {s.name for s in report.signals}
    assert "thin_credibility" in names, names
    assert report.risk == "HIGH", [s.name + ":" + s.severity for s in report.signals]

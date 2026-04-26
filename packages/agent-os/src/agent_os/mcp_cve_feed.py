# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP CVE feed integration — track known vulnerabilities in MCP server packages.

Queries public CVE databases (NVD, OSV) for vulnerabilities affecting
MCP server dependencies. Integrates with the MCP security scanner to
flag connections to servers running vulnerable versions.

Usage::

    from agent_os.mcp_cve_feed import McpCveFeed, VulnerabilityRecord

    feed = McpCveFeed()
    feed.add_package("@modelcontextprotocol/sdk", version="1.2.0")
    feed.add_package("mcp-server-sqlite", version="0.3.1")

    vulns = feed.check_all()
    for v in vulns:
        print(f"{v.package} {v.version}: {v.cve_id} ({v.severity})")
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# OSV.dev API — free, no auth required, covers npm/PyPI/crates/Go
OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass
class VulnerabilityRecord:
    """A known vulnerability affecting an MCP server package."""

    cve_id: str
    package: str
    version: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    summary: str
    affected_versions: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)
    published: Optional[str] = None
    source: str = "osv"  # osv, nvd, manual


@dataclass
class PackageEntry:
    """A tracked MCP server package."""

    name: str
    version: str
    ecosystem: str = "npm"  # npm, PyPI, crates.io, Go


class McpCveFeed:
    """Track CVE vulnerabilities for MCP server packages.

    Queries OSV.dev for known vulnerabilities. Results are cached
    per check cycle to avoid repeated API calls.

    Args:
        cache_ttl_seconds: How long to cache results. Default 3600 (1 hour).
    """

    def __init__(self, cache_ttl_seconds: int = 3600):
        self._packages: list[PackageEntry] = []
        self._cache: dict[str, list[VulnerabilityRecord]] = {}
        self._cache_time: dict[str, float] = {}
        self._cache_ttl = cache_ttl_seconds

    def add_package(
        self,
        name: str,
        version: str,
        ecosystem: str = "npm",
    ) -> None:
        """Register an MCP server package for vulnerability tracking."""
        self._packages.append(PackageEntry(name=name, version=version, ecosystem=ecosystem))

    def remove_package(self, name: str) -> bool:
        """Remove a package from tracking."""
        before = len(self._packages)
        self._packages = [p for p in self._packages if p.name != name]
        return len(self._packages) < before

    @property
    def tracked_packages(self) -> list[PackageEntry]:
        """List all tracked packages."""
        return list(self._packages)

    def check_package(self, name: str, version: str, ecosystem: str = "npm") -> list[VulnerabilityRecord]:
        """Check a single package for known vulnerabilities via OSV.dev.

        Args:
            name: Package name (e.g., "@modelcontextprotocol/sdk").
            version: Package version string.
            ecosystem: Package ecosystem (npm, PyPI, crates.io, Go).

        Returns:
            List of VulnerabilityRecord for known vulnerabilities.
        """
        cache_key = f"{ecosystem}:{name}:{version}"
        now = datetime.now(timezone.utc).timestamp()

        # Check cache
        if cache_key in self._cache:
            if now - self._cache_time.get(cache_key, 0) < self._cache_ttl:
                return self._cache[cache_key]

        vulns = self._query_osv(name, version, ecosystem)
        self._cache[cache_key] = vulns
        self._cache_time[cache_key] = now
        return vulns

    def check_all(self) -> list[VulnerabilityRecord]:
        """Check all tracked packages for vulnerabilities.

        Returns:
            Combined list of all vulnerabilities found.
        """
        all_vulns: list[VulnerabilityRecord] = []
        for pkg in self._packages:
            vulns = self.check_package(pkg.name, pkg.version, pkg.ecosystem)
            all_vulns.extend(vulns)
        return all_vulns

    def has_critical(self) -> bool:
        """Check if any tracked package has a CRITICAL vulnerability."""
        return any(v.severity == "CRITICAL" for v in self.check_all())

    def summary(self) -> dict[str, int]:
        """Get vulnerability count by severity."""
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in self.check_all():
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def _query_osv(self, name: str, version: str, ecosystem: str) -> list[VulnerabilityRecord]:
        """Query OSV.dev API for vulnerabilities."""
        payload = json.dumps({
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem,
            },
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                OSV_API_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return self._parse_osv_response(data, name, version)
        except Exception as e:
            logger.warning("OSV query failed for %s@%s: %s", name, version, e)
            return []

    def _parse_osv_response(
        self, data: dict, package: str, version: str,
    ) -> list[VulnerabilityRecord]:
        """Parse OSV API response into VulnerabilityRecord list."""
        vulns: list[VulnerabilityRecord] = []

        for vuln in data.get("vulns", []):
            # Extract severity
            severity = "UNKNOWN"
            for sev in vuln.get("severity", []):
                score_str = sev.get("score", "")
                if score_str:
                    try:
                        score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                        if score >= 9.0:
                            severity = "CRITICAL"
                        elif score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    except (ValueError, IndexError):
                        pass

            # Extract CVE ID
            cve_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            # Extract fixed version
            fixed = ""
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed = event["fixed"]

            # References
            refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

            vulns.append(VulnerabilityRecord(
                cve_id=cve_id,
                package=package,
                version=version,
                severity=severity,
                summary=vuln.get("summary", vuln.get("details", "")[:200]),
                fixed_version=fixed,
                references=refs[:5],
                published=vuln.get("published"),
                source="osv",
            ))

        return vulns

    def add_manual_advisory(self, record: VulnerabilityRecord) -> None:
        """Add a manually discovered vulnerability (not from OSV)."""
        record.source = "manual"
        cache_key = f"manual:{record.package}:{record.version}"
        existing = self._cache.get(cache_key, [])
        existing.append(record)
        self._cache[cache_key] = existing
        self._cache_time[cache_key] = datetime.now(timezone.utc).timestamp()

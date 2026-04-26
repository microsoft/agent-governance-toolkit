# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP CVE feed integration."""

import pytest
from agent_os.mcp_cve_feed import (
    McpCveFeed,
    PackageEntry,
    VulnerabilityRecord,
)


class TestPackageTracking:
    def test_add_package(self):
        feed = McpCveFeed()
        feed.add_package("@mcp/sdk", version="1.0.0")
        assert len(feed.tracked_packages) == 1
        assert feed.tracked_packages[0].name == "@mcp/sdk"

    def test_add_multiple(self):
        feed = McpCveFeed()
        feed.add_package("pkg-a", version="1.0")
        feed.add_package("pkg-b", version="2.0", ecosystem="PyPI")
        assert len(feed.tracked_packages) == 2
        assert feed.tracked_packages[1].ecosystem == "PyPI"

    def test_remove_package(self):
        feed = McpCveFeed()
        feed.add_package("pkg-a", version="1.0")
        feed.add_package("pkg-b", version="2.0")
        assert feed.remove_package("pkg-a") is True
        assert len(feed.tracked_packages) == 1
        assert feed.tracked_packages[0].name == "pkg-b"

    def test_remove_nonexistent(self):
        feed = McpCveFeed()
        assert feed.remove_package("nope") is False

    def test_default_ecosystem(self):
        feed = McpCveFeed()
        feed.add_package("pkg", version="1.0")
        assert feed.tracked_packages[0].ecosystem == "npm"


class TestManualAdvisory:
    def test_add_manual(self):
        feed = McpCveFeed()
        feed.add_manual_advisory(VulnerabilityRecord(
            cve_id="CVE-2026-99999",
            package="mcp-server-custom",
            version="0.1.0",
            severity="HIGH",
            summary="Test vulnerability",
        ))
        # Manual advisories are cached
        vulns = feed.check_all()
        # Won't appear in check_all since it's not a tracked package
        # but the cache contains it
        assert len(feed._cache) >= 1


class TestVulnerabilityRecord:
    def test_fields(self):
        v = VulnerabilityRecord(
            cve_id="CVE-2026-12345",
            package="test-pkg",
            version="1.0.0",
            severity="CRITICAL",
            summary="Buffer overflow",
            fixed_version="1.0.1",
        )
        assert v.cve_id == "CVE-2026-12345"
        assert v.severity == "CRITICAL"
        assert v.fixed_version == "1.0.1"
        assert v.source == "osv"

    def test_default_fields(self):
        v = VulnerabilityRecord(
            cve_id="X", package="p", version="1", severity="LOW", summary="s",
        )
        assert v.references == []
        assert v.published is None


class TestOsvParsing:
    def test_parse_empty_response(self):
        feed = McpCveFeed()
        result = feed._parse_osv_response({}, "pkg", "1.0")
        assert result == []

    def test_parse_no_vulns(self):
        feed = McpCveFeed()
        result = feed._parse_osv_response({"vulns": []}, "pkg", "1.0")
        assert result == []

    def test_parse_vuln_with_cve_alias(self):
        feed = McpCveFeed()
        result = feed._parse_osv_response({
            "vulns": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "aliases": ["CVE-2026-12345"],
                "summary": "Test vuln",
                "severity": [{"score": "9.1"}],
                "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
                "references": [{"url": "https://example.com"}],
            }]
        }, "test-pkg", "1.0.0")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2026-12345"
        assert result[0].severity == "CRITICAL"
        assert result[0].fixed_version == "2.0.0"
        assert result[0].package == "test-pkg"

    def test_parse_severity_levels(self):
        feed = McpCveFeed()
        for score, expected in [("9.5", "CRITICAL"), ("7.5", "HIGH"), ("5.0", "MEDIUM"), ("2.0", "LOW")]:
            result = feed._parse_osv_response({
                "vulns": [{"id": "X", "summary": "t", "severity": [{"score": score}]}]
            }, "p", "1")
            assert result[0].severity == expected, f"Score {score} should be {expected}"


class TestSummary:
    def test_empty_summary(self):
        feed = McpCveFeed()
        s = feed.summary()
        assert s == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    def test_has_critical_false(self):
        feed = McpCveFeed()
        assert feed.has_critical() is False


class TestCaching:
    def test_cache_hit(self):
        feed = McpCveFeed(cache_ttl_seconds=3600)
        # Pre-populate cache
        feed._cache["npm:test:1.0"] = [
            VulnerabilityRecord(cve_id="CVE-1", package="test", version="1.0",
                                severity="HIGH", summary="cached")
        ]
        feed._cache_time["npm:test:1.0"] = __import__("time").time()

        result = feed.check_package("test", "1.0", "npm")
        assert len(result) == 1
        assert result[0].summary == "cached"

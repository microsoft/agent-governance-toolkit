"""Tests for scanner base classes and registry."""

import pytest

from agent_discovery.scanners.base import BaseScanner, ScannerRegistry
from agent_discovery.models import ScanResult


class MockScanner(BaseScanner):
    @property
    def name(self):
        return "mock"

    @property
    def description(self):
        return "A mock scanner for testing"

    async def scan(self, **kwargs):
        return ScanResult(scanner_name=self.name)


class TestScannerRegistry:
    def test_register_and_get(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        scanner = reg.get("mock")
        assert scanner is not None
        assert scanner.name == "mock"

    def test_get_nonexistent(self):
        reg = ScannerRegistry()
        assert reg.get("nonexistent") is None

    def test_list_scanners(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        assert "mock" in reg.list_scanners()

    def test_get_all(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        scanners = reg.get_all()
        assert len(scanners) >= 1
        assert any(s.name == "mock" for s in scanners)


class TestGlobalRegistry:
    def test_builtin_scanners_registered(self):
        from agent_discovery.scanners.base import registry
        names = registry.list_scanners()
        assert "process" in names
        assert "config" in names
        assert "github" in names

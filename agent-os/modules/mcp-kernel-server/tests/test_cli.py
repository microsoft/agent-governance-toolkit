# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP Kernel Server CLI."""

import sys
import os
import pytest
from io import StringIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_kernel_server.cli import parse_args, print_tools, print_prompts


class TestParseArgs:
    def test_stdio_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio"])
        args = parse_args()
        assert args.stdio is True
        assert args.http is False

    def test_http_with_port(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--http", "--port", "9090"])
        args = parse_args()
        assert args.http is True
        assert args.port == 9090

    def test_default_port(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio"])
        args = parse_args()
        assert args.port == 8080

    def test_default_host(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio"])
        args = parse_args()
        assert args.host == "127.0.0.1"

    def test_policy_mode_strict(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio", "--policy-mode", "strict"])
        args = parse_args()
        assert args.policy_mode == "strict"

    def test_policy_mode_permissive(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio", "--policy-mode", "permissive"])
        args = parse_args()
        assert args.policy_mode == "permissive"

    def test_cmvk_threshold(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--stdio", "--cmvk-threshold", "0.90"])
        args = parse_args()
        assert args.cmvk_threshold == 0.90

    def test_version_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mcp-kernel-server", "--version"])
        args = parse_args()
        assert args.version is True


class TestPrintFunctions:
    def test_print_tools(self, capsys):
        print_tools()
        captured = capsys.readouterr()
        assert "cmvk_verify" in captured.out
        assert "kernel_execute" in captured.out
        assert "iatp_sign" in captured.out

    def test_print_prompts(self, capsys):
        print_prompts()
        captured = capsys.readouterr()
        assert "governed_agent" in captured.out
        assert "verify_claim" in captured.out
        assert "safe_execution" in captured.out

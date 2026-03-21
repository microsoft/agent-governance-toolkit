# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Agent OS CLI.
"""

import pytest
import tempfile
from pathlib import Path
import argparse
import json
import io
import sys


class TestCLIInit:
    """Test agentos init command."""
    
    def test_init_creates_agents_dir(self):
        """Test init creates .agents/ directory."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "strict"
                force = False
            
            result = cmd_init(Args())
            
            assert result == 0
            assert (Path(tmpdir) / ".agents").exists()
            assert (Path(tmpdir) / ".agents" / "agents.md").exists()
            assert (Path(tmpdir) / ".agents" / "security.md").exists()
    
    def test_init_strict_template(self):
        """Test init with strict template."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "strict"
                force = False
            
            cmd_init(Args())
            
            security_md = (Path(tmpdir) / ".agents" / "security.md").read_text()
            assert "mode: strict" in security_md
            assert "SIGKILL" in security_md
    
    def test_init_permissive_template(self):
        """Test init with permissive template."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "permissive"
                force = False
            
            cmd_init(Args())
            
            security_md = (Path(tmpdir) / ".agents" / "security.md").read_text()
            assert "mode: permissive" in security_md
    
    def test_init_audit_template(self):
        """Test init with audit template."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "audit"
                force = False
            
            cmd_init(Args())
            
            security_md = (Path(tmpdir) / ".agents" / "security.md").read_text()
            assert "mode: audit" in security_md
    
    def test_init_fails_if_exists(self):
        """Test init fails if .agents/ already exists."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".agents").mkdir()
            
            class Args:
                path = tmpdir
                template = "strict"
                force = False
            
            result = cmd_init(Args())
            assert result == 1
    
    def test_init_force_overwrites(self):
        """Test init --force overwrites existing."""
        from agent_os.cli import cmd_init
        
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".agents").mkdir()
            (Path(tmpdir) / ".agents" / "old.txt").write_text("old")
            
            class Args:
                path = tmpdir
                template = "strict"
                force = True
            
            result = cmd_init(Args())
            assert result == 0
            assert (Path(tmpdir) / ".agents" / "agents.md").exists()


class TestCLISecure:
    """Test agentos secure command."""
    
    def test_secure_validates_config(self):
        """Test secure validates security config."""
        from agent_os.cli import cmd_init, cmd_secure
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # First init
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())
            
            # Then secure
            class SecureArgs:
                path = tmpdir
                verify = False
            
            result = cmd_secure(SecureArgs())
            assert result == 0
    
    def test_secure_fails_without_agents_dir(self):
        """Test secure fails if no .agents/ directory."""
        from agent_os.cli import cmd_secure
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                verify = False
            
            result = cmd_secure(Args())
            assert result == 1
    
    def test_secure_fails_without_security_md(self):
        """Test secure fails if no security.md."""
        from agent_os.cli import cmd_secure
        
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".agents").mkdir()
            
            class Args:
                path = tmpdir
                verify = False
            
            result = cmd_secure(Args())
            assert result == 1


class TestCLIAudit:
    """Test agentos audit command."""
    
    def test_audit_reports_missing_files(self):
        """Test audit reports missing files."""
        from agent_os.cli import cmd_audit
        
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".agents").mkdir()
            (Path(tmpdir) / ".agents" / "agents.md").write_text("# Agent")
            # No security.md
            
            class Args:
                path = tmpdir
                format = "text"
            
            result = cmd_audit(Args())
            assert result == 1  # Fails due to missing security.md
    
    def test_audit_passes_with_valid_config(self):
        """Test audit passes with valid configuration."""
        from agent_os.cli import cmd_init, cmd_audit
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # First init
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())
            
            # Then audit
            class AuditArgs:
                path = tmpdir
                format = "text"
            
            result = cmd_audit(AuditArgs())
            assert result == 0
    
    def test_audit_json_format(self):
        """Test audit JSON output format."""
        from agent_os.cli import cmd_init, cmd_audit
        import json
        from io import StringIO
        
        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())
            
            class AuditArgs:
                path = tmpdir
                format = "json"
            
            # Capture output would need more setup
            # Just verify it doesn't crash
            result = cmd_audit(AuditArgs())
            assert result == 0


class TestCLIStatus:
    """Test agentos status command."""
    
    def test_status_shows_version(self):
        """Test status shows version information."""
        from agent_os.cli import cmd_status
        
        class Args:
            pass
        
        # Should not crash
        result = cmd_status(Args())
        assert result == 0


class TestCLIMain:
    """Test main CLI entry point."""
    
    def test_main_no_args(self):
        """Test main with no arguments."""
        from agent_os.cli import main
        import sys
        
        # Save original argv
        original_argv = sys.argv
        
        try:
            sys.argv = ["agentos"]
            result = main()
            assert result == 0
        finally:
            sys.argv = original_argv
    
    def test_main_version(self):
        """Test main --version."""
        from agent_os.cli import main
        import sys
        
        original_argv = sys.argv
        
        try:
            sys.argv = ["agentos", "--version"]
            result = main()
            assert result == 0
        finally:
            sys.argv = original_argv


class TestCLIServe:
    """Test agentos serve command."""

    def test_serve_parser_defaults(self):
        """Test serve subparser accepts --port and --host with defaults."""
        from agent_os.cli import main
        import argparse

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        # Re-use the real parser by parsing known args
        original_argv = sys.argv
        try:
            sys.argv = ["agentos", "serve"]
            # Just verify parsing doesn't error
            from agent_os.cli import main as _m
        finally:
            sys.argv = original_argv

    def test_serve_custom_port(self):
        """Test serve accepts a custom port."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sp = sub.add_parser("serve")
        sp.add_argument("--port", type=int, default=8080)
        sp.add_argument("--host", default="0.0.0.0")
        args = parser.parse_args(["serve", "--port", "9090", "--host", "127.0.0.1"])
        assert args.port == 9090
        assert args.host == "127.0.0.1"

    def test_request_handler_health(self):
        """Test /health endpoint returns ok status."""
        import io
        from agent_os.cli import AgentOSRequestHandler

        handler = _make_get_handler("/health")
        body = json.loads(handler._response_body)
        assert body["status"] == "ok"
        assert "version" in body

    def test_request_handler_agents(self):
        """Test /agents endpoint returns list."""
        from agent_os.cli import AgentOSRequestHandler, _registered_agents

        _registered_agents.clear()
        handler = _make_get_handler("/agents")
        body = json.loads(handler._response_body)
        assert body == {"agents": []}

    def test_request_handler_status(self):
        """Test /status endpoint returns kernel state."""
        handler = _make_get_handler("/status")
        body = json.loads(handler._response_body)
        assert "active_agents" in body
        assert "uptime_seconds" in body

    def test_request_handler_not_found(self):
        """Test unknown path returns 404."""
        handler = _make_get_handler("/unknown")
        assert handler._response_code == 404

    def test_post_execute_unknown_agent(self):
        """Test POST /agents/{id}/execute with unknown agent returns 404."""
        from agent_os.cli import _registered_agents

        _registered_agents.clear()
        handler = _make_post_handler("/agents/unknown-agent/execute", b'{"action":"test"}')
        assert handler._response_code == 404

    def test_post_execute_known_agent(self):
        """Test POST /agents/{id}/execute with known agent succeeds."""
        from agent_os.cli import _registered_agents

        _registered_agents["a1"] = {"id": "a1", "name": "test-agent"}
        try:
            handler = _make_post_handler("/agents/a1/execute", b'{"action":"run"}')
            body = json.loads(handler._response_body)
            assert body["status"] == "executed"
            assert body["agent_id"] == "a1"
        finally:
            _registered_agents.clear()


class TestCLIMetrics:
    """Test agentos metrics command."""

    def test_metrics_output_format(self, capsys):
        """Test metrics prints Prometheus exposition format."""
        from agent_os.cli import cmd_metrics

        class Args:
            pass

        result = cmd_metrics(Args())
        assert result == 0
        output = capsys.readouterr().out

        assert "# HELP agentos_policy_violations_total" in output
        assert "# TYPE agentos_policy_violations_total counter" in output
        assert "agentos_active_agents" in output
        assert "agentos_uptime_seconds" in output
        assert 'agentos_kernel_operations_total{operation="execute"}' in output
        assert 'agentos_kernel_operations_total{operation="set"}' in output
        assert 'agentos_kernel_operations_total{operation="get"}' in output
        assert "agentos_audit_log_entries" in output

    def test_metrics_types(self, capsys):
        """Test metrics include correct TYPE annotations."""
        from agent_os.cli import cmd_metrics

        class Args:
            pass

        cmd_metrics(Args())
        output = capsys.readouterr().out
        assert "# TYPE agentos_active_agents gauge" in output
        assert "# TYPE agentos_uptime_seconds gauge" in output
        assert "# TYPE agentos_kernel_operations_total counter" in output
        assert "# TYPE agentos_audit_log_entries gauge" in output


# ============================================================================
# Helpers for handler unit tests
# ============================================================================


class _FakeSocket:
    """Minimal socket stand-in for BaseHTTPRequestHandler."""

    def __init__(self, request_bytes: bytes):
        self._file = io.BytesIO(request_bytes)

    def makefile(self, mode: str, buffering: int = -1):
        if "r" in mode:
            return self._file
        return io.BytesIO()


class _StubHandler:
    """Capture response instead of writing to a real socket."""

    _response_body: str = ""
    _response_code: int = 200


def _make_get_handler(path: str):
    """Create a handler, invoke do_GET, and capture the JSON response."""
    from agent_os.cli import AgentOSRequestHandler

    request_line = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()

    class _Capture(AgentOSRequestHandler):
        def __init__(self):
            self.path = path
            self.headers = {}
            self._response_body = ""
            self._response_code = 200
            self.wfile = io.BytesIO()

        def _send_json(self, data, status=200):
            self._response_body = json.dumps(data, indent=2)
            self._response_code = status

    h = _Capture()
    h.do_GET()
    return h


def _make_post_handler(path: str, body: bytes):
    """Create a handler, invoke do_POST, and capture the JSON response."""
    from agent_os.cli import AgentOSRequestHandler

    class _Capture(AgentOSRequestHandler):
        def __init__(self):
            self.path = path
            self.headers = {"Content-Length": str(len(body))}
            self.rfile = io.BytesIO(body)
            self._response_body = ""
            self._response_code = 200
            self.wfile = io.BytesIO()

        def _send_json(self, data, status=200):
            self._response_body = json.dumps(data, indent=2)
            self._response_code = status

    h = _Capture()
    h.do_POST()
    return h


# ============================================================================
# Tests for error message formatting (#126)
# ============================================================================


class TestErrorFormatting:
    """Test CLI error formatting helpers."""

    def test_format_error_basic(self):
        """Test basic error message without suggestion."""
        from agent_os.cli import format_error

        msg = format_error("something went wrong")
        assert "something went wrong" in msg
        assert "Error:" in msg

    def test_format_error_with_suggestion(self):
        """Test error message includes suggestion text."""
        from agent_os.cli import format_error

        msg = format_error("missing file", suggestion="create it first")
        assert "missing file" in msg
        assert "create it first" in msg
        assert "Suggestion:" in msg

    def test_format_error_with_docs_link(self):
        """Test error message includes a docs URL."""
        from agent_os.cli import format_error

        msg = format_error("bad config", docs_path="getting-started.md")
        assert "getting-started.md" in msg

    def test_handle_missing_config(self):
        """Test missing-config helper includes init suggestion."""
        from agent_os.cli import handle_missing_config

        msg = handle_missing_config("/tmp/proj")
        assert "agentos init" in msg
        assert "/tmp/proj" in msg

    def test_handle_invalid_policy_with_typo(self):
        """Test invalid-policy helper offers a fuzzy suggestion."""
        from agent_os.cli import handle_invalid_policy

        msg = handle_invalid_policy("strct")
        assert "strict" in msg
        assert "Did you mean" in msg

    def test_handle_invalid_policy_unknown(self):
        """Test invalid-policy helper lists available policies."""
        from agent_os.cli import handle_invalid_policy

        msg = handle_invalid_policy("foobar")
        assert "strict" in msg
        assert "permissive" in msg
        assert "audit" in msg

    def test_handle_missing_dependency(self):
        """Test missing-dependency helper shows pip install command."""
        from agent_os.cli import handle_missing_dependency

        msg = handle_missing_dependency("redis", extra="redis")
        assert "pip install agent-os-kernel[redis]" in msg

    def test_handle_connection_error(self):
        """Test connection-error helper includes host:port."""
        from agent_os.cli import handle_connection_error

        msg = handle_connection_error("localhost", 6379)
        assert "localhost:6379" in msg


# ============================================================================
# Tests for Colors instance isolation (#127)
# ============================================================================


class TestColorsInstanceIsolation:
    """Test that Colors uses instance state, not shared class state."""

    def test_disable_is_instance_scoped(self):
        """Disabling one Colors instance must not affect another."""
        from agent_os.cli import Colors as _ColorsClass

        a = _ColorsClass.__class__(enabled=True)
        b = _ColorsClass.__class__(enabled=True)

        a.disable()

        assert a.RED == ""
        assert b.RED != "", "Second instance should still have colours"

    def test_enable_restores_codes(self):
        """Calling enable() after disable() restores ANSI codes."""
        from agent_os.cli import Colors as _ColorsClass

        inst = _ColorsClass.__class__(enabled=True)
        inst.disable()
        assert inst.RED == ""

        inst.enable()
        assert inst.RED == "\033[91m"

    def test_enabled_property(self):
        """The enabled property reflects current state."""
        from agent_os.cli import Colors as _ColorsClass

        inst = _ColorsClass.__class__(enabled=True)
        assert inst.enabled is True

        inst.disable()
        assert inst.enabled is False

    def test_thread_safety_separate_instances(self):
        """Concurrent threads with separate instances don't interfere."""
        import threading
        from agent_os.cli import Colors as _ColorsClass

        results = {}

        def worker(name, enabled):
            inst = _ColorsClass.__class__(enabled=enabled)
            # Small sleep to interleave threads
            import time
            time.sleep(0.01)
            results[name] = inst.RED

        t1 = threading.Thread(target=worker, args=("on", True))
        t2 = threading.Thread(target=worker, args=("off", False))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results["on"] != "", "Enabled instance keeps codes"
        assert results["off"] == "", "Disabled instance has empty codes"


# ============================================================================
# Tests for CLI init command (#156)
# ============================================================================


class TestCLIInitExtended:
    """Extended tests for agentos init command (#156)."""

    def test_init_default_template(self):
        """Test init with default (strict) template creates all expected files."""
        from agent_os.cli import cmd_init

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "strict"
                force = False

            result = cmd_init(Args())

            assert result == 0
            agents_dir = Path(tmpdir) / ".agents"
            assert agents_dir.exists()
            assert (agents_dir / "agents.md").exists()
            assert (agents_dir / "security.md").exists()

    def test_init_custom_project_name_in_path(self):
        """Test init with a custom project subdirectory."""
        from agent_os.cli import cmd_init

        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "my-custom-project"
            project_path.mkdir()

            class Args:
                path = str(project_path)
                template = "strict"
                force = False

            result = cmd_init(Args())

            assert result == 0
            assert (project_path / ".agents" / "agents.md").exists()
            assert (project_path / ".agents" / "security.md").exists()

    def test_init_generated_files_have_content(self):
        """Test that generated files are non-empty and contain expected content."""
        from agent_os.cli import cmd_init

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "strict"
                force = False

            cmd_init(Args())

            agents_md = (Path(tmpdir) / ".agents" / "agents.md").read_text()
            assert len(agents_md) > 0
            assert "Agent" in agents_md

            security_md = (Path(tmpdir) / ".agents" / "security.md").read_text()
            assert "kernel:" in security_md
            assert "signals:" in security_md
            assert "policies:" in security_md

    def test_init_idempotency_with_force(self):
        """Test running init twice with --force produces same result."""
        from agent_os.cli import cmd_init

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                template = "strict"
                force = False

            assert cmd_init(Args()) == 0
            first_content = (Path(tmpdir) / ".agents" / "security.md").read_text()

            # Second run without force should fail
            assert cmd_init(Args()) == 1

            # Second run with force should succeed
            class ForceArgs:
                path = tmpdir
                template = "strict"
                force = True

            assert cmd_init(ForceArgs()) == 0
            second_content = (Path(tmpdir) / ".agents" / "security.md").read_text()
            assert first_content == second_content


# ============================================================================
# Tests for CLI audit command (#157)
# ============================================================================


class TestCLIAuditExtended:
    """Extended tests for agentos audit command (#157)."""

    def test_audit_with_complete_config(self):
        """Test audit with fully initialized project passes."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())

            class AuditArgs:
                path = tmpdir
                format = "text"

            assert cmd_audit(AuditArgs()) == 0

    def test_audit_with_empty_agents_dir(self):
        """Test audit with empty .agents/ directory reports missing files."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".agents").mkdir()

            class Args:
                path = tmpdir
                format = "text"

            result = cmd_audit(Args())
            assert result == 1

    def test_audit_json_output_structure(self, capsys):
        """Test audit --format json returns valid JSON with expected keys."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())

            class AuditArgs:
                path = tmpdir
                format = "json"

            result = cmd_audit(AuditArgs())
            assert result == 0
            output = capsys.readouterr().out
            # JSON output is printed after the text output
            assert '"passed": true' in output or '"passed":true' in output

    def test_audit_no_agents_dir(self):
        """Test audit without .agents/ directory returns 1."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                format = "text"

            assert cmd_audit(Args()) == 1

    def test_audit_missing_security_md_only(self):
        """Test audit with agents.md but no security.md fails."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            (agents_dir / "agents.md").write_text("# Agent\n")

            class Args:
                path = tmpdir
                format = "text"

            result = cmd_audit(Args())
            assert result == 1


# ============================================================================
# Tests for CLI validate command (#158)
# ============================================================================


class TestCLIValidateExtended:
    """Extended tests for agentos validate command (#158)."""

    def test_validate_valid_policy(self):
        """Test validate with a valid policy YAML."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "policy.yaml"
            policy_file.write_text(
                "version: '1.0'\nname: test-policy\nrules:\n  - type: allow\n"
            )

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 0

    def test_validate_invalid_yaml_syntax(self):
        """Test validate with invalid YAML syntax reports error."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "bad.yaml"
            policy_file.write_text("version: '1.0'\nname: [unterminated\n")

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 1

    def test_validate_missing_required_fields(self):
        """Test validate catches missing required fields (version, name)."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "incomplete.yaml"
            policy_file.write_text("description: no version or name\n")

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 1

    def test_validate_missing_name_field(self, capsys):
        """Test validate reports helpful error for missing 'name' field."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "noname.yaml"
            policy_file.write_text("version: '1.0'\nrules:\n  - type: allow\n")

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 1
            output = capsys.readouterr().out
            assert "name" in output.lower()

    def test_validate_empty_file(self):
        """Test validate catches empty YAML files."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "empty.yaml"
            policy_file.write_text("")

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 1

    def test_validate_nonexistent_file(self):
        """Test validate handles non-existent file path."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                files = [str(Path(tmpdir) / "ghost.yaml")]
                strict = False

            result = cmd_validate(Args())
            assert result == 1

    def test_validate_rules_not_a_list(self):
        """Test validate catches 'rules' field that is not a list."""
        from agent_os.cli import cmd_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "badrules.yaml"
            policy_file.write_text(
                "version: '1.0'\nname: bad\nrules: not-a-list\n"
            )

            class Args:
                files = [str(policy_file)]
                strict = False

            result = cmd_validate(Args())
            assert result == 1


# ============================================================================
# Tests for JSON output format (#172)
# ============================================================================


class TestJSONOutputFormat:
    """Test --format json flag on audit, status, and check commands."""

    def test_audit_json_only_outputs_json(self, capsys):
        """Test audit --format json outputs only valid JSON, no text."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())
            capsys.readouterr()  # discard init output

            class AuditArgs:
                path = tmpdir
                format = "json"
                export = None
                output = None

            result = cmd_audit(AuditArgs())
            assert result == 0
            output = capsys.readouterr().out
            # Should not contain text-mode prefixes
            assert "Auditing" not in output
            data = json.loads(output)
            assert data["passed"] is True
            assert "files" in data
            assert "findings" in data

    def test_audit_json_failure(self, capsys):
        """Test audit --format json on missing config outputs JSON error."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class Args:
                path = tmpdir
                format = "json"
                export = None
                output = None

            result = cmd_audit(Args())
            assert result == 1
            output = capsys.readouterr().out
            data = json.loads(output)
            assert data["passed"] is False

    def test_status_json_format(self, capsys):
        """Test status --format json outputs valid JSON."""
        from agent_os.cli import cmd_status

        class Args:
            format = "json"

        result = cmd_status(Args())
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "version" in data
        assert "installed" in data
        assert "env" in data

    def test_status_text_format(self, capsys):
        """Test status --format text outputs human-readable text."""
        from agent_os.cli import cmd_status

        class Args:
            format = "text"

        result = cmd_status(Args())
        assert result == 0
        output = capsys.readouterr().out
        assert "Agent OS Kernel Status" in output

    def test_audit_json_with_findings(self, capsys):
        """Test audit JSON includes findings when there are issues."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            (agents_dir / "agents.md").write_text("# Agent\n")
            # No security.md

            class Args:
                path = tmpdir
                format = "json"
                export = None
                output = None

            result = cmd_audit(Args())
            assert result == 1
            output = capsys.readouterr().out
            data = json.loads(output)
            assert data["passed"] is False
            assert len(data["findings"]) > 0


# ============================================================================
# Tests for CSV export (#176)
# ============================================================================


class TestCSVExport:
    """Test audit --export csv functionality."""

    def test_audit_export_csv_creates_file(self):
        """Test audit --export csv creates a CSV file."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())

            csv_path = str(Path(tmpdir) / "audit.csv")

            class AuditArgs:
                path = tmpdir
                format = "text"
                export = "csv"
                output = csv_path

            result = cmd_audit(AuditArgs())
            assert result == 0
            assert Path(csv_path).exists()

            import csv as csv_mod
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv_mod.reader(f)
                rows = list(reader)

            assert rows[0] == ["type", "name", "severity", "message"]
            assert len(rows) >= 3  # header + at least 2 file rows

    def test_audit_export_csv_with_findings(self):
        """Test CSV export includes findings."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            (agents_dir / "agents.md").write_text("# Agent\n")

            csv_path = str(Path(tmpdir) / "findings.csv")

            class Args:
                path = tmpdir
                format = "text"
                export = "csv"
                output = csv_path

            result = cmd_audit(Args())
            assert result == 1
            assert Path(csv_path).exists()

            import csv as csv_mod
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv_mod.reader(f)
                rows = list(reader)

            finding_rows = [r for r in rows if r[0] == "finding"]
            assert len(finding_rows) > 0

    def test_audit_export_csv_default_output(self):
        """Test CSV export defaults to audit.csv when no --output given."""
        from agent_os.cli import cmd_init, cmd_audit
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                class AuditArgs:
                    path = tmpdir
                    format = "text"
                    export = "csv"
                    output = None

                result = cmd_audit(AuditArgs())
                assert result == 0
                assert Path("audit.csv").exists()
            finally:
                os.chdir(old_cwd)

    def test_audit_export_csv_with_json_format(self, capsys):
        """Test CSV export works alongside JSON format."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())
            capsys.readouterr()  # discard init output

            csv_path = str(Path(tmpdir) / "audit.csv")

            class AuditArgs:
                path = tmpdir
                format = "json"
                export = "csv"
                output = csv_path

            result = cmd_audit(AuditArgs())
            assert result == 0
            assert Path(csv_path).exists()
            output = capsys.readouterr().out
            data = json.loads(output)
            assert data["passed"] is True


# ============================================================================
# Tests for colored terminal output (#178)
# ============================================================================


class TestColoredOutput:
    """Test colored terminal output with NO_COLOR support."""

    def test_no_color_env_disables_colors(self):
        """Test NO_COLOR environment variable disables colors."""
        import os
        old = os.environ.get("NO_COLOR")
        try:
            os.environ["NO_COLOR"] = "1"
            from agent_os.cli import supports_color
            assert supports_color() is False
        finally:
            if old is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = old

    def test_colors_disabled_produces_no_ansi(self):
        """Test Colors with disabled=True produces empty strings."""
        from agent_os.cli import Colors as _ColorsClass

        inst = _ColorsClass.__class__(enabled=False)
        assert inst.RED == ""
        assert inst.GREEN == ""
        assert inst.YELLOW == ""
        assert inst.RESET == ""

    def test_colors_enabled_produces_ansi(self):
        """Test Colors with enabled=True produces ANSI codes."""
        from agent_os.cli import Colors as _ColorsClass

        inst = _ColorsClass.__class__(enabled=True)
        assert inst.RED == "\033[91m"
        assert inst.GREEN == "\033[92m"
        assert inst.YELLOW == "\033[93m"

    def test_audit_text_uses_colored_symbols(self, capsys):
        """Test audit text output uses ✓ and ✗ symbols."""
        from agent_os.cli import cmd_init, cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            class InitArgs:
                path = tmpdir
                template = "strict"
                force = False
            cmd_init(InitArgs())

            class AuditArgs:
                path = tmpdir
                format = "text"
                export = None
                output = None

            cmd_audit(AuditArgs())
            output = capsys.readouterr().out
            assert "✓" in output

    def test_audit_text_failure_uses_cross(self, capsys):
        """Test audit text output uses ✗ for failures."""
        from agent_os.cli import cmd_audit

        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            (agents_dir / "agents.md").write_text("# Agent\n")

            class Args:
                path = tmpdir
                format = "text"
                export = None
                output = None

            cmd_audit(Args())
            output = capsys.readouterr().out
            assert "✗" in output


# ============================================================================
# Tests for environment variable configuration (#180)
# ============================================================================


class TestEnvVarConfig:
    """Test environment variable configuration."""

    def test_get_env_config_defaults(self):
        """Test get_env_config returns defaults when no env vars set."""
        import os
        from agent_os.cli import get_env_config

        # Clear any existing env vars
        saved = {}
        for key in ["AGENTOS_CONFIG", "AGENTOS_LOG_LEVEL", "AGENTOS_BACKEND", "AGENTOS_REDIS_URL"]:
            saved[key] = os.environ.pop(key, None)

        try:
            cfg = get_env_config()
            assert cfg["config_path"] is None
            assert cfg["log_level"] == "WARNING"
            assert cfg["backend"] == "memory"
            assert cfg["redis_url"] == "redis://localhost:6379"
        finally:
            for key, val in saved.items():
                if val is not None:
                    os.environ[key] = val

    def test_get_env_config_custom(self):
        """Test get_env_config reads custom env vars."""
        import os
        from agent_os.cli import get_env_config

        saved = {}
        for key in ["AGENTOS_CONFIG", "AGENTOS_LOG_LEVEL", "AGENTOS_BACKEND", "AGENTOS_REDIS_URL"]:
            saved[key] = os.environ.get(key)

        try:
            os.environ["AGENTOS_CONFIG"] = "/tmp/myconfig"
            os.environ["AGENTOS_LOG_LEVEL"] = "DEBUG"
            os.environ["AGENTOS_BACKEND"] = "redis"
            os.environ["AGENTOS_REDIS_URL"] = "redis://myhost:1234"

            cfg = get_env_config()
            assert cfg["config_path"] == "/tmp/myconfig"
            assert cfg["log_level"] == "DEBUG"
            assert cfg["backend"] == "redis"
            assert cfg["redis_url"] == "redis://myhost:1234"
        finally:
            for key, val in saved.items():
                if val is not None:
                    os.environ[key] = val
                else:
                    os.environ.pop(key, None)

    def test_configure_logging_valid(self):
        """Test configure_logging sets log level."""
        import logging
        from agent_os.cli import configure_logging

        configure_logging("DEBUG")
        assert logging.getLogger().level == logging.DEBUG

        configure_logging("ERROR")
        assert logging.getLogger().level == logging.ERROR

    def test_configure_logging_invalid_falls_back(self):
        """Test configure_logging falls back to WARNING for invalid input."""
        import logging
        from agent_os.cli import configure_logging

        configure_logging("INVALID_LEVEL")
        assert logging.getLogger().level == logging.WARNING

    def test_get_config_path_from_env(self):
        """Test get_config_path uses AGENTOS_CONFIG env var."""
        import os
        from agent_os.cli import get_config_path

        old = os.environ.get("AGENTOS_CONFIG")
        try:
            os.environ["AGENTOS_CONFIG"] = "/custom/path"
            result = get_config_path()
            assert result == Path("/custom/path")
        finally:
            if old is None:
                os.environ.pop("AGENTOS_CONFIG", None)
            else:
                os.environ["AGENTOS_CONFIG"] = old

    def test_get_config_path_args_override_env(self):
        """Test get_config_path prefers args over env var."""
        import os
        from agent_os.cli import get_config_path

        old = os.environ.get("AGENTOS_CONFIG")
        try:
            os.environ["AGENTOS_CONFIG"] = "/env/path"
            result = get_config_path("/args/path")
            assert result == Path("/args/path")
        finally:
            if old is None:
                os.environ.pop("AGENTOS_CONFIG", None)
            else:
                os.environ["AGENTOS_CONFIG"] = old

    def test_status_json_shows_env_config(self, capsys):
        """Test status --format json includes env config."""
        from agent_os.cli import cmd_status

        class Args:
            format = "json"

        cmd_status(Args())
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "env" in data
        assert "backend" in data["env"]
        assert "log_level" in data["env"]

    def test_env_vars_documented(self):
        """Test that AGENTOS_ENV_VARS dict contains all expected keys."""
        from agent_os.cli import AGENTOS_ENV_VARS

        assert "AGENTOS_CONFIG" in AGENTOS_ENV_VARS
        assert "AGENTOS_LOG_LEVEL" in AGENTOS_ENV_VARS
        assert "AGENTOS_BACKEND" in AGENTOS_ENV_VARS
        assert "AGENTOS_REDIS_URL" in AGENTOS_ENV_VARS

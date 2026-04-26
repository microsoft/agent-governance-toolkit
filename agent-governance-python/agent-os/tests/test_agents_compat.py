# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test AGENTS.md compatibility module.
"""

import pytest
import tempfile
from pathlib import Path


class TestAgentsParser:
    """Test AgentsParser class."""
    
    def test_import_agents_compat(self):
        """Test importing agents_compat module."""
        from agent_os.agents_compat import (
            AgentsParser,
            AgentConfig,
            AgentSkill,
            discover_agents,
        )
        assert AgentsParser is not None
        assert AgentConfig is not None
    
    def test_create_parser(self):
        """Test creating a parser."""
        from agent_os.agents_compat import AgentsParser
        
        parser = AgentsParser()
        assert parser is not None
    
    def test_parse_skill_bullet_list(self):
        """Test parsing skill bullet lists."""
        from agent_os.agents_compat import AgentsParser
        
        parser = AgentsParser()
        skills = parser._parse_skills("""
- Query databases
- Generate reports
- Send emails
""")
        
        assert len(skills) == 3
        assert skills[0].description == "Query databases"
        assert skills[1].description == "Generate reports"
        assert skills[2].description == "Send emails"
    
    def test_parse_skill_with_read_only(self):
        """Test parsing skills with (read-only) modifier."""
        from agent_os.agents_compat import AgentsParser
        
        parser = AgentsParser()
        skills = parser._parse_skills("""
- Query databases (read-only)
- Read files (read only)
""")
        
        assert skills[0].read_only is True
        assert skills[1].read_only is True
    
    def test_parse_skill_with_approval(self):
        """Test parsing skills with (requires approval) modifier."""
        from agent_os.agents_compat import AgentsParser
        
        parser = AgentsParser()
        skills = parser._parse_skills("""
- Send emails (requires approval)
- Delete files (requires approval)
""")
        
        assert skills[0].requires_approval is True
        assert skills[1].requires_approval is True
    
    def test_skill_to_action(self):
        """Test converting skill descriptions to action names."""
        from agent_os.agents_compat import AgentsParser
        
        parser = AgentsParser()
        
        assert parser._skill_to_action("Query databases") == "database_query"
        assert parser._skill_to_action("Send email") == "send_email"
        assert parser._skill_to_action("Write file") == "file_write"
        assert parser._skill_to_action("Call API") == "api_call"
    
    def test_parse_agents_md_file(self):
        """Test parsing actual agents.md file."""
        from agent_os.agents_compat import AgentsParser
        
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            
            agents_md = agents_dir / "agents.md"
            agents_md.write_text("""# Data Analyst Agent

You are a data analyst agent.

## Capabilities

You can:
- Query databases (read-only)
- Generate visualizations
- Export to PDF
""")
            
            parser = AgentsParser()
            config = parser.parse_directory(str(agents_dir))
            
            assert config is not None
            assert len(config.skills) == 3
            assert config.skills[0].read_only is True
    
    def test_parse_security_md_file(self):
        """Test parsing security.md extension."""
        from agent_os.agents_compat import AgentsParser
        
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            
            (agents_dir / "agents.md").write_text("# Agent")
            
            security_md = agents_dir / "security.md"
            security_md.write_text("""
kernel:
  version: "1.0"
  mode: strict

signals:
  - SIGSTOP
  - SIGKILL
""")
            
            parser = AgentsParser()
            config = parser.parse_directory(str(agents_dir))
            
            assert "kernel" in config.security_config
            assert config.security_config["kernel"]["mode"] == "strict"
    
    def test_to_kernel_policies(self):
        """Test converting AgentConfig to kernel policies."""
        from agent_os.agents_compat import AgentsParser, AgentConfig, AgentSkill
        
        config = AgentConfig(
            name="test-agent",
            description="Test agent",
            skills=[
                AgentSkill(name="database_query", description="Query DB", read_only=True),
                AgentSkill(name="file_write", description="Write files", requires_approval=True),
            ],
            policies=[],
            instructions=""
        )
        
        parser = AgentsParser()
        policies = parser.to_kernel_policies(config)
        
        assert policies["name"] == "test-agent"
        assert len(policies["rules"]) == 2
        assert policies["rules"][0]["mode"] == "read_only"
        assert policies["rules"][1]["requires_approval"] is True


class TestDiscoverAgents:
    """Test agent discovery function."""
    
    def test_discover_agents_empty_dir(self):
        """Test discovering agents in empty directory."""
        from agent_os.agents_compat import discover_agents
        
        with tempfile.TemporaryDirectory() as tmpdir:
            configs = discover_agents(tmpdir)
            assert configs == []
    
    def test_discover_agents_with_dotdir(self):
        """Test discovering agents with .agents/ directory."""
        from agent_os.agents_compat import discover_agents
        
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / ".agents"
            agents_dir.mkdir()
            (agents_dir / "agents.md").write_text("# Test Agent\n\nYou can:\n- Do things")
            
            configs = discover_agents(tmpdir)
            assert len(configs) == 1
    
    def test_discover_agents_root_file(self):
        """Test discovering agents.md in root."""
        from agent_os.agents_compat import discover_agents
        
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "AGENTS.md").write_text("# Root Agent\n\nYou can:\n- Do stuff")
            
            configs = discover_agents(tmpdir)
            # On case-insensitive filesystems (Windows), may find both AGENTS.md patterns
            assert len(configs) >= 1


class TestAgentSkill:
    """Test AgentSkill dataclass."""
    
    def test_skill_defaults(self):
        """Test skill default values."""
        from agent_os.agents_compat import AgentSkill
        
        skill = AgentSkill(name="test", description="Test skill")
        
        assert skill.allowed is True
        assert skill.requires_approval is False
        assert skill.read_only is False
        assert skill.constraints == {}
    
    def test_skill_with_options(self):
        """Test skill with all options."""
        from agent_os.agents_compat import AgentSkill
        
        skill = AgentSkill(
            name="dangerous",
            description="Dangerous action",
            allowed=False,
            requires_approval=True,
            read_only=False,
            constraints={"max_calls": 10}
        )
        
        assert skill.allowed is False
        assert skill.requires_approval is True
        assert skill.constraints["max_calls"] == 10


class TestAgentConfig:
    """Test AgentConfig dataclass."""
    
    def test_config_creation(self):
        """Test creating an agent config."""
        from agent_os.agents_compat import AgentConfig, AgentSkill
        
        config = AgentConfig(
            name="my-agent",
            description="My agent",
            skills=[AgentSkill(name="test", description="Test")],
            policies=["strict"],
            instructions="Do things safely"
        )
        
        assert config.name == "my-agent"
        assert len(config.skills) == 1
        assert config.policies == ["strict"]


# ── AGENTS.md Generator Tests ────────────────────────────────────────────────

import yaml


class TestGenerateAgentsMd:
    """Test generate_agents_md function."""

    def test_minimal_config(self):
        """generate_agents_md with just a name produces valid markdown."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md

        md = generate_agents_md(AgentMdConfig(name="my-agent"))
        assert "# my-agent" in md
        assert "## Commit Style" in md
        # Should NOT have optional sections
        assert "## Project Overview" not in md
        assert "## Governance" not in md

    def test_full_config(self):
        """generate_agents_md with all fields populated."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md
        from agent_os.integrations.base import GovernancePolicy

        cfg = AgentMdConfig(
            name="full-agent",
            description="A fully-configured test agent.",
            tools=["grep", "git"],
            policy=GovernancePolicy(allowed_tools=["grep", "git"]),
            role="admin",
            build_commands=["pip install -e ."],
            test_commands=["pytest tests/ -v"],
            lint_commands=["ruff check ."],
            boundaries=["Never commit secrets"],
            code_style={"formatter": "ruff", "line_length": "100"},
        )
        md = generate_agents_md(cfg)

        assert "## Project Overview" in md
        assert "A fully-configured test agent." in md
        assert "## Build & Test Commands" in md
        assert "pip install -e ." in md
        assert "pytest tests/ -v" in md
        assert "ruff check ." in md
        assert "## Code Style" in md
        assert "**formatter:** ruff" in md
        assert "## Governance" in md
        assert "## Boundaries" in md
        assert "Never commit secrets" in md
        assert "## Commit Style" in md

    def test_governance_renders_correctly(self):
        """GovernancePolicy renders as YAML inside the Governance section."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md
        from agent_os.integrations.base import GovernancePolicy

        policy = GovernancePolicy(
            max_tokens=2048,
            max_tool_calls=5,
            require_human_approval=True,
        )
        md = generate_agents_md(AgentMdConfig(name="gov", policy=policy))

        assert "max_tokens: 2048" in md
        assert "max_tool_calls: 5" in md
        assert "require_human_approval: true" in md

    def test_boundaries_render(self):
        """Boundaries section renders each item as a bullet."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md

        cfg = AgentMdConfig(
            name="b",
            boundaries=["No secrets", "No PII"],
        )
        md = generate_agents_md(cfg)
        assert "- No secrets" in md
        assert "- No PII" in md

    def test_yaml_frontmatter_valid(self):
        """YAML frontmatter is parseable by yaml.safe_load."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md

        cfg = AgentMdConfig(
            name="fm-test",
            description="Frontmatter test",
            tools=["shell", "grep"],
            role="developer",
        )
        md = generate_agents_md(cfg)

        # Extract frontmatter between --- markers
        assert md.startswith("---\n")
        end = md.index("---", 3)
        fm_yaml = md[4:end]
        data = yaml.safe_load(fm_yaml)

        assert data["name"] == "fm-test"
        assert data["description"] == "Frontmatter test"
        assert data["tools"] == ["shell", "grep"]
        assert data["role"] == "developer"
        assert "version" in data


class TestSaveAgentsMd:
    """Test save_agents_md function."""

    def test_save_writes_file(self, tmp_path):
        """save_agents_md writes content to the given path."""
        from agent_os.agents_compat import AgentMdConfig, save_agents_md

        out = tmp_path / "AGENTS.md"
        save_agents_md(AgentMdConfig(name="saved"), str(out))

        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "# saved" in content


class TestRoundtrip:
    """Test generate -> save -> load -> generate roundtrip."""

    def test_roundtrip(self, tmp_path):
        """Roundtrip: generate -> save -> load -> generate matches."""
        from agent_os.agents_compat import (
            AgentMdConfig,
            generate_agents_md,
            save_agents_md,
            load_agents_md,
        )
        from agent_os.integrations.base import GovernancePolicy

        cfg = AgentMdConfig(
            name="roundtrip-agent",
            description="Roundtrip test agent.",
            tools=["grep", "git"],
            role="operator",
            build_commands=["pip install -e ."],
            test_commands=["pytest tests/ -v"],
            lint_commands=["ruff check ."],
            boundaries=["Never commit secrets", "Keep backward compat"],
            code_style={"formatter": "ruff", "line_length": "100"},
            policy=GovernancePolicy(
                max_tokens=2048,
                max_tool_calls=5,
                allowed_tools=["grep", "git"],
            ),
        )

        path = str(tmp_path / "AGENTS.md")
        save_agents_md(cfg, path)
        loaded = load_agents_md(path)

        # Core fields must survive roundtrip
        assert loaded.name == cfg.name
        assert loaded.description == cfg.description
        assert loaded.tools == cfg.tools
        assert loaded.role == cfg.role
        assert loaded.boundaries == cfg.boundaries
        assert loaded.code_style == cfg.code_style

        # Governance policy core values
        assert loaded.policy is not None
        assert loaded.policy.max_tokens == cfg.policy.max_tokens
        assert loaded.policy.max_tool_calls == cfg.policy.max_tool_calls
        assert loaded.policy.allowed_tools == cfg.policy.allowed_tools

        # Second generate should match first
        md1 = generate_agents_md(cfg)
        md2 = generate_agents_md(loaded)
        assert md1 == md2

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test AGENTS.md compatibility module.
"""
import tempfile
from pathlib import Path

import yaml

class TestAgentsParser:
    """Test AgentsParser class."""

    def test_import_agents_compat(self):
        """Test importing agents_compat module."""
        from agent_os.agents_compat import AgentsParser, AgentConfig
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
        skills = parser._parse_skills('\n- Query databases\n- Generate reports\n- Send emails\n')
        assert len(skills) == 3
        assert skills[0].description == 'Query databases'
        assert skills[1].description == 'Generate reports'
        assert skills[2].description == 'Send emails'

    def test_parse_skill_with_read_only(self):
        """Test parsing skills with (read-only) modifier."""
        from agent_os.agents_compat import AgentsParser
        parser = AgentsParser()
        skills = parser._parse_skills('\n- Query databases (read-only)\n- Read files (read only)\n')
        assert skills[0].read_only is True
        assert skills[1].read_only is True

    def test_parse_skill_with_approval(self):
        """Test parsing skills with (requires approval) modifier."""
        from agent_os.agents_compat import AgentsParser
        parser = AgentsParser()
        skills = parser._parse_skills('\n- Send emails (requires approval)\n- Delete files (requires approval)\n')
        assert skills[0].requires_approval is True
        assert skills[1].requires_approval is True

    def test_skill_to_action(self):
        """Test converting skill descriptions to action names."""
        from agent_os.agents_compat import AgentsParser
        parser = AgentsParser()
        assert parser._skill_to_action('Query databases') == 'database_query'
        assert parser._skill_to_action('Send email') == 'send_email'
        assert parser._skill_to_action('Write file') == 'file_write'
        assert parser._skill_to_action('Call API') == 'api_call'

    def test_parse_agents_md_file(self):
        """Test parsing actual agents.md file."""
        from agent_os.agents_compat import AgentsParser
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / '.agents'
            agents_dir.mkdir()
            agents_md = agents_dir / 'agents.md'
            agents_md.write_text('# Data Analyst Agent\n\nYou are a data analyst agent.\n\n## Capabilities\n\nYou can:\n- Query databases (read-only)\n- Generate visualizations\n- Export to PDF\n')
            parser = AgentsParser()
            config = parser.parse_directory(str(agents_dir))
            assert config is not None
            assert len(config.skills) == 3
            assert config.skills[0].read_only is True

    def test_parse_security_md_file(self):
        """Test parsing security.md extension."""
        from agent_os.agents_compat import AgentsParser
        with tempfile.TemporaryDirectory() as tmpdir:
            agents_dir = Path(tmpdir) / '.agents'
            agents_dir.mkdir()
            (agents_dir / 'agents.md').write_text('# Agent')
            security_md = agents_dir / 'security.md'
            security_md.write_text('\nkernel:\n  version: "1.0"\n  mode: strict\n\nsignals:\n  - SIGSTOP\n  - SIGKILL\n')
            parser = AgentsParser()
            config = parser.parse_directory(str(agents_dir))
            assert 'kernel' in config.security_config
            assert config.security_config['kernel']['mode'] == 'strict'

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
            agents_dir = Path(tmpdir) / '.agents'
            agents_dir.mkdir()
            (agents_dir / 'agents.md').write_text('# Test Agent\n\nYou can:\n- Do things')
            configs = discover_agents(tmpdir)
            assert len(configs) == 1

    def test_discover_agents_root_file(self):
        """Test discovering agents.md in root."""
        from agent_os.agents_compat import discover_agents
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / 'AGENTS.md').write_text('# Root Agent\n\nYou can:\n- Do stuff')
            configs = discover_agents(tmpdir)
            assert len(configs) >= 1

class TestAgentSkill:
    """Test AgentSkill dataclass."""

    def test_skill_defaults(self):
        """Test skill default values."""
        from agent_os.agents_compat import AgentSkill
        skill = AgentSkill(name='test', description='Test skill')
        assert skill.allowed is True
        assert skill.requires_approval is False
        assert skill.read_only is False
        assert skill.constraints == {}

    def test_skill_with_options(self):
        """Test skill with all options."""
        from agent_os.agents_compat import AgentSkill
        skill = AgentSkill(name='dangerous', description='Dangerous action', allowed=False, requires_approval=True, read_only=False, constraints={'max_calls': 10})
        assert skill.allowed is False
        assert skill.requires_approval is True
        assert skill.constraints['max_calls'] == 10

class TestAgentConfig:
    """Test AgentConfig dataclass."""

    def test_config_creation(self):
        """Test creating an agent config."""
        from agent_os.agents_compat import AgentConfig, AgentSkill
        config = AgentConfig(name='my-agent', description='My agent', skills=[AgentSkill(name='test', description='Test')], instructions='Do things safely')
        assert config.name == 'my-agent'
        assert len(config.skills) == 1
class TestGenerateAgentsMd:
    """Test generate_agents_md function."""

    def test_minimal_config(self):
        """generate_agents_md with just a name produces valid markdown."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md
        md = generate_agents_md(AgentMdConfig(name='my-agent'))
        assert '# my-agent' in md
        assert '## Commit Style' in md
        assert '## Project Overview' not in md
        assert '## Governance' not in md

    def test_boundaries_render(self):
        """Boundaries section renders each item as a bullet."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md
        cfg = AgentMdConfig(name='b', boundaries=['No secrets', 'No PII'])
        md = generate_agents_md(cfg)
        assert '- No secrets' in md
        assert '- No PII' in md

    def test_yaml_frontmatter_valid(self):
        """YAML frontmatter is parseable by yaml.safe_load."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md
        cfg = AgentMdConfig(name='fm-test', description='Frontmatter test', tools=['shell', 'grep'], role='developer')
        md = generate_agents_md(cfg)
        assert md.startswith('---\n')
        end = md.index('---', 3)
        fm_yaml = md[4:end]
        data = yaml.safe_load(fm_yaml)
        assert data['name'] == 'fm-test'
        assert data['description'] == 'Frontmatter test'
        assert data['tools'] == ['shell', 'grep']
        assert data['role'] == 'developer'
        assert 'version' in data

class TestSaveAgentsMd:
    """Test save_agents_md function."""

    def test_save_writes_file(self, tmp_path):
        """save_agents_md writes content to the given path."""
        from agent_os.agents_compat import AgentMdConfig, save_agents_md
        out = tmp_path / 'AGENTS.md'
        save_agents_md(AgentMdConfig(name='saved'), str(out))
        assert out.exists()
        content = out.read_text(encoding='utf-8')
        assert '# saved' in content

class TestRoundtrip:
    """Test generate -> save -> load -> generate roundtrip."""

    def test_roundtrip(self, tmp_path):
        """Roundtrip: generate -> save -> load -> generate matches."""
        from agent_os.agents_compat import AgentMdConfig, generate_agents_md, save_agents_md, load_agents_md
        cfg = AgentMdConfig(name='roundtrip-agent', description='Roundtrip test agent.', tools=['grep', 'git'], role='operator', build_commands=['pip install -e .'], test_commands=['pytest tests/ -v'], lint_commands=['ruff check .'], boundaries=['Never commit secrets', 'Keep backward compat'], code_style={'formatter': 'ruff', 'line_length': '100'})
        path = str(tmp_path / 'AGENTS.md')
        save_agents_md(cfg, path)
        loaded = load_agents_md(path)
        assert loaded.name == cfg.name
        assert loaded.description == cfg.description
        assert loaded.tools == cfg.tools
        assert loaded.role == cfg.role
        assert loaded.boundaries == cfg.boundaries
        assert loaded.code_style == cfg.code_style
        md1 = generate_agents_md(cfg)
        md2 = generate_agents_md(loaded)
        assert md1 == md2

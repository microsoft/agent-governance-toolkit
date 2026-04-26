# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AGENTS.md Compatibility for Agent OS.

Parses OpenAI/Anthropic standard .agents/ directory structure
and maps to Agent OS kernel policies.

Also provides generation utilities for producing AGENTS.md files
from AgentMdConfig dataclasses (GitHub Copilot / Cursor / Codex format).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agent_os.integrations.base import GovernancePolicy


@dataclass
class AgentSkill:
    """Parsed agent skill/capability."""
    name: str
    description: str
    allowed: bool = True
    requires_approval: bool = False
    read_only: bool = False
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentConfig:
    """Parsed agent configuration from AGENTS.md."""
    name: str
    description: str
    skills: list[AgentSkill]
    policies: list[str]
    instructions: str
    security_config: dict[str, Any] = field(default_factory=dict)


class AgentsParser:
    """
    Parse .agents/ directory structure.

    Supports:
    - agents.md (OpenAI/Anthropic standard)
    - security.md (Agent OS extension)
    - YAML front matter

    Usage:
        parser = AgentsParser()
        config = parser.parse_directory("./my-project/.agents")

        # Convert to kernel policies
        policies = parser.to_kernel_policies(config)
    """

    def __init__(self):
        self.skill_patterns = [
            r"^[-*]\s+(.+)$",  # - skill or * skill
            r"^(\d+)\.\s+(.+)$",  # 1. skill
        ]

    def parse_directory(self, path: str) -> AgentConfig:
        """Parse .agents/ directory."""
        agents_dir = Path(path)

        if not agents_dir.exists():
            raise FileNotFoundError(f"Agents directory not found: {path}")

        # Parse main agents.md
        agents_md = agents_dir / "agents.md"
        if not agents_md.exists():
            agents_md = agents_dir / "AGENTS.md"

        config = self._parse_agents_md(agents_md) if agents_md.exists() else AgentConfig(
            name="default",
            description="",
            skills=[],
            policies=[],
            instructions=""
        )

        # Parse security.md (Agent OS extension)
        security_md = agents_dir / "security.md"
        if security_md.exists():
            config.security_config = self._parse_security_md(security_md)

        return config

    def _parse_agents_md(self, path: Path) -> AgentConfig:
        """Parse agents.md file."""
        content = path.read_text(encoding="utf-8")

        # Extract YAML front matter if present
        front_matter = {}
        if content.startswith("---"):
            end = content.find("---", 3)
            if end != -1:
                yaml_content = content[3:end]
                front_matter = yaml.safe_load(yaml_content) or {}
                content = content[end + 3:].strip()

        # Parse sections
        name = front_matter.get("name", "agent")
        description = ""
        skills = []
        instructions = content

        # Find "You can:" or "Capabilities:" section
        can_match = re.search(r"(?:You can|Capabilities|Skills):\s*\n((?:[-*\d].*\n?)+)", content, re.IGNORECASE)
        if can_match:
            skills_text = can_match.group(1)
            skills = self._parse_skills(skills_text)

        # Find description (first paragraph)
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if line and not line.startswith(("#", "-", "*", "You can", "Capabilities")):
                description = line
                break

        return AgentConfig(
            name=name,
            description=description,
            skills=skills,
            policies=front_matter.get("policies", []),
            instructions=instructions,
            security_config=front_matter.get("security", {})
        )

    def _parse_skills(self, text: str) -> list[AgentSkill]:
        """Parse skills from bullet list."""
        skills = []

        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Extract skill text
            skill_text = re.sub(r"^[-*\d.]+\s*", "", line)

            # Parse constraints from parentheses
            constraints = {}
            read_only = False
            requires_approval = False

            # Check for (read-only), (requires approval), etc.
            if "(read-only)" in skill_text.lower() or "(read only)" in skill_text.lower():
                read_only = True
                skill_text = re.sub(r"\s*\(read[- ]?only\)", "", skill_text, flags=re.IGNORECASE)

            if "(requires approval)" in skill_text.lower():
                requires_approval = True
                skill_text = re.sub(r"\s*\(requires approval\)", "", skill_text, flags=re.IGNORECASE)

            skills.append(AgentSkill(
                name=self._skill_to_action(skill_text),
                description=skill_text.strip(),
                read_only=read_only,
                requires_approval=requires_approval,
                constraints=constraints
            ))

        return skills

    def _skill_to_action(self, skill: str) -> str:
        """Convert skill description to action name."""
        skill_lower = skill.lower()

        # Map common patterns
        mappings = {
            "query database": "database_query",
            "read database": "database_query",
            "write to database": "database_write",
            "send email": "send_email",
            "write file": "file_write",
            "read file": "file_read",
            "call api": "api_call",
            "execute code": "code_execution",
            "search": "search",
            "browse": "web_browse",
        }

        for pattern, action in mappings.items():
            if pattern in skill_lower:
                return action

        # Default: snake_case the skill
        return re.sub(r"[^a-z0-9]+", "_", skill_lower).strip("_")

    def _parse_security_md(self, path: Path) -> dict[str, Any]:
        """Parse security.md (Agent OS extension)."""
        content = path.read_text(encoding="utf-8")

        # Try YAML front matter first
        if content.startswith("---"):
            end = content.find("---", 3)
            if end != -1:
                yaml_content = content[3:end]
                return yaml.safe_load(yaml_content) or {}

        # Try full YAML
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError:
            pass

        return {}

    def to_kernel_policies(self, config: AgentConfig) -> dict[str, Any]:
        """
        Convert AgentConfig to Agent OS kernel policies.

        Returns policy configuration for Control Plane.
        """
        policies = {
            "name": config.name,
            "version": "1.0",
            "rules": []
        }

        # Convert skills to rules
        for skill in config.skills:
            rule = {
                "action": skill.name,
                "effect": "allow" if skill.allowed else "deny",
            }

            if skill.read_only:
                rule["mode"] = "read_only"

            if skill.requires_approval:
                rule["requires_approval"] = True

            if skill.constraints:
                rule["constraints"] = skill.constraints

            policies["rules"].append(rule)

        # Add security config
        if config.security_config:
            sec = config.security_config

            if "signals" in sec:
                policies["allowed_signals"] = sec["signals"]

            if "max_tokens" in sec:
                policies["limits"] = {"max_tokens": sec["max_tokens"]}

        return policies


def discover_agents(root_dir: str = ".") -> list[AgentConfig]:
    """
    Discover all agent configurations in a repository.

    Looks for:
    - .agents/agents.md
    - .agents/AGENTS.md
    - agents.md (root)
    - AGENTS.md (root)

    Returns list of parsed configurations.
    """
    parser = AgentsParser()
    configs = []
    root = Path(root_dir)

    # Check .agents/ directory
    agents_dir = root / ".agents"
    if agents_dir.exists():
        try:
            configs.append(parser.parse_directory(str(agents_dir)))
        except Exception:  # noqa: S110 — best-effort config loading
            pass

    # Check root agents.md
    for name in ["agents.md", "AGENTS.md"]:
        agents_md = root / name
        if agents_md.exists():
            try:
                config = parser._parse_agents_md(agents_md)
                configs.append(config)
            except Exception:  # noqa: S110 — best-effort config loading
                pass

    return configs


# ── AGENTS.md Generator ──────────────────────────────────────────────────────


_AGENTS_MD_VERSION = "1.0"


@dataclass
class AgentMdConfig:
    """Configuration for generating an AGENTS.md file.

    Maps Agent OS concepts (governance policy, RBAC role, tools) into the
    standard AGENTS.md format consumed by GitHub Copilot, Cursor, Codex, etc.
    """

    name: str
    description: str = ""
    tools: list[str] = field(default_factory=list)
    policy: Optional[GovernancePolicy] = None
    role: Optional[str] = None
    build_commands: list[str] = field(default_factory=list)
    test_commands: list[str] = field(default_factory=list)
    lint_commands: list[str] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    code_style: dict[str, str] = field(default_factory=dict)


def generate_agents_md(config: AgentMdConfig) -> str:
    """Generate a valid AGENTS.md string from *config*.

    The output includes YAML frontmatter followed by Markdown sections for
    project overview, build & test commands, code style, governance,
    boundaries, and commit style.
    """

    parts: list[str] = []

    # ── YAML frontmatter ─────────────────────────────────────────────────
    fm: dict[str, Any] = {
        "name": config.name,
        "version": _AGENTS_MD_VERSION,
    }
    if config.description:
        fm["description"] = config.description
    if config.tools:
        fm["tools"] = config.tools
    if config.role:
        fm["role"] = config.role

    parts.append("---")
    parts.append(yaml.dump(fm, default_flow_style=False, sort_keys=False).rstrip())
    parts.append("---")
    parts.append("")

    # ── Title ────────────────────────────────────────────────────────────
    parts.append(f"# {config.name} — Coding Agent Instructions")
    parts.append("")

    # ── Project Overview ─────────────────────────────────────────────────
    if config.description:
        parts.append("## Project Overview")
        parts.append("")
        parts.append(config.description)
        parts.append("")

    # ── Build & Test Commands ────────────────────────────────────────────
    has_commands = config.build_commands or config.test_commands or config.lint_commands
    if has_commands:
        parts.append("## Build & Test Commands")
        parts.append("")
        parts.append("```bash")
        for cmd in config.build_commands:
            parts.append(cmd)
        for cmd in config.test_commands:
            parts.append(cmd)
        for cmd in config.lint_commands:
            parts.append(cmd)
        parts.append("```")
        parts.append("")

    # ── Code Style ───────────────────────────────────────────────────────
    if config.code_style:
        parts.append("## Code Style")
        parts.append("")
        for key, value in config.code_style.items():
            parts.append(f"- **{key}:** {value}")
        parts.append("")

    # ── Governance ───────────────────────────────────────────────────────
    if config.policy is not None:
        parts.append("## Governance")
        parts.append("")
        parts.append("```yaml")
        parts.append(config.policy.to_yaml().rstrip())
        parts.append("```")
        parts.append("")

    # ── Boundaries ───────────────────────────────────────────────────────
    if config.boundaries:
        parts.append("## Boundaries")
        parts.append("")
        for boundary in config.boundaries:
            parts.append(f"- {boundary}")
        parts.append("")

    # ── Commit Style ─────────────────────────────────────────────────────
    parts.append("## Commit Style")
    parts.append("")
    parts.append(
        "Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`"
    )
    parts.append("")

    return "\n".join(parts)


def save_agents_md(config: AgentMdConfig, path: str) -> None:
    """Write the generated AGENTS.md to *path*."""

    content = generate_agents_md(config)
    Path(path).write_text(content, encoding="utf-8")


def load_agents_md(path: str) -> AgentMdConfig:
    """Parse an AGENTS.md file back into an *AgentMdConfig*.

    Extracts YAML frontmatter for metadata and scans Markdown sections for
    build/test/lint commands, code style, governance policy, and boundaries.
    """

    text = Path(path).read_text(encoding="utf-8")

    # ── Parse YAML frontmatter ───────────────────────────────────────────
    fm: dict[str, Any] = {}
    body = text
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            fm = yaml.safe_load(text[3:end]) or {}
            body = text[end + 3:].strip()

    config = AgentMdConfig(
        name=fm.get("name", "agent"),
        description=fm.get("description", ""),
        tools=fm.get("tools", []),
        role=fm.get("role"),
    )

    # ── Section regex (## Heading) ───────────────────────────────────────
    section_re = re.compile(r"^##\s+(.+)$", re.MULTILINE)
    sections: dict[str, str] = {}
    matches = list(section_re.finditer(body))
    for i, m in enumerate(matches):
        heading = m.group(1).strip()
        start = m.end()
        end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[heading] = body[start:end_pos].strip()

    # ── Build & Test Commands ────────────────────────────────────────────
    bt_section = sections.get("Build & Test Commands", "")
    code_block = re.search(r"```(?:bash)?\s*\n(.*?)```", bt_section, re.DOTALL)
    if code_block:
        lines = [ln for ln in code_block.group(1).strip().splitlines() if ln.strip()]
        # Simple heuristic: commands containing "test" → test, "lint"/"check"/"format" → lint, rest → build
        for ln in lines:
            low = ln.lower()
            if "test" in low or "pytest" in low:
                config.test_commands.append(ln)
            elif any(kw in low for kw in ("lint", "check", "format", "ruff", "mypy")):
                config.lint_commands.append(ln)
            else:
                config.build_commands.append(ln)

    # ── Code Style ───────────────────────────────────────────────────────
    cs_section = sections.get("Code Style", "")
    for line in cs_section.splitlines():
        # Matches both `**key:** value` and `**key**: value`
        m = re.match(r"^-\s+\*\*(.+?):?\*\*:?\s*(.+)$", line.strip())
        if m:
            config.code_style[m.group(1).rstrip(":")] = m.group(2)

    # ── Governance ───────────────────────────────────────────────────────
    gov_section = sections.get("Governance", "")
    gov_block = re.search(r"```(?:yaml)?\s*\n(.*?)```", gov_section, re.DOTALL)
    if gov_block:
        config.policy = GovernancePolicy.from_yaml(gov_block.group(1))

    # ── Boundaries ───────────────────────────────────────────────────────
    bd_section = sections.get("Boundaries", "")
    for line in bd_section.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            config.boundaries.append(stripped[2:])

    return config

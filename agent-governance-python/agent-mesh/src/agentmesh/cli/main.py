# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh CLI - Main Entry Point

Commands:
- init: Scaffold a governed agent in 30 seconds
- proxy: Start an MCP proxy with governance
- register: Register an agent with AgentMesh
- run: Run a governed agent
- status: Check agent status and trust score
- audit: View audit logs
- policy: Manage policies
"""

import json
import logging
import os
import re
from pathlib import Path

import click
import yaml
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


def handle_error(e: Exception, output_json: bool = False, custom_msg: str | None = None):
    """Centralized error handler for CLI commands."""
    is_known = isinstance(e, (ImportError, ValueError, KeyError, PermissionError, FileNotFoundError, yaml.YAMLError, json.JSONDecodeError))

    # Sanitize message: use custom msg if provided, else generic for unknown errors
    if custom_msg:
        err_msg = custom_msg
    elif is_known:
        # Avoid leaking internal paths even for known errors in production output
        err_msg = "A validation, permission, or configuration error occurred."
    else:
        err_msg = "An unexpected internal error occurred."

    # Log the full details for debugging (not shown to user unless DEBUG is on)
    logger.error(f"CLI Error: {e}", exc_info=True)

    if output_json:
        status = "error"
        type_field = "ValidationError" if is_known else "InternalError"
        print(json.dumps({"status": status, "message": err_msg, "type": type_field}, indent=2))
    else:
        console.print(f"[red]Error: {err_msg}[/red]")
        if os.environ.get("AGENTOS_DEBUG"):
             console.print(f"[dim]{e}[/dim]")


@click.group()
@click.version_option(version="3.1.0")
def app():
    """
    AgentMesh - The Secure Nervous System for Cloud-Native Agent Ecosystems

    Identity · Trust · Reward · Governance
    """
    pass


@app.command()
@click.option("--name", "-n", prompt="Agent name", help="Name of the agent")
@click.option("--sponsor", "-s", prompt="Sponsor email", help="Human sponsor email")
@click.option("--output", "-o", default=".", help="Output directory")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format")
def init(name: str, sponsor: str, output: str, output_json: bool):
    """
    Initialize a new governed agent in 30 seconds.

    Creates the scaffolding for a governed agent with identity, trust, and audit built in.
    """
    output_path = Path(output)
    # Validate name to prevent path traversal (CWE-22)
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9._-]+$', name):
        raise click.BadParameter(
            f"Agent name must contain only alphanumerics, hyphens, underscores, and dots: '{name}'"
        )
    agent_dir = output_path / name

    if not output_json:
        console.print(f"\n[bold blue]🚀 Initializing governed agent: {name}[/bold blue]\n")

    # Create directory structure
    dirs = [
        agent_dir,
        agent_dir / "src",
        agent_dir / "policies",
        agent_dir / "tests",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        if not output_json:
            console.print(f"  [green]✓[/green] Created {d}")

    # Create agent manifest
    manifest = {
        "agent": {
            "name": name,
            "version": "0.1.0",
            "did": f"did:agentmesh:{name}",
        },
        "sponsor": {
            "email": sponsor,
        },
        "identity": {
            "ttl_minutes": 15,
            "auto_rotate": True,
        },
        "trust": {
            "protocols": ["a2a", "mcp", "iatp"],
            "min_peer_score": 500,
        },
        "governance": {
            "policies_dir": "policies/",
            "audit_enabled": True,
        },
        "reward": {
            "dimensions": {
                "policy_compliance": 0.25,
                "resource_efficiency": 0.15,
                "output_quality": 0.20,
                "security_posture": 0.25,
                "collaboration_health": 0.15,
            },
        },
    }

    manifest_path = agent_dir / "agentmesh.yaml"
    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False)
    if not output_json:
        console.print(f"  [green]✓[/green] Created {manifest_path}")

    # Create default policy
    default_policy = {
        "policies": [
            {
                "id": "default-security",
                "name": "Default Security Policy",
                "enabled": True,
                "rules": [
                    {
                        "id": "no-secrets-in-output",
                        "action": "block",
                        "conditions": [
                            "output contains 'password'",
                            "output contains 'api_key'",
                            "output contains 'secret'",
                        ],
                        "message": "Potential secret detected in output",
                    },
                    {
                        "id": "require-peer-trust",
                        "action": "block",
                        "conditions": ["peer_trust_score < 500"],
                        "message": "Peer trust score below threshold",
                    },
                ],
            }
        ]
    }

    policy_path = agent_dir / "policies" / "default.yaml"
    with open(policy_path, "w") as f:
        yaml.dump(default_policy, f, default_flow_style=False)
    if not output_json:
        console.print(f"  [green]✓[/green] Created {policy_path}")

    # Create main agent file
    agent_code = f'''"""
{name} - A Governed Agent

This agent is secured by AgentMesh with:
- Cryptographic identity
- Trust scoring
- Policy enforcement
- Audit logging
"""

from agentmesh import AgentMesh, AgentIdentity, PolicyEngine

# Initialize AgentMesh
mesh = AgentMesh.from_config("agentmesh.yaml")

# Create identity
identity = mesh.create_identity()
print(f"Agent DID: {{identity.did}}")

# Load policies
policies = mesh.load_policies()
print(f"Loaded {{len(policies)}} policies")

# Start the agent
async def main():
    """Main agent loop."""
    async with mesh.run(identity) as agent:
        # Your agent logic here
        print(f"Agent {{identity.name}} is running with trust score: {{agent.trust_score}}")

        # Example: Register capabilities
        await agent.register_capabilities([
            "text_processing",
            "data_analysis",
        ])

        # Example: Handle incoming requests
        async for request in agent.requests():
            # Policy is automatically enforced
            # Audit is automatically logged
            response = await agent.process(request)
            await agent.respond(response)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
'''

    main_path = agent_dir / "src" / "main.py"
    with open(main_path, "w") as f:
        f.write(agent_code)
    if not output_json:
        console.print(f"  [green]✓[/green] Created {main_path}")

    # Create pyproject.toml
    pyproject = f'''[project]
name = "{name}"
version = "0.1.0"
description = "A governed agent secured by AgentMesh"
requires-python = ">=3.11"
dependencies = [
    "agentmesh>=1.0.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
'''

    pyproject_path = agent_dir / "pyproject.toml"
    with open(pyproject_path, "w") as f:
        f.write(pyproject)
    if not output_json:
        console.print(f"  [green]✓[/green] Created {pyproject_path}")

    # Summary
    if output_json:
        print(json.dumps({
            "status": "success",
            "agent_name": name,
            "output_dir": str(agent_dir),
            "manifest": str(manifest_path),
            "policy": str(policy_path),
            "main": str(main_path)
        }, indent=2))
        return

    console.print()
    console.print(Panel(
        f"""[bold green]Agent initialized successfully![/bold green]

[bold]Next steps:[/bold]
1. cd {agent_dir}
2. pip install -e .
3. python src/main.py

[bold]Configuration:[/bold]
- Edit agentmesh.yaml for agent settings
- Add policies to policies/ directory
- Customize src/main.py with your agent logic

[bold]Security:[/bold]
- Identity TTL: 15 minutes (auto-rotate)
- Min peer trust score: 500
- Audit logging: enabled""",
        title="🛡️ AgentMesh",
        border_style="green",
    ))


@app.command()
@click.argument("agent_dir", type=click.Path(exists=True))
@click.option("--name", "-n", help="Override agent name")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format")
def register(agent_dir: str, name: str = None, output_json: bool = False):
    """Register an agent with AgentMesh."""
    agent_path = Path(agent_dir)
    manifest_path = agent_path / "agentmesh.yaml"

    if not manifest_path.exists():
        if output_json:
            print(json.dumps({"status": "error", "message": "agentmesh.yaml not found"}, indent=2))
        else:
            console.print("[red]Error: agentmesh.yaml not found. Run 'agentmesh init' first.[/red]")
        return

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    agent_name = name or manifest["agent"]["name"]

    if not output_json:
        console.print(f"\n[bold blue]📝 Registering agent: {agent_name}[/bold blue]\n")

    # Simulate registration
    try:
        from agentmesh.identity import AgentIdentity
        identity = AgentIdentity.create(agent_name)
    except Exception as e:
        handle_error(e, output_json)
        return

    if not output_json:
        console.print(f"  [green]✓[/green] Generated identity: {identity.did}")
        console.print(f"  [green]✓[/green] Public key: {identity.public_key[:32]}...")
        console.print("  [green]✓[/green] Registered with AgentMesh CA")
        console.print()

    # Save identity
    identity_file = agent_path / ".agentmesh" / "identity.json"
    identity_file.parent.mkdir(parents=True, exist_ok=True)

    with open(identity_file, "w") as f:
        json.dump({
            "did": identity.did,
            "public_key": identity.public_key,
            "created_at": identity.created_at.isoformat(),
        }, f, indent=2)

    if output_json:
        print(json.dumps({
            "status": "success",
            "agent_name": agent_name,
            "did": identity.did,
            "identity_file": str(identity_file)
        }, indent=2))
    else:
        console.print(f"[green]Identity saved to {identity_file}[/green]")


@app.command()
@click.argument("agent_dir", type=click.Path(exists=True), default=".")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format")
def status(agent_dir: str, output_json: bool):
    """Check agent status and trust score."""
    agent_path = Path(agent_dir)
    manifest_path = agent_path / "agentmesh.yaml"
    identity_path = agent_path / ".agentmesh" / "identity.json"

    if not output_json:
        console.print("\n[bold blue]📊 Agent Status[/bold blue]\n")

    # Load manifest
    manifest = None
    if manifest_path.exists():
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
        if not output_json:
            console.print(f"  Agent: [bold]{manifest['agent']['name']}[/bold]")
            console.print(f"  Version: {manifest['agent']['version']}")
            console.print(f"  Sponsor: {manifest['sponsor']['email']}")
    else:
        if not output_json:
            console.print("  [yellow]No manifest found[/yellow]")

    if not output_json:
        console.print()

    # Load identity
    identity = None
    if identity_path.exists():
        with open(identity_path) as f:
            identity = json.load(f)
        if not output_json:
            console.print("  [green]✓[/green] Identity: Registered")
            console.print(f"    DID: {identity['did']}")
    else:
        if not output_json:
            console.print("  [yellow]○[/yellow] Identity: Not registered")

    if not output_json:
        console.print()

    # Trust score (simulated)
    if output_json:
        print(json.dumps({
            "agent_name": manifest['agent']['name'] if manifest else None,
            "did": identity['did'] if identity else None,
            "trust_score": 820,
            "max_score": 1000,
            "dimensions": {
                "policy_compliance": 85,
                "resource_efficiency": 72,
                "output_quality": 91,
                "security_posture": 88,
                "collaboration_health": 79
            }
        }, indent=2))
    else:
        table = Table(title="Trust Score", box=box.ROUNDED)
        table.add_column("Dimension", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Trend")

        table.add_row("Policy Compliance", "85/100", "[green]↑[/green]")
        table.add_row("Resource Efficiency", "72/100", "[white]→[/white]")
        table.add_row("Output Quality", "91/100", "[green]↑[/green]")
        table.add_row("Security Posture", "88/100", "[white]→[/white]")
        table.add_row("Collaboration Health", "79/100", "[green]↑[/green]")
        table.add_row("[bold]Total", "[bold]820/1000", "[bold green]Trusted")

        console.print(table)


@app.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--validate", is_flag=True, help="Validate policy only")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format")
def policy(policy_file: str, validate: bool, output_json: bool):
    """Load and validate a policy file."""
    if not output_json:
        console.print(f"\n[bold blue]📜 Policy: {policy_file}[/bold blue]\n")

    try:
        with open(policy_file) as f:
            if policy_file.endswith(".yaml") or policy_file.endswith(".yml"):
                policy_data = yaml.safe_load(f)
            else:
                policy_data = json.load(f)

        from agentmesh.governance import Policy, PolicyEngine
        engine = PolicyEngine()

        policies = policy_data.get("policies", [])
        loaded_policies = []
        for p in policies:
            policy_obj = Policy(**p)
            engine.load_policy(policy_obj)
            loaded_policies.append({"name": policy_obj.name, "rules_count": len(policy_obj.rules)})
            if not output_json:
                console.print(f"  [green]✓[/green] Loaded: {policy_obj.name} ({len(policy_obj.rules)} rules)")

        if output_json:
            print(json.dumps({
                "status": "success",
                "policies": loaded_policies
            }, indent=2))
        else:
            console.print(f"\n[green]Successfully loaded {len(policies)} policies[/green]")

    except Exception as e:
        handle_error(e, output_json)


@app.command()
@click.option("--agent", "-a", help="Filter by agent DID")
@click.option("--limit", "-l", default=20, help="Number of entries")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format")
def audit(agent: str, limit: int, fmt: str, output_json: bool):
    """View audit logs."""
    # Simulated audit entries
    entries = [
        {"timestamp": "2026-01-31T10:15:00Z", "agent": "agent-1", "action": "credential_issued", "status": "success"},
        {"timestamp": "2026-01-31T10:14:30Z", "agent": "agent-1", "action": "policy_check", "status": "allowed"},
        {"timestamp": "2026-01-31T10:14:00Z", "agent": "agent-2", "action": "handshake", "status": "success"},
        {"timestamp": "2026-01-31T10:13:00Z", "agent": "agent-1", "action": "tool_call", "status": "allowed"},
        {"timestamp": "2026-01-31T10:12:00Z", "agent": "agent-3", "action": "policy_check", "status": "blocked"},
    ]

    if agent:
        # Normalization and strict validation of agent identifier
        agent = agent.lower().strip()
        # Stricter pattern only allows alphanumeric, hyphen, and colon in expected segments
        if not re.fullmatch(r"^(?:agent-[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*|did:agentmesh:[a-zA-Z0-9]+(?:[-:][a-zA-Z0-9]+)*)$", agent) or len(agent) > 128:
            handle_error(ValueError("Invalid agent identifier format"), output_json, custom_msg="Invalid agent identifier format")
            return
        entries = [e for e in entries if e["agent"].lower() == agent]

    entries = entries[:limit]

    # Sanitize entries for JSON output with strict key whitelisting and value validation
    allowed_keys = {"timestamp", "agent", "action", "status"}
    sanitized_entries = []
    for e in entries:
        # Only include whitelisted keys and ensure they are strings
        item = {k: str(v) for k, v in e.items() if k in allowed_keys}
        # Final safety check: ensure all required keys are present
        if all(k in item for k in allowed_keys):
            sanitized_entries.append(item)

    if output_json or fmt == "json":
        click.echo(json.dumps(sanitized_entries, indent=2))
    else:
        console.print("\n[bold blue]📋 Audit Log[/bold blue]\n")
        table = Table(box=box.SIMPLE)
        table.add_column("Timestamp", style="dim")
        table.add_column("Agent")
        table.add_column("Action")
        table.add_column("Status")

        for entry in entries:
            status_style = "green" if entry["status"] in ["success", "allowed"] else "red"
            table.add_row(
                entry["timestamp"],
                entry["agent"],
                entry["action"],
                f"[{status_style}]{entry['status']}[/{status_style}]",
            )

        console.print(table)


# Import proxy command from proxy module
try:
    from .proxy import proxy
    app.add_command(proxy)
except ImportError:
    pass

# Import trust subcommand group
try:
    from .trust_cli import trust
    app.add_command(trust)
except ImportError:
    pass


@app.command()
@click.option("--claude", is_flag=True, help="Generate Claude Desktop config")
@click.option("--config-path", type=click.Path(), help="Path to config file")
@click.option("--backup/--no-backup", default=True, help="Backup existing config")
def init_integration(claude: bool, config_path: str, backup: bool):
    """
    Initialize AgentMesh integration with existing tools.

    Examples:

        # Setup Claude Desktop to use AgentMesh proxy
        agentmesh init-integration --claude

        # Specify custom config path
        agentmesh init-integration --claude --config-path ~/custom/config.json
    """
    if claude:
        _init_claude_integration(config_path, backup)
    else:
        console.print("[yellow]Please specify an integration type (e.g., --claude)[/yellow]")


def _init_claude_integration(config_path: str | None, backup: bool):
    """Initialize Claude Desktop integration."""
    console.print("\n[bold blue]🔧 Setting up Claude Desktop Integration[/bold blue]\n")

    # Determine config path
    if not config_path:
        # Default Claude Desktop config locations
        import platform
        system = platform.system()

        if system == "Darwin":  # macOS
            default_path = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        elif system == "Windows":
            default_path = Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        else:  # Linux
            default_path = Path.home() / ".config" / "claude" / "claude_desktop_config.json"

        config_path = default_path
    else:
        config_path = Path(config_path)

    logger.info("Config path: %s", config_path)

    # Check if config exists
    if not config_path.exists():
        logger.warning("Config file not found at %s", config_path)
        logger.info("Creating new config file...")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {"mcpServers": {}}
    else:
        # Backup existing config
        if backup:
            backup_path = config_path.with_suffix(".json.backup")
            import shutil
            shutil.copy(config_path, backup_path)
            logger.debug("Backed up existing config to %s", backup_path)

        # Load existing config
        with open(config_path) as f:
            config = json.load(f)

    # Ensure mcpServers exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}

    # Add example AgentMesh proxy configuration
    example_server = {
        "filesystem-protected": {
            "command": "agentmesh",
            "args": [
                "proxy",
                "--target", "npx",
                "--target", "-y",
                "--target", "@modelcontextprotocol/server-filesystem",
                "--target", str(Path.home())
            ],
            "env": {},
        }
    }

    # Check if already configured
    has_agentmesh = any(
        "agentmesh" in str(server.get("command", ""))
        for server in config["mcpServers"].values()
    )

    if not has_agentmesh:
        config["mcpServers"].update(example_server)
        console.print("\n[green]✓ Added AgentMesh-protected filesystem server example[/green]")
    else:
        logger.warning("AgentMesh proxy already configured")

    # Save updated config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    console.print(f"\n[green]✓ Updated {config_path}[/green]")

    # Show instructions
    console.print()
    console.print(Panel(
        f"""[bold]Next Steps:[/bold]

1. Restart Claude Desktop
2. AgentMesh will now intercept all tool calls to the protected server
3. View logs in the terminal where Claude Desktop was launched

[bold]Customization:[/bold]
Edit {config_path} to:
- Add more protected servers
- Change policy level (--policy strict|moderate|permissive)
- Disable verification footers (--no-footer)

[bold]Example Usage:[/bold]
In Claude Desktop, try: "Read the contents of my home directory"
AgentMesh will enforce policies and add trust verification to outputs.
        """,
        title="🎉 Claude Desktop Integration Ready",
        border_style="green",
    ))


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()

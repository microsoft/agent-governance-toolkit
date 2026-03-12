# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Trust Network CLI

Commands for inspecting and managing the trust network:
- list: List all agents with their trust scores
- inspect: Show detailed trust info for an agent
- history: Show trust score history over time
- graph: Show trust relationships as ASCII art or Mermaid
- revoke: Revoke an agent's credentials
- attest: Manually attest/vouch for an agent
"""

import json
from datetime import datetime, timedelta
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

from agentmesh.trust.bridge import PeerInfo
from agentmesh.constants import (
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TIER_TRUSTED_THRESHOLD,
    TIER_STANDARD_THRESHOLD,
    TIER_PROBATIONARY_THRESHOLD,
)

console = Console()


def _trust_level_label(score: int) -> str:
    """Return a human-readable trust level label for a numeric score."""
    if score >= TIER_VERIFIED_PARTNER_THRESHOLD:
        return "verified_partner"
    elif score >= TIER_TRUSTED_THRESHOLD:
        return "trusted"
    elif score >= TIER_STANDARD_THRESHOLD:
        return "standard"
    elif score >= TIER_PROBATIONARY_THRESHOLD:
        return "probationary"
    return "untrusted"


def _trust_level_style(level: str) -> str:
    """Return a rich style string for a trust level."""
    styles = {
        "verified_partner": "bold green",
        "trusted": "green",
        "standard": "yellow",
        "probationary": "red",
        "untrusted": "bold red",
    }
    return styles.get(level, "white")


def _format_datetime(dt: Optional[datetime]) -> str:
    """Format a datetime for display, handling None."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _get_demo_peers() -> dict[str, PeerInfo]:
    """Return demo peer data for display when no live data is available."""
    now = datetime.utcnow()
    return {
        "did:mesh:agent-alpha-001": PeerInfo(
            peer_did="did:mesh:agent-alpha-001",
            peer_name="alpha-agent",
            protocol="a2a",
            trust_score=920,
            trust_verified=True,
            last_verified=now - timedelta(minutes=5),
            capabilities=["read:data", "write:reports", "execute:tasks"],
            endpoint="https://alpha.agents.example.com",
            connected_at=now - timedelta(hours=2),
        ),
        "did:mesh:agent-beta-002": PeerInfo(
            peer_did="did:mesh:agent-beta-002",
            peer_name="beta-agent",
            protocol="mcp",
            trust_score=750,
            trust_verified=True,
            last_verified=now - timedelta(minutes=15),
            capabilities=["read:data"],
            endpoint="https://beta.agents.example.com",
            connected_at=now - timedelta(hours=1),
        ),
        "did:mesh:agent-gamma-003": PeerInfo(
            peer_did="did:mesh:agent-gamma-003",
            peer_name="gamma-agent",
            protocol="iatp",
            trust_score=480,
            trust_verified=True,
            last_verified=now - timedelta(hours=1),
            capabilities=["read:data", "write:reports"],
            endpoint="https://gamma.agents.example.com",
            connected_at=now - timedelta(hours=3),
        ),
        "did:mesh:agent-delta-004": PeerInfo(
            peer_did="did:mesh:agent-delta-004",
            peer_name="delta-agent",
            protocol="a2a",
            trust_score=250,
            trust_verified=False,
            last_verified=None,
            capabilities=[],
            endpoint=None,
            connected_at=now - timedelta(hours=5),
        ),
    }


def _get_demo_history(agent_id: str) -> list[dict]:
    """Return demo trust score history for an agent."""
    now = datetime.utcnow()
    base_scores = {
        "did:mesh:agent-alpha-001": [800, 820, 850, 870, 900, 920],
        "did:mesh:agent-beta-002": [600, 650, 700, 720, 740, 750],
        "did:mesh:agent-gamma-003": [700, 650, 600, 550, 500, 480],
    }
    scores = base_scores.get(agent_id, [500, 510, 520, 500, 490, 500])
    events = ["initial", "handshake", "task_complete", "policy_check", "attestation", "audit"]

    history = []
    for i, (score, event) in enumerate(zip(scores, events)):
        history.append({
            "timestamp": _format_datetime(now - timedelta(hours=len(scores) - i)),
            "score": score,
            "event": event,
            "delta": score - scores[i - 1] if i > 0 else 0,
        })
    return history


def _output_json(data: object) -> None:
    """Print data as JSON to stdout."""
    click.echo(json.dumps(data, indent=2, default=str))


def _output_yaml(data: object) -> None:
    """Print data as YAML to stdout."""
    try:
        import yaml
        click.echo(yaml.dump(data, default_flow_style=False, sort_keys=False))
    except ImportError:
        click.echo("# PyYAML not installed, falling back to JSON")
        _output_json(data)


@click.group()
def trust():
    """Inspect and manage the AgentMesh trust network.

    View trust scores, inspect agents, visualize relationships,
    and manage attestations and revocations.
    """
    pass


@trust.command("list")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format (table, json, or yaml).",
)
@click.option("--json", "json_flag", is_flag=True, help="Output as JSON (shorthand for --format json).")
@click.option(
    "--min-score", type=int, default=None,
    help="Only show agents with trust score >= this value.",
)
@click.option(
    "--verified-only", is_flag=True, default=False,
    help="Only show verified agents.",
)
def list_agents(fmt: str, json_flag: bool, min_score: Optional[int], verified_only: bool):
    """List all agents with their trust scores."""
    if json_flag:
        fmt = "json"

    peers = _get_demo_peers()

    # Apply filters
    filtered: list[PeerInfo] = list(peers.values())
    if min_score is not None:
        filtered = [p for p in filtered if p.trust_score >= min_score]
    if verified_only:
        filtered = [p for p in filtered if p.trust_verified]

    if fmt in ("json", "yaml"):
        data = []
        for p in filtered:
            data.append({
                "agent_id": p.peer_did,
                "name": p.peer_name,
                "trust_score": p.trust_score,
                "trust_level": _trust_level_label(p.trust_score),
                "verified": p.trust_verified,
                "protocol": p.protocol,
                "capabilities": p.capabilities,
                "last_verified": _format_datetime(p.last_verified),
            })
        if fmt == "json":
            _output_json(data)
        else:
            _output_yaml(data)
        return

    # Table output
    console.print("\n[bold blue]🛡️  Trust Network — Agent List[/bold blue]\n")
    table = Table(box=box.ROUNDED)
    table.add_column("Agent ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Score", justify="right")
    table.add_column("Level")
    table.add_column("Verified")
    table.add_column("Protocol")
    table.add_column("Last Verified", style="dim")

    for p in filtered:
        level = _trust_level_label(p.trust_score)
        style = _trust_level_style(level)
        verified_icon = "[green]✓[/green]" if p.trust_verified else "[red]✗[/red]"
        table.add_row(
            p.peer_did,
            p.peer_name or "—",
            str(p.trust_score),
            f"[{style}]{level}[/{style}]",
            verified_icon,
            p.protocol,
            _format_datetime(p.last_verified),
        )

    console.print(table)
    console.print(f"\n  Total agents: {len(filtered)}\n")


@trust.command()
@click.argument("agent_id")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format.",
)
@click.option("--json", "json_flag", is_flag=True, help="Output as JSON.")
def inspect(agent_id: str, fmt: str, json_flag: bool):
    """Show detailed trust information for a specific agent.

    AGENT_ID is the DID of the agent to inspect (e.g. did:mesh:agent-alpha-001).
    """
    if json_flag:
        fmt = "json"

    peers = _get_demo_peers()
    peer = peers.get(agent_id)

    if peer is None:
        click.echo(f"Error: Agent '{agent_id}' not found.", err=True)
        raise SystemExit(1)

    info = {
        "agent_id": peer.peer_did,
        "name": peer.peer_name,
        "trust_score": peer.trust_score,
        "trust_level": _trust_level_label(peer.trust_score),
        "verified": peer.trust_verified,
        "protocol": peer.protocol,
        "capabilities": peer.capabilities,
        "endpoint": peer.endpoint,
        "connected_at": _format_datetime(peer.connected_at),
        "last_verified": _format_datetime(peer.last_verified),
    }

    if fmt in ("json", "yaml"):
        if fmt == "json":
            _output_json(info)
        else:
            _output_yaml(info)
        return

    # Table output
    level = _trust_level_label(peer.trust_score)
    style = _trust_level_style(level)
    console.print(f"\n[bold blue]🔍 Agent Inspection: {peer.peer_name or peer.peer_did}[/bold blue]\n")

    detail_table = Table(box=box.SIMPLE, show_header=False)
    detail_table.add_column("Field", style="bold cyan", no_wrap=True)
    detail_table.add_column("Value")

    detail_table.add_row("Agent ID", peer.peer_did)
    detail_table.add_row("Name", peer.peer_name or "—")
    detail_table.add_row("Trust Score", f"{peer.trust_score}/1000")
    detail_table.add_row("Trust Level", f"[{style}]{level}[/{style}]")
    verified_icon = "[green]✓ Yes[/green]" if peer.trust_verified else "[red]✗ No[/red]"
    detail_table.add_row("Verified", verified_icon)
    detail_table.add_row("Protocol", peer.protocol)
    detail_table.add_row("Capabilities", ", ".join(peer.capabilities) if peer.capabilities else "None")
    detail_table.add_row("Endpoint", peer.endpoint or "—")
    detail_table.add_row("Connected At", _format_datetime(peer.connected_at))
    detail_table.add_row("Last Verified", _format_datetime(peer.last_verified))

    console.print(detail_table)
    console.print()


@trust.command()
@click.argument("agent_id")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format.",
)
@click.option("--json", "json_flag", is_flag=True, help="Output as JSON.")
@click.option("--limit", type=int, default=None, help="Max number of history entries.")
def history(agent_id: str, fmt: str, json_flag: bool, limit: Optional[int]):
    """Show trust score history for an agent over time.

    AGENT_ID is the DID of the agent (e.g. did:mesh:agent-alpha-001).
    """
    if json_flag:
        fmt = "json"

    entries = _get_demo_history(agent_id)
    if limit is not None:
        entries = entries[-limit:]

    if fmt in ("json", "yaml"):
        data = {"agent_id": agent_id, "history": entries}
        if fmt == "json":
            _output_json(data)
        else:
            _output_yaml(data)
        return

    console.print(f"\n[bold blue]📈 Trust History: {agent_id}[/bold blue]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Timestamp", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Event")

    for entry in entries:
        delta = entry["delta"]
        if delta > 0:
            delta_str = f"[green]+{delta}[/green]"
        elif delta < 0:
            delta_str = f"[red]{delta}[/red]"
        else:
            delta_str = "[dim]0[/dim]"

        table.add_row(
            entry["timestamp"],
            str(entry["score"]),
            delta_str,
            entry["event"],
        )

    console.print(table)
    console.print()


@trust.command()
@click.option(
    "--format", "fmt",
    type=click.Choice(["ascii", "mermaid"]),
    default="ascii",
    help="Graph format: ascii (default) or mermaid.",
)
@click.option("--json", "json_flag", is_flag=True, help="Output graph data as JSON.")
def graph(fmt: str, json_flag: bool):
    """Show trust relationships as an ASCII art or Mermaid diagram."""
    peers = _get_demo_peers()

    if json_flag:
        nodes = []
        edges = []
        for peer in peers.values():
            nodes.append({
                "id": peer.peer_did,
                "name": peer.peer_name,
                "trust_score": peer.trust_score,
                "verified": peer.trust_verified,
            })
        # Generate demo edges between verified peers
        verified = [p for p in peers.values() if p.trust_verified]
        for i, a in enumerate(verified):
            for b in verified[i + 1:]:
                edges.append({
                    "from": a.peer_did,
                    "to": b.peer_did,
                    "protocol": a.protocol,
                })
        _output_json({"nodes": nodes, "edges": edges})
        return

    if fmt == "mermaid":
        lines = ["graph LR"]
        id_map = {}
        for i, peer in enumerate(peers.values()):
            short_id = f"A{i}"
            id_map[peer.peer_did] = short_id
            label = peer.peer_name or peer.peer_did.split(":")[-1]
            lines.append(f"    {short_id}[\"{label}<br/>Score: {peer.trust_score}\"]")

        verified = [p for p in peers.values() if p.trust_verified]
        for i, a in enumerate(verified):
            for b in verified[i + 1:]:
                a_id = id_map[a.peer_did]
                b_id = id_map[b.peer_did]
                lines.append(f"    {a_id} -->|{a.protocol}| {b_id}")

        click.echo("\n".join(lines))
        return

    # ASCII art graph
    click.echo("")
    click.echo("Trust Network Graph")
    click.echo("=" * 60)
    click.echo("")

    for peer in peers.values():
        label = peer.peer_name or peer.peer_did.split(":")[-1]
        _trust_level_label(peer.trust_score)
        bar_len = peer.trust_score // 20  # Scale 0-1000 to 0-50
        bar = "█" * bar_len
        verified_mark = "✓" if peer.trust_verified else "✗"
        click.echo(f"  [{verified_mark}] {label:<20s} {peer.trust_score:>4d} |{bar}")

    click.echo("")
    click.echo("Connections:")
    click.echo("-" * 60)

    verified = [p for p in peers.values() if p.trust_verified]
    for i, a in enumerate(verified):
        for b in verified[i + 1:]:
            a_name = a.peer_name or a.peer_did.split(":")[-1]
            b_name = b.peer_name or b.peer_did.split(":")[-1]
            click.echo(f"  {a_name} <--({a.protocol})--> {b_name}")

    click.echo("")


@trust.command()
@click.argument("agent_id")
@click.option("--reason", "-r", default="Manual revocation via CLI", help="Reason for revocation.")
@click.option("--force", is_flag=True, help="Skip confirmation prompt.")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format.",
)
@click.option("--json", "json_flag", is_flag=True, help="Output as JSON.")
def revoke(agent_id: str, reason: str, force: bool, fmt: str, json_flag: bool):
    """Revoke an agent's credentials and trust.

    AGENT_ID is the DID of the agent to revoke (e.g. did:mesh:agent-alpha-001).
    """
    if json_flag:
        fmt = "json"

    peers = _get_demo_peers()
    peer = peers.get(agent_id)

    if peer is None:
        click.echo(f"Error: Agent '{agent_id}' not found.", err=True)
        raise SystemExit(1)

    if not force:
        click.echo(
            f"Revoking trust for agent '{peer.peer_name or agent_id}' "
            f"(score: {peer.trust_score})."
        )
        confirmed = click.confirm("Are you sure?", default=False)
        if not confirmed:
            click.echo("Revocation cancelled.")
            return

    revocation_info = {
        "agent_id": agent_id,
        "name": peer.peer_name,
        "action": "revoked",
        "reason": reason,
        "previous_score": peer.trust_score,
        "new_score": 0,
        "revoked_at": _format_datetime(datetime.utcnow()),
    }

    if fmt in ("json", "yaml"):
        if fmt == "json":
            _output_json(revocation_info)
        else:
            _output_yaml(revocation_info)
        return

    console.print(f"\n[bold red]⚠️  Agent Revoked: {peer.peer_name or agent_id}[/bold red]\n")
    console.print(f"  Agent ID:       {agent_id}")
    console.print(f"  Reason:         {reason}")
    console.print(f"  Previous Score: {peer.trust_score}")
    console.print("  New Score:      [red]0[/red]")
    console.print(f"  Revoked At:     {revocation_info['revoked_at']}")
    console.print()


@trust.command()
@click.argument("agent_id")
@click.option("--note", "-n", default="Manual attestation via CLI", help="Attestation note.")
@click.option("--score-boost", type=int, default=50, help="Trust score boost (default: 50).")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format.",
)
@click.option("--json", "json_flag", is_flag=True, help="Output as JSON.")
def attest(agent_id: str, note: str, score_boost: int, fmt: str, json_flag: bool):
    """Manually attest or vouch for an agent.

    AGENT_ID is the DID of the agent to attest (e.g. did:mesh:agent-alpha-001).
    """
    if json_flag:
        fmt = "json"

    peers = _get_demo_peers()
    peer = peers.get(agent_id)

    if peer is None:
        click.echo(f"Error: Agent '{agent_id}' not found.", err=True)
        raise SystemExit(1)

    new_score = min(peer.trust_score + score_boost, 1000)

    attestation_info = {
        "agent_id": agent_id,
        "name": peer.peer_name,
        "action": "attested",
        "note": note,
        "previous_score": peer.trust_score,
        "score_boost": score_boost,
        "new_score": new_score,
        "new_level": _trust_level_label(new_score),
        "attested_at": _format_datetime(datetime.utcnow()),
    }

    if fmt in ("json", "yaml"):
        if fmt == "json":
            _output_json(attestation_info)
        else:
            _output_yaml(attestation_info)
        return

    level = _trust_level_label(new_score)
    style = _trust_level_style(level)

    console.print(f"\n[bold green]✅ Agent Attested: {peer.peer_name or agent_id}[/bold green]\n")
    console.print(f"  Agent ID:       {agent_id}")
    console.print(f"  Note:           {note}")
    console.print(f"  Previous Score: {peer.trust_score}")
    console.print(f"  Score Boost:    +{score_boost}")
    console.print(f"  New Score:      [{style}]{new_score}[/{style}]")
    console.print(f"  New Level:      [{style}]{level}[/{style}]")
    console.print(f"  Attested At:    {attestation_info['attested_at']}")
    console.print()

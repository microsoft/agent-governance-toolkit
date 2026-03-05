#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Registration - Hello World (Simulated)

This script demonstrates the registration handshake between an agent and
AgentMesh without requiring a running server. It simulates both sides of
the protocol to illustrate the flow and data structures.

Run: python simulated_registration.py
"""

import asyncio
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Import AgentMesh components
import sys
sys.path.insert(0, "../../src")

from agentmesh.identity import AgentIdentity, AgentDID

console = Console()


def print_header(text: str):
    """Print a formatted header."""
    console.print()
    console.print(f"[bold cyan]{text}[/bold cyan]")
    console.print()


def print_step(step: int, description: str):
    """Print a step header."""
    console.print(f"[bold]Step {step}:[/bold] {description}")


def print_success(message: str):
    """Print a success message."""
    console.print(f"  [green]✓[/green] {message}")


def print_info(label: str, value: str):
    """Print an info line."""
    console.print(f"  • [dim]{label}:[/dim] {value}")


async def simulate_registration():
    """Simulate the complete registration flow."""
    
    console.print()
    console.print(Panel(
        "[bold]AgentMesh Registration - Hello World[/bold]\n\n"
        "This example demonstrates:\n"
        "  1. Agent identity generation\n"
        "  2. Human sponsor accountability\n"
        "  3. Registration handshake with AgentMesh\n"
        "  4. Credential issuance and trust scoring",
        title="🚀 Hello World",
        border_style="cyan",
    ))
    
    # ========================================================================
    # STEP 1: Generate Agent Identity
    # ========================================================================
    print_header("Step 1: Generating Agent Identity")
    
    # Generate Ed25519 keypair (agent side)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    print_success("Generated Ed25519 keypair")
    print_info("Public key (base64)", public_key_b64[:32] + "...")
    print_info("Key algorithm", "Ed25519")
    
    # Agent metadata
    agent_name = "hello-world-agent"
    agent_description = "My first governed agent"
    sponsor_email = "alice@company.com"
    capabilities = ["read:data", "write:reports"]
    
    print_success(f"Agent name: {agent_name}")
    print_info("Description", agent_description)
    print_info("Sponsor", sponsor_email)
    print_info("Capabilities", ", ".join(capabilities))
    
    # ========================================================================
    # STEP 2: Obtain Sponsor Signature
    # ========================================================================
    print_header("Step 2: Obtaining Sponsor Signature")
    
    # In a real system, the sponsor would sign the agent details
    # For this simulation, we generate a mock signature
    sponsor_private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Message to sign: agent_name + sponsor_email + capabilities
    message = f"{agent_name}{sponsor_email}{','.join(sorted(capabilities))}"
    sponsor_signature = sponsor_private_key.sign(message.encode())
    sponsor_signature_b64 = base64.b64encode(sponsor_signature).decode()
    
    print_success("Sponsor signature obtained")
    print_info("Signature (base64)", sponsor_signature_b64[:32] + "...")
    print_info("Message signed", message[:50] + "...")
    
    # ========================================================================
    # STEP 3: Send Registration Request
    # ========================================================================
    print_header("Step 3: Sending Registration Request")
    
    # Build the registration request
    request = {
        "agent_name": agent_name,
        "agent_description": agent_description,
        "public_key": public_key_b64,
        "key_algorithm": "Ed25519",
        "sponsor_email": sponsor_email,
        "sponsor_id": "sponsor_001",
        "sponsor_signature": sponsor_signature_b64,
        "capabilities": capabilities,
        "supported_protocols": ["a2a", "mcp", "iatp"],
        "requested_at": datetime.utcnow().isoformat() + "Z",
    }
    
    print_success("Built RegistrationRequest")
    print_info("Request size", f"{len(str(request))} bytes")
    
    # Simulate network transmission
    console.print("  [dim]→ Sending to AgentMesh Identity Core...[/dim]")
    await asyncio.sleep(0.5)  # Simulate network latency
    
    # ========================================================================
    # STEP 4: AgentMesh Processes Request (Server Side)
    # ========================================================================
    print_header("Step 4: AgentMesh Validates & Issues Credentials")
    
    console.print("  [dim]AgentMesh is processing...[/dim]")
    
    # Validate sponsor
    await asyncio.sleep(0.2)
    print_success("Sponsor validated: alice@company.com")
    
    # Verify signature
    await asyncio.sleep(0.2)
    print_success("Sponsor signature verified")
    
    # Generate DID
    did = AgentDID.generate(agent_name, org="default")
    print_success(f"Generated DID: {did}")
    
    # Issue SVID certificate (simulated)
    svid_expires_at = datetime.utcnow() + timedelta(minutes=15)
    print_success(f"Issued SVID certificate (expires in 15 minutes)")
    
    # Calculate initial trust score
    # New agents start with score of 500/1000
    initial_score_data = {
        "total": 500,
        "dimensions": {
            "policy_compliance": 80,      # No violations yet
            "resource_efficiency": 50,    # No history
            "output_quality": 50,         # No history
            "security_posture": 70,       # Basic security
            "collaboration_health": 50,   # No peer interactions
        }
    }
    print_success(f"Calculated initial trust score: {initial_score_data['total']}/1000")
    
    # ========================================================================
    # STEP 5: Receive Registration Response
    # ========================================================================
    print_header("Step 5: Receiving Registration Response")
    
    # Simulate network latency
    console.print("  [dim]← Receiving RegistrationResponse...[/dim]")
    await asyncio.sleep(0.3)
    
    # Build the registration response
    response = {
        "agent_did": str(did),
        "agent_name": agent_name,
        "svid_certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",  # Mock cert
        "svid_key_id": f"key_{did.unique_id[:8]}",
        "svid_expires_at": svid_expires_at.isoformat() + "Z",
        "initial_trust_score": initial_score_data['total'],
        "trust_dimensions": initial_score_data['dimensions'],
        "access_token": f"agentmesh_token_{did.unique_id[:16]}",
        "refresh_token": f"agentmesh_refresh_{did.unique_id[:16]}",
        "token_ttl_seconds": 900,  # 15 minutes
        "registry_endpoint": "https://registry.agentmesh.io",
        "status": "success",
        "registered_at": datetime.utcnow().isoformat() + "Z",
        "next_rotation_at": svid_expires_at.isoformat() + "Z",
    }
    
    print_success("Received RegistrationResponse")
    
    # ========================================================================
    # STEP 6: Display Results
    # ========================================================================
    print_header("Step 6: Registration Complete!")
    
    # Create identity panel
    identity_info = f"""[green]✓ Registration successful![/green]

[bold]Agent Identity:[/bold]
  • DID: [cyan]{response['agent_did']}[/cyan]
  • Name: {response['agent_name']}
  • Key ID: {response['svid_key_id']}
  • Status: [green]ACTIVE[/green]

[bold]Credentials:[/bold]
  • SVID expires: {datetime.fromisoformat(response['svid_expires_at'].rstrip('Z')).strftime('%Y-%m-%d %H:%M:%S')} UTC
  • Token TTL: {response['token_ttl_seconds'] // 60} minutes
  • Registry: {response['registry_endpoint']}

[bold]Trust Score: {response['initial_trust_score']}/1000[/bold]"""
    
    console.print()
    console.print(Panel(identity_info, title="🎉 Agent Registered", border_style="green"))
    
    # Trust score breakdown table
    console.print()
    table = Table(title="Trust Score Breakdown", box=box.ROUNDED)
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Rating", justify="center")
    
    dimensions = response['trust_dimensions']
    
    def get_stars(score: int) -> str:
        """Convert score to star rating."""
        if score >= 90:
            return "⭐⭐⭐⭐⭐"
        elif score >= 70:
            return "⭐⭐⭐⭐"
        elif score >= 50:
            return "⭐⭐⭐"
        elif score >= 30:
            return "⭐⭐"
        else:
            return "⭐"
    
    table.add_row("Policy Compliance", f"{dimensions['policy_compliance']}/100", get_stars(dimensions['policy_compliance']))
    table.add_row("Resource Efficiency", f"{dimensions['resource_efficiency']}/100", get_stars(dimensions['resource_efficiency']))
    table.add_row("Output Quality", f"{dimensions['output_quality']}/100", get_stars(dimensions['output_quality']))
    table.add_row("Security Posture", f"{dimensions['security_posture']}/100", get_stars(dimensions['security_posture']))
    table.add_row("Collaboration Health", f"{dimensions['collaboration_health']}/100", get_stars(dimensions['collaboration_health']))
    
    console.print(table)
    
    # Next steps
    console.print()
    console.print(Panel(
        """[bold]What Happens Next:[/bold]

1. [cyan]Store credentials securely[/cyan]
   • Save SVID certificate and private key
   • Store access and refresh tokens
   
2. [cyan]Begin credential rotation[/cyan]
   • Rotate credentials every 15 minutes
   • Use refresh token to get new credentials
   
3. [cyan]Start agent operations[/cyan]
   • Connect to AgentMesh with mTLS
   • Perform work governed by policies
   • Trust score will adjust based on behavior
   
4. [cyan]Monitor trust score[/cyan]
   • Score increases with good behavior
   • Score decreases with policy violations
   • Credentials revoked if score drops below 300

[green]✓ Agent is now part of the AgentMesh![/green]""",
        title="📋 Next Steps",
        border_style="blue",
    ))
    
    console.print()


async def main():
    """Main entry point."""
    try:
        await simulate_registration()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

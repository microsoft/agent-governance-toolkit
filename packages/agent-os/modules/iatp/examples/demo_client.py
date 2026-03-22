#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IATP Demo Client

This script demonstrates the Inter-Agent Trust Protocol in action.
It shows how a client interacts with both trusted and untrusted agents
through their IATP sidecars.

Usage:
    python examples/demo_client.py

Prerequisites:
    docker-compose up -d
"""
import httpx
import json
import sys
from typing import Optional

# Configuration
BANK_SIDECAR_URL = "http://localhost:8081"
HONEYPOT_SIDECAR_URL = "http://localhost:9001"

def print_header(title: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_json(data: dict, indent: int = 2):
    """Print formatted JSON."""
    print(json.dumps(data, indent=indent, default=str))

def make_request(url: str, method: str = "GET", data: Optional[dict] = None, headers: Optional[dict] = None):
    """Make an HTTP request and handle errors gracefully."""
    try:
        if method == "GET":
            response = httpx.get(url, headers=headers, timeout=10)
        else:
            response = httpx.post(url, json=data, headers=headers, timeout=10)
        
        print(f"Status: {response.status_code}")
        
        # Print response headers
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            if key.lower().startswith("x-agent"):
                print(f"  {key}: {value}")
        
        # Print response body
        print("\nResponse Body:")
        try:
            print_json(response.json())
        except ValueError:
            print(response.text)
            
        return response
        
    except httpx.ConnectError:
        print(f"❌ Connection failed. Is the service running at {url}?")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def demo_health_checks():
    """Check health of both sidecars."""
    print_header("1. HEALTH CHECKS")
    
    print("\n📍 Bank Sidecar Health:")
    make_request(f"{BANK_SIDECAR_URL}/health")
    
    print("\n📍 Honeypot Sidecar Health:")
    make_request(f"{HONEYPOT_SIDECAR_URL}/health")


def demo_capability_handshake():
    """Demonstrate the IATP handshake to exchange capabilities."""
    print_header("2. CAPABILITY HANDSHAKE (The Trust Negotiation)")
    
    print("\n📍 Bank Agent Manifest (Trusted):")
    print("   This agent has high trust level and ephemeral data retention.")
    make_request(f"{BANK_SIDECAR_URL}/.well-known/agent-manifest")
    
    print("\n📍 Honeypot Agent Manifest (Untrusted):")
    print("   This agent has low trust and permanent data retention - DANGER!")
    make_request(f"{HONEYPOT_SIDECAR_URL}/.well-known/agent-manifest")


def demo_trusted_request():
    """Send a normal request to the trusted bank agent."""
    print_header("3. REQUEST TO TRUSTED AGENT")
    
    print("\n📍 Sending balance check to Bank Agent (via Sidecar):")
    print("   This should succeed because the agent is trusted.")
    
    data = {
        "action": "check_balance",
        "account_id": "ACC-12345",
        "customer_name": "John Doe"
    }
    
    print(f"\nRequest: POST {BANK_SIDECAR_URL}/proxy")
    print(f"Payload: {json.dumps(data, indent=2)}")
    
    make_request(f"{BANK_SIDECAR_URL}/proxy", method="POST", data=data)


def demo_sensitive_data_blocked():
    """Demonstrate how sensitive data is blocked."""
    print_header("4. SENSITIVE DATA PROTECTION")
    
    print("\n📍 Sending request with CREDIT CARD to agent with permanent retention:")
    print("   This should be BLOCKED by the sidecar!")
    
    data = {
        "action": "store_payment",
        "card_number": "4532015112830366",  # Valid Luhn number
        "customer_name": "Jane Doe"
    }
    
    print(f"\nRequest: POST {HONEYPOT_SIDECAR_URL}/proxy")
    print(f"Payload: {json.dumps(data, indent=2)}")
    
    make_request(f"{HONEYPOT_SIDECAR_URL}/proxy", method="POST", data=data)


def demo_ssn_blocked():
    """Demonstrate SSN blocking."""
    print_header("5. SSN PROTECTION")
    
    print("\n📍 Sending request with SSN to agent with non-ephemeral retention:")
    print("   This should be BLOCKED!")
    
    data = {
        "action": "verify_identity",
        "ssn": "123-45-6789",
        "name": "Bob Smith"
    }
    
    print(f"\nRequest: POST {HONEYPOT_SIDECAR_URL}/proxy")
    print(f"Payload: {json.dumps(data, indent=2)}")
    
    make_request(f"{HONEYPOT_SIDECAR_URL}/proxy", method="POST", data=data)


def demo_user_override():
    """Demonstrate the user override flow."""
    print_header("6. USER OVERRIDE FLOW")
    
    print("\n📍 Step 1: Send request to low-trust agent (no override):")
    print("   This should return a WARNING requiring user confirmation.")
    
    data = {
        "action": "get_recommendations",
        "user_id": "USER-789"
    }
    
    print(f"\nRequest: POST {HONEYPOT_SIDECAR_URL}/proxy")
    response = make_request(f"{HONEYPOT_SIDECAR_URL}/proxy", method="POST", data=data)
    
    if response and response.status_code == 449:
        print("\n📍 Step 2: Retry with X-User-Override header:")
        print("   User has acknowledged the risk and wants to proceed.")
        
        headers = {"X-User-Override": "true"}
        make_request(f"{HONEYPOT_SIDECAR_URL}/proxy", method="POST", data=data, headers=headers)


def demo_distributed_tracing():
    """Demonstrate distributed tracing."""
    print_header("7. DISTRIBUTED TRACING")
    
    print("\n📍 Sending request with custom trace ID:")
    
    data = {"action": "audit_log", "event": "demo_test"}
    headers = {"X-Agent-Trace-ID": "DEMO-TRACE-12345"}
    
    print(f"Trace ID: DEMO-TRACE-12345")
    make_request(f"{BANK_SIDECAR_URL}/proxy", method="POST", data=data, headers=headers)
    
    print("\n📍 Retrieving trace logs:")
    make_request(f"{BANK_SIDECAR_URL}/trace/DEMO-TRACE-12345")


def main():
    """Run the full demonstration."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗ █████╗ ████████╗██████╗     ██████╗ ███████╗███╗   ███╗ ██████╗        ║
║   ██║██╔══██╗╚══██╔══╝██╔══██╗    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗       ║
║   ██║███████║   ██║   ██████╔╝    ██║  ██║█████╗  ██╔████╔██║██║   ██║       ║
║   ██║██╔══██║   ██║   ██╔═══╝     ██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║       ║
║   ██║██║  ██║   ██║   ██║         ██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝       ║
║   ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝         ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝        ║
║                                                                              ║
║   Inter-Agent Trust Protocol - The Envoy for AI Agents                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    print("This demo shows how IATP protects agents and enforces trust policies.\n")
    print(f"Bank Sidecar URL:     {BANK_SIDECAR_URL}")
    print(f"Honeypot Sidecar URL: {HONEYPOT_SIDECAR_URL}")
    
    try:
        demo_health_checks()
        demo_capability_handshake()
        demo_trusted_request()
        demo_sensitive_data_blocked()
        demo_ssn_blocked()
        demo_user_override()
        demo_distributed_tracing()
        
        print_header("DEMO COMPLETE")
        print("""
✅ Key Takeaways:
   1. IATP sidecars intercept ALL agent traffic
   2. Capability manifests enable trust negotiation
   3. Sensitive data (credit cards, SSN) is automatically blocked
   4. Low-trust agents require user override
   5. Every request gets a trace ID for debugging

📚 Next Steps:
   - Try modifying the manifests in docker-compose.yml
   - Add your own agent and protect it with a sidecar
   - Explore the flight recorder logs

🔗 Documentation: https://github.com/microsoft/agent-governance-toolkit
        """)
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()

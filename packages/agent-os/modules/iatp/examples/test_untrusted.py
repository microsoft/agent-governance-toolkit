# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script to demonstrate the untrusted agent scenario with warnings and override.
"""
import httpx
import json

print("="*70)
print("Testing IATP with UNTRUSTED agent scenario")
print("="*70)

# First, let's test a request WITHOUT override - should get a warning
print("\n1. Testing request without override (should get warning)...")
print("-" * 70)

try:
    response = httpx.post(
        "http://localhost:8002/proxy",  # We'll start an untrusted sidecar on 8002
        json={
            "task": "book_cheap_flight",
            "data": {
                "destination": "NYC"
            }
        },
        timeout=10.0
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Connection failed - untrusted sidecar not running: {e}")
    print("\nTo test the untrusted scenario:")
    print("1. Uncomment 'create_untrusted_manifest()' in examples/run_sidecar.py")
    print("2. Change port to 8002 in run_sidecar.py")
    print("3. Restart the sidecar")
    print("4. Run this script again")
    exit(0)

# Now test WITH override
print("\n2. Testing request WITH override (should succeed but be quarantined)...")
print("-" * 70)

try:
    response = httpx.post(
        "http://localhost:8002/proxy",
        headers={"X-User-Override": "true"},
        json={
            "task": "book_cheap_flight",
            "data": {
                "destination": "NYC"
            }
        },
        timeout=10.0
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print(f"\nResponse Headers:")
    print(f"  X-Agent-Trace-ID: {response.headers.get('X-Agent-Trace-ID')}")
    print(f"  X-Agent-Trust-Score: {response.headers.get('X-Agent-Trust-Score')}")
    print(f"  X-Agent-Quarantined: {response.headers.get('X-Agent-Quarantined')}")
except Exception as e:
    print(f"Error: {e}")

# Test blocked request - credit card with permanent storage
print("\n3. Testing BLOCKED request (credit card with untrusted agent)...")
print("-" * 70)

try:
    response = httpx.post(
        "http://localhost:8002/proxy",
        json={
            "task": "payment",
            "card": "4532-0151-1283-0366"
        },
        timeout=10.0
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*70)
print("Testing complete!")
print("="*70)

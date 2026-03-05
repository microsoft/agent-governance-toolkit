# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Client Making Requests Through the Sidecar

This example shows how a client would interact with the sidecar,
including handling warnings and overrides.
"""
import httpx
import json


def test_simple_request():
    """Test a simple request through the sidecar."""
    print("\n" + "="*60)
    print("TEST 1: Simple Request (Trusted Agent)")
    print("="*60)
    
    try:
        response = httpx.post(
            "http://localhost:8001/proxy",
            json={
                "task": "book_flight",
                "data": {
                    "destination": "NYC",
                    "date": "2026-02-15"
                }
            }
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        print(f"Trace ID: {response.headers.get('X-Agent-Trace-ID')}")
        print(f"Trust Score: {response.headers.get('X-Agent-Trust-Score')}")
    except Exception as e:
        print(f"Error: {e}")


def test_sensitive_data_blocked():
    """Test that sensitive data is blocked for untrusted agents."""
    print("\n" + "="*60)
    print("TEST 2: Sensitive Data (Should be Blocked)")
    print("="*60)
    print("Note: Change manifest to untrusted in run_sidecar.py first!")
    
    try:
        response = httpx.post(
            "http://localhost:8001/proxy",
            json={
                "task": "book_flight",
                "data": {
                    "destination": "NYC",
                    "credit_card": "4532-0151-1283-0366"  # Test credit card
                }
            }
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")


def test_warning_and_override():
    """Test warning system and user override."""
    print("\n" + "="*60)
    print("TEST 3: Warning and User Override")
    print("="*60)
    print("Note: Change manifest to untrusted in run_sidecar.py first!")
    
    # First request without override - should get warning
    print("\n--- Request without override ---")
    try:
        response = httpx.post(
            "http://localhost:8001/proxy",
            json={
                "task": "book_flight",
                "data": {
                    "destination": "NYC"
                }
            }
        )
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 449:
            print("\n⚠️  Got warning! Now trying with override...")
            
            # Second request with override
            print("\n--- Request WITH override ---")
            response = httpx.post(
                "http://localhost:8001/proxy",
                headers={"X-User-Override": "true"},
                json={
                    "task": "book_flight",
                    "data": {
                        "destination": "NYC"
                    }
                }
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
            print(f"Quarantined: {response.headers.get('X-Agent-Quarantined')}")
    except Exception as e:
        print(f"Error: {e}")


def test_get_manifest():
    """Test getting the capability manifest."""
    print("\n" + "="*60)
    print("TEST 4: Get Capability Manifest")
    print("="*60)
    
    try:
        response = httpx.get("http://localhost:8001/.well-known/agent-manifest")
        print(f"Status: {response.status_code}")
        print(f"Manifest: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")


def test_trace_retrieval():
    """Test retrieving trace logs."""
    print("\n" + "="*60)
    print("TEST 5: Retrieve Trace Logs")
    print("="*60)
    
    # First make a request to get a trace ID
    try:
        response = httpx.post(
            "http://localhost:8001/proxy",
            json={"task": "test", "data": {}}
        )
        trace_id = response.headers.get("X-Agent-Trace-ID")
        print(f"Made request with trace ID: {trace_id}")
        
        # Now retrieve the logs
        trace_response = httpx.get(f"http://localhost:8001/trace/{trace_id}")
        print(f"\nTrace logs: {json.dumps(trace_response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")


def main():
    """
    Run the test client.
    
    Make sure both the backend agent and sidecar are running first:
    1. Terminal 1: python examples/backend_agent.py
    2. Terminal 2: python examples/run_sidecar.py
    3. Terminal 3: python examples/client.py
    """
    print("IATP Client Test Suite")
    print("="*60)
    print("Make sure the backend agent and sidecar are running!")
    
    test_get_manifest()
    test_simple_request()
    test_trace_retrieval()
    
    print("\n" + "="*60)
    print("To test warnings and overrides:")
    print("1. Stop the sidecar")
    print("2. Edit run_sidecar.py to use create_untrusted_manifest()")
    print("3. Restart the sidecar")
    print("4. Run: test_warning_and_override() and test_sensitive_data_blocked()")
    print("="*60)


if __name__ == "__main__":
    main()

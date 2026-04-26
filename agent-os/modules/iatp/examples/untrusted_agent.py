# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Untrusted Agent (Rogue Agent for Testing)

This agent demonstrates the "worst case scenario":
- Untrusted status
- Permanent data retention (stores forever)
- No reversibility
- Human review enabled
- ML training consent enabled
- Low trust score (0-1/10)

This agent is useful for testing that your sidecar correctly:
1. Detects and blocks dangerous requests (credit cards to untrusted agents)
2. Generates appropriate warnings
3. Requires user override
4. Logs quarantined transactions

This is the "honeypot" agent mentioned in the problem statement.
"""
from fastapi import FastAPI, Header
from typing import Optional
import json
from datetime import datetime, timezone

app = FastAPI(title="Untrusted Agent (Test)")

# This agent "maliciously" stores everything forever
permanent_storage = []


@app.post("/")
async def process_request(
    request: dict,
    x_agent_trace_id: Optional[str] = Header(None)
):
    """
    Process a request - but store everything permanently!
    
    This simulates a rogue agent that doesn't respect privacy.
    The sidecar should detect this and warn users.
    """
    task = request.get("task", "unknown")
    data = request.get("data", {})
    
    # "Maliciously" store the data forever
    permanent_storage.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "task": task,
        "data": data,
        "trace_id": x_agent_trace_id
    })
    
    # Pretend to process normally
    result = {
        "status": "success",
        "task": task,
        "result": f"Processed {task}",
        "data_stored_permanently": True,  # Honest about its behavior
        "will_train_ml_models": True,  # Will use data for training
        "human_reviewed": True,  # Humans will see the data
        "reversibility": "none"  # Cannot undo
    }
    
    return result


@app.get("/storage")
async def view_storage():
    """
    View what this agent has stored (demonstrates the problem).
    
    In a real rogue agent, this wouldn't be exposed, but we expose it
    for testing purposes to show that the agent stores everything.
    """
    return {
        "message": "This agent stores everything permanently!",
        "total_items": len(permanent_storage),
        "storage": permanent_storage
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Untrusted Agent",
        "trust_level": "untrusted",
        "warning": "⚠️ This agent stores data permanently and cannot undo operations!"
    }


# This agent intentionally DOES NOT implement a /compensate endpoint
# to demonstrate "no reversibility"


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("⚠️  WARNING: Starting UNTRUSTED AGENT")
    print("=" * 60)
    print("")
    print("This agent demonstrates BAD behavior:")
    print("  ❌ Stores data permanently (forever)")
    print("  ❌ No reversibility (cannot undo)")
    print("  ❌ Human review enabled (privacy risk)")
    print("  ❌ Uses data for ML training")
    print("  ❌ Trust score: 0-1/10")
    print("")
    print("The IATP sidecar should:")
    print("  ✓ Block credit cards sent to this agent")
    print("  ✓ Warn about low trust score")
    print("  ✓ Require user override to proceed")
    print("  ✓ Quarantine all transactions")
    print("")
    print("Start the sidecar with: python examples/run_untrusted_sidecar.py")
    print("Test with: python examples/test_untrusted.py")
    print("")
    uvicorn.run(app, host="0.0.0.0", port=8000)

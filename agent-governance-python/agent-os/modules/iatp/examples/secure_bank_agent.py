# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Secure Bank Agent

This agent demonstrates a "verified_partner" with strong security guarantees:
- Full reversibility within 5-minute fraud detection window
- Ephemeral data retention
- No human review
- No ML training on user data
- High trust score (10/10)
"""
from fastapi import FastAPI, Header, HTTPException
from typing import Optional
import time
import uuid

app = FastAPI(title="Secure Bank Agent")

# Simulated transaction store (in-memory for demo)
transactions = {}


@app.post("/")
async def process_banking_request(
    request: dict,
    x_agent_trace_id: Optional[str] = Header(None)
):
    """
    Process a secure banking transaction.
    
    This agent demonstrates best practices:
    - Idempotent operations
    - Transaction tracking
    - Reversibility support
    - Clear audit trails
    """
    task = request.get("task")
    data = request.get("data", {})
    
    if task == "transfer":
        # Simulate a bank transfer
        transaction_id = str(uuid.uuid4())
        amount = data.get("amount", 0)
        from_account = data.get("from_account")
        to_account = data.get("to_account")
        
        # Store transaction for potential reversal
        transactions[transaction_id] = {
            "amount": amount,
            "from_account": from_account,
            "to_account": to_account,
            "timestamp": time.time(),
            "status": "completed",
            "trace_id": x_agent_trace_id
        }
        
        return {
            "status": "success",
            "transaction_id": transaction_id,
            "message": f"Transferred ${amount} from {from_account} to {to_account}",
            "reversible_until": time.time() + 300  # 5 minutes
        }
    
    elif task == "check_balance":
        # Simulate balance check (read-only, always reversible)
        account = data.get("account")
        return {
            "status": "success",
            "account": account,
            "balance": 1000.00,  # Simulated balance
            "currency": "USD"
        }
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown task: {task}")


@app.post("/compensate/{transaction_id}")
async def compensate_transaction(transaction_id: str):
    """
    Reverse a transaction (compensation endpoint).
    
    This demonstrates the IATP reversibility protocol.
    """
    UNDO_WINDOW_SECONDS = 300  # 5 minutes
    
    if transaction_id not in transactions:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    transaction = transactions[transaction_id]
    
    # Check if still within undo window (5 minutes)
    if time.time() - transaction["timestamp"] > UNDO_WINDOW_SECONDS:
        raise HTTPException(
            status_code=400,
            detail="Undo window expired (5 minutes)"
        )
    
    if transaction["status"] == "reversed":
        return {
            "success": True,
            "message": "Transaction already reversed",
            "transaction_id": transaction_id
        }
    
    # Reverse the transaction
    transaction["status"] = "reversed"
    transaction["reversed_at"] = time.time()
    
    return {
        "success": True,
        "message": "Transaction reversed successfully",
        "transaction_id": transaction_id,
        "amount_returned": transaction["amount"],
        "compensation_method": "rollback"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Secure Bank Agent",
        "trust_level": "verified_partner",
        "active_transactions": len(transactions)
    }


if __name__ == "__main__":
    import uvicorn
    print("Starting Secure Bank Agent on port 8000")
    print("This agent demonstrates:")
    print("  - Full reversibility (5-minute window)")
    print("  - Ephemeral data retention")
    print("  - High trust score (10/10)")
    print("")
    print("Start the sidecar with: python examples/run_secure_bank_sidecar.py")
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Simple Backend Agent

This is a simple FastAPI agent that the sidecar will proxy.
In a real scenario, this would be your existing agent service.
"""
from fastapi import FastAPI, Header
from typing import Optional

app = FastAPI(title="Example Backend Agent")


@app.post("/")
async def process_request(
    request: dict,
    x_agent_trace_id: Optional[str] = Header(None)
):
    """
    Process a request from the sidecar.
    
    The agent receives clean, validated JSON and doesn't need to worry
    about security checks or privacy validation - the sidecar handles that.
    """
    # Simulate some processing
    task = request.get("task", "unknown")
    data = request.get("data", {})
    
    return {
        "status": "success",
        "task": task,
        "result": f"Processed {task} with data: {data}",
        "trace_id": x_agent_trace_id
    }


if __name__ == "__main__":
    import uvicorn
    # Run on port 8000 (the sidecar will run on 8001)
    uvicorn.run(app, host="0.0.0.0", port=8000)

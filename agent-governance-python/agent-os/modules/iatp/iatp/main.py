# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IATP Sidecar Proxy - Main Application

This is the main entry point for the IATP Sidecar Proxy.
It can be run directly with: uvicorn iatp.main:app --host 0.0.0.0 --port 8081

The sidecar acts as a gateway that:
1. Intercepts all requests to/from the agent
2. Validates requests using the built-in Policy Engine
3. Handles failures using the Recovery Engine (scak)
4. Enforces privacy and security policies
5. Records all events in the Flight Recorder for distributed tracing
"""
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.policy_engine import IATPPolicyEngine
from iatp.recovery import IATPRecoveryEngine
from iatp.security import PrivacyScrubber, SecurityValidator
from iatp.telemetry import FlightRecorder, TraceIDGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("iatp.sidecar")

# Configuration from environment variables
UPSTREAM_AGENT_URL = os.getenv("IATP_AGENT_URL", "http://localhost:8000")
SIDECAR_PORT = int(os.getenv("IATP_PORT", "8081"))
AGENT_ID = os.getenv("IATP_AGENT_ID", "secure-bank-agent")
TRUST_LEVEL = os.getenv("IATP_TRUST_LEVEL", "verified_partner")
REVERSIBILITY = os.getenv("IATP_REVERSIBILITY", "full")
RETENTION = os.getenv("IATP_RETENTION", "ephemeral")
HUMAN_IN_LOOP = os.getenv("IATP_HUMAN_IN_LOOP", "false").lower() == "true"
TRAINING_CONSENT = os.getenv("IATP_TRAINING_CONSENT", "false").lower() == "true"

# Initialize engines and validators
policy_engine = IATPPolicyEngine()
recovery_engine = IATPRecoveryEngine()
security_validator = SecurityValidator()
privacy_scrubber = PrivacyScrubber()
flight_recorder = FlightRecorder()

# Build the manifest from environment
def get_manifest() -> CapabilityManifest:
    """Create capability manifest from environment configuration."""
    return CapabilityManifest(
        agent_id=AGENT_ID,
        agent_version="0.2.0",
        trust_level=TrustLevel(TRUST_LEVEL),
        capabilities=AgentCapabilities(
            reversibility=ReversibilityLevel(REVERSIBILITY),
            idempotency=True,
            undo_window="24h",
            sla_latency="2000ms",
            rate_limit=100
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy(RETENTION),
            human_review=HUMAN_IN_LOOP,
            encryption_at_rest=True,
            encryption_in_transit=True
        )
    )

manifest = get_manifest()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown."""
    logger.info("=" * 60)
    logger.info("IATP Sidecar Proxy Starting")
    logger.info("=" * 60)
    logger.info(f"  Upstream Agent: {UPSTREAM_AGENT_URL}")
    logger.info(f"  Agent ID: {AGENT_ID}")
    logger.info(f"  Trust Level: {TRUST_LEVEL}")
    logger.info(f"  Reversibility: {REVERSIBILITY}")
    logger.info(f"  Retention: {RETENTION}")
    logger.info("=" * 60)
    yield
    logger.info("IATP Sidecar shutting down...")


# Create FastAPI application
app = FastAPI(
    title="IATP Sidecar Proxy",
    description="Inter-Agent Trust Protocol Sidecar - The Envoy for AI Agents",
    version="0.2.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "component": "sidecar",
        "agent_id": AGENT_ID,
        "upstream": UPSTREAM_AGENT_URL
    }


@app.get("/.well-known/agent-manifest")
@app.options("/capabilities")
async def get_capabilities():
    """
    IATP Handshake Endpoint.

    Returns this agent's capability manifest for trust negotiation.
    External agents call this to understand what this agent can do
    and what its security/privacy posture is.
    """
    return JSONResponse(content=manifest.model_dump())


@app.post("/proxy")
@app.post("/proxy/v1/task")
async def proxy_task(
    request: Request,
    x_user_override: Optional[str] = Header(None),
    x_agent_trace_id: Optional[str] = Header(None)
):
    """
    The Main Gateway - Intercepts and validates all requests.

    Flow:
    1. Generate/validate trace ID
    2. Parse and validate the payload
    3. Run Policy Engine checks
    4. Run Security Validator checks
    5. Forward to upstream agent
    6. Handle failures with Recovery Engine (scak)
    7. Log everything to Flight Recorder

    Headers:
    - X-User-Override: Set to "true" to bypass security warnings
    - X-Agent-Trace-ID: Optional trace ID for distributed tracing
    """
    # 1. GENERATE TRACE ID
    trace_id = x_agent_trace_id or TraceIDGenerator.generate()

    # 2. PARSE PAYLOAD
    try:
        payload = await request.json()
    except Exception as e:
        logger.warning(f"[{trace_id}] Invalid JSON payload: {e}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "Invalid JSON payload",
                "trace_id": trace_id
            }
        )

    # 3. POLICY ENGINE CHECK
    policy_allowed, policy_error, policy_warning = policy_engine.validate_manifest(manifest)

    if not policy_allowed:
        logger.warning(f"[{trace_id}] Policy Engine BLOCKED: {policy_error}")
        flight_recorder.log_blocked_request(
            trace_id=trace_id,
            agent_id=AGENT_ID,
            payload=payload,
            reason=f"Policy Engine: {policy_error}",
            manifest=manifest
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": policy_error,
                "trace_id": trace_id,
                "blocked": True,
                "blocked_by": "policy_engine"
            }
        )

    # 4. SECURITY VALIDATOR CHECK
    is_valid, error_message = security_validator.validate_privacy_policy(manifest, payload)

    if not is_valid:
        logger.warning(f"[{trace_id}] Security Validator BLOCKED: {error_message}")
        flight_recorder.log_blocked_request(
            trace_id=trace_id,
            agent_id=AGENT_ID,
            payload=payload,
            reason=error_message or "Security policy violation",
            manifest=manifest
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": error_message,
                "trace_id": trace_id,
                "blocked": True,
                "blocked_by": "security_validator"
            }
        )

    # 5. CHECK IF WARNING/OVERRIDE NEEDED
    warning = security_validator.generate_warning_message(manifest, payload)
    if policy_warning:
        warning = f"{warning}\n{policy_warning}" if warning else policy_warning

    if warning and not x_user_override:
        trust_score = manifest.calculate_trust_score()
        logger.info(f"[{trace_id}] Requires user override. Trust score: {trust_score}")
        return JSONResponse(
            status_code=449,  # Retry With User Override
            content={
                "warning": warning,
                "trust_score": trust_score,
                "requires_override": True,
                "trace_id": trace_id,
                "message": (
                    "This request requires user confirmation. "
                    "Retry with header 'X-User-Override: true'"
                )
            }
        )

    # Log the request
    flight_recorder.log_request(
        trace_id=trace_id,
        agent_id=AGENT_ID,
        payload=payload,
        manifest=manifest,
        quarantined=security_validator.should_quarantine(manifest)
    )

    # 6. FORWARD TO UPSTREAM AGENT
    import time
    start_time = time.time()

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{UPSTREAM_AGENT_URL}/process",
                json=payload,
                headers={
                    "X-Agent-Trace-ID": trace_id,
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )

            latency_ms = (time.time() - start_time) * 1000

            # Parse response
            try:
                response_data = response.json()
            except Exception:
                response_data = {"raw": response.text}

            # Log response
            flight_recorder.log_response(
                trace_id=trace_id,
                agent_id=AGENT_ID,
                response=response_data,
                status_code=response.status_code,
                latency_ms=latency_ms
            )

            logger.info(f"[{trace_id}] Proxied request. Status: {response.status_code}, Latency: {latency_ms:.2f}ms")

            # Return with tracing headers
            return JSONResponse(
                content=response_data,
                status_code=response.status_code,
                headers={
                    "X-Agent-Trace-ID": trace_id,
                    "X-Agent-Latency-Ms": str(int(latency_ms)),
                    "X-Agent-Trust-Score": str(manifest.calculate_trust_score())
                }
            )

    except httpx.TimeoutException as e:
        # 7. TIMEOUT - TRIGGER RECOVERY
        logger.error(f"[{trace_id}] Upstream timeout: {e}")
        flight_recorder.log_error(
            trace_id=trace_id,
            agent_id=AGENT_ID,
            error="Request timeout",
            details={"timeout_seconds": 30, "upstream": UPSTREAM_AGENT_URL}
        )

        recovery_result = await recovery_engine.handle_failure(
            trace_id=trace_id,
            error=e,
            manifest=manifest,
            payload=payload
        )

        return JSONResponse(
            status_code=504,
            content={
                "error": "Upstream agent timeout",
                "trace_id": trace_id,
                "recovery": recovery_result
            }
        )

    except Exception as e:
        # GENERAL ERROR - TRIGGER RECOVERY
        logger.error(f"[{trace_id}] Upstream error: {e}")
        flight_recorder.log_error(
            trace_id=trace_id,
            agent_id=AGENT_ID,
            error=str(e),
            details={"exception_type": type(e).__name__, "upstream": UPSTREAM_AGENT_URL}
        )

        recovery_result = await recovery_engine.handle_failure(
            trace_id=trace_id,
            error=e,
            manifest=manifest,
            payload=payload
        )

        if recovery_result.get("success"):
            return JSONResponse(
                status_code=200,
                content={
                    "status": "recovered",
                    "trace_id": trace_id,
                    "recovery": recovery_result
                }
            )

        return JSONResponse(
            status_code=502,
            content={
                "error": "Upstream agent error",
                "trace_id": trace_id,
                "recovery": recovery_result
            }
        )


@app.get("/trace/{trace_id}")
async def get_trace(trace_id: str):
    """
    Retrieve flight recorder logs for a specific trace ID.

    Useful for debugging and distributed tracing across agent calls.
    """
    logs = flight_recorder.get_trace_logs(trace_id)
    if not logs:
        raise HTTPException(status_code=404, detail="Trace not found")
    return {"trace_id": trace_id, "logs": logs}


@app.get("/metrics")
async def get_metrics():
    """
    Get sidecar metrics and statistics.
    """
    return {
        "agent_id": AGENT_ID,
        "upstream": UPSTREAM_AGENT_URL,
        "trust_level": TRUST_LEVEL,
        "trust_score": manifest.calculate_trust_score(),
        "manifest": manifest.model_dump()
    }


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "iatp.main:app",
        host="0.0.0.0",
        port=SIDECAR_PORT,
        reload=True,
        log_level="info"
    )

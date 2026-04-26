# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Cloud Board API

The central API service for the Nexus Trust Exchange.
Provides REST endpoints for agent registration, reputation, escrow, and compliance.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os

# Import routes
from .routes import registry, reputation, escrow, arbiter, compliance

# Import core components
import sys
sys.path.insert(0, "../..")  # Add modules to path
from modules.nexus import (
    AgentRegistry,
    ReputationEngine,
    EscrowManager,
    Arbiter,
    DMZProtocol,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Global instances (would use dependency injection in production)
_registry: AgentRegistry = None
_reputation: ReputationEngine = None
_escrow: EscrowManager = None
_arbiter: Arbiter = None
_dmz: DMZProtocol = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup resources."""
    global _registry, _reputation, _escrow, _arbiter, _dmz
    
    logger.info("Initializing Nexus Cloud Board...")
    
    # Initialize components
    _reputation = ReputationEngine()
    _registry = AgentRegistry(_reputation)
    _escrow = EscrowManager(_reputation)
    _arbiter = Arbiter(_reputation, _escrow)
    _dmz = DMZProtocol()
    
    logger.info("Nexus Cloud Board initialized successfully")
    
    yield
    
    logger.info("Shutting down Nexus Cloud Board...")


# Create FastAPI app
app = FastAPI(
    title="Nexus Cloud Board",
    description="The Agent Trust Exchange - Registry and Communication Board for AI Agents",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency injection
def get_registry() -> AgentRegistry:
    return _registry


def get_reputation() -> ReputationEngine:
    return _reputation


def get_escrow() -> EscrowManager:
    return _escrow


def get_arbiter() -> Arbiter:
    return _arbiter


def get_dmz() -> DMZProtocol:
    return _dmz


# Include routers
app.include_router(
    registry.router,
    prefix="/v1/agents",
    tags=["Registry"],
)

app.include_router(
    reputation.router,
    prefix="/v1/reputation",
    tags=["Reputation"],
)

app.include_router(
    escrow.router,
    prefix="/v1/escrow",
    tags=["Escrow"],
)

app.include_router(
    arbiter.router,
    prefix="/v1/disputes",
    tags=["Disputes"],
)

app.include_router(
    compliance.router,
    prefix="/v1/compliance",
    tags=["Compliance"],
)


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "nexus-cloud-board",
        "version": "0.1.0",
    }


# Stats endpoint
@app.get("/v1/stats")
async def get_stats():
    """Get Nexus network statistics."""
    return {
        "total_agents": _registry.get_agent_count() if _registry else 0,
        "active_escrows": len(_escrow.list_escrows()) if _escrow else 0,
        "pending_disputes": len(_arbiter.list_disputes(resolved=False)) if _arbiter else 0,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

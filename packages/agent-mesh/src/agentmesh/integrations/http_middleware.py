# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HTTP Trust Middleware for AgentMesh
====================================

Framework-agnostic middleware that validates incoming HTTP requests against
AgentMesh trust headers (X-Agent-DID, X-Agent-Public-Key, X-Agent-Capabilities).

Provides a generic ``TrustMiddleware`` class plus thin decorators for Flask
(``flask_trust_required``) and FastAPI (``fastapi_trust_required``).  Missing
frameworks are handled gracefully — the decorators simply raise ImportError
at call time if their framework is unavailable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

from agentmesh.identity.agent_id import AgentIdentity

logger = logging.getLogger(__name__)


@dataclass
class TrustConfig:
    """Configuration for trust verification."""

    required_trust_score: float = 0.5
    required_capabilities: List[str] = field(default_factory=list)
    # V16: Default to strict mode — require explicit opt-in for permissive
    permissive_mode: bool = False


@dataclass
class VerificationResult:
    """Outcome of a trust verification check."""

    verified: bool
    trust_score: float = 0.0
    reason: str = ""
    peer_did: str = ""


class TrustMiddleware:
    """Framework-agnostic HTTP trust verification.

    Parameters
    ----------
    identity : AgentIdentity, optional
        Local agent identity used to verify signatures and attach response
        headers.
    config : TrustConfig, optional
        Verification thresholds and behaviour knobs.
    """

    def __init__(
        self,
        identity: Optional[AgentIdentity] = None,
        config: Optional[TrustConfig] = None,
    ) -> None:
        self.identity = identity
        self.config = config or TrustConfig()

    # -- core verification (framework-independent) -------------------------

    def verify_request(
        self,
        headers: Dict[str, str],
        config_override: Optional[TrustConfig] = None,
    ) -> Tuple[VerificationResult, Optional[Dict[str, Any]]]:
        """Verify trust headers and return *(result, error_body | None)*.

        *error_body* is a JSON-serialisable dict when verification fails, or
        ``None`` on success.  The caller decides how to turn it into a
        framework-specific response.
        """
        cfg = config_override or self.config
        peer_did = headers.get("X-Agent-DID", "")
        peer_public_key = headers.get("X-Agent-Public-Key", "")
        raw_caps = headers.get("X-Agent-Capabilities", "")
        peer_caps = [c.strip() for c in raw_caps.split(",") if c.strip()]

        if not peer_did:
            if cfg.permissive_mode:
                return VerificationResult(verified=True), None
            return (
                VerificationResult(verified=False, reason="Missing X-Agent-DID header"),
                {"error": "Trust headers required", "reason": "Missing X-Agent-DID header"},
            )

        # Verify signature when both identity and peer key are available
        score = 1.0
        if self.identity and peer_public_key:
            try:
                self.identity.verify_signature(peer_did.encode(), peer_public_key)
            except Exception:
                score = 0.3  # unverifiable signature lowers trust

        # Check required capabilities
        missing = [c for c in cfg.required_capabilities if c not in peer_caps]
        if missing:
            return (
                VerificationResult(verified=False, peer_did=peer_did, trust_score=score,
                                   reason=f"Missing capabilities: {missing}"),
                {"error": "Insufficient capabilities", "missing": missing},
            )

        if score < cfg.required_trust_score:
            return (
                VerificationResult(verified=False, peer_did=peer_did, trust_score=score,
                                   reason="Trust score too low"),
                {"error": "Insufficient trust score", "required": cfg.required_trust_score,
                 "actual": score},
            )

        return VerificationResult(verified=True, peer_did=peer_did, trust_score=score), None

    def response_headers(self) -> Dict[str, str]:
        """Return trust headers to attach to outgoing responses."""
        if not self.identity:
            return {}
        return {
            "X-Agent-DID": str(self.identity.did),
            "X-Agent-Public-Key": self.identity.public_key,
            "X-Agent-Capabilities": ",".join(self.identity.capabilities),
        }


# -- Framework-specific decorators -----------------------------------------

def flask_trust_required(
    middleware: TrustMiddleware,
    config: Optional[TrustConfig] = None,
) -> Callable:
    """Flask decorator that rejects untrusted requests."""
    from flask import request, g, jsonify  # noqa: late import

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result, err = middleware.verify_request(dict(request.headers), config)
            if err:
                status = 401 if "required" in err.get("error", "") else 403
                return jsonify(err), status
            g.trust_result = result
            g.peer_did = result.peer_did
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def fastapi_trust_required(
    middleware: TrustMiddleware,
    config: Optional[TrustConfig] = None,
) -> Callable:
    """FastAPI dependency that rejects untrusted requests."""
    from fastapi import Request  # noqa: late import

    async def dependency(request: Request) -> Optional[VerificationResult]:
        result, err = middleware.verify_request(dict(request.headers), config)
        if err:
            status = 401 if "required" in err.get("error", "") else 403
            raise _fastapi_http_exc(status, err)
        return result

    return dependency


def _fastapi_http_exc(status: int, detail: Any) -> Exception:
    from fastapi import HTTPException  # noqa: late import
    return HTTPException(status_code=status, detail=detail)

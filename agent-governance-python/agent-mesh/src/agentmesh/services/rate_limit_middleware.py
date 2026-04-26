# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""HTTP-layer rate limiting middleware for Agent Mesh.

This module integrates the service-level token bucket limiter with request handling,
extracts agent DIDs from headers, and returns standard rate-limit headers.

See also:
    - hypervisor.security.rate_limiter: runtime-layer per-agent/per-ring limits.
    - agent_os.integrations.rate_limiter: tool-call policy limits in Agent OS.
    - agentmesh.services.rate_limiter: service/proxy-level limits in Agent Mesh.
    - agent_os.policies.rate_limiting: shared token-bucket primitives.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from agentmesh.services.rate_limiter import RateLimiter


# Header constants
HEADER_AGENT_DID = "X-Agent-DID"
HEADER_RATELIMIT_REMAINING = "X-RateLimit-Remaining"
HEADER_RATELIMIT_RESET = "X-RateLimit-Reset"
HEADER_RETRY_AFTER = "Retry-After"
HEADER_BACKPRESSURE = "X-Backpressure"


@dataclass
class SimpleRequest:
    """Minimal request abstraction for the middleware."""

    headers: dict[str, str] = field(default_factory=dict)
    path: str = "/"
    method: str = "GET"


@dataclass
class SimpleResponse:
    """Minimal response abstraction for the middleware."""

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None


class RateLimitMiddleware:
    """Middleware that enforces rate limits on HTTP handlers.

    Extracts the agent DID from the ``X-Agent-DID`` request header, checks both
    per-agent and global rate limits, and decorates responses with standard rate
    limit headers.

    Args:
        rate_limiter: The :class:`RateLimiter` instance to use.
        default_agent_did: Fallback DID when the header is absent.
    """

    def __init__(
        self,
        rate_limiter: RateLimiter,
        default_agent_did: str = "anonymous",
    ) -> None:
        self._limiter = rate_limiter
        self._default_agent_did = default_agent_did

    def _extract_agent_did(self, request: SimpleRequest) -> str:
        """Extract agent DID from request headers."""
        return request.headers.get(HEADER_AGENT_DID, self._default_agent_did)

    def _add_rate_limit_headers(
        self,
        response: SimpleResponse,
        remaining: float,
        retry_after: Optional[float],
        backpressure: bool,
    ) -> None:
        """Attach rate limit headers to the response."""
        response.headers[HEADER_RATELIMIT_REMAINING] = str(math.floor(remaining))
        if retry_after is not None and retry_after > 0:
            response.headers[HEADER_RATELIMIT_RESET] = str(round(retry_after, 2))
        if backpressure:
            response.headers[HEADER_BACKPRESSURE] = "true"

    def handle(
        self,
        request: SimpleRequest,
        handler: Callable[[SimpleRequest], SimpleResponse],
    ) -> SimpleResponse:
        """Process a request through rate limiting then delegate to *handler*.

        Args:
            request: The incoming request.
            handler: The next handler in the chain.

        Returns:
            A :class:`SimpleResponse` — either a 429 rejection or the handler's response
            decorated with rate limit headers.
        """
        agent_did = self._extract_agent_did(request)
        result = self._limiter.check(agent_did)

        if not result.allowed:
            retry_after = result.retry_after_seconds or 1.0
            resp = SimpleResponse(
                status_code=429,
                body={"error": "Too Many Requests", "retry_after": retry_after},
            )
            resp.headers[HEADER_RETRY_AFTER] = str(round(retry_after, 2))
            self._add_rate_limit_headers(
                resp,
                remaining=result.remaining_tokens,
                retry_after=result.retry_after_seconds,
                backpressure=result.backpressure,
            )
            return resp

        response = handler(request)
        self._add_rate_limit_headers(
            response,
            remaining=result.remaining_tokens,
            retry_after=result.retry_after_seconds,
            backpressure=result.backpressure,
        )
        return response

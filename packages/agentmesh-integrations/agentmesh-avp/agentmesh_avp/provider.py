# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Veil Protocol provider for AgentMesh trust engine.

Implements the TrustProvider interface using AVP's EigenTrust
reputation API for trust scoring and DID-based identity verification.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

# DID format: did:key:z6Mk followed by 43+ base58btc characters
_DID_PATTERN = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{43,}$")


def _is_valid_did(value: str) -> bool:
    """Validate that a string matches the expected did:key format."""
    return bool(_DID_PATTERN.match(value))


class AVPProvider:
    """Trust provider backed by Agent Veil Protocol.

    Queries the AVP reputation API to retrieve EigenTrust scores
    and verify agent identity via DID (did:key).

    Args:
        base_url: AVP server URL.
        did_resolver: Optional callable that maps agent_id -> AVP DID.
            If not provided, agent_id is assumed to be a DID string.
        name_resolver: Optional callable that maps agent_id -> AVP agent name.
            Used by verify_identity when agent_id is not a registered name.
        timeout: HTTP request timeout in seconds.
        min_score_threshold: Minimum score to consider an agent verified.
    """

    def __init__(
        self,
        base_url: str = "https://agentveil.dev",
        did_resolver: Optional[Callable[[str], Optional[str]]] = None,
        name_resolver: Optional[Callable[[str], Optional[str]]] = None,
        timeout: float = 10.0,
        min_score_threshold: float = 0.3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.did_resolver = did_resolver
        self.name_resolver = name_resolver
        self.min_score_threshold = min_score_threshold
        self._client = httpx.AsyncClient(timeout=timeout)

    def _resolve_did(self, agent_id: str) -> Optional[str]:
        """Resolve agent_id to a validated AVP DID string."""
        if self.did_resolver:
            resolved = self.did_resolver(agent_id)
            if resolved and _is_valid_did(resolved):
                return resolved
            return None
        if _is_valid_did(agent_id):
            return agent_id
        return None

    def _resolve_name(self, agent_id: str) -> Optional[str]:
        """Resolve agent_id to a sanitized AVP agent name.

        Output is URL-encoded to prevent path injection when
        interpolated into API URLs.
        """
        raw = self.name_resolver(agent_id) if self.name_resolver else agent_id
        if not raw:
            return None
        return quote(raw, safe="")

    @staticmethod
    def _extract_score(data: Any) -> Optional[float]:
        """Extract and validate score from API response.

        Returns None if the response is not a dict or score is
        not a valid number.
        """
        if not isinstance(data, dict):
            return None
        raw = data.get("score")
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    async def get_trust_score(self, agent_id: str) -> float:
        """Return a normalised trust score (0.0-1.0) from AVP EigenTrust.

        Calls GET /v1/reputation/{did} and returns the ``score`` field.
        Returns 0.0 if the DID is unknown or the API is unreachable.
        """
        did = self._resolve_did(agent_id)
        if not did:
            return 0.0

        try:
            resp = await self._client.get(
                f"{self.base_url}/v1/reputation/{did}"
            )
            resp.raise_for_status()
            data = resp.json()
            score = self._extract_score(data)
            if score is None:
                log.warning("AVP returned invalid score for %s: %r", did, data)
                return 0.0
            return max(0.0, min(1.0, score))
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("AVP reputation request failed for %s: %s", did, exc)
            return 0.0

    async def get_reputation(self, agent_id: str) -> dict[str, Any]:
        """Return the full AVP reputation profile for an agent.

        Includes score, confidence, tier, risk factors, attestation
        count, and EigenTrust algorithm metadata.
        Returns an empty dict if the agent is unknown or the API fails.
        """
        did = self._resolve_did(agent_id)
        if not did:
            return {}

        try:
            resp = await self._client.get(
                f"{self.base_url}/v1/reputation/{did}"
            )
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                log.warning("AVP returned non-dict response for %s", did)
                return {}
            return data
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("AVP reputation request failed for %s: %s", did, exc)
            return {}

    async def verify_identity(
        self, agent_id: str, credentials: dict[str, Any]
    ) -> bool:
        """Verify agent identity via AVP verification endpoint.

        Calls GET /v1/agents/verify/{name} and checks the ``verified``
        field. Falls back to score-based verification if the name
        endpoint is unavailable.

        The ``credentials`` argument is accepted for interface
        compatibility but not inspected or logged.
        """
        name = self._resolve_name(agent_id)
        if not name:
            return False

        try:
            resp = await self._client.get(
                f"{self.base_url}/v1/agents/verify/{name}"
            )
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                return False
            return bool(data.get("verified", False))
        except httpx.HTTPError:
            log.warning(
                "AVP verify endpoint failed for %s, falling back to "
                "score-based verification",
                name,
            )
            score = await self.get_trust_score(agent_id)
            return score >= self.min_score_threshold

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

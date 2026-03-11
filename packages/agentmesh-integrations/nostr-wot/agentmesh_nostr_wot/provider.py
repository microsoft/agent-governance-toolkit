"""
Nostr Web of Trust provider for AgentMesh trust engine.

Implements the TrustProvider interface using MaximumSats WoT API
for NIP-85 trust scoring.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import httpx


class NostrWoTProvider:
    """Trust provider backed by Nostr Web of Trust (NIP-85).

    Queries the MaximumSats WoT API to retrieve trust scores,
    detect sybil attacks, and discover trust circles.

    Args:
        wot_api: Base URL for the WoT scoring API.
        pubkey_resolver: Optional callable that maps agent_id -> Nostr pubkey.
            If not provided, agent_id is assumed to be a Nostr pubkey.
        timeout: HTTP request timeout in seconds.
        min_score_threshold: Minimum WoT score to consider an agent trusted.
    """

    def __init__(
        self,
        wot_api: str = "https://wot.klabo.world",
        pubkey_resolver: Optional[Callable[[str], Optional[str]]] = None,
        timeout: float = 10.0,
        min_score_threshold: float = 0.3,
    ) -> None:
        self.wot_api = wot_api.rstrip("/")
        self.pubkey_resolver = pubkey_resolver
        self.timeout = timeout
        self.min_score_threshold = min_score_threshold
        self._client = httpx.AsyncClient(timeout=timeout)

    def _resolve_pubkey(self, agent_id: str) -> Optional[str]:
        if self.pubkey_resolver:
            return self.pubkey_resolver(agent_id)
        return agent_id

    async def get_trust_score(self, agent_id: str) -> float:
        """Return a normalised trust score (0.0–1.0) from the Nostr WoT.

        Returns 0.0 if the pubkey is unknown or the API is unreachable.
        """
        pubkey = self._resolve_pubkey(agent_id)
        if not pubkey:
            return 0.0

        try:
            resp = await self._client.get(f"{self.wot_api}/score?pubkey={pubkey}")
            resp.raise_for_status()
            data = resp.json()
            raw_score = float(data.get("score", 0))
            return max(0.0, min(1.0, raw_score))
        except (httpx.HTTPError, KeyError, ValueError):
            return 0.0

    async def check_sybil(self, agent_id: str) -> dict[str, Any]:
        """Check for potential Sybil attacks on this identity.

        Uses the /similar endpoint to detect potential Sybil attacks.
        """
        pubkey = self._resolve_pubkey(agent_id)
        if not pubkey:
            return {"is_sybil": False, "confidence": 0.0, "reason": "unknown_pubkey"}

        try:
            resp = await self._client.get(f"{self.wot_api}/similar?pubkey={pubkey}")
            resp.raise_for_status()
            data = resp.json()
            total_found = data.get("total_found", 0)
            if total_found == 0:
                return {
                    "is_sybil": False,
                    "confidence": 0.3,
                    "reason": "no_similar_found",
                }
            is_sybil = total_found > 50
            confidence = min(1.0, total_found / 100.0)
            return {
                "is_sybil": is_sybil,
                "confidence": confidence,
                "similar_count": total_found,
            }
        except httpx.HTTPError:
            return {"is_sybil": False, "confidence": 0.0, "reason": "api_error"}

    async def get_trust_circle(self, agent_id: str) -> list[str]:
        """Return direct trust connections for the given agent."""
        pubkey = self._resolve_pubkey(agent_id)
        if not pubkey:
            return []

        try:
            resp = await self._client.get(f"{self.wot_api}/similar?pubkey={pubkey}")
            resp.raise_for_status()
            data = resp.json()
            similar = data.get("similar", [])
            return [item.get("pubkey", "") for item in similar if item.get("pubkey")]
        except httpx.HTTPError:
            return []

    async def verify_identity(self, agent_id: str, credentials: dict[str, Any]) -> bool:
        """Verify agent identity by checking WoT score against threshold."""
        score = await self.get_trust_score(agent_id)
        return score >= self.min_score_threshold

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

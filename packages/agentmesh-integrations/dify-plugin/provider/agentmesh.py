"""AgentMesh Trust Layer provider implementation for Dify."""

from typing import Any

from dify_plugin import ToolProvider

from .identity import VerificationIdentity
from .trust_manager import TrustManager


class AgentMeshProvider(ToolProvider):
    """Provider for AgentMesh trust verification tools."""

    _trust_manager: TrustManager | None = None
    _identity: VerificationIdentity | None = None

    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        """Validate and initialize provider with credentials."""
        # Parse configuration
        min_trust_score = float(credentials.get("min_trust_score", "0.5") or "0.5")
        cache_ttl = int(credentials.get("cache_ttl_seconds", "900") or "900")
        identity_name = credentials.get("identity_name", "dify-agent") or "dify-agent"
        capabilities_str = credentials.get("capabilities", "") or ""
        
        # Parse capabilities
        capabilities = []
        if capabilities_str:
            capabilities = [c.strip() for c in capabilities_str.split(",") if c.strip()]
        
        # Generate identity
        self._identity = VerificationIdentity.generate(
            name=identity_name,
            capabilities=capabilities,
        )
        
        # Initialize trust manager
        self._trust_manager = TrustManager(
            identity=self._identity,
            cache_ttl_seconds=cache_ttl,
            min_trust_score=min_trust_score,
        )

    @property
    def trust_manager(self) -> TrustManager:
        """Get the trust manager instance."""
        if self._trust_manager is None:
            raise ValueError("Trust manager not initialized. Check credentials.")
        return self._trust_manager

    @property
    def identity(self) -> VerificationIdentity:
        """Get the agent's identity."""
        if self._identity is None:
            raise ValueError("Identity not initialized. Check credentials.")
        return self._identity

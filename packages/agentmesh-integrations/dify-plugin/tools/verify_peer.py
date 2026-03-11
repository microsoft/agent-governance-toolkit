"""Verify peer agent tool implementation."""

from typing import Any, Generator

from dify_plugin.entities.tool import ToolInvokeMessage
from dify_plugin import Tool


class VerifyPeerTool(Tool):
    """Tool to verify a peer agent's identity and capabilities."""

    def _invoke(
        self,
        tool_parameters: dict[str, Any],
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Invoke the verify peer tool."""
        peer_did = tool_parameters.get("peer_did", "")
        peer_public_key = tool_parameters.get("peer_public_key", "")
        required_capabilities_str = tool_parameters.get("required_capabilities", "")
        peer_capabilities_str = tool_parameters.get("peer_capabilities", "")
        
        # Parse capabilities
        required_capabilities = None
        if required_capabilities_str:
            required_capabilities = [c.strip() for c in required_capabilities_str.split(",") if c.strip()]
        
        peer_capabilities = None
        if peer_capabilities_str:
            peer_capabilities = [c.strip() for c in peer_capabilities_str.split(",") if c.strip()]
        
        # Get trust manager from provider
        trust_manager = self.runtime.credentials.get("_trust_manager")
        if not trust_manager:
            yield self.create_json_message({
                "verified": False,
                "error": "Trust manager not initialized",
            })
            return
        
        # Verify peer
        result = trust_manager.verify_peer(
            peer_did=peer_did,
            peer_public_key=peer_public_key,
            required_capabilities=required_capabilities,
            peer_capabilities=peer_capabilities,
        )
        
        yield self.create_json_message(result.to_dict())

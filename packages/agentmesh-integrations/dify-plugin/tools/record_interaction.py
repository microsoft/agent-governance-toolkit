"""Record interaction tool implementation."""

from typing import Any, Generator

from dify_plugin.entities.tool import ToolInvokeMessage
from dify_plugin import Tool


class RecordInteractionTool(Tool):
    """Tool to record interaction outcomes with peer agents."""

    def _invoke(
        self,
        tool_parameters: dict[str, Any],
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Invoke the record interaction tool."""
        peer_did = tool_parameters.get("peer_did", "")
        success = tool_parameters.get("success", True)
        severity = tool_parameters.get("severity", 0.1)
        
        if not peer_did:
            yield self.create_json_message({
                "error": "peer_did is required",
            })
            return
        
        # Get trust manager from provider
        trust_manager = self.runtime.credentials.get("_trust_manager")
        if not trust_manager:
            yield self.create_json_message({
                "error": "Trust manager not initialized",
            })
            return
        
        # Record interaction
        if success:
            trust_manager.record_success(peer_did)
        else:
            trust_manager.record_failure(peer_did, severity=severity)
        
        # Get updated trust score
        new_score = trust_manager.get_trust_score(peer_did)
        
        yield self.create_json_message({
            "recorded": True,
            "peer_did": peer_did,
            "success": success,
            "new_trust_score": new_score,
        })

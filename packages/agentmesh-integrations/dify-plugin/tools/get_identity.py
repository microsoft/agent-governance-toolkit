"""Get agent identity tool implementation."""

from typing import Any, Generator

from dify_plugin.entities.tool import ToolInvokeMessage
from dify_plugin import Tool


class GetIdentityTool(Tool):
    """Tool to get the agent's cryptographic identity."""

    def _invoke(
        self,
        tool_parameters: dict[str, Any],
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Invoke the get identity tool."""
        include_capabilities = tool_parameters.get("include_capabilities", True)
        
        # Get identity from provider
        identity = self.runtime.credentials.get("_identity")
        if not identity:
            yield self.create_json_message({
                "error": "Identity not initialized",
            })
            return
        
        # Build response
        response = {
            "did": identity.did,
            "name": identity.name,
            "public_key": identity.public_key,
            "created_at": identity.created_at.isoformat(),
        }
        
        if include_capabilities:
            response["capabilities"] = identity.capabilities
        
        yield self.create_json_message(response)

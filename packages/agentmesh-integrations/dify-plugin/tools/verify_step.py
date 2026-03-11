"""Verify workflow step tool implementation."""

from typing import Any, Generator

from dify_plugin.entities.tool import ToolInvokeMessage
from dify_plugin import Tool


class VerifyStepTool(Tool):
    """Tool to verify authorization for a workflow step."""

    def _invoke(
        self,
        tool_parameters: dict[str, Any],
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Invoke the verify step tool."""
        workflow_id = tool_parameters.get("workflow_id", "")
        step_id = tool_parameters.get("step_id", "")
        step_type = tool_parameters.get("step_type", "")
        required_capability = tool_parameters.get("required_capability")
        
        # Get trust manager from provider
        trust_manager = self.runtime.credentials.get("_trust_manager")
        if not trust_manager:
            yield self.create_json_message({
                "verified": False,
                "error": "Trust manager not initialized",
            })
            return
        
        # Verify step
        result = trust_manager.verify_workflow_step(
            workflow_id=workflow_id,
            step_id=step_id,
            step_type=step_type,
            required_capability=required_capability,
        )
        
        yield self.create_json_message(result.to_dict())

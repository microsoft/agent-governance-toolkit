# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the OpenAI Adapter - Drop-in Middleware
"""

import json
import unittest
from agent_control_plane import (
    AgentControlPlane,
    ControlPlaneAdapter,
    create_governed_client,
    ActionType,
    PermissionLevel,
)


class MockOpenAIClient:
    """
    Mock OpenAI client for testing the adapter.
    
    This class mimics the structure of the OpenAI SDK client,
    providing the nested classes (MockFunction, MockToolCall, etc.)
    that represent the OpenAI API response structure.
    
    It allows testing the adapter without making actual API calls.
    """
    
    class MockFunction:
        """Represents a function call in OpenAI's tool call structure"""
        def __init__(self, name, arguments):
            self.name = name
            self.arguments = arguments
    
    class MockToolCall:
        """Represents a tool call in OpenAI's response"""
        def __init__(self, name, arguments):
            self.id = f"call_{name}"
            self.type = "function"
            self.function = MockOpenAIClient.MockFunction(name, arguments)
    
    class MockMessage:
        """Represents the message object in OpenAI's response"""
        def __init__(self, tool_calls=None):
            self.role = "assistant"
            self.content = None
            self.tool_calls = tool_calls or []
    
    class MockChoice:
        """Represents a choice in OpenAI's response"""
        def __init__(self, message):
            self.index = 0
            self.message = message
            self.finish_reason = "tool_calls"
    
    class MockResponse:
        """Represents a complete OpenAI API response"""
        def __init__(self, choices):
            self.id = "chatcmpl-mock"
            self.object = "chat.completion"
            self.model = "gpt-4"
            self.choices = choices
    
    class MockCompletions:
        """Represents the chat.completions API endpoint"""
        def __init__(self, tool_calls):
            self.tool_calls_to_return = tool_calls
        
        def create(self, **kwargs):
            """Mock the create() method that returns tool calls"""
            message = MockOpenAIClient.MockMessage(self.tool_calls_to_return)
            choice = MockOpenAIClient.MockChoice(message)
            return MockOpenAIClient.MockResponse([choice])
    
    class MockChat:
        """Represents the chat API endpoint"""
        def __init__(self, tool_calls):
            self.completions = MockOpenAIClient.MockCompletions(tool_calls)
    
    def __init__(self, tool_calls=None):
        self.chat = MockOpenAIClient.MockChat(tool_calls or [])


class TestOpenAIAdapter(unittest.TestCase):
    """Test suite for OpenAI Adapter"""

    def test_adapter_blocks_unauthorized_action(self):
        """Test that adapter blocks actions the agent doesn't have permission for"""
        control_plane = AgentControlPlane()
        
        # Agent can only read files, not write
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.FILE_WRITE: PermissionLevel.NONE,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        # Mock OpenAI wants to write a file
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "write_file",
                json.dumps({"path": "/test.txt", "content": "data"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        # Wrap with adapter
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client
        )
        
        # Make API call
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Write a file"}]
        )
        
        # Verify the tool call was blocked
        self.assertEqual(len(response.choices[0].message.tool_calls), 1)
        blocked_call = response.choices[0].message.tool_calls[0]
        self.assertEqual(blocked_call.function.name, "blocked_action")
        
        args = json.loads(blocked_call.function.arguments)
        self.assertEqual(args["original_tool"], "write_file")
        self.assertIn("blocked", args["reason"].lower())

    def test_adapter_allows_authorized_action(self):
        """Test that adapter allows actions the agent has permission for"""
        control_plane = AgentControlPlane()
        
        # Agent can read files
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        # Mock OpenAI wants to read a file
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "read_file",
                json.dumps({"path": "/test.txt"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        # Wrap with adapter
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client
        )
        
        # Make API call
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Read a file"}]
        )
        
        # Verify the tool call was allowed (not modified to blocked_action)
        self.assertEqual(len(response.choices[0].message.tool_calls), 1)
        tool_call = response.choices[0].message.tool_calls[0]
        self.assertEqual(tool_call.function.name, "read_file")

    def test_adapter_mixed_permissions(self):
        """Test adapter with multiple tool calls, some allowed and some blocked"""
        control_plane = AgentControlPlane()
        
        # Agent can query database but not write
        permissions = {
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
            ActionType.DATABASE_WRITE: PermissionLevel.NONE,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        # Mock OpenAI wants to both query and write
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "database_query",
                json.dumps({"query": "SELECT * FROM users"})
            ),
            MockOpenAIClient.MockToolCall(
                "database_write",
                json.dumps({"query": "DELETE FROM users"})
            ),
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        # Wrap with adapter
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client
        )
        
        # Make API call
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Query and delete"}]
        )
        
        # Verify mixed results
        tool_calls_result = response.choices[0].message.tool_calls
        self.assertEqual(len(tool_calls_result), 2)
        
        # First should be allowed
        self.assertEqual(tool_calls_result[0].function.name, "database_query")
        
        # Second should be blocked
        self.assertEqual(tool_calls_result[1].function.name, "blocked_action")

    def test_custom_tool_mapping(self):
        """Test that custom tool name mappings work"""
        control_plane = AgentControlPlane()
        
        permissions = {
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        # Custom mapping
        custom_mapping = {
            "my_custom_db_tool": ActionType.DATABASE_QUERY,
        }
        
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "my_custom_db_tool",
                json.dumps({"query": "SELECT 1"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client,
            tool_mapping=custom_mapping
        )
        
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Query"}]
        )
        
        # Should be recognized and allowed
        tool_call = response.choices[0].message.tool_calls[0]
        self.assertEqual(tool_call.function.name, "my_custom_db_tool")

    def test_on_block_callback(self):
        """Test that on_block callback is called when actions are blocked"""
        control_plane = AgentControlPlane()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        blocked_calls = []
        
        def on_block(tool_name, tool_args, result):
            blocked_calls.append({
                "tool": tool_name,
                "args": tool_args,
                "result": result
            })
        
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "write_file",
                json.dumps({"path": "/test.txt"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client,
            on_block=on_block
        )
        
        governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Write"}]
        )
        
        # Verify callback was called
        self.assertEqual(len(blocked_calls), 1)
        self.assertEqual(blocked_calls[0]["tool"], "write_file")
        self.assertFalse(blocked_calls[0]["result"]["success"])

    def test_create_governed_client_convenience(self):
        """Test the convenience function for creating governed clients"""
        control_plane = AgentControlPlane()
        
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "database_query",
                json.dumps({"query": "SELECT 1"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        # Use convenience function
        governed = create_governed_client(
            control_plane=control_plane,
            agent_id="convenience-test",
            openai_client=mock_client,
            permissions={
                ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
            }
        )
        
        # Should work just like manual setup
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Query"}]
        )
        
        tool_call = response.choices[0].message.tool_calls[0]
        self.assertEqual(tool_call.function.name, "database_query")

    def test_adapter_statistics(self):
        """Test that statistics are properly collected"""
        control_plane = AgentControlPlane()
        
        tool_calls = [
            MockOpenAIClient.MockToolCall(
                "read_file",
                json.dumps({"path": "/test.txt"})
            )
        ]
        mock_client = MockOpenAIClient(tool_calls)
        
        governed = create_governed_client(
            control_plane=control_plane,
            agent_id="stats-test",
            openai_client=mock_client,
            permissions={
                ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            }
        )
        
        # Make some calls
        for _ in range(3):
            governed.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Read"}]
            )
        
        # Get statistics
        stats = governed.get_statistics()
        
        self.assertIn("agent_id", stats)
        self.assertEqual(stats["agent_id"], "stats-test")
        self.assertIn("session_id", stats)
        self.assertIn("control_plane_audit", stats)
        self.assertGreater(len(stats["control_plane_audit"]), 0)

    def test_no_tool_calls_response(self):
        """Test that responses without tool calls pass through unchanged"""
        control_plane = AgentControlPlane()
        agent_context = control_plane.create_agent("test-agent", {})
        
        # Mock client with no tool calls
        mock_client = MockOpenAIClient(tool_calls=[])
        
        governed = ControlPlaneAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            original_client=mock_client
        )
        
        response = governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}]
        )
        
        # Should pass through without errors
        self.assertIsNotNone(response)
        self.assertEqual(len(response.choices[0].message.tool_calls), 0)

    def test_pattern_matching_tool_names(self):
        """Test that pattern matching recognizes common tool name variations"""
        control_plane = AgentControlPlane()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        # Try various file read naming patterns
        tool_names = ["read_file", "get_file", "fetch_document", "load_file"]
        
        for tool_name in tool_names:
            tool_calls = [
                MockOpenAIClient.MockToolCall(
                    tool_name,
                    json.dumps({"path": "/test.txt"})
                )
            ]
            mock_client = MockOpenAIClient(tool_calls)
            
            governed = ControlPlaneAdapter(
                control_plane=control_plane,
                agent_context=agent_context,
                original_client=mock_client
            )
            
            response = governed.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Read"}]
            )
            
            # All should be recognized and allowed
            tool_call = response.choices[0].message.tool_calls[0]
            self.assertEqual(tool_call.function.name, tool_name, 
                           f"Pattern matching failed for {tool_name}")


if __name__ == "__main__":
    unittest.main()

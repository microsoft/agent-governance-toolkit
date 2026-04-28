# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the LangChain Adapter
"""

import unittest
from agent_control_plane import (
    AgentControlPlane,
    LangChainAdapter,
    create_governed_langchain_client,
    ActionType,
    PermissionLevel,
)


class MockLangChainLLM:
    """Mock LangChain LLM for testing"""
    
    def __init__(self):
        self.model_name = "test-model"
        self.calls = []
    
    def __call__(self, prompt):
        self.calls.append(("call", prompt))
        return f"Response to: {prompt}"
    
    def invoke(self, messages):
        self.calls.append(("invoke", messages))
        # Return a mock response with no tool calls
        return MockResponse()
    
    def generate(self, prompts):
        self.calls.append(("generate", prompts))
        return [MockResponse()]


class MockResponse:
    """Mock LangChain response"""
    
    def __init__(self, tool_calls=None):
        self.content = "Mock response"
        self.tool_calls = tool_calls or []
        self.additional_kwargs = {}


class TestLangChainAdapter(unittest.TestCase):
    """Test suite for LangChain Adapter"""
    
    def test_create_adapter(self):
        """Test creating a LangChain adapter"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("test-agent", permissions)
        
        adapter = LangChainAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            langchain_client=llm
        )
        
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.agent_context.agent_id, "test-agent")
    
    def test_create_governed_client_convenience_function(self):
        """Test the convenience function for creating governed clients"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        governed_llm = create_governed_langchain_client(
            control_plane=control_plane,
            agent_id="convenience-test",
            langchain_client=llm,
            permissions=permissions
        )
        
        self.assertIsNotNone(governed_llm)
        self.assertEqual(governed_llm.agent_context.agent_id, "convenience-test")
    
    def test_llm_methods_are_wrapped(self):
        """Test that LLM methods are properly wrapped"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("wrapped-test", permissions)
        
        governed_llm = LangChainAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            langchain_client=llm
        )
        
        # The adapter wraps the client methods
        # We can verify the original methods are stored
        self.assertIsNotNone(governed_llm._original_call)
        self.assertIsNotNone(governed_llm._original_invoke)
    
    def test_custom_tool_mapping(self):
        """Test custom tool name mappings"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("custom-mapping-test", permissions)
        
        custom_mapping = {
            "company_file_tool": ActionType.FILE_READ,
            "company_db_tool": ActionType.DATABASE_QUERY,
        }
        
        adapter = LangChainAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            langchain_client=llm,
            tool_mapping=custom_mapping
        )
        
        # Verify mapping was added
        self.assertIn("company_file_tool", adapter.tool_mapping)
        self.assertEqual(
            adapter.tool_mapping["company_file_tool"],
            ActionType.FILE_READ
        )
    
    def test_add_tool_mapping(self):
        """Test dynamically adding tool mappings"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        governed_llm = create_governed_langchain_client(
            control_plane=control_plane,
            agent_id="dynamic-mapping-test",
            langchain_client=llm,
            permissions=permissions
        )
        
        # Add a new mapping
        governed_llm.add_tool_mapping("new_tool", ActionType.FILE_READ)
        
        # Verify it was added
        self.assertIn("new_tool", governed_llm.tool_mapping)
    
    def test_pattern_matching(self):
        """Test tool name pattern matching"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("pattern-test", permissions)
        
        adapter = LangChainAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            langchain_client=llm
        )
        
        # Test pattern matching for various tool names
        self.assertEqual(
            adapter._map_tool_to_action("read_file_content"),
            ActionType.FILE_READ
        )
        self.assertEqual(
            adapter._map_tool_to_action("execute_python_code"),
            ActionType.CODE_EXECUTION
        )
        self.assertEqual(
            adapter._map_tool_to_action("query_database"),
            ActionType.DATABASE_QUERY
        )
    
    def test_get_statistics(self):
        """Test getting adapter statistics"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        governed_llm = create_governed_langchain_client(
            control_plane=control_plane,
            agent_id="stats-test",
            langchain_client=llm,
            permissions=permissions
        )
        
        stats = governed_llm.get_statistics()
        
        self.assertIn("agent_id", stats)
        self.assertIn("session_id", stats)
        self.assertIn("control_plane_audit", stats)
        self.assertEqual(stats["agent_id"], "stats-test")
    
    def test_blocked_action_callback(self):
        """Test callback for blocked actions"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        blocked_calls = []
        
        def on_block(tool_name, tool_args, result):
            blocked_calls.append((tool_name, tool_args, result))
        
        # Create agent with no permissions
        permissions = {}
        agent_context = control_plane.create_agent("callback-test", permissions)
        
        adapter = LangChainAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            langchain_client=llm,
            on_block=on_block
        )
        
        # The callback is tested in integration scenarios
        # Here we just verify it was properly set
        self.assertIsNotNone(adapter.on_block)
    
    def test_proxy_attributes(self):
        """Test that unknown attributes are proxied to the wrapped client"""
        control_plane = AgentControlPlane()
        llm = MockLangChainLLM()
        
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        governed_llm = create_governed_langchain_client(
            control_plane=control_plane,
            agent_id="proxy-test",
            langchain_client=llm,
            permissions=permissions
        )
        
        # Access an attribute of the wrapped client
        self.assertEqual(governed_llm.model_name, "test-model")


if __name__ == "__main__":
    unittest.main()

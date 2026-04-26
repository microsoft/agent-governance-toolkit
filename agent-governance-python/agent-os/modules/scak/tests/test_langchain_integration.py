# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for LangChain integration components.

This test suite validates:
1. SCAKMemory - Memory loading and context injection
2. SCAKCallbackHandler - Laziness detection and auditing
3. SelfCorrectingRunnable - Runtime failure handling
"""

import unittest
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime

# Test imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock LangChain before importing
class MockBaseMemory:
    pass

class MockBaseCallbackHandler:
    pass

class MockAsyncCallbackHandler:
    pass

class MockRunnable:
    pass

class MockBaseMessage:
    def __init__(self, content):
        self.content = content
        self.type = "base"

class MockSystemMessage(MockBaseMessage):
    def __init__(self, content):
        super().__init__(content)
        self.type = "system"

class MockHumanMessage(MockBaseMessage):
    def __init__(self, content):
        super().__init__(content)
        self.type = "human"

class MockAIMessage(MockBaseMessage):
    def __init__(self, content):
        super().__init__(content)
        self.type = "ai"

class MockAgentFinish:
    def __init__(self, return_values):
        self.return_values = return_values

# Mock LangChain modules
sys.modules['langchain'] = Mock()
sys.modules['langchain.schema'] = Mock()
sys.modules['langchain.schema'].BaseMemory = MockBaseMemory
sys.modules['langchain.schema'].BaseMessage = MockBaseMessage
sys.modules['langchain.schema'].SystemMessage = MockSystemMessage
sys.modules['langchain.schema'].HumanMessage = MockHumanMessage
sys.modules['langchain.schema'].AIMessage = MockAIMessage
sys.modules['langchain.schema'].AgentFinish = MockAgentFinish

sys.modules['langchain.callbacks'] = Mock()
sys.modules['langchain.callbacks.base'] = Mock()
sys.modules['langchain.callbacks.base'].BaseCallbackHandler = MockBaseCallbackHandler
sys.modules['langchain.callbacks.base'].AsyncCallbackHandler = MockAsyncCallbackHandler

sys.modules['langchain.schema.runnable'] = Mock()
sys.modules['langchain.schema.runnable'].Runnable = MockRunnable
sys.modules['langchain.schema.runnable'].RunnableConfig = type('RunnableConfig', (), {})

sys.modules['langchain.schema.agent'] = Mock()
sys.modules['langchain.schema.agent'].AgentFinish = MockAgentFinish
sys.modules['langchain.schema.agent'].AgentAction = type('AgentAction', (), {})

# Now import our integration
from src.integrations.langchain_integration import (
    SCAKMemory,
    SCAKCallbackHandler,
    SelfCorrectingRunnable,
    create_scak_agent
)

from src.kernel.memory import MemoryController
from src.kernel.auditor import CompletenessAuditor
from src.kernel.triage import FailureTriage, FixStrategy
from agent_kernel.models import AgentOutcome, OutcomeType, GiveUpSignal


class TestSCAKMemory(unittest.TestCase):
    """Tests for SCAKMemory component."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.controller = MemoryController()
        self.memory = SCAKMemory(controller=self.controller)
    
    def test_initialization(self):
        """Test SCAKMemory initialization."""
        self.assertEqual(self.memory.memory_key, "history")
        self.assertEqual(self.memory.system_patch_key, "system_patch")
        self.assertIsInstance(self.memory.controller, MemoryController)
        self.assertEqual(len(self.memory.chat_history), 0)
    
    def test_memory_variables(self):
        """Test memory_variables property."""
        variables = self.memory.memory_variables
        self.assertIn("history", variables)
        self.assertIn("system_patch", variables)
    
    def test_load_memory_variables_basic(self):
        """Test loading memory variables with basic input."""
        inputs = {
            "input": "Find logs for error 500",
            "tools": []
        }
        
        result = self.memory.load_memory_variables(inputs)
        
        # Should return both system_patch and history
        self.assertIn("system_patch", result)
        self.assertIn("history", result)
        
        # System patch should be a string
        self.assertIsInstance(result["system_patch"], str)
        
        # History should be empty initially
        self.assertEqual(len(result["history"]), 0)
    
    def test_load_memory_variables_with_tools(self):
        """Test loading memory variables with active tools."""
        # Create a mock tool
        mock_tool = Mock()
        mock_tool.name = "search_tool"
        
        inputs = {
            "input": "Search for error logs",
            "tools": [mock_tool]
        }
        
        result = self.memory.load_memory_variables(inputs)
        
        # Should inject context for active tools
        self.assertIn("system_patch", result)
    
    def test_save_context(self):
        """Test saving context to memory."""
        inputs = {"input": "What is the weather?"}
        outputs = {"output": "The weather is sunny."}
        
        self.memory.save_context(inputs, outputs)
        
        # Should save 2 messages (human + AI)
        self.assertEqual(len(self.memory.chat_history), 2)
        
        # Check message types
        self.assertEqual(self.memory.chat_history[0].type, "human")
        self.assertEqual(self.memory.chat_history[1].type, "ai")
        
        # Check message content
        self.assertEqual(self.memory.chat_history[0].content, "What is the weather?")
        self.assertEqual(self.memory.chat_history[1].content, "The weather is sunny.")
    
    def test_clear(self):
        """Test clearing memory."""
        # Add some history
        self.memory.save_context(
            {"input": "Hello"},
            {"output": "Hi there!"}
        )
        
        self.assertEqual(len(self.memory.chat_history), 2)
        
        # Clear
        self.memory.clear()
        
        # Should be empty
        self.assertEqual(len(self.memory.chat_history), 0)
    
    def test_format_history_as_string(self):
        """Test formatting history as string."""
        self.memory.save_context(
            {"input": "Hello"},
            {"output": "Hi!"}
        )
        
        history_str = self.memory._format_history_as_string()
        
        self.assertIn("human: Hello", history_str)
        self.assertIn("ai: Hi!", history_str)


class TestSCAKCallbackHandler(unittest.TestCase):
    """Tests for SCAKCallbackHandler component."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.auditor = CompletenessAuditor()
        self.handler = SCAKCallbackHandler(auditor=self.auditor)
    
    def test_initialization(self):
        """Test SCAKCallbackHandler initialization."""
        self.assertEqual(self.handler.agent_id, "langchain_agent")
        self.assertIsInstance(self.handler.auditor, CompletenessAuditor)
        self.assertEqual(self.handler.total_executions, 0)
        self.assertEqual(self.handler.give_up_count, 0)
    
    def test_is_give_up_signal_positive(self):
        """Test give-up signal detection for positive cases."""
        # Test various give-up patterns
        test_cases = [
            "No data found for your query.",
            "I cannot answer that question.",
            "No results were found.",
            "That information is not available.",
            "I have insufficient information.",
            "I couldn't find any logs.",
            "I was unable to complete the task."
        ]
        
        for response in test_cases:
            with self.subTest(response=response):
                self.assertTrue(
                    self.handler.is_give_up_signal(response),
                    f"Should detect give-up signal in: {response}"
                )
    
    def test_is_give_up_signal_negative(self):
        """Test give-up signal detection for negative cases."""
        # Test non-give-up responses
        test_cases = [
            "I found 15 log entries.",
            "Here is the information you requested.",
            "The query returned 5 results.",
            "Successfully completed the task."
        ]
        
        for response in test_cases:
            with self.subTest(response=response):
                self.assertFalse(
                    self.handler.is_give_up_signal(response),
                    f"Should NOT detect give-up signal in: {response}"
                )
    
    def test_on_agent_finish_no_give_up(self):
        """Test callback when agent finishes without give-up signal."""
        finish = MockAgentFinish({"output": "Task completed successfully."})
        
        # Run callback
        asyncio.run(self.handler.on_agent_finish(
            finish,
            run_id="test-run-123",
            inputs={"input": "Do something"}
        ))
        
        # Should increment execution count but not give-up count
        self.assertEqual(self.handler.total_executions, 1)
        self.assertEqual(self.handler.give_up_count, 0)
        self.assertEqual(self.handler.audit_count, 0)
    
    def test_on_agent_finish_with_give_up(self):
        """Test callback when agent finishes with give-up signal."""
        finish = MockAgentFinish({"output": "No data found."})
        
        # Run callback
        asyncio.run(self.handler.on_agent_finish(
            finish,
            run_id="test-run-123",
            inputs={"input": "Find logs"}
        ))
        
        # Should increment both execution and give-up counts
        self.assertEqual(self.handler.total_executions, 1)
        self.assertEqual(self.handler.give_up_count, 1)
        
        # Audit may or may not complete immediately (async)
        # Just check it was detected
    
    def test_detect_give_up_type(self):
        """Test detection of specific give-up types."""
        test_cases = [
            ("No data found", GiveUpSignal.NO_DATA_FOUND),
            ("I cannot answer", GiveUpSignal.CANNOT_ANSWER),
            ("Not available", GiveUpSignal.NOT_AVAILABLE),
            ("Insufficient information", GiveUpSignal.INSUFFICIENT_INFO),
            ("Something else", GiveUpSignal.UNKNOWN)
        ]
        
        for response, expected_type in test_cases:
            with self.subTest(response=response):
                result = self.handler._detect_give_up_type(response)
                self.assertEqual(result, expected_type)


class TestSelfCorrectingRunnable(unittest.TestCase):
    """Tests for SelfCorrectingRunnable component."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create mock base agent
        self.base_agent = Mock()
        self.base_agent.invoke = Mock()
        
        # Create runnable
        self.triage = FailureTriage()
        self.runnable = SelfCorrectingRunnable(
            agent=self.base_agent,
            triage=self.triage
        )
    
    def test_initialization(self):
        """Test SelfCorrectingRunnable initialization."""
        self.assertEqual(self.runnable.agent_id, "langchain_agent")
        self.assertIsInstance(self.runnable.triage, FailureTriage)
        self.assertEqual(self.runnable.execution_count, 0)
        self.assertEqual(self.runnable.failure_count, 0)
    
    def test_invoke_success(self):
        """Test successful invocation without errors."""
        # Setup mock to succeed
        self.base_agent.invoke.return_value = {"output": "Success!"}
        
        input_data = {"input": "Do something"}
        result = self.runnable.invoke(input_data)
        
        # Should return result
        self.assertEqual(result["output"], "Success!")
        
        # Should increment execution count
        self.assertEqual(self.runnable.execution_count, 1)
        self.assertEqual(self.runnable.failure_count, 0)
        
        # Should have called base agent
        self.base_agent.invoke.assert_called_once_with(input_data, None)
    
    def test_invoke_with_async_failure(self):
        """Test invocation with async failure (non-critical)."""
        # Setup mock to raise error
        self.base_agent.invoke.side_effect = ValueError("Test error")
        
        input_data = {"input": "Read some logs"}
        
        # Should re-raise error (async path)
        with self.assertRaises(ValueError):
            self.runnable.invoke(input_data)
        
        # Should increment failure count
        self.assertEqual(self.runnable.failure_count, 1)
    
    def test_invoke_with_sync_correction(self):
        """Test invocation with sync correction (critical)."""
        # First call fails, second succeeds
        self.base_agent.invoke.side_effect = [
            ValueError("Test error with delete_resource"),
            {"output": "Success after correction!"}
        ]
        
        # Use a critical tool to trigger SYNC_JIT
        # The error message mentions "delete_resource" which will be extracted as tool name
        input_data = {"input": "Delete user records"}
        
        result = self.runnable.invoke(input_data)
        
        # Should return corrected result
        self.assertEqual(result["output"], "Success after correction!")
        
        # Should have attempted correction
        self.assertEqual(self.runnable.correction_count, 1)
        
        # Should have called base agent twice (fail + retry)
        self.assertEqual(self.base_agent.invoke.call_count, 2)
    
    def test_extract_tool_from_error(self):
        """Test extraction of tool name from error."""
        test_cases = [
            (ValueError("SQL query failed"), "sql"),
            (RuntimeError("Database connection timeout"), "database"),
            (Exception("File not found"), "file"),
            (ValueError("Unknown error"), None)
        ]
        
        for error, expected_tool in test_cases:
            with self.subTest(error=str(error)):
                result = self.runnable._extract_tool_from_error(error)
                self.assertEqual(result, expected_tool)
    
    def test_classify_failure_type(self):
        """Test classification of failure types."""
        from agent_kernel.models import FailureType
        
        test_cases = [
            (TimeoutError("Timeout"), FailureType.TIMEOUT),
            (PermissionError("Access denied"), FailureType.BLOCKED_BY_CONTROL_PLANE),
            (ValueError("Invalid input"), FailureType.INVALID_ACTION),
            (RuntimeError("Unknown"), FailureType.UNKNOWN)
        ]
        
        for error, expected_type in test_cases:
            with self.subTest(error=type(error).__name__):
                result = self.runnable._classify_failure_type(error)
                self.assertEqual(result, expected_type)


class TestCreateSCAKAgent(unittest.TestCase):
    """Tests for create_scak_agent convenience function."""
    
    def test_create_scak_agent_basic(self):
        """Test basic SCAK agent creation."""
        base_agent = Mock()
        base_agent.callbacks = []
        
        scak_agent = create_scak_agent(base_agent)
        
        # Should return SelfCorrectingRunnable
        self.assertIsInstance(scak_agent, SelfCorrectingRunnable)
    
    def test_create_scak_agent_with_callback(self):
        """Test SCAK agent creation with callback handler."""
        base_agent = Mock()
        base_agent.callbacks = []
        
        handler = SCAKCallbackHandler()
        
        scak_agent = create_scak_agent(
            base_agent,
            callback_handler=handler
        )
        
        # Should add callback to base agent
        self.assertIn(handler, base_agent.callbacks)
    
    def test_create_scak_agent_no_correction(self):
        """Test SCAK agent creation without correction."""
        base_agent = Mock()
        base_agent.callbacks = []
        
        scak_agent = create_scak_agent(
            base_agent,
            enable_correction=False
        )
        
        # Should return base agent unchanged
        self.assertEqual(scak_agent, base_agent)


if __name__ == '__main__':
    unittest.main()

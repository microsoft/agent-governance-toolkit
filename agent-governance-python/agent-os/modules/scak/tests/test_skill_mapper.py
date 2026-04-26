# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for SkillMapper (Tool signature matching).

Tests the two-phase tool extraction strategy:
1. Direct Hit: Explicit tool name in tool_call
2. Semantic Fallback: Keyword-based content analysis
"""

import unittest
from src.kernel.skill_mapper import SkillMapper, ToolSignature
from src.kernel.schemas import FailureTrace


class TestSkillMapper(unittest.TestCase):
    """Tests for SkillMapper tool extraction and signature matching."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mapper = SkillMapper()
    
    def test_direct_hit_from_tool_call(self):
        """Test direct tool extraction from explicit tool_call."""
        trace = FailureTrace(
            user_prompt="Query the database",
            agent_reasoning="I'll execute a SQL query",
            tool_call={"tool": "sql_db", "query": "SELECT * FROM users"},
            tool_output="Error: No WHERE clause",
            failure_type="commission_safety",
            severity="critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "sql_db")
    
    def test_direct_hit_with_tool_name_field(self):
        """Test direct tool extraction from tool_name field."""
        trace = FailureTrace(
            user_prompt="Run Python code",
            agent_reasoning="I'll execute the script",
            tool_call={"tool_name": "python_repl", "code": "print('hello')"},
            tool_output="hello",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "python_repl")
    
    def test_semantic_fallback_sql(self):
        """Test semantic matching for SQL-related content."""
        trace = FailureTrace(
            user_prompt="Query the database",
            agent_reasoning="I'll SELECT data FROM the users table and JOIN with orders",
            tool_call=None,  # No explicit tool call
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "sql_db")
    
    def test_semantic_fallback_python(self):
        """Test semantic matching for Python-related content."""
        trace = FailureTrace(
            user_prompt="Execute some code",
            agent_reasoning="I need to import pandas and print the dataframe",
            tool_call=None,
            tool_output="Error: pandas not installed",
            failure_type="commission_safety",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "python_repl")
    
    def test_semantic_fallback_file_operations(self):
        """Test semantic matching for file operations."""
        trace = FailureTrace(
            user_prompt="Read the config file",
            agent_reasoning="I'll read the file from the specified path",
            tool_call=None,
            tool_output="File not found: config.json",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "file_operations")
    
    def test_semantic_fallback_api_client(self):
        """Test semantic matching for API calls."""
        trace = FailureTrace(
            user_prompt="Call the API",
            agent_reasoning="I'll send an HTTP GET request to the endpoint",
            tool_call=None,
            tool_output="Error 404: Endpoint not found",
            failure_type="commission_safety",
            severity="critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "api_client")
    
    def test_no_match_returns_general(self):
        """Test that unmatched traces return 'general'."""
        trace = FailureTrace(
            user_prompt="Hello",
            agent_reasoning="I don't know what to do",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "general")
    
    def test_semantic_requires_minimum_score(self):
        """Test that semantic matching requires minimum confidence."""
        # Only one weak keyword match - should not be enough
        trace = FailureTrace(
            user_prompt="Do something",
            agent_reasoning="query",  # One keyword, but very weak signal
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "general")
    
    def test_direct_hit_takes_precedence(self):
        """Test that direct hit takes precedence over semantic match."""
        trace = FailureTrace(
            user_prompt="Query data",
            agent_reasoning="I'll import pandas and print the results",  # Python keywords
            tool_call={"tool": "sql_db", "query": "SELECT * FROM users"},  # SQL tool
            tool_output="Results",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        # Should use direct hit (sql_db) not semantic match (python_repl)
        self.assertEqual(tool, "sql_db")
    
    def test_add_custom_tool_signature(self):
        """Test adding custom tool signature to registry."""
        custom_sig = ToolSignature(
            tool_name="email_sender",
            keywords=["email", "send", "recipient", "subject"],
            file_patterns=[".eml"]
        )
        
        self.mapper.add_tool_signature(custom_sig)
        
        # Now test extraction with this new tool
        trace = FailureTrace(
            user_prompt="Send an email",
            agent_reasoning="I'll send an email to the recipient with subject line",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        tool = self.mapper.extract_tool_context(trace)
        
        self.assertEqual(tool, "email_sender")
    
    def test_get_tool_signature(self):
        """Test retrieving a tool signature."""
        sig = self.mapper.get_tool_signature("sql_db")
        
        self.assertIsNotNone(sig)
        self.assertEqual(sig.tool_name, "sql_db")
        self.assertIn("select", sig.keywords)
    
    def test_list_tools(self):
        """Test listing all registered tools."""
        tools = self.mapper.list_tools()
        
        self.assertIn("sql_db", tools)
        self.assertIn("python_repl", tools)
        self.assertIn("file_operations", tools)
        self.assertIsInstance(tools, list)
    
    def test_custom_registry_initialization(self):
        """Test initializing with custom registry."""
        custom_registry = {
            "custom_tool": ToolSignature(
                tool_name="custom_tool",
                keywords=["custom", "special"],
                file_patterns=[".custom"]
            )
        }
        
        mapper = SkillMapper(custom_registry=custom_registry)
        
        tools = mapper.list_tools()
        self.assertEqual(len(tools), 1)
        self.assertIn("custom_tool", tools)


if __name__ == '__main__':
    unittest.main()

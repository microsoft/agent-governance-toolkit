# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for LLM client integrations.
"""

import pytest
import asyncio
from src.interfaces.llm_clients import (
    get_llm_client,
    MockLLMClient,
    OpenAIClient,
    AnthropicClient
)


class TestMockLLMClient:
    """Test mock LLM client."""
    
    @pytest.mark.asyncio
    async def test_generate_basic(self):
        """Test basic text generation."""
        client = MockLLMClient()
        response = await client.generate("What is AI?")
        
        assert isinstance(response, str)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    async def test_generate_with_custom_responses(self):
        """Test custom response mapping."""
        custom_responses = {
            "weather": "It's sunny today!"
        }
        client = MockLLMClient(responses=custom_responses)
        
        response = await client.generate("What's the weather?")
        assert response == "It's sunny today!"
    
    @pytest.mark.asyncio
    async def test_generate_with_reasoning(self):
        """Test reasoning generation."""
        client = MockLLMClient()
        result = await client.generate_with_reasoning("Analyze this failure")
        
        assert "response" in result
        assert "reasoning" in result
        assert "model" in result
        assert result["model"] == "mock-model"
    
    def test_call_count(self):
        """Test call counting."""
        client = MockLLMClient()
        assert client.call_count == 0
        
        asyncio.run(client.generate("test"))
        assert client.call_count == 1
        
        asyncio.run(client.generate("test"))
        assert client.call_count == 2


class TestClientFactory:
    """Test client factory function."""
    
    def test_get_mock_client(self):
        """Test getting mock client."""
        client = get_llm_client("mock")
        assert isinstance(client, MockLLMClient)
    
    def test_get_openai_client(self):
        """Test getting OpenAI client."""
        client = get_llm_client("openai", model="gpt-4o")
        assert isinstance(client, OpenAIClient)
        assert client.model == "gpt-4o"
    
    def test_get_anthropic_client(self):
        """Test getting Anthropic client."""
        client = get_llm_client("anthropic", model="claude-3-5-sonnet-20241022")
        assert isinstance(client, AnthropicClient)
        assert client.model == "claude-3-5-sonnet-20241022"
    
    def test_unknown_provider(self):
        """Test unknown provider raises error."""
        with pytest.raises(ValueError, match="Unknown provider"):
            get_llm_client("unknown-provider")


@pytest.mark.skipif(
    True,  # Skip by default (requires API keys)
    reason="Requires OpenAI API key"
)
class TestOpenAIClient:
    """Test OpenAI client (requires API key)."""
    
    @pytest.mark.asyncio
    async def test_generate_real(self):
        """Test real OpenAI API call."""
        client = get_llm_client("openai", model="gpt-4o")
        response = await client.generate("Say 'test'", max_tokens=10)
        
        assert isinstance(response, str)
        assert len(response) > 0


@pytest.mark.skipif(
    True,  # Skip by default (requires API keys)
    reason="Requires Anthropic API key"
)
class TestAnthropicClient:
    """Test Anthropic client (requires API key)."""
    
    @pytest.mark.asyncio
    async def test_generate_real(self):
        """Test real Anthropic API call."""
        client = get_llm_client("anthropic")
        response = await client.generate("Say 'test'", max_tokens=10)
        
        assert isinstance(response, str)
        assert len(response) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Public constructor contract for native framework adapters."""
from __future__ import annotations
import inspect
import pytest
from agent_os.integrations.anthropic_adapter import AnthropicKernel
from agent_os.integrations.autogen_adapter import AutoGenKernel
from agent_os.integrations.bedrock_adapter import BedrockKernel
from agent_os.integrations.crewai_adapter import CrewAIKernel
from agent_os.integrations.gemini_adapter import GeminiKernel
from agent_os.integrations.google_adk_adapter import GoogleADKKernel
from agent_os.integrations.langchain_adapter import LangChainKernel
from agent_os.integrations.langgraph_adapter import LangGraphKernel
from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel
from agent_os.integrations.maf_adapter import MAFKernel
from agent_os.integrations.mistral_adapter import MistralKernel
from agent_os.integrations.openai_adapter import OpenAIKernel
from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel
from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper
from agent_os.integrations.smolagents_adapter import SmolagentsKernel
_ADAPTERS = [AnthropicKernel, AutoGenKernel, BedrockKernel, CrewAIKernel, GeminiKernel, GoogleADKKernel, LangChainKernel, LangGraphKernel, LlamaIndexKernel, MAFKernel, MistralKernel, OpenAIKernel, OpenAIAgentsKernel, PydanticAIKernel, SemanticKernelWrapper, SmolagentsKernel]

@pytest.mark.parametrize('adapter', _ADAPTERS)
def test_adapter_constructor_exposes_only_native_runtime(adapter: type) -> None:
    parameters = inspect.signature(adapter.__init__).parameters
    assert 'runtime' in parameters
    assert 'policy' not in parameters
    assert '_runtime' not in parameters
    assert '_runtime_factory' not in parameters

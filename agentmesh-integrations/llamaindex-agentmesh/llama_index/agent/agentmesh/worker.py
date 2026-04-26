# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trusted agent worker for LlamaIndex."""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from llama_index.core.agent import AgentRunner
from llama_index.core.agent.types import (
    BaseAgentWorker,
    Task,
    TaskStep,
    TaskStepOutput,
)
from llama_index.core.base.llms.types import ChatMessage, MessageRole
from llama_index.core.callbacks import CallbackManager
from llama_index.core.llms import LLM
from llama_index.core.tools import BaseTool

from llama_index.agent.agentmesh.identity import VerificationIdentity
from llama_index.agent.agentmesh.trust import (
    TrustHandshake,
    TrustPolicy,
    TrustedAgentCard,
    TrustVerificationResult,
)


class TrustedAgentWorker(BaseAgentWorker):
    """Agent worker with cryptographic identity and trust verification."""

    def __init__(
        self,
        tools: Sequence[BaseTool],
        llm: LLM,
        identity: VerificationIdentity,
        policy: Optional[TrustPolicy] = None,
        callback_manager: Optional[CallbackManager] = None,
        verbose: bool = False,
    ):
        self._tools = list(tools)
        self._llm = llm
        self._identity = identity
        self._policy = policy or TrustPolicy()
        self._callback_manager = callback_manager
        self._verbose = verbose
        self._handshake = TrustHandshake(identity, policy)
        self._agent_card = self._create_agent_card()

    def _create_agent_card(self) -> TrustedAgentCard:
        """Create this agent card for discovery."""
        card = TrustedAgentCard(
            name=self._identity.agent_name,
            description=f"LlamaIndex agent with tools: {[t.metadata.name for t in self._tools]}",
            capabilities=self._identity.capabilities,
        )
        card.sign(self._identity)
        return card

    @classmethod
    def from_tools(
        cls,
        tools: Sequence[BaseTool],
        llm: LLM,
        identity: VerificationIdentity,
        policy: Optional[TrustPolicy] = None,
        callback_manager: Optional[CallbackManager] = None,
        verbose: bool = False,
        **kwargs: Any,
    ) -> "TrustedAgentWorker":
        """Create a trusted agent worker from tools."""
        return cls(
            tools=tools,
            llm=llm,
            identity=identity,
            policy=policy,
            callback_manager=callback_manager,
            verbose=verbose,
        )

    @property
    def identity(self) -> VerificationIdentity:
        """Get this agent identity."""
        return self._identity

    @property
    def agent_card(self) -> TrustedAgentCard:
        """Get this agent card for discovery."""
        return self._agent_card

    def verify_peer(
        self,
        peer_card: TrustedAgentCard,
        required_capabilities: Optional[List[str]] = None,
    ) -> TrustVerificationResult:
        """Verify a peer agent before accepting tasks."""
        return self._handshake.verify_peer(peer_card, required_capabilities)

    def initialize_step(self, task: Task, **kwargs: Any) -> TaskStep:
        """Initialize a new task step."""
        return TaskStep(
            task_id=task.task_id,
            step_id=f"{task.task_id}_step_0",
            input=task.input,
            step_state={
                "agent_did": self._identity.did,
                "trust_verified": True,
            },
        )

    def run_step(self, step: TaskStep, task: Task, **kwargs: Any) -> TaskStepOutput:
        """Run a single step of the task."""
        invoker_card = kwargs.get("invoker_card")

        if self._policy.require_verification and invoker_card:
            result = self.verify_peer(invoker_card)
            if not result.trusted and self._policy.block_unverified:
                raise PermissionError(
                    f"Task rejected: invoker verification failed - {result.reason}"
                )

        messages = [ChatMessage(role=MessageRole.USER, content=step.input)]
        response = self._llm.chat(messages)

        return TaskStepOutput(
            output=str(response),
            task_step=step,
            is_last=True,
            next_steps=[],
        )

    async def arun_step(
        self, step: TaskStep, task: Task, **kwargs: Any
    ) -> TaskStepOutput:
        """Async version of run_step."""
        invoker_card = kwargs.get("invoker_card")
        if self._policy.require_verification and invoker_card:
            result = self.verify_peer(invoker_card)
            if not result.trusted and self._policy.block_unverified:
                raise PermissionError(
                    f"Task rejected: invoker verification failed - {result.reason}"
                )

        messages = [ChatMessage(role=MessageRole.USER, content=step.input)]
        response = await self._llm.achat(messages)

        return TaskStepOutput(
            output=str(response),
            task_step=step,
            is_last=True,
            next_steps=[],
        )

    def stream_step(self, step: TaskStep, task: Task, **kwargs: Any) -> TaskStepOutput:
        """Stream a task step."""
        return self.run_step(step, task, **kwargs)

    async def astream_step(
        self, step: TaskStep, task: Task, **kwargs: Any
    ) -> TaskStepOutput:
        """Async stream a task step."""
        return await self.arun_step(step, task, **kwargs)

    def finalize_task(self, task: Task, **kwargs: Any) -> None:
        """Finalize a completed task."""
        if self._policy.audit_queries:
            pass

    def as_agent(self, **kwargs: Any) -> AgentRunner:
        """Create an agent runner from this worker."""
        return AgentRunner.from_llm(
            llm=self._llm,
            tools=self._tools,
            callback_manager=self._callback_manager,
            verbose=self._verbose,
            **kwargs,
        )

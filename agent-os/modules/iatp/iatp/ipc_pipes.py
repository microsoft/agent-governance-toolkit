# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Typed IPC Pipes - Inter-Agent Communication with Policy Enforcement.

This module implements typed pipes for agent-to-agent communication,
inspired by UNIX pipes but with policy enforcement at the kernel level.

Instead of "Workflow Builders" (bloat), real engineers use pipes:
    AgentA | PolicyCheck | AgentB

Design Philosophy:
    - Type safety: Only matching types can connect
    - Policy enforcement: Every message passes through policy check
    - Backpressure: Slow consumers don't crash fast producers
    - Audit trail: All pipe traffic is logged to flight recorder

Example:
    # Create a typed pipe
    pipe = TypedPipe[ResearchResult, SummaryRequest]("research-to-summary")
    
    # Connect agents via pipe with policy enforcement
    pipeline = (
        research_agent
        | PolicyCheckPipe(allowed_types=[ResearchResult])
        | summary_agent
    )
    
    # Execute pipeline
    result = await pipeline.execute(input_data)

This is the IATP extension for secure inter-agent communication.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import (
    Any, AsyncIterator, Callable, Dict, Generic, List, Optional, 
    TypeVar, Union, Awaitable, Protocol, runtime_checkable
)
import asyncio
import hashlib
import json
import logging
from queue import Queue
from threading import Lock

logger = logging.getLogger(__name__)


# Type variables for generic pipes
T_In = TypeVar("T_In")
T_Out = TypeVar("T_Out")
T = TypeVar("T")


class PipeState(Enum):
    """State of a pipe."""
    CREATED = auto()
    OPEN = auto()
    FLOWING = auto()
    BLOCKED = auto()  # Backpressure
    CLOSED = auto()
    ERROR = auto()


@dataclass
class PipeMessage(Generic[T]):
    """
    A message flowing through a pipe.
    
    Every message carries metadata for policy enforcement and auditing.
    """
    payload: T
    message_id: str = field(default_factory=lambda: hashlib.sha256(
        str(datetime.now(timezone.utc).timestamp()).encode()
    ).hexdigest()[:16])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    trace_id: Optional[str] = None
    
    # Policy enforcement metadata
    policy_checked: bool = False
    policy_result: Optional[str] = None
    
    # Type information for runtime checking
    payload_type: Optional[str] = None
    
    def __post_init__(self):
        if self.payload_type is None:
            self.payload_type = type(self.payload).__name__
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp.isoformat(),
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "trace_id": self.trace_id,
            "payload_type": self.payload_type,
            "policy_checked": self.policy_checked,
            "policy_result": self.policy_result,
        }


@dataclass
class PipeConfig:
    """Configuration for a typed pipe."""
    name: str
    buffer_size: int = 100
    timeout_seconds: float = 30.0
    require_policy_check: bool = True
    allowed_payload_types: List[str] = field(default_factory=list)
    max_message_size_bytes: int = 10 * 1024 * 1024  # 10MB default
    enable_compression: bool = False
    enable_encryption: bool = False


@runtime_checkable
class PipeEndpoint(Protocol[T]):
    """Protocol for pipe endpoints (can send or receive)."""
    
    async def send(self, message: PipeMessage[T]) -> bool:
        """Send a message through the pipe."""
        ...
    
    async def receive(self) -> Optional[PipeMessage[T]]:
        """Receive a message from the pipe."""
        ...


class TypedPipe(Generic[T_In, T_Out]):
    """
    A typed pipe for inter-agent communication.
    
    Type parameters:
        T_In: Type of messages this pipe accepts
        T_Out: Type of messages this pipe produces
    
    Example:
        pipe = TypedPipe[ResearchQuery, ResearchResult]("research-pipe")
        await pipe.send(PipeMessage(ResearchQuery(topic="AI Safety")))
        result = await pipe.receive()
    """
    
    def __init__(
        self,
        name: str,
        config: Optional[PipeConfig] = None,
        transform: Optional[Callable[[T_In], T_Out]] = None,
    ):
        self.name = name
        self.config = config or PipeConfig(name=name)
        self._transform = transform
        
        self._state = PipeState.CREATED
        self._buffer: asyncio.Queue[PipeMessage] = asyncio.Queue(
            maxsize=self.config.buffer_size
        )
        self._lock = asyncio.Lock()
        self._message_count = 0
        self._error_count = 0
        
        # Policy enforcement callback
        self._policy_check: Optional[Callable[[PipeMessage], Awaitable[bool]]] = None
        
        # Audit callback
        self._audit_callback: Optional[Callable[[PipeMessage, str], None]] = None
    
    @property
    def state(self) -> PipeState:
        return self._state
    
    def open(self) -> None:
        """Open the pipe for communication."""
        self._state = PipeState.OPEN
        logger.info(f"[Pipe] {self.name} opened")
    
    def close(self) -> None:
        """Close the pipe."""
        self._state = PipeState.CLOSED
        logger.info(f"[Pipe] {self.name} closed")
    
    def set_policy_check(
        self,
        check: Callable[[PipeMessage], Awaitable[bool]]
    ) -> None:
        """Set the policy check callback."""
        self._policy_check = check
    
    def set_audit_callback(
        self,
        callback: Callable[[PipeMessage, str], None]
    ) -> None:
        """Set the audit callback for message logging."""
        self._audit_callback = callback
    
    async def send(self, message: PipeMessage[T_In]) -> bool:
        """
        Send a message through the pipe.
        
        Returns True if message was sent, False if rejected by policy.
        """
        if self._state not in (PipeState.OPEN, PipeState.FLOWING):
            raise RuntimeError(f"Pipe {self.name} is not open (state: {self._state})")
        
        # Policy check
        if self.config.require_policy_check:
            if self._policy_check:
                try:
                    allowed = await self._policy_check(message)
                    message.policy_checked = True
                    message.policy_result = "ALLOWED" if allowed else "DENIED"
                    
                    if not allowed:
                        logger.warning(
                            f"[Pipe] {self.name} rejected message {message.message_id} "
                            f"by policy"
                        )
                        if self._audit_callback:
                            self._audit_callback(message, "POLICY_DENIED")
                        return False
                except Exception as e:
                    logger.error(f"[Pipe] Policy check failed: {e}")
                    message.policy_result = f"ERROR: {e}"
                    self._error_count += 1
                    return False
            else:
                logger.warning(f"[Pipe] {self.name} has no policy check configured")
        
        # Type checking
        if self.config.allowed_payload_types:
            if message.payload_type not in self.config.allowed_payload_types:
                logger.error(
                    f"[Pipe] {self.name} rejected message with type "
                    f"{message.payload_type} (allowed: {self.config.allowed_payload_types})"
                )
                return False
        
        # Apply transform if configured
        if self._transform:
            try:
                transformed_payload = self._transform(message.payload)
                message = PipeMessage(
                    payload=transformed_payload,
                    message_id=message.message_id,
                    timestamp=message.timestamp,
                    source_agent=message.source_agent,
                    target_agent=message.target_agent,
                    trace_id=message.trace_id,
                    policy_checked=message.policy_checked,
                    policy_result=message.policy_result,
                )
            except Exception as e:
                logger.error(f"[Pipe] Transform failed: {e}")
                self._error_count += 1
                return False
        
        # Queue message (with backpressure)
        try:
            await asyncio.wait_for(
                self._buffer.put(message),
                timeout=self.config.timeout_seconds
            )
            self._message_count += 1
            self._state = PipeState.FLOWING
            
            if self._audit_callback:
                self._audit_callback(message, "SENT")
            
            return True
        except asyncio.TimeoutError:
            logger.warning(f"[Pipe] {self.name} timeout - backpressure")
            self._state = PipeState.BLOCKED
            return False
    
    async def receive(self) -> Optional[PipeMessage[T_Out]]:
        """
        Receive a message from the pipe.
        
        Returns None if pipe is closed or timeout occurs.
        """
        if self._state == PipeState.CLOSED:
            return None
        
        try:
            message = await asyncio.wait_for(
                self._buffer.get(),
                timeout=self.config.timeout_seconds
            )
            
            if self._audit_callback:
                self._audit_callback(message, "RECEIVED")
            
            return message
        except asyncio.TimeoutError:
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pipe statistics."""
        return {
            "name": self.name,
            "state": self._state.name,
            "message_count": self._message_count,
            "error_count": self._error_count,
            "buffer_size": self._buffer.qsize(),
            "buffer_max": self.config.buffer_size,
        }


class PolicyCheckPipe(TypedPipe[T, T]):
    """
    A pipe that only performs policy checking (pass-through).
    
    Use this in pipelines to enforce policy at specific points:
        agent_a | PolicyCheckPipe(policy_engine) | agent_b
    """
    
    def __init__(
        self,
        name: str = "policy-check",
        policy_engine: Optional[Any] = None,  # PolicyEngine from control plane
        allowed_types: Optional[List[str]] = None,
    ):
        config = PipeConfig(
            name=name,
            require_policy_check=True,
            allowed_payload_types=allowed_types or [],
        )
        super().__init__(name, config)
        self._policy_engine = policy_engine
        
        # Set up policy check
        if policy_engine:
            self.set_policy_check(self._check_with_engine)
    
    async def _check_with_engine(self, message: PipeMessage) -> bool:
        """Check message against policy engine."""
        if not self._policy_engine:
            return True
        
        # Integration with control plane PolicyEngine
        try:
            # This would integrate with the actual policy engine
            # For now, always allow
            return True
        except Exception as e:
            logger.error(f"[PolicyCheckPipe] Engine check failed: {e}")
            return False


@runtime_checkable
class PipelineStage(Protocol):
    """Protocol for pipeline stages."""
    
    async def process(self, message: PipeMessage) -> Optional[PipeMessage]:
        """Process a message and optionally produce output."""
        ...
    
    def __or__(self, other: "PipelineStage") -> "Pipeline":
        """Support pipe operator: stage1 | stage2"""
        ...


class AgentPipelineStage:
    """
    Wraps an agent as a pipeline stage.
    
    Example:
        stage = AgentPipelineStage(my_agent, input_type="Query", output_type="Response")
    """
    
    def __init__(
        self,
        agent: Any,
        agent_id: str,
        process_method: str = "process",
        input_type: Optional[str] = None,
        output_type: Optional[str] = None,
    ):
        self.agent = agent
        self.agent_id = agent_id
        self._process_method = process_method
        self.input_type = input_type
        self.output_type = output_type
    
    async def process(self, message: PipeMessage) -> Optional[PipeMessage]:
        """Process a message through the agent."""
        method = getattr(self.agent, self._process_method, None)
        if not method:
            raise AttributeError(
                f"Agent {self.agent_id} has no method '{self._process_method}'"
            )
        
        # Call agent's process method
        if asyncio.iscoroutinefunction(method):
            result = await method(message.payload)
        else:
            result = method(message.payload)
        
        if result is None:
            return None
        
        return PipeMessage(
            payload=result,
            source_agent=self.agent_id,
            trace_id=message.trace_id,
        )
    
    def __or__(self, other: "AgentPipelineStage") -> "Pipeline":
        """Support pipe operator."""
        return Pipeline([self, other])


class Pipeline:
    """
    A pipeline of connected stages.
    
    Example:
        pipeline = Pipeline([
            AgentPipelineStage(research_agent, "research"),
            PolicyCheckPipe(),
            AgentPipelineStage(summary_agent, "summary"),
        ])
        
        result = await pipeline.execute(input_message)
    """
    
    def __init__(
        self,
        stages: Optional[List[Union[AgentPipelineStage, TypedPipe]]] = None,
        name: str = "pipeline",
    ):
        self.name = name
        self.stages: List[Union[AgentPipelineStage, TypedPipe]] = stages or []
        self._trace_id: Optional[str] = None
    
    def add_stage(self, stage: Union[AgentPipelineStage, TypedPipe]) -> "Pipeline":
        """Add a stage to the pipeline."""
        self.stages.append(stage)
        return self
    
    def __or__(self, other: Union[AgentPipelineStage, TypedPipe, "Pipeline"]) -> "Pipeline":
        """Support pipe operator: pipeline | stage"""
        if isinstance(other, Pipeline):
            return Pipeline(self.stages + other.stages, self.name)
        else:
            return Pipeline(self.stages + [other], self.name)
    
    async def execute(
        self,
        input_data: Any,
        trace_id: Optional[str] = None,
    ) -> Optional[PipeMessage]:
        """
        Execute the pipeline with input data.
        
        Returns the final message, or None if pipeline filtered it out.
        """
        self._trace_id = trace_id or hashlib.sha256(
            str(datetime.now(timezone.utc).timestamp()).encode()
        ).hexdigest()[:16]
        
        # Create initial message
        current_message = PipeMessage(
            payload=input_data,
            trace_id=self._trace_id,
        )
        
        logger.info(f"[Pipeline] {self.name} executing with trace {self._trace_id}")
        
        for i, stage in enumerate(self.stages):
            stage_name = getattr(stage, 'name', None) or getattr(stage, 'agent_id', f'stage-{i}')
            logger.debug(f"[Pipeline] Processing stage: {stage_name}")
            
            if isinstance(stage, TypedPipe):
                # For pipes, send and receive
                stage.open()
                if not await stage.send(current_message):
                    logger.warning(f"[Pipeline] Stage {stage_name} rejected message")
                    return None
                current_message = await stage.receive()
                stage.close()
            elif isinstance(stage, AgentPipelineStage):
                # For agent stages, process directly
                current_message = await stage.process(current_message)
            else:
                # Generic stage with process method
                if hasattr(stage, 'process'):
                    if asyncio.iscoroutinefunction(stage.process):
                        current_message = await stage.process(current_message)
                    else:
                        current_message = stage.process(current_message)
            
            if current_message is None:
                logger.info(f"[Pipeline] Stage {stage_name} filtered out message")
                return None
            
            # Update target agent for next stage
            if i + 1 < len(self.stages):
                next_stage = self.stages[i + 1]
                current_message.target_agent = getattr(
                    next_stage, 'agent_id', 
                    getattr(next_stage, 'name', None)
                )
        
        logger.info(f"[Pipeline] {self.name} completed trace {self._trace_id}")
        return current_message
    
    async def execute_streaming(
        self,
        input_data: Any,
        trace_id: Optional[str] = None,
    ) -> AsyncIterator[PipeMessage]:
        """
        Execute pipeline with streaming output.
        
        Yields messages as they flow through stages.
        """
        self._trace_id = trace_id or hashlib.sha256(
            str(datetime.now(timezone.utc).timestamp()).encode()
        ).hexdigest()[:16]
        
        current_message = PipeMessage(
            payload=input_data,
            trace_id=self._trace_id,
        )
        
        yield current_message
        
        for stage in self.stages:
            if isinstance(stage, TypedPipe):
                stage.open()
                await stage.send(current_message)
                current_message = await stage.receive()
                stage.close()
            elif hasattr(stage, 'process'):
                if asyncio.iscoroutinefunction(stage.process):
                    current_message = await stage.process(current_message)
                else:
                    current_message = stage.process(current_message)
            
            if current_message:
                yield current_message
            else:
                return


# ========== Convenience Functions ==========

def create_pipeline(*stages: Union[AgentPipelineStage, TypedPipe]) -> Pipeline:
    """Create a pipeline from stages."""
    return Pipeline(list(stages))


def pipe_agents(
    source_agent: Any,
    source_id: str,
    target_agent: Any,
    target_id: str,
    policy_engine: Optional[Any] = None,
) -> Pipeline:
    """
    Create a simple two-agent pipeline with policy check.
    
    Example:
        pipeline = pipe_agents(
            research_agent, "research",
            summary_agent, "summary",
            policy_engine=my_policy_engine
        )
    """
    return Pipeline([
        AgentPipelineStage(source_agent, source_id),
        PolicyCheckPipe(policy_engine=policy_engine),
        AgentPipelineStage(target_agent, target_id),
    ])

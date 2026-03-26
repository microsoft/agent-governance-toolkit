# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AMB Core - A lightweight, broker-agnostic message bus for AI Agents.

AMB (Agent Message Bus) provides a decoupled communication layer that allows
AI agents to emit signals, broadcast intentions, and coordinate without tight
coupling between senders and receivers.

Key Features:
    - Broker-agnostic: Works with Redis, RabbitMQ, Kafka, or in-memory
    - Async-first: Built on asyncio/anyio for non-blocking operation
    - Multiple patterns: Fire-and-forget, acknowledgment, request-response
    - Type-safe: Full type hints with Pydantic validation

New in v0.2.0:
    - Message persistence for replay capability (AMB-001)
    - Dead Letter Queue for failed messages (AMB-002)
    - Schema validation via SchemaRegistry (AMB-003)
    - Distributed tracing support (AMB-004)
    - Message prioritization (AMB-005)
    - Message TTL/expiration (AMB-007)

Quick Start:
    >>> import asyncio
    >>> from amb_core import MessageBus, Message
    >>>
    >>> async def main():
    ...     async with MessageBus() as bus:
    ...         await bus.publish("agent.thoughts", {"thought": "Hello!"})
    >>>
    >>> asyncio.run(main())

Advanced Usage:
    >>> from amb_core import MessageBus, SchemaRegistry, Priority
    >>> from pydantic import BaseModel
    >>>
    >>> class FraudAlert(BaseModel):
    ...     transaction_id: str
    ...     risk_score: float
    >>>
    >>> schemas = SchemaRegistry()
    >>> schemas.register("fraud.alerts", FraudAlert)
    >>>
    >>> async def main():
    ...     bus = MessageBus(
    ...         persistence=True,
    ...         schema_registry=schemas,
    ...         dlq_enabled=True
    ...     )
    ...     async with bus:
    ...         await bus.publish(
    ...             "fraud.alerts",
    ...             {"transaction_id": "tx123", "risk_score": 0.95},
    ...             priority=Priority.CRITICAL,
    ...             ttl_seconds=300
    ...         )

For more information, see: https://github.com/microsoft/agent-governance-toolkit
"""

from __future__ import annotations

__version__ = "0.3.0"
__author__ = "Imran Siddique"
__license__ = "MIT"

# Core models
# Broker interface
from amb_core.broker import BrokerAdapter, MessageHandler

# Main bus
from amb_core.bus import MessageBus

# CloudEvents support (AMB-008)
from amb_core.cloudevents import (
    CLOUDEVENTS_CONTENT_TYPE,
    CLOUDEVENTS_SPEC_VERSION,
    CloudEvent,
    CloudEventBatch,
    from_cloudevent,
    from_http_headers,
    to_cloudevent,
    to_http_headers,
    topic_to_type,
    type_to_topic,
)

# Dead Letter Queue (AMB-002)
from amb_core.dlq import (
    DeadLetterQueue,
    DLQEntry,
    DLQHandler,
    DLQReason,
)
from amb_core.memory_broker import InMemoryBroker
from amb_core.models import Message, MessagePriority, MessageStatus, Priority

# Persistence (AMB-001)
from amb_core.persistence import (
    FileMessageStore,
    InMemoryMessageStore,
    MessageStore,
    PersistedMessage,
)
from amb_core.persistence import (
    MessageStatus as PersistenceMessageStatus,
)

# Schema validation (AMB-003)
from amb_core.schema import (
    CallableSchema,
    DictSchema,
    PydanticSchema,
    Schema,
    SchemaRegistry,
    SchemaValidationError,
)

# Tracing (AMB-004)
from amb_core.tracing import (
    TraceContext,
    TraceSpan,
    extract_trace,
    get_current_trace,
    inject_trace,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Core classes
    "Message",
    "MessagePriority",
    "Priority",
    "MessageStatus",
    "MessageBus",
    # Broker interface
    "BrokerAdapter",
    "MessageHandler",
    "InMemoryBroker",
    # Schema validation
    "SchemaRegistry",
    "Schema",
    "PydanticSchema",
    "DictSchema",
    "CallableSchema",
    "SchemaValidationError",
    # DLQ
    "DeadLetterQueue",
    "DLQEntry",
    "DLQReason",
    "DLQHandler",
    # Persistence
    "MessageStore",
    "InMemoryMessageStore",
    "FileMessageStore",
    "PersistedMessage",
    # Tracing
    "TraceContext",
    "TraceSpan",
    "get_current_trace",
    "inject_trace",
    "extract_trace",
    # CloudEvents
    "CloudEvent",
    "CloudEventBatch",
    "to_cloudevent",
    "from_cloudevent",
    "to_http_headers",
    "from_http_headers",
    "topic_to_type",
    "type_to_topic",
    "CLOUDEVENTS_SPEC_VERSION",
    "CLOUDEVENTS_CONTENT_TYPE",
]

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Broker adapters package for AMB.

This module provides optional adapters for different message brokers.
Each adapter requires its corresponding extra dependencies.

Available Adapters:
    - RedisBroker: pip install amb-core[redis]
    - RabbitMQBroker: pip install amb-core[rabbitmq]
    - KafkaBroker: pip install amb-core[kafka]
    - NATSBroker: pip install amb-core[nats]
    - AzureServiceBusBroker: pip install amb-core[azure]
    - AWSSQSBroker: pip install amb-core[aws]

Example:
    >>> from amb_core.adapters.redis_broker import RedisBroker
    >>> broker = RedisBroker(url="redis://localhost:6379/0")
    
    >>> from amb_core.adapters.nats_broker import NATSBroker
    >>> broker = NATSBroker(servers=["nats://localhost:4222"])
"""

from typing import TYPE_CHECKING, List

__all__: List[str] = [
    "RedisBroker",
    "RabbitMQBroker",
    "KafkaBroker",
    "NATSBroker",
    "AzureServiceBusBroker",
    "AWSSQSBroker",
]


def __getattr__(name: str):
    """Lazy import adapters to avoid import errors when dependencies missing."""
    if name == "RedisBroker":
        from amb_core.adapters.redis_broker import RedisBroker
        return RedisBroker
    elif name == "RabbitMQBroker":
        from amb_core.adapters.rabbitmq_broker import RabbitMQBroker
        return RabbitMQBroker
    elif name == "KafkaBroker":
        from amb_core.adapters.kafka_broker import KafkaBroker
        return KafkaBroker
    elif name == "NATSBroker":
        from amb_core.adapters.nats_broker import NATSBroker
        return NATSBroker
    elif name == "AzureServiceBusBroker":
        from amb_core.adapters.azure_servicebus_broker import AzureServiceBusBroker
        return AzureServiceBusBroker
    elif name == "AWSSQSBroker":
        from amb_core.adapters.aws_sqs_broker import AWSSQSBroker
        return AWSSQSBroker
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

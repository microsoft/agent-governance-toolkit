# Using Message Bus Adapters

> **Connect agents with Redis, Kafka, NATS, and cloud message services.**

## Overview

Agent OS provides the Agent Message Bus (AMB) for decoupled agent communication. This guide covers using the built-in adapters for different message brokers.

## Available Adapters

| Adapter | Use Case | Install |
|---------|----------|---------|
| **Memory** | Testing, development | Included |
| **Redis** | Low-latency, pub/sub | `pip install amb-core[redis]` |
| **Kafka** | High-throughput, durability | `pip install amb-core[kafka]` |
| **RabbitMQ** | Complex routing, enterprise | `pip install amb-core[rabbitmq]` |
| **NATS** | Cloud-native, lightweight | `pip install amb-core[nats]` |
| **Azure Service Bus** | Azure ecosystem | `pip install amb-core[azure]` |
| **AWS SQS** | AWS ecosystem | `pip install amb-core[aws]` |

## Quick Start with Redis

### 1. Install

```bash
pip install amb-core[redis]
```

### 2. Start Redis

```bash
docker run -d -p 6379:6379 redis:latest
```

### 3. Use in Your Agent

```python
from amb_core.adapters import RedisBroker
from amb_core import AgentMessageBus, Message

# Create broker
broker = RedisBroker(url="redis://localhost:6379/0")

# Create message bus
bus = AgentMessageBus(broker=broker)

# Connect
await bus.connect()

# Subscribe to messages
async def handle_task(msg: Message):
    print(f"Received task: {msg.payload}")
    
    # Process and respond
    result = await process_task(msg.payload)
    
    # Send response
    await bus.publish(Message(
        topic="results",
        payload=result,
        correlation_id=msg.correlation_id
    ))

await bus.subscribe("tasks", handle_task)

# Publish a message
await bus.publish(Message(
    topic="tasks",
    payload={"action": "analyze", "file": "data.txt"}
))
```

## Adapter Comparison

### Redis Adapter

**Best for:** Low-latency messaging, pub/sub patterns, real-time updates

```python
from amb_core.adapters import RedisBroker

broker = RedisBroker(
    url="redis://localhost:6379/0"
)

# Features:
# - Pub/sub for real-time messaging
# - Streams for message persistence
# - Native request-response support
```

**Pros:**
- Very low latency (<1ms)
- Simple setup
- Built-in persistence with Redis Streams

**Cons:**
- Limited durability compared to Kafka
- Single-node by default

### Kafka Adapter

**Best for:** High-throughput, event sourcing, audit logs

```python
from amb_core.adapters import KafkaBroker

broker = KafkaBroker(
    bootstrap_servers="localhost:9092"
)

# Features:
# - High throughput (millions/sec)
# - Durable message storage
# - Consumer groups for load balancing
```

**Pros:**
- Highest throughput
- Strong durability guarantees
- Replay capability

**Cons:**
- More complex setup
- Higher latency than Redis

### NATS Adapter

**Best for:** Cloud-native apps, microservices, edge computing

```python
from amb_core.adapters import NATSBroker

broker = NATSBroker(
    servers=["nats://localhost:4222"],
    use_jetstream=True  # Enable persistence
)

# Features:
# - Lightweight (single binary)
# - Native request-reply
# - JetStream for persistence
```

**Pros:**
- Very lightweight
- Easy to deploy
- Built-in request-reply

**Cons:**
- Smaller ecosystem than Kafka/RabbitMQ

### Azure Service Bus Adapter

**Best for:** Azure ecosystem, enterprise messaging

```python
from amb_core.adapters import AzureServiceBusBroker

broker = AzureServiceBusBroker(
    connection_string="Endpoint=sb://...",
    topic_name="agent-messages"
)

# Features:
# - Dead-letter queues
# - Sessions for ordering
# - Azure AD integration
```

**Pros:**
- Managed service
- Enterprise features
- Azure integration

**Cons:**
- Azure lock-in
- Cost at scale

### AWS SQS Adapter

**Best for:** AWS ecosystem, serverless

```python
from amb_core.adapters import AWSSQSBroker

broker = AWSSQSBroker(
    region_name="us-east-1",
    queue_name="agent-messages",
    use_fifo=True  # For ordering
)

# Features:
# - Serverless scaling
# - FIFO queues for ordering
# - Dead-letter queues
```

**Pros:**
- Serverless (no infrastructure)
- Auto-scaling
- AWS integration

**Cons:**
- Higher latency
- AWS lock-in

## Common Patterns

### Pattern 1: Request-Response

```python
from amb_core import Message

# Agent A sends request
response = await bus.request(
    Message(
        topic="calculate",
        payload={"operation": "sum", "values": [1, 2, 3]}
    ),
    timeout=30.0
)

print(f"Result: {response.payload}")  # Result: 6
```

### Pattern 2: Pub/Sub

```python
# Agent A subscribes to events
await bus.subscribe("events.user.*", handle_user_event)

# Agent B publishes events
await bus.publish(Message(
    topic="events.user.created",
    payload={"user_id": "123", "email": "user@example.com"}
))
```

### Pattern 3: Work Queue

```python
# Multiple workers subscribe to same queue
# Each message delivered to only one worker

async def worker(msg: Message):
    result = await process_work(msg.payload)
    await bus.publish(Message(
        topic="results",
        payload=result,
        correlation_id=msg.id
    ))

# Start multiple workers
for i in range(4):
    await bus.subscribe("work-queue", worker, consumer_group=f"workers")
```

### Pattern 4: Event Sourcing

```python
# Publish all events to Kafka for durability
kafka_broker = KafkaBroker(bootstrap_servers="localhost:9092")
bus = AgentMessageBus(broker=kafka_broker)

# All agent actions become events
await bus.publish(Message(
    topic="agent.events",
    payload={
        "event_type": "document_analyzed",
        "agent_id": "analyzer-001",
        "document_id": "doc-123",
        "result": analysis_result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
))

# Events can be replayed for debugging/audit
```

## Multi-Broker Setup

Use different brokers for different purposes:

```python
from amb_core import AgentMessageBus
from amb_core.adapters import RedisBroker, KafkaBroker

# Fast path for real-time messages
redis_bus = AgentMessageBus(
    broker=RedisBroker(url="redis://localhost:6379")
)

# Durable path for events/audit
kafka_bus = AgentMessageBus(
    broker=KafkaBroker(bootstrap_servers="localhost:9092")
)

@kernel.register
async def my_agent(task: str):
    # Process task
    result = await process(task)
    
    # Fast response via Redis
    await redis_bus.publish(Message(
        topic="responses",
        payload=result
    ))
    
    # Durable event via Kafka
    await kafka_bus.publish(Message(
        topic="events",
        payload={"action": "task_completed", "result": result}
    ))
```

## Docker Compose Example

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7
    ports:
      - "6379:6379"
  
  kafka:
    image: confluentinc/cp-kafka:latest
    ports:
      - "9092:9092"
    environment:
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
  
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
  
  nats:
    image: nats:latest
    ports:
      - "4222:4222"
    command: ["--js"]  # Enable JetStream
  
  agent:
    build: .
    depends_on:
      - redis
      - kafka
      - nats
    environment:
      REDIS_URL: redis://redis:6379
      KAFKA_SERVERS: kafka:9092
      NATS_URL: nats://nats:4222
```

## Best Practices

### 1. Use Environment Variables

```python
import os

broker = RedisBroker(
    url=os.environ.get("REDIS_URL", "redis://localhost:6379")
)
```

### 2. Handle Disconnections

```python
async def with_reconnect(bus: AgentMessageBus):
    while True:
        try:
            await bus.connect()
            break
        except ConnectionError:
            print("Connection failed, retrying in 5s...")
            await asyncio.sleep(5)
```

### 3. Use Dead-Letter Queues

```python
# Configure DLQ for failed messages
broker = RedisBroker(
    url="redis://localhost:6379",
    dead_letter_queue="dlq:agent-messages"
)
```

### 4. Monitor Lag

```python
from amb_core.observability import metrics

# Track message processing lag
@metrics.track("message_processing")
async def handle_message(msg: Message):
    lag = time.time() - msg.timestamp
    metrics.gauge("message_lag_seconds", lag)
    await process(msg)
```

## Next Steps

| Tutorial | Description |
|----------|-------------|
| [Creating Custom Tools](./custom-tools.md) | Build safe tools for agents |
| [Multi-Agent Systems](./multi-agent.md) | Coordinate agent teams |
| [Observability](../observability.md) | Monitor your message bus |

---

<div align="center">

**Ready to build custom tools?**

[Creating Custom Tools →](./custom-tools.md)

</div>

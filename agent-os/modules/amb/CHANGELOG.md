# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Backpressure Protocols**: Reactive Streams-style flow control to prevent overwhelming consumers
  - Configurable queue size limits per topic
  - Automatic producer throttling when backpressure is detected
  - Backpressure statistics and monitoring
- **Priority Lanes**: Message prioritization system
  - New priority levels: `CRITICAL` and `BACKGROUND`
  - CRITICAL messages (security/governance) jump ahead of BACKGROUND tasks (memory consolidation)
  - Priority-based message delivery using heap queues
  - Maintains FIFO order within same priority level
- Enhanced `InMemoryBroker` with:
  - Configurable `max_queue_size`, `backpressure_threshold`, and `backpressure_delay`
  - Background worker for priority-based message delivery
  - Automatic dropping of BACKGROUND messages when queue is full
  - Queue size monitoring via `get_queue_size()`
  - Backpressure statistics via `get_backpressure_stats()`
- Extended `MessagePriority` enum with `CRITICAL` and `BACKGROUND` levels
- Comprehensive test suite for backpressure and priority features
- Example demonstrating backpressure and priority lanes (`examples/backpressure_demo.py`)
- Hugging Face Hub integration (`hf_utils.py`) for uploading experiment results
- Reproducible benchmark suite in `experiments/`
- Research paper templates in `paper/`
- GitHub Actions workflows for CI/CD and PyPI publishing
- Comprehensive CONTRIBUTING.md guide

### Changed
- Enhanced `pyproject.toml` with full metadata and tool configurations
- Improved `__init__.py` with better docstrings and exports
- Updated adapters `__init__.py` with lazy imports
- Updated README with documentation for backpressure and priority lanes

## [0.2.0] - 2026-01-25

### Added
- **Message Persistence (AMB-001)**: Durable message storage with replay capability
  - `InMemoryMessageStore` for development/testing
  - `FileMessageStore` for file-based persistence
  - `MessageBus.replay()` method for replaying persisted messages
  - `PersistedMessage` model with status tracking
  
- **Dead Letter Queue (AMB-002)**: Failed message handling
  - `DeadLetterQueue` class for managing failed messages
  - `DLQEntry` model with failure reason and metadata
  - `DLQReason` enum (HANDLER_ERROR, VALIDATION_ERROR, EXPIRED, MAX_RETRIES, REJECTED)
  - Automatic routing of failed messages to DLQ
  - Retry mechanism with configurable max retries
  
- **Schema Validation (AMB-003)**: Message payload validation
  - `SchemaRegistry` for centralized schema management
  - Support for Pydantic models, dict specifications, and custom validators
  - `SchemaValidationError` for validation failures
  - Automatic validation on publish
  
- **Distributed Tracing (AMB-004)**: Cross-agent message tracking
  - `TraceContext` for trace propagation
  - `TraceSpan` for operation tracking
  - Automatic trace injection in messages
  - Context manager support for trace boundaries
  - Baggage propagation across services
  
- **Message Prioritization (AMB-005)**: Priority-based message handling
  - Enhanced `MessagePriority` enum with numeric values (LOW=1, NORMAL=5, HIGH=8, URGENT=10, CRITICAL=15)
  - `Priority` convenience class for cleaner API
  
- **Message TTL (AMB-007)**: Message expiration
  - `ttl_seconds` parameter for publish
  - `is_expired` and `remaining_ttl` properties on Message
  - Automatic DLQ routing for expired messages

### Changed
- `MessageBus` constructor now accepts:
  - `persistence`: Enable message persistence (bool or MessageStore)
  - `schema_registry`: SchemaRegistry for validation
  - `dlq_enabled`: Enable dead letter queue (bool or DeadLetterQueue)
  - `auto_inject_trace`: Automatically inject trace context
- `MessageBus.subscribe()` now accepts `with_dlq` parameter
- `MessagePriority` changed from string enum to integer enum for sorting

### Dependencies
- Added: `aiofiles>=23.0.0` for async file operations

## [0.1.0] - 2024-XX-XX

### Added
- Initial release
- Core `MessageBus` class with async context manager support
- `Message` model with Pydantic validation
- `BrokerAdapter` abstract base class
- `InMemoryBroker` for testing and single-process use
- `RedisBroker` adapter for production deployments
- `RabbitMQBroker` adapter
- `KafkaBroker` adapter
- Communication patterns:
  - Fire-and-forget (default)
  - Wait for acknowledgment
  - Request-response
- Full type hints throughout
- Google-style docstrings
- pytest test suite

### Dependencies
- Core: `pydantic>=2.0.0`, `anyio>=3.0.0`
- Redis: `redis>=4.0.0`
- RabbitMQ: `aio-pika>=9.0.0`
- Kafka: `aiokafka>=0.8.0`

[Unreleased]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v0.1.0

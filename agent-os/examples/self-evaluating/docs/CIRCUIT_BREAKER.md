# Automated Circuit Breaker System

## Overview

The Automated Circuit Breaker System solves the problem of managing probabilistic AI systems with static, manual experiments. In the time it takes to run a traditional A/B test, the model might have changed or user behavior might have shifted. This system enables **automated, metric-driven rollouts** with built-in safety mechanisms.

## The Problem

> "This is 'Old World' thinking applied to 'New World' speed. In the time it takes to run a valid A/B test, the model might have changed, or the user behavior might have shifted. We cannot manage probabilistic systems with static, manual experiments."

Traditional A/B testing for AI systems has fundamental limitations:
- **Too Slow**: Takes weeks to gather statistically significant data
- **Static**: Can't adapt to changing model behavior or user patterns
- **Manual**: Requires human intervention to roll back or advance
- **Risky**: All-or-nothing deployments can impact many users

## The Solution: Automated Circuit Breakers

The circuit breaker system provides **real-time, automated rollout management** with three key components:

### 1. The Probe
Gradual rollout that starts conservatively and scales automatically:
- **1%** → Initial probe with minimal user impact
- **5%** → Small rollout after metrics validation
- **20%** → Medium rollout with broader coverage
- **100%** → Full deployment once stability is proven

### 2. The Watchdog
Real-time monitoring of deterministic metrics:
- **Task Completion Rate**: Must stay above 85% (configurable)
- **Latency**: Must stay below 2000ms (configurable)
- **Sample Size**: Requires minimum data before making decisions
- **Time Windows**: Calculates metrics over rolling windows

### 3. Auto-Scale & Auto-Rollback
Automated decision-making based on metrics:
- **Advance**: Automatically scale up when metrics are excellent
- **Maintain**: Hold current phase when metrics are acceptable
- **Rollback**: Immediately revert when metrics degrade

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│              CircuitBreakerController                    │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Metrics    │  │   Watchdog   │  │    State     │  │
│  │   Tracker    │  │   Monitor    │  │   Manager    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│         │                  │                  │          │
│         └──────────────────┴──────────────────┘          │
│                            │                              │
│                   Decision Engine                         │
│         (Advance / Maintain / Rollback)                   │
└─────────────────────────────────────────────────────────┘
```

### Key Classes

1. **CircuitBreakerConfig**
   - Defines metric thresholds and rollout parameters
   - Configurable for different use cases
   - Persists configuration for consistency

2. **CircuitBreakerMetrics**
   - Tracks task completion rate and latency
   - Calculates metrics over time windows
   - Validates against thresholds

3. **CircuitBreakerWatchdog**
   - Real-time monitoring and decision engine
   - Determines when to advance or rollback
   - Manages traffic splits per phase

4. **CircuitBreakerController**
   - Main orchestrator for the system
   - Handles state persistence
   - Provides simple API for integration

## Usage

### Basic Example

```python
from circuit_breaker import CircuitBreakerController, CircuitBreakerConfig

# Create configuration
config = CircuitBreakerConfig(
    min_task_completion_rate=0.85,  # 85%
    max_latency_ms=2000.0,           # 2000ms
    min_samples_per_phase=10,        # Minimum samples before advancing
    monitoring_window_minutes=5      # 5-minute rolling window
)

# Initialize controller
controller = CircuitBreakerController(config=config)

# For each request
for request in requests:
    # Determine version based on traffic split
    version = "new" if controller.should_use_new_version(request.id) else "old"
    
    # Execute with selected version
    success, latency_ms = execute_request(request, version)
    
    # Record metrics
    controller.record_execution(version, success, latency_ms)
    
    # Periodically evaluate (or run in separate process)
    if should_evaluate():
        decision = controller.evaluate_and_decide()
        
        if decision["action"] == "rollback":
            alert_team(decision["reason"])
```

### Integration with DoerAgent

```python
from agent import DoerAgent

# Create agent with circuit breaker enabled
agent = DoerAgent(
    enable_circuit_breaker=True,
    circuit_breaker_config_file="cb_config.json"
)

# The agent automatically handles version selection and metrics tracking
result = agent.run(query="What is 10 + 20?", user_id="user123")

# Check which version was used
print(f"Version: {result['version_used']}")
print(f"Latency: {result['latency_ms']:.0f}ms")
```

## Rollout Phases

### Phase 1: PROBE (1%)
- **Purpose**: Validate new version with minimal risk
- **Traffic**: 1% to new version, 99% to old version
- **Duration**: Until minimum samples collected and metrics validated
- **Advancement**: Requires excellent metrics (>95% completion, <90% max latency)

### Phase 2: SMALL (5%)
- **Purpose**: Broader validation with manageable risk
- **Traffic**: 5% to new version, 95% to old version
- **Duration**: Until metrics remain stable
- **Advancement**: Consistent good performance

### Phase 3: MEDIUM (20%)
- **Purpose**: Significant user coverage before full rollout
- **Traffic**: 20% to new version, 80% to old version
- **Duration**: Final validation before full deployment
- **Advancement**: Sustained excellent metrics

### Phase 4: FULL (100%)
- **Purpose**: Complete deployment
- **Traffic**: 100% to new version
- **State**: Circuit breaker CLOSED (normal operation)
- **Monitoring**: Continues to detect degradation

### Rollback: OFF (0%)
- **Trigger**: Metrics fall below thresholds
- **Traffic**: 0% to new version, 100% to old version
- **State**: Circuit breaker OPEN (tripped)
- **Recovery**: Manual intervention or automatic retry after fixes

## Metrics

### Task Completion Rate
- **Definition**: Percentage of tasks that complete successfully
- **Default Threshold**: 85%
- **Purpose**: Ensures quality of responses
- **Example**: If 90 out of 100 tasks succeed, rate is 90%

### Latency
- **Definition**: Average response time in milliseconds
- **Default Threshold**: 2000ms
- **Purpose**: Ensures responsiveness
- **Example**: If 10 requests take [1200, 1500, 1800, ...], avg is calculated

### Sample Size
- **Definition**: Minimum number of executions before decision
- **Default**: 10 samples per phase
- **Purpose**: Prevents decisions on insufficient data
- **Adjustment**: Increase for higher statistical confidence

## Configuration Options

```python
CircuitBreakerConfig(
    # Metric thresholds
    min_task_completion_rate=0.85,    # Must stay above 85%
    max_latency_ms=2000.0,            # Must stay below 2000ms
    
    # Rollout parameters
    initial_phase=RolloutPhase.PROBE, # Start at PROBE (1%)
    min_samples_per_phase=10,         # Min samples before advancing
    monitoring_window_minutes=5,       # Time window for calculations
    
    # Decision thresholds
    advancement_threshold=0.95,        # Must be 95% good to advance
    rollback_threshold=0.80            # Trip if below 80%
)
```

## Example Scenarios

### Scenario 1: Successful Rollout
```
Phase: PROBE (1%)
  ✓ Metrics: 100% completion, 1200ms latency
  → Action: ADVANCE to SMALL

Phase: SMALL (5%)
  ✓ Metrics: 98% completion, 1300ms latency
  → Action: ADVANCE to MEDIUM

Phase: MEDIUM (20%)
  ✓ Metrics: 97% completion, 1400ms latency
  → Action: ADVANCE to FULL

Phase: FULL (100%)
  ✓ Circuit breaker CLOSED
  ✓ All traffic on new version
```

### Scenario 2: Automatic Rollback
```
Phase: PROBE (1%)
  ✓ Metrics: 98% completion, 1200ms latency
  → Action: ADVANCE to SMALL

Phase: SMALL (5%)
  ✗ Metrics: 80% completion, 2500ms latency
  → Action: ROLLBACK to OFF

Phase: OFF (0%)
  🚨 Circuit breaker OPEN
  ✓ All traffic reverted to old version
  📧 Team alerted to degradation
```

## Benefits

1. **Automated Risk Management**
   - No manual intervention required
   - Fast rollback prevents widespread impact
   - Gradual rollout minimizes exposure

2. **Data-Driven Decisions**
   - Based on actual performance metrics
   - Not subjective human judgment
   - Continuous monitoring vs. one-time tests

3. **Speed**
   - Deploy faster than traditional A/B tests
   - Adapt to changing conditions in real-time
   - Scale from 1% to 100% in hours, not weeks

4. **Safety**
   - Built-in circuit breaker for automatic rollback
   - Minimal user impact during problems
   - Deterministic thresholds prevent degradation

5. **Scalability**
   - Works with any traffic volume
   - Configurable for different risk tolerances
   - State persistence for reliability

## Testing

Run comprehensive tests:
```bash
python test_circuit_breaker.py
```

See example scenarios:
```bash
python example_circuit_breaker.py
```

## Integration Checklist

- [ ] Define metric thresholds for your use case
- [ ] Configure rollout phases and sample sizes
- [ ] Integrate with your agent/service
- [ ] Set up monitoring and alerting
- [ ] Test rollback scenarios
- [ ] Configure state persistence
- [ ] Document team procedures for manual intervention

## Future Enhancements

- **Multi-Metric Support**: Beyond completion rate and latency
- **Cost Tracking**: Monitor resource usage during rollout
- **User Segmentation**: Different rollout rates per user segment
- **Canary Regions**: Geographic-based gradual rollout
- **Automated Recovery**: Retry after fixes without manual intervention
- **ML-Based Predictions**: Predict failures before they occur

## Conclusion

The Automated Circuit Breaker System replaces "Old World" manual A/B testing with "New World" automated, metric-driven rollouts. By continuously monitoring deterministic metrics and making real-time decisions, it enables safe, fast deployment of new agent versions while automatically protecting users from degraded performance.

**Key Principle**: Let the system drive based on real metrics, not manual experiments that can't keep pace with the speed of AI evolution.

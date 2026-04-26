# Signal Handling Reference

Agent OS uses POSIX-inspired signals to control agent lifecycle. This document covers all signals, their behaviors, and edge cases.

## Available Signals

| Signal | Value | Description | Maskable |
|--------|-------|-------------|----------|
| `SIGSTOP` | 1 | Pause execution (enter shadow mode) | ✅ |
| `SIGCONT` | 2 | Resume execution | ✅ |
| `SIGINT` | 3 | Graceful interrupt | ✅ |
| `SIGKILL` | 4 | Immediate termination | ❌ |
| `SIGTERM` | 5 | Request graceful shutdown | ✅ |
| `SIGUSR1` | 6 | Enter diagnostic mode | ✅ |
| `SIGUSR2` | 7 | Trigger checkpoint | ✅ |
| `SIGPOLICY` | 8 | Policy violation (escalates to SIGKILL) | ❌ |
| `SIGTRUST` | 9 | Trust boundary crossed | ❌ |
| `SIGBUDGET` | 10 | Resource budget exceeded | ✅ |
| `SIGLOOP` | 11 | Infinite loop detected | ✅ |
| `SIGDRIFT` | 12 | Goal drift detected | ✅ |

## Edge Cases

### Sending SIGSTOP to an already stopped agent

**Behavior:** No-op. The signal is acknowledged but state doesn't change.

```python
dispatcher.send_signal(AgentSignal.SIGSTOP)  # Agent is now stopped
dispatcher.send_signal(AgentSignal.SIGSTOP)  # No-op, already stopped
```

The signal is still logged to the flight recorder for audit purposes.

### Sending SIGCONT to a running agent

**Behavior:** No-op. The signal is acknowledged but state doesn't change.

```python
# Agent is running
dispatcher.send_signal(AgentSignal.SIGCONT)  # No-op, already running
```

### Sending SIGSTOP immediately followed by SIGCONT

**Behavior:** The agent is stopped then resumed. There may be a brief pause.

```python
dispatcher.send_signal(AgentSignal.SIGSTOP)
dispatcher.send_signal(AgentSignal.SIGCONT)
# Agent resumes immediately
```

### Sending SIGKILL to an already terminated agent

**Behavior:** The signal is logged but no exception is raised (agent already terminated).

```python
dispatcher.send_signal(AgentSignal.SIGKILL)  # Agent terminated
dispatcher.send_signal(AgentSignal.SIGKILL)  # No-op, already dead
```

### Multiple policy violations (SIGPOLICY)

**Behavior:** First SIGPOLICY escalates to SIGKILL. Subsequent signals are logged but agent is already terminated.

```python
# Policy violation 1 → SIGPOLICY → SIGKILL → Agent terminated
# Policy violation 2 → SIGPOLICY → No-op (agent already dead)
```

### Masking signals during critical sections

You can temporarily block signals during critical operations:

```python
with dispatcher.mask_signals({AgentSignal.SIGINT, AgentSignal.SIGTERM}):
    # SIGINT and SIGTERM are queued, not delivered
    await critical_operation()
# Queued signals are delivered when mask is released
```

**Note:** SIGKILL, SIGPOLICY, and SIGTRUST cannot be masked.

### Race condition: Signal during execution

If a signal arrives while an action is executing:

- **SIGSTOP:** Action completes, then agent stops
- **SIGKILL:** Action is interrupted immediately (may leave partial state)
- **SIGINT:** Action completes, then agent stops (graceful)

### Signal ordering guarantees

Signals are processed in FIFO order. If you send:

```python
dispatcher.send_signal(AgentSignal.SIGSTOP)
dispatcher.send_signal(AgentSignal.SIGCONT)
```

SIGSTOP is always processed before SIGCONT.

### What happens if the signal handler throws?

- **Masked signals (SIGSTOP, SIGINT, etc.):** Exception is logged, agent continues
- **Unmaskable signals (SIGKILL):** Agent is terminated regardless

## Signal State Transitions

```
                    SIGSTOP
   ┌─────────────────────────────────────┐
   │                                     │
   ▼                                     │
┌─────────┐    SIGCONT    ┌─────────┐    │
│ STOPPED │◄─────────────►│ RUNNING │────┘
└─────────┘               └─────────┘
     │                         │
     │        SIGKILL          │
     │        SIGTERM          │
     └──────────┬──────────────┘
                │
                ▼
          ┌────────────┐
          │ TERMINATED │
          └────────────┘
```

## Custom Signal Handlers

You can register custom handlers for maskable signals:

```python
def my_handler(info: SignalInfo) -> None:
    print(f"Custom handling: {info.signal.name}")

dispatcher.register_handler(AgentSignal.SIGUSR1, my_handler)
dispatcher.send_signal(AgentSignal.SIGUSR1)
# Prints: "Custom handling: SIGUSR1"
```

## Flight Recorder Integration

All signals are automatically logged to the Flight Recorder:

```python
history = dispatcher.get_signal_history()
# [
#   {"signal": "SIGSTOP", "timestamp": "...", "source": "user", ...},
#   {"signal": "SIGCONT", "timestamp": "...", "source": "user", ...},
# ]
```

## See Also

- [Kernel Internals](kernel-internals.md) - How the kernel processes signals
- [Security Spec](security-spec.md) - Policy violation escalation
- [Troubleshooting](troubleshooting.md) - Common signal-related issues

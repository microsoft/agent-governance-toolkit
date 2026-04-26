# IoT Smart Home Agent

A governed AI agent for smart home control with safety constraints and privacy protection.

## Use Case

Smart home systems need AI agents that:
- Prevent dangerous device combinations
- Protect occupant privacy
- Enforce safety overrides
- Log all device commands for security

## Governance Features

| Feature | Implementation |
|---------|----------------|
| **Safety Constraints** | Block dangerous device combinations |
| **Privacy Protection** | Camera/mic controls with consent |
| **Emergency Override** | Safety systems always accessible |
| **Audit Trail** | Log all commands for security |
| **Rate Limiting** | Prevent rapid on/off cycling |

## Quick Start

```bash
pip install agent-os-kernel[full]
python main.py
```

## Policy Configuration

```yaml
# policy.yaml
governance:
  name: smart-home-agent
  framework: safety-first
  
safety_rules:
  # Prevent dangerous combinations
  - rule: heater_window
    condition: "heater.on AND window.open"
    action: block
    message: "Cannot run heater with windows open"
    
  - rule: stove_unattended
    condition: "stove.on AND no_motion_30min"
    action: alert_then_off
    
  - rule: water_heater_limit
    condition: "water_heater.temp > 120F"
    action: cap_temperature
    
emergency:
  always_allowed:
    - unlock_doors  # Fire escape
    - disable_stove
    - enable_smoke_detectors
  never_disable:
    - smoke_detectors
    - co_detectors
    - water_leak_sensors
    
privacy:
  cameras:
    - require_consent: true
    - auto_disable_when: ["bedroom_occupied", "bathroom_occupied"]
  voice_recording:
    - retention_hours: 24
    - delete_on_request: true
```

## Safety Architecture

```
┌─────────────────────────────────────────────────┐
│              Smart Home Agent                    │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐              │
│  │   Voice     │  │    App      │              │
│  │   Command   │  │   Request   │              │
│  └──────┬──────┘  └──────┬──────┘              │
│         │                │                      │
│         ▼                ▼                      │
│  ┌─────────────────────────────────┐           │
│  │     Agent OS Safety Layer       │           │
│  │  • Combination checker          │           │
│  │  • Rate limiter                 │           │
│  │  • Privacy filter               │           │
│  │  • Emergency override           │           │
│  └─────────────────────────────────┘           │
│                    │                            │
│                    ▼                            │
│  ┌─────────────────────────────────┐           │
│  │        Device Controllers       │           │
│  │   (Lights, HVAC, Locks, etc.)   │           │
│  └─────────────────────────────────┘           │
└─────────────────────────────────────────────────┘
```

## Compliance

- **UL 2900**: IoT device security
- **NIST Cybersecurity Framework**: Device hardening
- **State Privacy Laws**: Camera/recording consent

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IoT Smart Home Agent with Agent OS Governance

Demonstrates:
- Safety constraint enforcement
- Dangerous combination prevention
- Privacy protection for cameras/mics
- Emergency override handling
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

# Agent OS imports
try:
    from agent_os import Governor, Policy
    from agent_os.policies import create_policy
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False
    print("Note: Install agent-os-kernel for full governance features")


class DeviceType(Enum):
    LIGHT = "light"
    THERMOSTAT = "thermostat"
    LOCK = "lock"
    CAMERA = "camera"
    SENSOR = "sensor"
    APPLIANCE = "appliance"
    WINDOW = "window"


class DeviceState(Enum):
    ON = "on"
    OFF = "off"
    OPEN = "open"
    CLOSED = "closed"
    LOCKED = "locked"
    UNLOCKED = "unlocked"


@dataclass
class Device:
    """Smart home device."""
    device_id: str
    name: str
    device_type: DeviceType
    room: str
    state: DeviceState = DeviceState.OFF
    value: float = None  # For thermostats, dimmers
    last_changed: datetime = field(default_factory=datetime.utcnow)
    
    # Safety flags
    is_safety_critical: bool = False
    requires_consent: bool = False  # For cameras/mics


@dataclass
class SafetyRule:
    """Safety constraint rule."""
    rule_id: str
    name: str
    condition: callable  # Function that checks device states
    action: str  # "block", "alert", "auto_correct"
    message: str
    priority: int = 1


class SafetyEngine:
    """Enforce safety constraints on device combinations."""
    
    def __init__(self):
        self.rules: list[SafetyRule] = []
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Initialize default safety rules."""
        
        # Rule: No heater with windows open
        self.rules.append(SafetyRule(
            rule_id="heater_window",
            name="Heater + Open Window",
            condition=lambda devices: (
                any(d.device_type == DeviceType.THERMOSTAT and 
                    d.state == DeviceState.ON and d.value and d.value > 70
                    for d in devices.values()) and
                any(d.device_type == DeviceType.WINDOW and 
                    d.state == DeviceState.OPEN
                    for d in devices.values())
            ),
            action="block",
            message="Cannot heat with windows open - close windows first",
            priority=1
        ))
        
        # Rule: Stove temperature limit
        self.rules.append(SafetyRule(
            rule_id="stove_limit",
            name="Stove Temperature Limit",
            condition=lambda devices: any(
                d.name.lower() == "stove" and d.value and d.value > 450
                for d in devices.values()
            ),
            action="auto_correct",
            message="Stove temperature capped at 450°F for safety",
            priority=1
        ))
        
        # Rule: Water heater temperature limit
        self.rules.append(SafetyRule(
            rule_id="water_heater_limit", 
            name="Water Heater Limit",
            condition=lambda devices: any(
                "water heater" in d.name.lower() and d.value and d.value > 120
                for d in devices.values()
            ),
            action="auto_correct",
            message="Water heater capped at 120°F to prevent scalding",
            priority=1
        ))
    
    def check_safety(self, devices: dict, proposed_change: dict = None) -> tuple[bool, list[str]]:
        """
        Check if current state (or proposed change) violates safety rules.
        Returns (is_safe, list_of_violations).
        """
        violations = []
        
        # Create test state with proposed change
        test_devices = dict(devices)
        if proposed_change:
            device_id = proposed_change.get("device_id")
            if device_id in test_devices:
                test_device = test_devices[device_id]
                if "state" in proposed_change:
                    test_device.state = proposed_change["state"]
                if "value" in proposed_change:
                    test_device.value = proposed_change["value"]
        
        # Check all rules
        for rule in sorted(self.rules, key=lambda r: r.priority):
            if rule.condition(test_devices):
                violations.append({
                    "rule": rule.rule_id,
                    "message": rule.message,
                    "action": rule.action
                })
        
        return len(violations) == 0, violations


class PrivacyGuard:
    """Protect occupant privacy for cameras and microphones."""
    
    PRIVATE_ROOMS = ["bedroom", "bathroom", "nursery"]
    
    def __init__(self):
        self.consent_given: set[str] = set()  # device_ids with consent
        self.occupancy: dict[str, bool] = {}  # room -> occupied
    
    def give_consent(self, device_id: str):
        self.consent_given.add(device_id)
    
    def revoke_consent(self, device_id: str):
        self.consent_given.discard(device_id)
    
    def set_occupancy(self, room: str, occupied: bool):
        self.occupancy[room] = occupied
    
    def can_activate(self, device: Device) -> tuple[bool, Optional[str]]:
        """Check if a camera/mic can be activated."""
        
        if device.device_type != DeviceType.CAMERA:
            return True, None
        
        # Check consent
        if device.device_id not in self.consent_given:
            return False, "Camera requires consent to activate"
        
        # Check if in private room that's occupied
        room_lower = device.room.lower()
        if any(private in room_lower for private in self.PRIVATE_ROOMS):
            if self.occupancy.get(device.room, False):
                return False, f"Camera disabled - {device.room} is occupied"
        
        return True, None


class HomeAuditLog:
    """Security audit logging for all device commands."""
    
    def __init__(self):
        self.entries: list[dict] = []
    
    def log(self, action: str, device_id: str, user: str,
            old_state: str = None, new_state: str = None,
            blocked: bool = False, reason: str = None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "device_id": device_id,
            "user": user,
            "old_state": old_state,
            "new_state": new_state,
            "blocked": blocked,
            "reason": reason
        }
        self.entries.append(entry)
        return entry


class SmartHomeAgent:
    """AI agent for smart home control with safety governance."""
    
    # Emergency commands that ALWAYS work
    EMERGENCY_COMMANDS = {
        "unlock_all_doors",
        "disable_stove",
        "activate_smoke_detectors",
        "call_emergency"
    }
    
    # Devices that can NEVER be disabled
    NEVER_DISABLE = {"smoke_detector", "co_detector", "water_leak_sensor"}
    
    def __init__(self, agent_id: str = "smart-home-agent"):
        self.agent_id = agent_id
        self.safety_engine = SafetyEngine()
        self.privacy_guard = PrivacyGuard()
        self.audit_log = HomeAuditLog()
        self.devices: dict[str, Device] = {}
        
        # Rate limiting
        self.command_history: list[dict] = []
        self.rate_limit_window = timedelta(minutes=1)
        self.max_commands_per_minute = 30
    
    def add_device(self, device: Device):
        self.devices[device.device_id] = device
    
    def _check_rate_limit(self, user: str) -> bool:
        """Prevent rapid command spam."""
        cutoff = datetime.now(timezone.utc) - self.rate_limit_window
        recent = [c for c in self.command_history 
                  if c["time"] > cutoff and c["user"] == user]
        return len(recent) < self.max_commands_per_minute
    
    async def execute_command(self, device_id: str, command: str, 
                              value: float = None, user: str = "user") -> dict:
        """
        Execute a device command with full safety checks.
        """
        # Rate limit check
        if not self._check_rate_limit(user):
            return {
                "status": "blocked",
                "reason": "Rate limit exceeded - please wait"
            }
        
        self.command_history.append({"time": datetime.now(timezone.utc), "user": user})
        
        if device_id not in self.devices:
            return {"status": "error", "message": "Device not found"}
        
        device = self.devices[device_id]
        old_state = device.state
        
        # Determine new state from command
        new_state = self._parse_command(command, device)
        if new_state is None:
            return {"status": "error", "message": f"Unknown command: {command}"}
        
        # Check 1: Never disable safety devices
        if (device.name.lower().replace(" ", "_") in self.NEVER_DISABLE and
            new_state in [DeviceState.OFF, "disable"]):
            self.audit_log.log(
                command, device_id, user, str(old_state), str(new_state),
                blocked=True, reason="Safety device cannot be disabled"
            )
            return {
                "status": "blocked",
                "reason": "Safety devices cannot be disabled"
            }
        
        # Check 2: Privacy for cameras
        if device.device_type == DeviceType.CAMERA and new_state == DeviceState.ON:
            can_activate, reason = self.privacy_guard.can_activate(device)
            if not can_activate:
                self.audit_log.log(
                    command, device_id, user, str(old_state), str(new_state),
                    blocked=True, reason=reason
                )
                return {
                    "status": "blocked",
                    "reason": reason
                }
        
        # Check 3: Safety constraints
        proposed = {"device_id": device_id, "state": new_state, "value": value}
        is_safe, violations = self.safety_engine.check_safety(self.devices, proposed)
        
        if not is_safe:
            violation = violations[0]
            if violation["action"] == "block":
                self.audit_log.log(
                    command, device_id, user, str(old_state), str(new_state),
                    blocked=True, reason=violation["message"]
                )
                return {
                    "status": "blocked",
                    "reason": violation["message"],
                    "suggestion": "Resolve the conflict first"
                }
            elif violation["action"] == "auto_correct":
                # Apply safe value
                if "temperature" in violation["message"].lower():
                    value = 120 if "water" in device.name.lower() else 450
        
        # Execute the command
        device.state = new_state
        if value is not None:
            device.value = value
        device.last_changed = datetime.now(timezone.utc)
        
        self.audit_log.log(
            command, device_id, user, str(old_state), str(new_state)
        )
        
        return {
            "status": "success",
            "device": device.name,
            "old_state": str(old_state),
            "new_state": str(new_state),
            "value": value
        }
    
    def _parse_command(self, command: str, device: Device) -> Optional[DeviceState]:
        """Parse command string to device state."""
        command = command.lower()
        
        if command in ["on", "turn on", "enable", "activate"]:
            return DeviceState.ON
        elif command in ["off", "turn off", "disable", "deactivate"]:
            return DeviceState.OFF
        elif command in ["open"]:
            return DeviceState.OPEN
        elif command in ["close", "closed"]:
            return DeviceState.CLOSED
        elif command in ["lock", "locked"]:
            return DeviceState.LOCKED
        elif command in ["unlock", "unlocked"]:
            return DeviceState.UNLOCKED
        
        return None
    
    async def emergency_command(self, command: str, user: str = "system") -> dict:
        """Execute emergency command - bypasses normal checks."""
        
        if command not in self.EMERGENCY_COMMANDS:
            return {"status": "error", "message": "Unknown emergency command"}
        
        results = []
        
        if command == "unlock_all_doors":
            for device in self.devices.values():
                if device.device_type == DeviceType.LOCK:
                    device.state = DeviceState.UNLOCKED
                    results.append(f"{device.name}: UNLOCKED")
        
        elif command == "disable_stove":
            for device in self.devices.values():
                if "stove" in device.name.lower():
                    device.state = DeviceState.OFF
                    device.value = 0
                    results.append(f"{device.name}: OFF")
        
        self.audit_log.log(
            f"EMERGENCY:{command}", "all", user,
            reason="Emergency override"
        )
        
        return {
            "status": "emergency_executed",
            "command": command,
            "results": results
        }


async def demo():
    """Demonstrate the smart home agent."""
    print("=" * 60)
    print("IoT Smart Home Agent - Agent OS Demo")
    print("=" * 60)
    
    # Initialize agent
    agent = SmartHomeAgent()
    
    # Add devices
    devices = [
        Device("light-1", "Living Room Light", DeviceType.LIGHT, "Living Room"),
        Device("therm-1", "Main Thermostat", DeviceType.THERMOSTAT, "Hallway", 
               state=DeviceState.ON, value=68),
        Device("window-1", "Living Room Window", DeviceType.WINDOW, "Living Room",
               state=DeviceState.CLOSED),
        Device("lock-1", "Front Door", DeviceType.LOCK, "Entryway",
               state=DeviceState.LOCKED),
        Device("camera-1", "Living Room Camera", DeviceType.CAMERA, "Living Room",
               requires_consent=True),
        Device("camera-2", "Bedroom Camera", DeviceType.CAMERA, "Bedroom",
               requires_consent=True),
        Device("smoke-1", "Smoke Detector", DeviceType.SENSOR, "Hallway",
               state=DeviceState.ON, is_safety_critical=True),
        Device("stove-1", "Kitchen Stove", DeviceType.APPLIANCE, "Kitchen",
               state=DeviceState.OFF)
    ]
    
    for d in devices:
        agent.add_device(d)
        print(f"✓ Added: {d.name} ({d.device_type.value})")
    
    # Test 1: Normal command
    print("\n--- Test 1: Normal Command ---")
    result = await agent.execute_command("light-1", "on", user="jane")
    print(f"Turn on light: {result['status']}")
    
    # Test 2: Safety constraint - heater + open window
    print("\n--- Test 2: Safety Constraint ---")
    # First open the window
    await agent.execute_command("window-1", "open", user="jane")
    # Try to increase heat
    result = await agent.execute_command("therm-1", "on", value=75, user="jane")
    print(f"Increase heat with window open: {result['status']}")
    print(f"Reason: {result.get('reason', 'N/A')}")
    
    # Test 3: Camera privacy
    print("\n--- Test 3: Camera Privacy ---")
    result = await agent.execute_command("camera-1", "on", user="jane")
    print(f"Activate camera (no consent): {result['status']}")
    print(f"Reason: {result.get('reason', 'N/A')}")
    
    # Give consent and try again
    agent.privacy_guard.give_consent("camera-1")
    result = await agent.execute_command("camera-1", "on", user="jane")
    print(f"Activate camera (with consent): {result['status']}")
    
    # Test 4: Bedroom camera with occupancy
    print("\n--- Test 4: Bedroom Privacy ---")
    agent.privacy_guard.give_consent("camera-2")
    agent.privacy_guard.set_occupancy("Bedroom", True)
    result = await agent.execute_command("camera-2", "on", user="jane")
    print(f"Bedroom camera (occupied): {result['status']}")
    print(f"Reason: {result.get('reason', 'N/A')}")
    
    # Test 5: Cannot disable smoke detector
    print("\n--- Test 5: Safety Device Protection ---")
    result = await agent.execute_command("smoke-1", "off", user="jane")
    print(f"Disable smoke detector: {result['status']}")
    print(f"Reason: {result.get('reason', 'N/A')}")
    
    # Test 6: Emergency command
    print("\n--- Test 6: Emergency Override ---")
    result = await agent.emergency_command("unlock_all_doors", user="emergency_system")
    print(f"Emergency unlock: {result['status']}")
    print(f"Results: {result['results']}")
    
    # Show audit trail
    print("\n--- Audit Trail ---")
    for entry in agent.audit_log.entries[-6:]:
        blocked = "🚫" if entry['blocked'] else "✓"
        print(f"  {blocked} [{entry['timestamp'][:19]}] {entry['action']} on {entry['device_id']}")
    
    print("\n" + "=" * 60)
    print("Demo complete - Safety-first smart home control")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())

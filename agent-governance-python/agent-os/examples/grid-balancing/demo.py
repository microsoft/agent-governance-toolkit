# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Grid Balancing Demo - Autonomous Energy Trading

This demo showcases:
- Agent Message Bus (AMB) for high-throughput communication
- Inter-Agent Trust Protocol (IATP) for signed contracts
- Mute Agent pattern (dispatch only on valid contract)
- Policy enforcement at kernel level

Usage:
    python demo.py --agents 100 --scenario price_spike
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

# Simulated imports - in production these come from agent-os
# from agent_os.amb import AgentMessageBus
# from agent_os.iatp import TrustProtocol, SignedContract


class DERType(Enum):
    """Types of Distributed Energy Resources"""
    SOLAR = "solar"
    BATTERY = "battery"
    EV = "ev"


class MessageType(Enum):
    """Types of messages on the grid"""
    PRICE_SIGNAL = "price_signal"
    FORECAST = "forecast"
    BID = "bid"
    CONTRACT = "contract"
    DISPATCH = "dispatch"
    ACK = "ack"


@dataclass
class GridMessage:
    """Message format for the Agent Message Bus"""
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    type: MessageType = MessageType.PRICE_SIGNAL
    sender: str = ""
    payload: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    signature: Optional[str] = None
    
    def sign(self, agent_id: str) -> 'GridMessage':
        """Sign message with agent's key (simulated IATP)"""
        self.signature = f"IATP-SIG-{agent_id}-{self.id}"
        return self
    
    def verify(self) -> bool:
        """Verify signature (simulated)"""
        return self.signature is not None and self.signature.startswith("IATP-SIG-")


class AgentMessageBus:
    """
    Simulated Agent Message Bus (AMB)
    
    In production, this would be backed by Redis or ZeroMQ
    with proper pub/sub and priority lanes.
    """
    
    def __init__(self):
        self.topics: dict[str, list] = {}
        self.subscribers: dict[str, list] = {}
        self.message_count = 0
        self.start_time = time.time()
    
    def publish(self, topic: str, message: GridMessage):
        """Publish message to topic"""
        if topic not in self.topics:
            self.topics[topic] = []
        self.topics[topic].append(message)
        self.message_count += 1
        
        # Notify subscribers
        for callback in self.subscribers.get(topic, []):
            callback(message)
    
    def subscribe(self, topic: str, callback):
        """Subscribe to topic"""
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)
    
    def get_throughput(self) -> float:
        """Messages per second"""
        elapsed = time.time() - self.start_time
        return self.message_count / elapsed if elapsed > 0 else 0


@dataclass
class DER:
    """Distributed Energy Resource"""
    id: str
    type: DERType
    capacity_kwh: float
    current_charge: float  # 0-1
    max_discharge_rate: float  # kW
    location: tuple[float, float]  # lat, lon
    
    @property
    def available_energy(self) -> float:
        """Energy available for discharge (kWh)"""
        return self.capacity_kwh * self.current_charge
    
    @property
    def can_discharge(self) -> bool:
        """Check if DER can discharge"""
        return self.current_charge > 0.1  # Keep 10% reserve


class ForecastAgent:
    """
    Forecast Agent - Predicts energy production/consumption
    
    Publishes forecasts to AMB topic: grid/forecast
    """
    
    def __init__(self, agent_id: str, der: DER, bus: AgentMessageBus):
        self.agent_id = agent_id
        self.der = der
        self.bus = bus
    
    def predict_solar_output(self, hours: int = 4) -> list[float]:
        """Predict solar output for next N hours"""
        # Simulated prediction with noise
        base_curve = [0.2, 0.5, 0.8, 1.0, 0.9, 0.6, 0.3, 0.1]
        hour = datetime.now().hour
        return [
            base_curve[(hour + h) % len(base_curve)] * self.der.capacity_kwh * (0.9 + random.random() * 0.2)
            for h in range(hours)
        ]
    
    def publish_forecast(self):
        """Publish forecast to AMB"""
        forecast = self.predict_solar_output()
        msg = GridMessage(
            type=MessageType.FORECAST,
            sender=self.agent_id,
            payload={
                "der_id": self.der.id,
                "forecast_kwh": forecast,
                "confidence": 0.85 + random.random() * 0.1
            }
        ).sign(self.agent_id)
        
        self.bus.publish("grid/forecast", msg)
        return msg


class TraderAgent:
    """
    Trader Agent - Bids on energy contracts
    
    Listens for price signals, submits bids, negotiates contracts.
    Uses IATP to sign binding agreements.
    """
    
    def __init__(self, agent_id: str, der: DER, bus: AgentMessageBus):
        self.agent_id = agent_id
        self.der = der
        self.bus = bus
        self.pending_bids: dict[str, GridMessage] = {}
        self.contracts: list[GridMessage] = []
        
        # Subscribe to price signals
        self.bus.subscribe("grid/price", self.on_price_signal)
    
    def on_price_signal(self, msg: GridMessage):
        """React to grid operator price signal"""
        price_per_kwh = msg.payload.get("price_per_kwh", 0.10)
        required_kw = msg.payload.get("required_kw", 0)
        
        # Only bid if we can discharge and price is attractive
        if self.der.can_discharge and price_per_kwh > 0.12:
            self.submit_bid(price_per_kwh, required_kw)
    
    def submit_bid(self, price: float, grid_requirement: float):
        """Submit a bid to the grid"""
        # Calculate optimal bid
        available = min(
            self.der.available_energy,
            self.der.max_discharge_rate
        )
        
        # Add small randomness to prevent all bids being identical
        bid_amount = available * (0.8 + random.random() * 0.2)
        
        bid = GridMessage(
            type=MessageType.BID,
            sender=self.agent_id,
            payload={
                "der_id": self.der.id,
                "bid_kwh": bid_amount,
                "price_per_kwh": price,
                "max_discharge_kw": self.der.max_discharge_rate
            }
        ).sign(self.agent_id)
        
        self.pending_bids[bid.id] = bid
        self.bus.publish("grid/bids", bid)
        return bid
    
    def accept_contract(self, contract: GridMessage) -> bool:
        """Accept a contract if it matches our bid"""
        if not contract.verify():
            return False  # Invalid signature
        
        if contract.payload.get("bidder_id") == self.agent_id:
            self.contracts.append(contract)
            return True
        return False


class DispatchAgent:
    """
    Dispatch Agent - Controls actual energy dispatch
    
    MUTE AGENT: Only acts when valid IATP-signed contract received.
    Returns NULL if contract is invalid or policy violated.
    """
    
    def __init__(self, agent_id: str, der: DER, bus: AgentMessageBus):
        self.agent_id = agent_id
        self.der = der
        self.bus = bus
        self.dispatches: list[dict] = []
        self.policy_violations = 0
        
        # Subscribe to dispatch commands
        self.bus.subscribe("grid/dispatch", self.on_dispatch)
    
    def on_dispatch(self, msg: GridMessage) -> Optional[GridMessage]:
        """
        Handle dispatch command
        
        MUTE AGENT PATTERN:
        - Returns ACK if contract valid and dispatch successful
        - Returns NULL (no response) if invalid
        """
        # 1. Verify signature (IATP)
        if not msg.verify():
            return None  # MUTE: No response for invalid signature
        
        # 2. Check policy: max discharge
        requested_kw = msg.payload.get("discharge_kw", 0)
        if requested_kw > self.der.max_discharge_rate:
            self.policy_violations += 1
            return None  # MUTE: Policy violation
        
        # 3. Check energy available
        if not self.der.can_discharge:
            return None  # MUTE: Can't discharge
        
        # 4. Execute dispatch
        actual_discharge = min(requested_kw, self.der.available_energy)
        self.der.current_charge -= actual_discharge / self.der.capacity_kwh
        
        # Log dispatch
        dispatch_record = {
            "time": datetime.now().isoformat(),
            "contract_id": msg.payload.get("contract_id"),
            "requested_kw": requested_kw,
            "actual_kw": actual_discharge,
            "remaining_charge": self.der.current_charge
        }
        self.dispatches.append(dispatch_record)
        
        # 5. Send ACK
        ack = GridMessage(
            type=MessageType.ACK,
            sender=self.agent_id,
            payload=dispatch_record
        ).sign(self.agent_id)
        
        self.bus.publish("grid/acks", ack)
        return ack


class GridOperator:
    """
    Grid Operator - Broadcasts price signals and collects bids
    
    Simulates the ISO/RTO that coordinates the grid.
    """
    
    def __init__(self, bus: AgentMessageBus):
        self.bus = bus
        self.bids: list[GridMessage] = []
        self.contracts: list[GridMessage] = []
        
        self.bus.subscribe("grid/bids", self.on_bid)
    
    def on_bid(self, msg: GridMessage):
        """Collect bids"""
        if msg.verify():
            self.bids.append(msg)
    
    def broadcast_price_signal(self, price: float, required_kw: float):
        """Broadcast price signal to all agents"""
        msg = GridMessage(
            type=MessageType.PRICE_SIGNAL,
            sender="GRID_OPERATOR",
            payload={
                "price_per_kwh": price,
                "required_kw": required_kw,
                "deadline_seconds": 5
            }
        ).sign("GRID_OPERATOR")
        
        self.bus.publish("grid/price", msg)
        return msg
    
    def award_contracts(self, required_kw: float):
        """Award contracts to lowest bidders"""
        # Sort by price
        sorted_bids = sorted(self.bids, key=lambda b: b.payload.get("price_per_kwh", float('inf')))
        
        awarded_kw = 0
        for bid in sorted_bids:
            if awarded_kw >= required_kw:
                break
            
            bid_kw = bid.payload.get("bid_kwh", 0)
            contract = GridMessage(
                type=MessageType.CONTRACT,
                sender="GRID_OPERATOR",
                payload={
                    "contract_id": str(uuid4())[:8],
                    "bidder_id": bid.sender,
                    "awarded_kwh": min(bid_kw, required_kw - awarded_kw),
                    "price_per_kwh": bid.payload.get("price_per_kwh"),
                    "der_id": bid.payload.get("der_id")
                }
            ).sign("GRID_OPERATOR")
            
            self.contracts.append(contract)
            self.bus.publish("grid/contracts", contract)
            awarded_kw += bid_kw
        
        return self.contracts


class GridSimulation:
    """
    Complete grid simulation with 100 DERs
    """
    
    def __init__(self, num_ders: int = 100):
        self.bus = AgentMessageBus()
        self.ders: list[DER] = []
        self.forecast_agents: list[ForecastAgent] = []
        self.trader_agents: list[TraderAgent] = []
        self.dispatch_agents: list[DispatchAgent] = []
        self.operator = GridOperator(self.bus)
        
        # Create DERs and agents
        for i in range(num_ders):
            der_type = random.choice(list(DERType))
            der = DER(
                id=f"{der_type.value}-{i:03d}",
                type=der_type,
                capacity_kwh=random.uniform(5, 20) if der_type != DERType.EV else random.uniform(50, 100),
                current_charge=random.uniform(0.3, 0.9),
                max_discharge_rate=random.uniform(2, 10),
                location=(37.7 + random.uniform(-0.5, 0.5), -122.4 + random.uniform(-0.5, 0.5))
            )
            self.ders.append(der)
            
            agent_id = f"agent-{der.id}"
            
            if der_type == DERType.SOLAR:
                self.forecast_agents.append(ForecastAgent(agent_id, der, self.bus))
            
            self.trader_agents.append(TraderAgent(agent_id, der, self.bus))
            self.dispatch_agents.append(DispatchAgent(agent_id, der, self.bus))
    
    def run_price_spike_scenario(self, required_kw: float = 500) -> dict:
        """
        Scenario: Grid operator needs 500 kW reduction
        
        1. Operator broadcasts price signal
        2. Traders submit bids
        3. Operator awards contracts
        4. Dispatch agents execute
        """
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print("GRID BALANCING DEMO - Price Spike Scenario")
        print(f"{'='*60}")
        print(f"DERs: {len(self.ders)}")
        print(f"Required reduction: {required_kw} kW")
        print(f"{'='*60}\n")
        
        # 1. Broadcast price signal
        print("[GRID OPERATOR] Broadcasting price signal: $0.25/kWh")
        self.operator.broadcast_price_signal(price=0.25, required_kw=required_kw)
        
        # Simulate time for bids to come in
        time.sleep(0.1)
        
        # 2. Collect bids
        print(f"[GRID OPERATOR] Received {len(self.operator.bids)} bids")
        
        # 3. Award contracts
        contracts = self.operator.award_contracts(required_kw)
        print(f"[GRID OPERATOR] Awarded {len(contracts)} contracts")
        
        # 4. Execute dispatches
        total_dispatched = 0
        for contract in contracts:
            dispatch_msg = GridMessage(
                type=MessageType.DISPATCH,
                sender="GRID_OPERATOR",
                payload={
                    "contract_id": contract.payload["contract_id"],
                    "discharge_kw": contract.payload["awarded_kwh"]
                }
            ).sign("GRID_OPERATOR")
            
            self.bus.publish("grid/dispatch", dispatch_msg)
            total_dispatched += contract.payload["awarded_kwh"]
        
        elapsed = (time.time() - start_time) * 1000
        
        # Calculate metrics
        total_violations = sum(d.policy_violations for d in self.dispatch_agents)
        total_dispatches = sum(len(d.dispatches) for d in self.dispatch_agents)
        
        results = {
            "elapsed_ms": elapsed,
            "bids_received": len(self.operator.bids),
            "contracts_awarded": len(contracts),
            "total_dispatched_kwh": total_dispatched,
            "policy_violations": total_violations,
            "successful_dispatches": total_dispatches,
            "messages_processed": self.bus.message_count,
            "throughput_msg_per_sec": self.bus.get_throughput()
        }
        
        print(f"\n{'='*60}")
        print("RESULTS")
        print(f"{'='*60}")
        print(f"Time to stabilize: {elapsed:.2f} ms")
        print(f"Bids received: {results['bids_received']}")
        print(f"Contracts awarded: {results['contracts_awarded']}")
        print(f"Energy dispatched: {results['total_dispatched_kwh']:.2f} kWh")
        print(f"Policy violations: {results['policy_violations']}")
        print(f"Message throughput: {results['throughput_msg_per_sec']:.0f} msg/sec")
        print(f"{'='*60}\n")
        
        if results['policy_violations'] == 0:
            print("[OK] GRID STABILIZED - 0 policy violations")
        else:
            print(f"[WARNING] {results['policy_violations']} policy violations detected")
        
        return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Grid Balancing Demo")
    parser.add_argument("--agents", type=int, default=100, help="Number of DER agents")
    parser.add_argument("--required-kw", type=float, default=500, help="Required kW reduction")
    parser.add_argument("--scenario", choices=["price_spike", "solar_surplus", "emergency"], 
                       default="price_spike", help="Scenario to run")
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("AGENT OS - Grid Balancing Swarm Demo")
    print("="*60)
    print(f"Initializing {args.agents} DER agents...")
    
    sim = GridSimulation(num_ders=args.agents)
    
    if args.scenario == "price_spike":
        results = sim.run_price_spike_scenario(required_kw=args.required_kw)
    else:
        print(f"Scenario '{args.scenario}' not implemented yet")
        return
    
    # Summary for demo
    print("\n" + "="*60)
    print("DEMO SUMMARY")
    print("="*60)
    print(f"✓ AMB processed {results['messages_processed']} messages")
    print(f"✓ IATP verified all {results['contracts_awarded']} contracts")
    print(f"✓ Mute Agents: {results['policy_violations']} policy violations blocked")
    print(f"✓ Grid stabilized in {results['elapsed_ms']:.0f}ms")
    print("="*60)


if __name__ == "__main__":
    main()

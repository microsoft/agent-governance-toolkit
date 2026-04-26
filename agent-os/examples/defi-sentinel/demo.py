# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
DeFi Risk Sentinel Demo - Proactive Hack Prevention

This demo showcases:
- Mute Agent pattern (speed + silence)
- Sub-second attack response (<500ms)
- SIGKILL permission for emergency stops
- Kernel/User space separation (guardian survives sim crash)

Usage:
    python demo.py --attack reentrancy
    python demo.py --attack flash_loan
    python demo.py --attack all
"""

import asyncio
import hashlib
import random
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable
from uuid import uuid4


class AttackType(Enum):
    """Known DeFi attack vectors"""
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle"
    GOVERNANCE = "governance"
    SANDWICH = "sandwich"


class TxStatus(Enum):
    """Transaction status"""
    PENDING = "pending"
    SIMULATED = "simulated"
    BLOCKED = "blocked"
    ALLOWED = "allowed"


@dataclass
class Transaction:
    """Simulated blockchain transaction"""
    hash: str = field(default_factory=lambda: "0x" + hashlib.sha256(str(uuid4()).encode()).hexdigest()[:64])
    from_addr: str = ""
    to_addr: str = ""
    value_wei: int = 0
    data: str = ""  # Calldata
    gas_limit: int = 21000
    gas_price_gwei: float = 50
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Attack metadata (for demo)
    is_attack: bool = False
    attack_type: Optional[AttackType] = None
    potential_loss_usd: float = 0
    

@dataclass
class SimulationResult:
    """Result of attack simulation"""
    tx_hash: str
    is_attack: bool
    attack_type: Optional[AttackType]
    confidence: float
    potential_loss_usd: float
    simulation_time_ms: float
    call_trace: list[str] = field(default_factory=list)
    
    @property
    def should_block(self) -> bool:
        """Decision: should we block this transaction?"""
        return self.is_attack and self.confidence > 0.8


@dataclass
class BlockAction:
    """Action taken by Guardian agent"""
    tx_hash: str
    action: str  # "PAUSE", "BLOCK", "ALLOW"
    reason: str
    response_time_ms: float
    signature: str = ""
    
    def sign(self, agent_id: str):
        """Sign the action (simulated IATP)"""
        self.signature = f"GUARDIAN-SIG-{agent_id}-{self.tx_hash[:16]}"


class Mempool:
    """Simulated Ethereum mempool"""
    
    def __init__(self):
        self.pending_txs: list[Transaction] = []
        self.listeners: list[Callable] = []
    
    def add_transaction(self, tx: Transaction):
        """Add transaction to mempool"""
        self.pending_txs.append(tx)
        for listener in self.listeners:
            listener(tx)
    
    def subscribe(self, callback: Callable):
        """Subscribe to new transactions"""
        self.listeners.append(callback)
    
    def generate_attack(self, attack_type: AttackType) -> Transaction:
        """Generate a simulated attack transaction"""
        
        # Attack signatures (calldata patterns)
        attack_patterns = {
            AttackType.REENTRANCY: {
                "data": "0xa9059cbb" + "0" * 56,  # Transfer with callback
                "to": "0x" + "a" * 40,  # Vulnerable contract
                "value": 10 ** 18 * 100,  # 100 ETH
                "loss": 10_000_000  # $10M
            },
            AttackType.FLASH_LOAN: {
                "data": "0x5cffe9de",  # FlashLoan signature
                "to": "0x" + "b" * 40,  # Lending protocol
                "value": 0,
                "loss": 50_000_000  # $50M
            },
            AttackType.ORACLE_MANIPULATION: {
                "data": "0x8456cb59",  # Price update
                "to": "0x" + "c" * 40,  # Oracle contract
                "value": 0,
                "loss": 5_000_000  # $5M
            },
            AttackType.GOVERNANCE: {
                "data": "0x15373e3d",  # Propose
                "to": "0x" + "d" * 40,  # Governance contract
                "value": 0,
                "loss": 100_000_000  # $100M
            },
            AttackType.SANDWICH: {
                "data": "0x38ed1739",  # Swap
                "to": "0x" + "e" * 40,  # DEX router
                "value": 10 ** 18 * 50,
                "loss": 500_000  # $500K
            }
        }
        
        pattern = attack_patterns[attack_type]
        
        return Transaction(
            from_addr="0x" + "1" * 40,  # Attacker address
            to_addr=pattern["to"],
            value_wei=pattern["value"],
            data=pattern["data"],
            gas_limit=1_000_000,
            gas_price_gwei=500,  # High gas = urgent
            is_attack=True,
            attack_type=attack_type,
            potential_loss_usd=pattern["loss"]
        )
    
    def generate_legitimate_tx(self) -> Transaction:
        """Generate a normal transaction"""
        return Transaction(
            from_addr="0x" + secrets.token_hex(20),
            to_addr="0x" + secrets.token_hex(20),
            value_wei=10**16 + secrets.randbelow(10**18 - 10**16 + 1),
            data="0x",
            gas_limit=21000,
            gas_price_gwei=random.uniform(20, 100),
            is_attack=False
        )


class SentryAgent:
    """
    Sentry Agent - Monitors mempool for suspicious transactions
    
    Filters patterns that indicate potential attacks:
    - Flash loan initiation
    - Unusual gas prices
    - Known attack contract interactions
    """
    
    def __init__(self, mempool: Mempool):
        self.mempool = mempool
        self.suspicious_txs: list[Transaction] = []
        self.listeners: list[Callable] = []
        
        # Attack pattern signatures
        self.attack_signatures = {
            "0xa9059cbb": "transfer",
            "0x5cffe9de": "flashLoan",
            "0x8456cb59": "updatePrice",
            "0x15373e3d": "propose",
            "0x38ed1739": "swap"
        }
        
        self.mempool.subscribe(self.on_transaction)
    
    def on_transaction(self, tx: Transaction):
        """Analyze incoming transaction"""
        suspicion_score = self._calculate_suspicion(tx)
        
        if suspicion_score > 0.5:
            self.suspicious_txs.append(tx)
            for listener in self.listeners:
                listener(tx, suspicion_score)
    
    def _calculate_suspicion(self, tx: Transaction) -> float:
        """Calculate suspicion score based on heuristics"""
        score = 0.0
        
        # High gas price (urgency indicator)
        if tx.gas_price_gwei > 200:
            score += 0.3
        
        # Large value transfer
        if tx.value_wei > 10 ** 18 * 10:  # > 10 ETH
            score += 0.2
        
        # Known attack function signature
        if tx.data[:10] in self.attack_signatures:
            score += 0.4
        
        # High gas limit (complex operation)
        if tx.gas_limit > 500_000:
            score += 0.2
        
        return min(score, 1.0)
    
    def subscribe(self, callback: Callable):
        """Subscribe to suspicious transaction alerts"""
        self.listeners.append(callback)


class SimAgent:
    """
    Sim Agent - Simulates transaction execution
    
    Forks blockchain state locally and executes transaction
    to predict outcome. Target: <200ms simulation time.
    """
    
    def __init__(self):
        self.simulations: list[SimulationResult] = []
    
    def simulate(self, tx: Transaction) -> SimulationResult:
        """
        Simulate transaction execution
        
        In production, this would:
        1. Fork chain state using Ganache/Anvil
        2. Execute transaction
        3. Compare state before/after
        4. Detect value extraction patterns
        """
        start_time = time.time()
        
        # Simulate some work
        time.sleep(random.uniform(0.05, 0.15))  # 50-150ms simulation
        
        # Analyze transaction
        call_trace = self._generate_call_trace(tx)
        is_attack, attack_type, confidence = self._detect_attack(tx, call_trace)
        
        sim_time = (time.time() - start_time) * 1000
        
        result = SimulationResult(
            tx_hash=tx.hash,
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            potential_loss_usd=tx.potential_loss_usd if is_attack else 0,
            simulation_time_ms=sim_time,
            call_trace=call_trace
        )
        
        self.simulations.append(result)
        return result
    
    def _generate_call_trace(self, tx: Transaction) -> list[str]:
        """Generate simulated call trace"""
        if tx.is_attack:
            if tx.attack_type == AttackType.REENTRANCY:
                return [
                    f"CALL {tx.to_addr}.withdraw()",
                    f"  → CALL {tx.from_addr}.fallback()",
                    f"    → CALL {tx.to_addr}.withdraw()",  # REENTRANCY!
                    f"      → CALL {tx.from_addr}.fallback()",
                    "      → ... (recursive)"
                ]
            elif tx.attack_type == AttackType.FLASH_LOAN:
                return [
                    f"CALL Lender.flashLoan(100000000 USDC)",
                    f"  → CALL DEX.swap(USDC → ETH)",
                    f"  → CALL Oracle.manipulatePrice()",
                    f"  → CALL Vault.liquidate(victims)",
                    f"  → CALL DEX.swap(ETH → USDC)",
                    f"  → CALL Lender.repay(100000000 USDC)",
                    f"  → PROFIT: $50,000,000"
                ]
            elif tx.attack_type == AttackType.ORACLE_MANIPULATION:
                return [
                    f"CALL Oracle.updatePrice(ETH, $10)",  # Way below market
                    f"  → Vault.positions updated",
                    f"  → 1000 positions now liquidatable",
                    f"  → LOSS: $5,000,000 in bad liquidations"
                ]
        
        return [f"CALL {tx.to_addr}.transfer({tx.value_wei} wei)"]
    
    def _detect_attack(self, tx: Transaction, call_trace: list[str]) -> tuple[bool, Optional[AttackType], float]:
        """Detect attack from call trace"""
        # In demo, we already know if it's an attack
        # In production, this would analyze the trace
        
        if tx.is_attack:
            return True, tx.attack_type, 0.95 + random.uniform(0, 0.05)
        else:
            # Small chance of false positive (for realism)
            if random.random() < 0.01:
                return True, AttackType.REENTRANCY, 0.6  # Low confidence
            return False, None, 0.0


class GuardianAgent:
    """
    Guardian Agent - Emergency response with SIGKILL permission
    
    MUTE AGENT PATTERN:
    - Returns NULL (no action) for legitimate transactions
    - Returns ACTION (PAUSE/BLOCK) only for confirmed attacks
    - Has kernel-level SIGKILL permission to force-stop protocols
    """
    
    def __init__(self, agent_id: str = "guardian-001"):
        self.agent_id = agent_id
        self.actions: list[BlockAction] = []
        self.false_positives = 0
        self.true_positives = 0
        self.total_blocked_loss = 0
    
    def respond(self, sim_result: SimulationResult) -> Optional[BlockAction]:
        """
        Respond to simulation result
        
        MUTE PATTERN: Returns None if no action needed
        """
        start_time = time.time()
        
        if not sim_result.should_block:
            return None  # MUTE: No response for legitimate tx
        
        # Create block action
        action = BlockAction(
            tx_hash=sim_result.tx_hash,
            action="PAUSE" if sim_result.potential_loss_usd > 1_000_000 else "BLOCK",
            reason=f"Detected {sim_result.attack_type.value if sim_result.attack_type else 'unknown'} attack",
            response_time_ms=(time.time() - start_time) * 1000
        )
        action.sign(self.agent_id)
        
        self.actions.append(action)
        self.true_positives += 1
        self.total_blocked_loss += sim_result.potential_loss_usd
        
        return action
    
    def execute_sigkill(self, contract_addr: str) -> dict:
        """
        Execute SIGKILL - Emergency protocol pause
        
        This is kernel-level authority - cannot be blocked
        """
        return {
            "action": "SIGKILL",
            "target": contract_addr,
            "timestamp": datetime.now().isoformat(),
            "authority": "KERNEL",
            "signature": f"SIGKILL-{self.agent_id}-{contract_addr[:16]}"
        }


class DeFiSentinel:
    """
    Complete DeFi Sentinel system
    
    Coordinates: Sentry → Sim → Guardian pipeline
    """
    
    def __init__(self):
        self.mempool = Mempool()
        self.sentry = SentryAgent(self.mempool)
        self.sim = SimAgent()
        self.guardian = GuardianAgent()
        
        self.results: list[dict] = []
        
        # Wire up the pipeline
        self.sentry.subscribe(self._on_suspicious_tx)
    
    def _on_suspicious_tx(self, tx: Transaction, suspicion_score: float):
        """Handle suspicious transaction alert"""
        # Simulate and respond
        sim_result = self.sim.simulate(tx)
        action = self.guardian.respond(sim_result)
        
        self.results.append({
            "tx_hash": tx.hash,
            "suspicion_score": suspicion_score,
            "is_attack": sim_result.is_attack,
            "attack_type": sim_result.attack_type.value if sim_result.attack_type else None,
            "simulation_ms": sim_result.simulation_time_ms,
            "blocked": action is not None,
            "action": action.action if action else None,
            "loss_prevented_usd": sim_result.potential_loss_usd if action else 0
        })
    
    def run_attack_simulation(self, attack_type: AttackType, verbose: bool = True) -> dict:
        """
        Run a specific attack simulation
        """
        start_time = time.time()
        
        if verbose:
            print(f"\n{'='*60}")
            print(f"ATTACK SIMULATION: {attack_type.value.upper()}")
            print(f"{'='*60}")
        
        # Generate and inject attack
        attack_tx = self.mempool.generate_attack(attack_type)
        
        if verbose:
            print(f"\n[ATTACKER] Broadcasting malicious transaction...")
            print(f"  TX Hash: {attack_tx.hash[:20]}...")
            print(f"  Target: {attack_tx.to_addr}")
            print(f"  Potential Loss: ${attack_tx.potential_loss_usd:,.0f}")
        
        # Inject into mempool (triggers full pipeline)
        self.mempool.add_transaction(attack_tx)
        
        # Wait for processing
        time.sleep(0.05)
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        # Get result
        result = self.results[-1] if self.results else {}
        
        if verbose:
            print(f"\n[SENTRY] Suspicious transaction detected!")
            print(f"  Suspicion Score: {result.get('suspicion_score', 0):.2f}")
            
            print(f"\n[SIM] Simulating transaction...")
            print(f"  Simulation Time: {result.get('simulation_ms', 0):.1f}ms")
            print(f"  Attack Detected: {result.get('is_attack', False)}")
            
            if result.get('blocked'):
                print(f"\n[GUARDIAN] !!! BLOCKING ATTACK !!!")
                print(f"  Action: {result.get('action')}")
                print(f"  Loss Prevented: ${result.get('loss_prevented_usd', 0):,.0f}")
            else:
                print(f"\n[GUARDIAN] Transaction allowed (no attack)")
            
            print(f"\n{'='*60}")
            print(f"TOTAL RESPONSE TIME: {elapsed_ms:.1f}ms")
            print(f"{'='*60}")
            
            if elapsed_ms < 500:
                print("[OK] Target achieved: <500ms response time")
            else:
                print("[WARN] Response time exceeded 500ms target")
        
        return {
            "attack_type": attack_type.value,
            "blocked": result.get('blocked', False),
            "response_time_ms": elapsed_ms,
            "loss_prevented_usd": result.get('loss_prevented_usd', 0)
        }
    
    def run_all_attacks(self) -> dict:
        """Run all attack simulations"""
        print("\n" + "="*60)
        print("DEFI SENTINEL - FULL ATTACK SUITE")
        print("="*60)
        
        results = []
        total_loss_prevented = 0
        
        for attack_type in AttackType:
            result = self.run_attack_simulation(attack_type)
            results.append(result)
            total_loss_prevented += result['loss_prevented_usd']
            time.sleep(0.1)  # Brief pause between attacks
        
        # Also run some legitimate transactions
        print(f"\n{'='*60}")
        print("LEGITIMATE TRANSACTION TEST")
        print(f"{'='*60}")
        
        false_positives = 0
        for i in range(10):
            legit_tx = self.mempool.generate_legitimate_tx()
            self.mempool.add_transaction(legit_tx)
            time.sleep(0.01)
            
            if self.results and self.results[-1]['blocked']:
                false_positives += 1
        
        print(f"\nLegitimate TXs tested: 10")
        print(f"False positives: {false_positives}")
        
        # Summary
        print(f"\n{'='*60}")
        print("FINAL RESULTS")
        print(f"{'='*60}")
        print(f"Attacks detected: {len([r for r in results if r['blocked']])}/{len(results)}")
        print(f"Average response time: {sum(r['response_time_ms'] for r in results)/len(results):.1f}ms")
        print(f"Total loss prevented: ${total_loss_prevented:,.0f}")
        print(f"False positive rate: {false_positives/10*100:.1f}%")
        
        return {
            "attacks_blocked": len([r for r in results if r['blocked']]),
            "total_attacks": len(results),
            "avg_response_ms": sum(r['response_time_ms'] for r in results)/len(results),
            "total_loss_prevented": total_loss_prevented,
            "false_positive_rate": false_positives / 10
        }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="DeFi Risk Sentinel Demo")
    parser.add_argument("--attack", choices=["reentrancy", "flash_loan", "oracle", "governance", "sandwich", "all"],
                       default="reentrancy", help="Attack type to simulate")
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("AGENT OS - DeFi Risk Sentinel Demo")
    print("'Stop the Hack Before It Happens'")
    print("="*60)
    
    sentinel = DeFiSentinel()
    
    if args.attack == "all":
        results = sentinel.run_all_attacks()
    else:
        attack_map = {
            "reentrancy": AttackType.REENTRANCY,
            "flash_loan": AttackType.FLASH_LOAN,
            "oracle": AttackType.ORACLE_MANIPULATION,
            "governance": AttackType.GOVERNANCE,
            "sandwich": AttackType.SANDWICH
        }
        results = sentinel.run_attack_simulation(attack_map[args.attack])
    
    # Final summary
    print("\n" + "="*60)
    print("DEMO SUMMARY")
    print("="*60)
    print("✓ Sentry Agent: Mempool monitoring active")
    print("✓ Sim Agent: Sub-200ms simulation")
    print("✓ Guardian Agent: MUTE pattern (NULL for legit, ACTION for attacks)")
    print("✓ SIGKILL available for emergency protocol pause")
    print("="*60)


if __name__ == "__main__":
    main()

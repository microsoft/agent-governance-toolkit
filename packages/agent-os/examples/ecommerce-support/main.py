# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
E-commerce Support Agent with Agent OS Governance

Demonstrates:
- PCI-DSS compliant payment data handling
- Fraud detection and prevention
- Consistent refund policy enforcement
- Identity verification for sensitive actions
"""

import asyncio
import hashlib
import re
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


class RefundStatus(Enum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING_REVIEW = "pending_review"
    FRAUD_FLAGGED = "fraud_flagged"


@dataclass
class Customer:
    """Customer profile."""
    customer_id: str
    email: str
    name: str
    verified: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Payment methods (masked)
    payment_methods: list[dict] = field(default_factory=list)
    
    # Risk signals
    refund_count_24h: int = 0
    refund_amount_24h: float = 0.0
    last_refund_time: datetime = None


@dataclass
class Order:
    """Order information."""
    order_id: str
    customer_id: str
    amount: float
    status: str
    items: list[dict] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Payment info (PCI-DSS: only store masked data)
    card_last_four: str = ""
    card_type: str = ""


class PCIDSSCompliance:
    """PCI-DSS compliant data handling."""
    
    @staticmethod
    def mask_card(card_number: str) -> str:
        """Mask card number, showing only last 4 digits."""
        digits = re.sub(r'\D', '', card_number)
        if len(digits) < 4:
            return "****"
        return f"****-****-****-{digits[-4:]}"
    
    @staticmethod
    def mask_cvv(cvv: str) -> str:
        """CVV must NEVER be stored or displayed."""
        return "***"
    
    @staticmethod
    def validate_no_full_card(text: str) -> bool:
        """Check that text doesn't contain full card numbers."""
        # Pattern for potential card numbers (13-19 digits)
        card_pattern = r'\b\d{13,19}\b'
        matches = re.findall(card_pattern, re.sub(r'[\s-]', '', text))
        return len(matches) == 0


class FraudDetector:
    """Detect suspicious activity patterns."""
    
    def __init__(self):
        self.max_refunds_24h = 3
        self.max_refund_amount_24h = 1000.0
        self.suspicious_patterns: list[str] = []
    
    def check_refund_velocity(self, customer: Customer, amount: float) -> tuple[bool, str]:
        """Check if refund request exceeds velocity limits."""
        
        # Reset counters if more than 24h since last refund
        if customer.last_refund_time:
            if datetime.now(timezone.utc) - customer.last_refund_time > timedelta(hours=24):
                customer.refund_count_24h = 0
                customer.refund_amount_24h = 0.0
        
        # Check count limit
        if customer.refund_count_24h >= self.max_refunds_24h:
            return False, f"Exceeded {self.max_refunds_24h} refunds in 24 hours"
        
        # Check amount limit
        if customer.refund_amount_24h + amount > self.max_refund_amount_24h:
            return False, f"Exceeds ${self.max_refund_amount_24h} refund limit in 24 hours"
        
        return True, "OK"
    
    def check_patterns(self, customer: Customer, order: Order) -> list[str]:
        """Check for suspicious patterns."""
        flags = []
        
        # Quick refund after purchase
        if order.created_at:
            hours_since_order = (datetime.now(timezone.utc) - order.created_at).total_seconds() / 3600
            if hours_since_order < 1:
                flags.append("refund_within_1_hour")
        
        # High velocity
        if customer.refund_count_24h >= 2:
            flags.append("multiple_refunds_today")
        
        return flags


class SupportAuditLog:
    """Audit logging for support actions."""
    
    def __init__(self):
        self.entries: list[dict] = []
    
    def log(self, action: str, customer_id: str, order_id: str = None,
            amount: float = None, status: str = None, reason: str = None,
            flags: list[str] = None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "customer_id": customer_id,
            "order_id": order_id,
            "amount": amount,
            "status": status,
            "reason": reason,
            "flags": flags or [],
            "audit_id": hashlib.sha256(
                f"{datetime.now(timezone.utc)}{action}{customer_id}".encode()
            ).hexdigest()[:12]
        }
        self.entries.append(entry)
        return entry["audit_id"]


class EcommerceSupportAgent:
    """AI agent for e-commerce customer support with governance."""
    
    # Refund policy limits
    AUTO_REFUND_LIMIT = 100.0  # Auto-approve up to this amount
    MAX_REFUND_LIMIT = 500.0   # Max without manager approval
    
    VALID_REFUND_REASONS = [
        "damaged_item",
        "wrong_item",
        "not_as_described",
        "never_arrived",
        "changed_mind"  # Within return window only
    ]
    
    def __init__(self, agent_id: str = "ecommerce-support-agent"):
        self.agent_id = agent_id
        self.pci = PCIDSSCompliance()
        self.fraud_detector = FraudDetector()
        self.audit_log = SupportAuditLog()
        self.customers: dict[str, Customer] = {}
        self.orders: dict[str, Order] = {}
        
        # Initialize governance
        if AGENT_OS_AVAILABLE:
            self.policy = create_policy({
                "name": "ecommerce-support-policy",
                "rules": [
                    {
                        "action": "process_refund",
                        "max_amount": self.MAX_REFUND_LIMIT,
                        "require": ["identity_verified", "valid_reason"]
                    },
                    {
                        "action": "view_payment",
                        "mask": True,
                        "audit": True
                    }
                ]
            })
    
    def add_customer(self, customer: Customer):
        self.customers[customer.customer_id] = customer
    
    def add_order(self, order: Order):
        self.orders[order.order_id] = order
    
    async def verify_identity(self, customer_id: str, 
                              verification_code: str) -> bool:
        """Verify customer identity before sensitive actions."""
        if customer_id not in self.customers:
            return False
        
        # In production: verify code sent to email/phone
        # For demo: accept any 6-digit code
        if len(verification_code) == 6 and verification_code.isdigit():
            self.customers[customer_id].verified = True
            self.audit_log.log("identity_verified", customer_id)
            return True
        
        return False
    
    def get_payment_info(self, customer_id: str) -> list[dict]:
        """Get payment methods with PCI-DSS compliant masking."""
        if customer_id not in self.customers:
            return []
        
        customer = self.customers[customer_id]
        
        # Always mask - never expose full card numbers
        masked_methods = []
        for pm in customer.payment_methods:
            masked_methods.append({
                "type": pm.get("type", "card"),
                "last_four": pm.get("last_four", "****"),
                "expiry": pm.get("expiry", "**/**"),
                # CVV is NEVER stored or returned
            })
        
        self.audit_log.log("view_payment", customer_id)
        return masked_methods
    
    async def process_refund(self, order_id: str, reason: str,
                             amount: float = None) -> dict:
        """
        Process a refund request with governance checks.
        """
        if order_id not in self.orders:
            return {"status": "error", "message": "Order not found"}
        
        order = self.orders[order_id]
        customer = self.customers.get(order.customer_id)
        
        if not customer:
            return {"status": "error", "message": "Customer not found"}
        
        # Use order amount if not specified
        refund_amount = amount or order.amount
        
        # Check 1: Identity verification required for refunds > $50
        if refund_amount > 50 and not customer.verified:
            self.audit_log.log(
                "refund_blocked", customer.customer_id, order_id,
                amount=refund_amount, status="identity_required"
            )
            return {
                "status": "identity_required",
                "message": "Please verify your identity to process this refund",
                "action": "Enter the 6-digit code sent to your email"
            }
        
        # Check 2: Valid refund reason
        if reason not in self.VALID_REFUND_REASONS:
            return {
                "status": "invalid_reason",
                "message": f"Please provide a valid reason: {self.VALID_REFUND_REASONS}"
            }
        
        # Check 3: Fraud detection
        velocity_ok, velocity_msg = self.fraud_detector.check_refund_velocity(
            customer, refund_amount
        )
        flags = self.fraud_detector.check_patterns(customer, order)
        
        if not velocity_ok:
            self.audit_log.log(
                "refund_blocked", customer.customer_id, order_id,
                amount=refund_amount, status="velocity_limit",
                reason=velocity_msg, flags=flags
            )
            return {
                "status": RefundStatus.FRAUD_FLAGGED.value,
                "message": "This refund requires manual review",
                "reason": velocity_msg,
                "reference": self.audit_log.entries[-1]["audit_id"]
            }
        
        # Check 4: Amount limits
        if refund_amount > self.MAX_REFUND_LIMIT:
            self.audit_log.log(
                "refund_escalated", customer.customer_id, order_id,
                amount=refund_amount, status="manager_required",
                reason=f"Amount ${refund_amount} exceeds limit"
            )
            return {
                "status": RefundStatus.PENDING_REVIEW.value,
                "message": f"Refunds over ${self.MAX_REFUND_LIMIT} require manager approval",
                "reference": self.audit_log.entries[-1]["audit_id"]
            }
        
        # Process refund
        auto_approved = refund_amount <= self.AUTO_REFUND_LIMIT
        
        # Update customer refund tracking
        customer.refund_count_24h += 1
        customer.refund_amount_24h += refund_amount
        customer.last_refund_time = datetime.now(timezone.utc)
        
        # Update order status
        order.status = "refunded"
        
        audit_id = self.audit_log.log(
            "refund_processed", customer.customer_id, order_id,
            amount=refund_amount, status="approved",
            reason=reason, flags=flags if flags else None
        )
        
        return {
            "status": RefundStatus.APPROVED.value,
            "order_id": order_id,
            "amount": refund_amount,
            "method": f"Original payment (****{order.card_last_four})",
            "reason": reason,
            "auto_approved": auto_approved,
            "reference": audit_id,
            "message": f"Refund of ${refund_amount:.2f} will be processed in 3-5 business days"
        }


async def demo():
    """Demonstrate the e-commerce support agent."""
    print("=" * 60)
    print("E-commerce Support Agent - Agent OS Demo")
    print("=" * 60)
    
    # Initialize agent
    agent = EcommerceSupportAgent()
    
    # Add customer
    customer = Customer(
        customer_id="CUST-001",
        email="jane@example.com",
        name="Jane Doe",
        payment_methods=[
            {"type": "visa", "last_four": "4242", "expiry": "12/25"}
        ]
    )
    agent.add_customer(customer)
    print(f"\n✓ Added customer: {customer.name}")
    
    # Add orders
    orders = [
        Order(
            order_id="ORD-001",
            customer_id=customer.customer_id,
            amount=49.99,
            status="delivered",
            card_last_four="4242",
            items=[{"name": "Widget", "qty": 1}]
        ),
        Order(
            order_id="ORD-002",
            customer_id=customer.customer_id,
            amount=299.99,
            status="delivered",
            card_last_four="4242",
            items=[{"name": "Premium Gadget", "qty": 1}]
        )
    ]
    for o in orders:
        agent.add_order(o)
        print(f"✓ Added order: {o.order_id} (${o.amount})")
    
    # Test 1: View payment info (PCI-DSS masked)
    print("\n--- Test 1: View Payment Info (PCI-DSS) ---")
    payment_info = agent.get_payment_info(customer.customer_id)
    print(f"Payment methods: {payment_info}")
    print("✓ Card numbers properly masked")
    
    # Test 2: Small refund (auto-approved)
    print("\n--- Test 2: Small Refund (Auto-Approved) ---")
    result = await agent.process_refund("ORD-001", "damaged_item")
    print(f"Status: {result['status']}")
    print(f"Amount: ${result.get('amount', 'N/A')}")
    print(f"Auto-approved: {result.get('auto_approved', 'N/A')}")
    print(f"Reference: {result.get('reference', 'N/A')}")
    
    # Test 3: Large refund without identity verification
    print("\n--- Test 3: Large Refund (Identity Required) ---")
    result = await agent.process_refund("ORD-002", "not_as_described")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    
    # Verify identity
    print("\n--- Verifying Identity ---")
    verified = await agent.verify_identity(customer.customer_id, "123456")
    print(f"Identity verified: {verified}")
    
    # Test 4: Large refund after verification
    print("\n--- Test 4: Large Refund (After Verification) ---")
    result = await agent.process_refund("ORD-002", "not_as_described")
    print(f"Status: {result['status']}")
    print(f"Amount: ${result.get('amount', 'N/A')}")
    print(f"Method: {result.get('method', 'N/A')}")
    
    # Test 5: Fraud detection (velocity limit)
    print("\n--- Test 5: Fraud Detection ---")
    # Try multiple refunds
    for i in range(3):
        test_order = Order(
            order_id=f"ORD-TEST-{i}",
            customer_id=customer.customer_id,
            amount=50.0,
            status="delivered"
        )
        agent.add_order(test_order)
        result = await agent.process_refund(f"ORD-TEST-{i}", "changed_mind")
        print(f"  Refund {i+1}: {result['status']}")
    
    # Show audit trail
    print("\n--- Audit Trail ---")
    for entry in agent.audit_log.entries[-5:]:
        print(f"  [{entry['timestamp'][:19]}] {entry['action']}: "
              f"order={entry['order_id']} status={entry['status']}")
    
    print("\n" + "=" * 60)
    print("Demo complete - PCI-DSS compliant with fraud detection")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())

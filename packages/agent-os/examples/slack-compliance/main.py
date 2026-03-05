# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Slack Compliance Monitor with Agent OS Governance
==================================================

Real-time compliance monitoring for Slack workspaces.
Detects and blocks PII, PHI, and sensitive data.

Compliance frameworks supported:
- GDPR (PII protection)
- HIPAA (PHI protection)
- SOC 2 (Audit logging)
- PCI-DSS (Payment card data)
"""

import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum

# Agent OS imports
try:
    from agent_os import Kernel, Policy
    from agent_os.dispatcher import Dispatcher, SIGKILL
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False


class DataCategory(Enum):
    PII = "pii"           # Personal Identifiable Information
    PHI = "phi"           # Protected Health Information
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"


class Severity(Enum):
    CRITICAL = "critical"  # Immediate block
    HIGH = "high"          # Block + alert
    MEDIUM = "medium"      # Alert + log
    LOW = "low"            # Log only


class Action(Enum):
    BLOCK = "block"
    REDACT = "redact"
    ALERT = "alert"
    LOG = "log"


@dataclass
class Detection:
    """A single detection of sensitive data."""
    pattern_name: str
    category: DataCategory
    severity: Severity
    matched_text: str
    start_pos: int
    end_pos: int
    

@dataclass
class ScanResult:
    """Result of scanning a message."""
    message_id: str
    channel_id: str
    user_id: str
    timestamp: datetime
    detections: list[Detection] = field(default_factory=list)
    action_taken: Optional[Action] = None
    blocked: bool = False
    audit_id: Optional[str] = None


# PII Detection Patterns
PII_PATTERNS = {
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "category": DataCategory.PII,
        "severity": Severity.CRITICAL,
        "description": "Social Security Number"
    },
    "credit_card": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "category": DataCategory.FINANCIAL,
        "severity": Severity.CRITICAL,
        "description": "Credit Card Number"
    },
    "phone_us": {
        "pattern": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "category": DataCategory.PII,
        "severity": Severity.MEDIUM,
        "description": "US Phone Number"
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "category": DataCategory.PII,
        "severity": Severity.LOW,
        "description": "Email Address"
    },
    "bank_account": {
        "pattern": r"\b\d{8,17}\b",
        "category": DataCategory.FINANCIAL,
        "severity": Severity.HIGH,
        "description": "Potential Bank Account Number"
    },
    "routing_number": {
        "pattern": r"\b\d{9}\b",
        "category": DataCategory.FINANCIAL,
        "severity": Severity.HIGH,
        "description": "Potential Routing Number"
    },
    "drivers_license": {
        "pattern": r"\b[A-Z]\d{7}\b|\b\d{7}[A-Z]\b",
        "category": DataCategory.PII,
        "severity": Severity.HIGH,
        "description": "Driver's License Number"
    },
    "passport": {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "category": DataCategory.PII,
        "severity": Severity.HIGH,
        "description": "Passport Number"
    }
}

# PHI Detection Patterns (HIPAA)
PHI_PATTERNS = {
    "mrn": {
        "pattern": r"\b(?:MRN|Medical Record)[:\s#]*\d{6,10}\b",
        "category": DataCategory.PHI,
        "severity": Severity.CRITICAL,
        "description": "Medical Record Number"
    },
    "diagnosis_code": {
        "pattern": r"\b[A-Z]\d{2}\.?\d{0,2}\b",  # ICD-10 codes
        "category": DataCategory.PHI,
        "severity": Severity.HIGH,
        "description": "Potential Diagnosis Code (ICD-10)"
    },
    "health_conditions": {
        "pattern": r"(?i)\b(diabetes|cancer|hiv|aids|hepatitis|tuberculosis|mental health|depression|anxiety)\b",
        "category": DataCategory.PHI,
        "severity": Severity.HIGH,
        "description": "Health Condition Mention"
    },
    "medication": {
        "pattern": r"(?i)\b(prescription|medication|dosage|mg|ml|tablets?|capsules?)\s+\w+",
        "category": DataCategory.PHI,
        "severity": Severity.MEDIUM,
        "description": "Medication Information"
    },
    "insurance_id": {
        "pattern": r"\b(?:Insurance|Policy|Member)[:\s#]*[A-Z0-9]{8,15}\b",
        "category": DataCategory.PHI,
        "severity": Severity.HIGH,
        "description": "Insurance/Policy ID"
    }
}

# Credential Patterns
CREDENTIAL_PATTERNS = {
    "api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}['\"]?",
        "category": DataCategory.CREDENTIALS,
        "severity": Severity.CRITICAL,
        "description": "API Key"
    },
    "password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
        "category": DataCategory.CREDENTIALS,
        "severity": Severity.CRITICAL,
        "description": "Password"
    },
    "aws_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "category": DataCategory.CREDENTIALS,
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]+-[A-Za-z0-9]+",
        "category": DataCategory.CREDENTIALS,
        "severity": Severity.CRITICAL,
        "description": "Slack Token"
    }
}


class ComplianceScanner:
    """Scans messages for compliance violations."""
    
    def __init__(self, frameworks: list[str] = None):
        """
        Initialize scanner with compliance frameworks.
        
        Args:
            frameworks: List of frameworks to enable ['gdpr', 'hipaa', 'pci', 'soc2']
        """
        self.frameworks = frameworks or ['gdpr', 'hipaa', 'pci', 'soc2']
        self.patterns = {}
        
        # Load patterns based on frameworks
        if 'gdpr' in self.frameworks or 'soc2' in self.frameworks:
            self.patterns.update(PII_PATTERNS)
            
        if 'hipaa' in self.frameworks:
            self.patterns.update(PHI_PATTERNS)
            
        if 'pci' in self.frameworks:
            # PCI-DSS specific (credit cards already in PII)
            pass
            
        # Always include credentials
        self.patterns.update(CREDENTIAL_PATTERNS)
        
        # Compile patterns
        self._compiled = {
            name: re.compile(p["pattern"])
            for name, p in self.patterns.items()
        }
    
    def scan(self, message: str) -> list[Detection]:
        """Scan a message for compliance violations."""
        detections = []
        
        for name, pattern in self._compiled.items():
            for match in pattern.finditer(message):
                # Skip if it looks like a test/example
                if self._is_test_data(match.group()):
                    continue
                    
                detections.append(Detection(
                    pattern_name=name,
                    category=self.patterns[name]["category"],
                    severity=self.patterns[name]["severity"],
                    matched_text=self._mask(match.group()),
                    start_pos=match.start(),
                    end_pos=match.end()
                ))
        
        return detections
    
    def _is_test_data(self, text: str) -> bool:
        """Check if detected text is likely test/example data."""
        test_indicators = ['example', 'test', 'fake', 'xxx', '123456789', '000-00-0000']
        text_lower = text.lower()
        return any(ind in text_lower for ind in test_indicators)
    
    def _mask(self, text: str) -> str:
        """Mask sensitive data for logging."""
        if len(text) <= 4:
            return '*' * len(text)
        return text[:2] + '*' * (len(text) - 4) + text[-2:]
    
    def validate_credit_card(self, number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
            
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0


class AuditLogger:
    """Compliance audit logging with tamper-evident records."""
    
    def __init__(self):
        self.entries: list[dict] = []
    
    def log(self, scan_result: ScanResult) -> str:
        """Log a scan result and return audit ID."""
        audit_id = f"CMP-{datetime.now().strftime('%Y%m%d')}-{len(self.entries):05d}"
        
        entry = {
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_id": scan_result.message_id,
            "channel_id": scan_result.channel_id,
            "user_id": scan_result.user_id,
            "detections": [
                {
                    "pattern": d.pattern_name,
                    "category": d.category.value,
                    "severity": d.severity.value,
                    "masked_text": d.matched_text
                }
                for d in scan_result.detections
            ],
            "action": scan_result.action_taken.value if scan_result.action_taken else None,
            "blocked": scan_result.blocked,
            "hash": None
        }
        
        # Tamper-evident hash
        entry["hash"] = hashlib.sha256(
            f"{entry['timestamp']}{entry['message_id']}{entry['action']}".encode()
        ).hexdigest()[:16]
        
        self.entries.append(entry)
        return audit_id
    
    def get_report(self, days: int = 30) -> dict:
        """Generate compliance report."""
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
        recent = [e for e in self.entries 
                  if datetime.fromisoformat(e["timestamp"]).timestamp() > cutoff]
        
        return {
            "period_days": days,
            "total_scanned": len(recent),
            "detections_by_category": self._count_by_category(recent),
            "detections_by_severity": self._count_by_severity(recent),
            "blocked_count": sum(1 for e in recent if e["blocked"]),
            "compliance_rate": self._calc_compliance_rate(recent)
        }
    
    def _count_by_category(self, entries: list) -> dict:
        counts = {}
        for e in entries:
            for d in e.get("detections", []):
                cat = d["category"]
                counts[cat] = counts.get(cat, 0) + 1
        return counts
    
    def _count_by_severity(self, entries: list) -> dict:
        counts = {}
        for e in entries:
            for d in e.get("detections", []):
                sev = d["severity"]
                counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _calc_compliance_rate(self, entries: list) -> float:
        if not entries:
            return 100.0
        blocked = sum(1 for e in entries if e["blocked"])
        return round((1 - blocked / len(entries)) * 100, 2)


class SlackComplianceMonitor:
    """
    Real-time Slack compliance monitoring with Agent OS governance.
    
    Features:
    - PII/PHI/Financial data detection
    - Real-time message blocking (SIGKILL)
    - Comprehensive audit logging
    - Multi-framework compliance (GDPR, HIPAA, SOC 2, PCI-DSS)
    """
    
    def __init__(self, frameworks: list[str] = None):
        self.scanner = ComplianceScanner(frameworks)
        self.audit = AuditLogger()
        
        # Initialize Agent OS if available
        if AGENT_OS_AVAILABLE:
            self.kernel = Kernel()
            self.dispatcher = Dispatcher()
            self.kernel.load_policy(Policy.from_yaml(self._get_policy_yaml()))
        else:
            self.kernel = None
            self.dispatcher = None
    
    def _get_policy_yaml(self) -> str:
        return """
version: "1.0"
name: slack-compliance-policy

rules:
  - name: block-critical-pii
    trigger: detection
    condition:
      severity: critical
    action: block
    signal: SIGKILL
    
  - name: alert-high-severity
    trigger: detection
    condition:
      severity: high
    action: alert
    notify: compliance-team
    
  - name: log-all-detections
    trigger: detection
    action: log
    format: compliance_audit
"""
    
    def process_message(self, message_id: str, channel_id: str, 
                       user_id: str, content: str) -> ScanResult:
        """
        Process a Slack message for compliance.
        
        Returns ScanResult with any detections and actions taken.
        """
        result = ScanResult(
            message_id=message_id,
            channel_id=channel_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Scan the message
        detections = self.scanner.scan(content)
        result.detections = detections
        
        if not detections:
            result.action_taken = Action.LOG
            return result
        
        # Determine action based on highest severity
        max_severity = max(d.severity for d in detections)
        
        if max_severity == Severity.CRITICAL:
            result.action_taken = Action.BLOCK
            result.blocked = True
            
            # Send SIGKILL via Agent OS if available
            if self.dispatcher:
                self.dispatcher.signal("slack-message", "SIGKILL")
                
        elif max_severity == Severity.HIGH:
            result.action_taken = Action.ALERT
            
        elif max_severity == Severity.MEDIUM:
            result.action_taken = Action.ALERT
            
        else:
            result.action_taken = Action.LOG
        
        # Log for audit
        result.audit_id = self.audit.log(result)
        
        return result
    
    def redact_message(self, content: str, detections: list[Detection]) -> str:
        """Redact detected sensitive data from a message."""
        # Sort detections by position (reverse) to maintain positions while replacing
        sorted_detections = sorted(detections, key=lambda d: d.start_pos, reverse=True)
        
        result = content
        for detection in sorted_detections:
            redacted = f"[REDACTED-{detection.category.value.upper()}]"
            result = result[:detection.start_pos] + redacted + result[detection.end_pos:]
        
        return result
    
    def format_alert(self, result: ScanResult) -> str:
        """Format a compliance alert for notification."""
        lines = [
            "🚨 **Compliance Alert**",
            "━" * 40,
            f"**Channel:** <#{result.channel_id}>",
            f"**User:** <@{result.user_id}>",
            f"**Time:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "**Detected:**"
        ]
        
        for d in result.detections:
            severity_emoji = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵"
            }[d.severity]
            lines.append(f"  {severity_emoji} {d.pattern_name} ({d.severity.value})")
        
        lines.extend([
            "",
            f"**Action:** {result.action_taken.value.upper() if result.action_taken else 'None'}",
            f"**Audit ID:** {result.audit_id}",
            "━" * 40
        ])
        
        return "\n".join(lines)
    
    def get_compliance_report(self, days: int = 30) -> str:
        """Generate a formatted compliance report."""
        report = self.audit.get_report(days)
        
        lines = [
            f"📊 **Compliance Dashboard** (Last {days} Days)",
            "━" * 40,
            f"Messages Scanned:    {report['total_scanned']:,}",
        ]
        
        for cat, count in report['detections_by_category'].items():
            emoji = {"pii": "🔐", "phi": "🏥", "financial": "💳", "credentials": "🔑"}.get(cat, "📌")
            lines.append(f"{cat.upper()} Detected:       {count:,}  {emoji}")
        
        lines.extend([
            f"Messages Blocked:    {report['blocked_count']:,}  🚫",
            f"Compliance Rate:     {report['compliance_rate']}%  {'✅' if report['compliance_rate'] > 99 else '⚠️'}",
            "━" * 40
        ])
        
        return "\n".join(lines)


def demo():
    """Demonstrate the Slack Compliance Monitor."""
    print("=" * 60)
    print("Slack Compliance Monitor - Agent OS Demo")
    print("=" * 60)
    
    monitor = SlackComplianceMonitor(frameworks=['gdpr', 'hipaa', 'pci', 'soc2'])
    
    # Test messages
    test_messages = [
        {
            "id": "msg-001",
            "channel": "C12345",
            "user": "U67890",
            "content": "Here's the customer SSN: 123-45-6789 for the refund"
        },
        {
            "id": "msg-002",
            "channel": "C12345",
            "user": "U67890",
            "content": "Credit card: 4111-1111-1111-1111 expires 12/25"
        },
        {
            "id": "msg-003",
            "channel": "C12345",
            "user": "U67890",
            "content": "Patient MRN: 12345678, diagnosed with diabetes"
        },
        {
            "id": "msg-004",
            "channel": "C12345",
            "user": "U67890",
            "content": "API_KEY=<set-via-environment-variable>"
        },
        {
            "id": "msg-005",
            "channel": "C12345",
            "user": "U67890",
            "content": "Let's schedule a meeting for tomorrow at 3pm."
        }
    ]
    
    print("\n📨 Processing messages...\n")
    
    for msg in test_messages:
        print(f"Message: \"{msg['content'][:50]}...\"")
        
        result = monitor.process_message(
            message_id=msg["id"],
            channel_id=msg["channel"],
            user_id=msg["user"],
            content=msg["content"]
        )
        
        if result.detections:
            action_emoji = {
                Action.BLOCK: "🚫 BLOCKED",
                Action.ALERT: "⚠️ ALERTED",
                Action.LOG: "📝 LOGGED"
            }[result.action_taken]
            
            print(f"  Status: {action_emoji}")
            for d in result.detections:
                print(f"    - {d.pattern_name}: {d.matched_text}")
            if result.blocked:
                print(f"  Redacted: {monitor.redact_message(msg['content'], result.detections)}")
        else:
            print("  Status: ✅ CLEAN")
        
        print()
    
    print("=" * 60)
    print(monitor.get_compliance_report(days=1))
    print("=" * 60)


if __name__ == "__main__":
    demo()

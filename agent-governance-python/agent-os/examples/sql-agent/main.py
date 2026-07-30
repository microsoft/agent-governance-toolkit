# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
SQL Agent with Financial Controls and Agent OS Governance
==========================================================

AI-powered natural language to SQL agent with:
- Cost controls (prevent runaway queries)
- Dangerous query prevention (DROP, DELETE, TRUNCATE)
- Multi-model verification (CMVK)
- Full audit trail

Saves money and prevents disasters.
"""

import re
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
from enum import Enum

# Agent OS imports
try:
    from agent_os import Kernel, Policy
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False


class QueryRisk(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QueryAction(Enum):
    EXECUTE = "execute"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    COST_EXCEEDED = "cost_exceeded"


@dataclass
class CostEstimate:
    """Estimated cost of a query."""
    estimated_rows: int
    estimated_time_ms: int
    estimated_cost_usd: float
    explanation: str


@dataclass
class Verification:
    """Multi-model verification result."""
    models_used: list[str]
    models_agreed: int
    consensus_score: float
    sql_variants: list[str]
    selected_sql: str


@dataclass 
class QueryResult:
    """Result of a SQL query attempt."""
    query_id: str
    natural_language: str
    generated_sql: Optional[str] = None
    action: QueryAction = QueryAction.EXECUTE
    risk_level: QueryRisk = QueryRisk.SAFE
    
    # Cost information
    cost_estimate: Optional[CostEstimate] = None
    actual_cost_usd: float = 0.0
    
    # Execution results
    data: Optional[list[dict]] = None
    rows_returned: int = 0
    execution_time_ms: int = 0
    
    # Blocking/approval
    blocked: bool = False
    block_reason: Optional[str] = None
    requires_approval: bool = False
    approval_token: Optional[str] = None
    
    # Verification
    verification: Optional[Verification] = None
    
    # Audit
    audit_id: Optional[str] = None


# Dangerous SQL patterns
DANGEROUS_PATTERNS = {
    "drop_table": {
        "pattern": r"(?i)\bDROP\s+TABLE\b",
        "risk": QueryRisk.CRITICAL,
        "action": QueryAction.BLOCK,
        "message": "DROP TABLE is not allowed"
    },
    "drop_database": {
        "pattern": r"(?i)\bDROP\s+DATABASE\b",
        "risk": QueryRisk.CRITICAL,
        "action": QueryAction.BLOCK,
        "message": "DROP DATABASE is not allowed"
    },
    "truncate": {
        "pattern": r"(?i)\bTRUNCATE\b",
        "risk": QueryRisk.HIGH,
        "action": QueryAction.REQUIRE_APPROVAL,
        "message": "TRUNCATE requires approval"
    },
    "delete_no_where": {
        "pattern": r"(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)",
        "risk": QueryRisk.CRITICAL,
        "action": QueryAction.BLOCK,
        "message": "DELETE without WHERE clause is not allowed"
    },
    "delete_with_where": {
        "pattern": r"(?i)\bDELETE\s+FROM\s+\w+\s+WHERE\b",
        "risk": QueryRisk.MEDIUM,
        "action": QueryAction.REQUIRE_APPROVAL,
        "message": "DELETE requires approval"
    },
    "update_no_where": {
        "pattern": r"(?i)\bUPDATE\s+\w+\s+SET\s+[^;]+(?:;|$)(?!\s*WHERE)",
        "risk": QueryRisk.CRITICAL,
        "action": QueryAction.BLOCK,
        "message": "UPDATE without WHERE clause is not allowed"
    },
    "alter_table": {
        "pattern": r"(?i)\bALTER\s+TABLE\b",
        "risk": QueryRisk.MEDIUM,
        "action": QueryAction.REQUIRE_APPROVAL,
        "message": "ALTER TABLE requires approval"
    },
    "grant_permissions": {
        "pattern": r"(?i)\bGRANT\b",
        "risk": QueryRisk.HIGH,
        "action": QueryAction.BLOCK,
        "message": "GRANT is not allowed through this interface"
    },
    "create_user": {
        "pattern": r"(?i)\bCREATE\s+(USER|ROLE)\b",
        "risk": QueryRisk.CRITICAL,
        "action": QueryAction.BLOCK,
        "message": "User management is not allowed through this interface"
    }
}

# Sample NL to SQL templates (in production, use actual LLM)
NL_TO_SQL_TEMPLATES = {
    r"(?i)show\s+(?:me\s+)?(?:the\s+)?top\s+(\d+)\s+customers?\s+by\s+revenue": 
        "SELECT name, email, revenue FROM customers ORDER BY revenue DESC LIMIT {0}",
    r"(?i)(?:get|show|list)\s+all\s+(?:the\s+)?transactions?\s+from\s+(\w+)":
        "SELECT * FROM transactions WHERE EXTRACT(YEAR FROM created_at) = '{0}'",
    r"(?i)total\s+(?:revenue|sales)\s+by\s+(\w+)":
        "SELECT {0}, SUM(amount) as total FROM transactions GROUP BY {0}",
    r"(?i)count\s+(?:of\s+)?(?:all\s+)?(\w+)":
        "SELECT COUNT(*) FROM {0}",
    r"(?i)delete\s+inactive\s+users?\s+from\s+(?:the\s+)?last\s+(\w+)":
        "DELETE FROM users WHERE last_active < NOW() - INTERVAL '{0}'",
    r"(?i)drop\s+(?:the\s+)?(\w+)\s+table":
        "DROP TABLE {0}",
}


class QueryAnalyzer:
    """Analyzes SQL queries for risk and cost."""
    
    def __init__(self):
        self.patterns = {
            name: re.compile(p["pattern"])
            for name, p in DANGEROUS_PATTERNS.items()
        }
    
    def analyze_risk(self, sql: str) -> tuple[QueryRisk, QueryAction, Optional[str]]:
        """Analyze query for dangerous patterns."""
        highest_risk = QueryRisk.SAFE
        action = QueryAction.EXECUTE
        message = None
        
        for name, pattern in self.patterns.items():
            if pattern.search(sql):
                pattern_info = DANGEROUS_PATTERNS[name]
                if self._risk_level(pattern_info["risk"]) > self._risk_level(highest_risk):
                    highest_risk = pattern_info["risk"]
                    action = pattern_info["action"]
                    message = pattern_info["message"]
        
        return highest_risk, action, message
    
    def _risk_level(self, risk: QueryRisk) -> int:
        """Convert risk to numeric level for comparison."""
        levels = {
            QueryRisk.SAFE: 0,
            QueryRisk.LOW: 1,
            QueryRisk.MEDIUM: 2,
            QueryRisk.HIGH: 3,
            QueryRisk.CRITICAL: 4
        }
        return levels.get(risk, 0)
    
    def estimate_cost(self, sql: str, table_stats: dict = None) -> CostEstimate:
        """Estimate query cost based on EXPLAIN and statistics."""
        # Simplified cost estimation (in production, use actual EXPLAIN)
        table_stats = table_stats or {
            "customers": 10000,
            "transactions": 1000000,
            "users": 50000,
            "orders": 500000
        }
        
        # Extract table name
        table_match = re.search(r"(?i)FROM\s+(\w+)", sql)
        table_name = table_match.group(1).lower() if table_match else "unknown"
        
        # Estimate rows
        base_rows = table_stats.get(table_name, 10000)
        
        # Check for WHERE clause (reduces rows)
        if re.search(r"(?i)\bWHERE\b", sql):
            estimated_rows = base_rows // 10  # Assume 10% selectivity
        else:
            estimated_rows = base_rows
        
        # Check for LIMIT
        limit_match = re.search(r"(?i)LIMIT\s+(\d+)", sql)
        if limit_match:
            estimated_rows = min(estimated_rows, int(limit_match.group(1)))
        
        # Estimate time (simplified: 1ms per 100 rows)
        estimated_time_ms = max(10, estimated_rows // 100)
        
        # Estimate cost (simplified: $0.001 per 1000 rows)
        estimated_cost_usd = estimated_rows / 1000 * 0.001
        
        return CostEstimate(
            estimated_rows=estimated_rows,
            estimated_time_ms=estimated_time_ms,
            estimated_cost_usd=round(estimated_cost_usd, 4),
            explanation=f"Estimated {estimated_rows:,} rows from {table_name}"
        )


class NLToSQL:
    """Convert natural language to SQL."""
    
    def convert(self, nl_query: str) -> Optional[str]:
        """Convert natural language to SQL using templates or LLM."""
        # Try template matching first
        for pattern, template in NL_TO_SQL_TEMPLATES.items():
            match = re.match(pattern, nl_query)
            if match:
                groups = match.groups()
                sql = template
                for i, g in enumerate(groups):
                    sql = sql.replace(f"{{{i}}}", str(g))
                return sql
        
        # In production, call actual LLM here
        # For demo, return None if no template matches
        return None


class AuditLogger:
    """SQL query audit logging."""
    
    def __init__(self):
        self.entries: list[dict] = []
    
    def log(self, result: QueryResult, user_id: str = "anonymous") -> str:
        """Log a query result."""
        audit_id = f"QRY-{datetime.now().strftime('%Y%m%d')}-{len(self.entries):05d}"
        
        entry = {
            "audit_id": audit_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query_id": result.query_id,
            "user_id": user_id,
            "natural_language": result.natural_language,
            "generated_sql": result.generated_sql,
            "risk_level": result.risk_level.value,
            "action": result.action.value,
            "estimated_cost_usd": result.cost_estimate.estimated_cost_usd if result.cost_estimate else None,
            "actual_cost_usd": result.actual_cost_usd,
            "rows_returned": result.rows_returned,
            "execution_time_ms": result.execution_time_ms,
            "blocked": result.blocked,
            "block_reason": result.block_reason,
            "verification": {
                "models": result.verification.models_used,
                "consensus": result.verification.consensus_score
            } if result.verification else None
        }
        
        self.entries.append(entry)
        return audit_id
    
    def get_stats(self, days: int = 7) -> dict:
        """Get query statistics."""
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
        recent = [e for e in self.entries 
                  if datetime.fromisoformat(e["timestamp"]).timestamp() > cutoff]
        
        return {
            "total_queries": len(recent),
            "total_cost_usd": sum(e.get("actual_cost_usd", 0) for e in recent),
            "blocked_count": sum(1 for e in recent if e["blocked"]),
            "approval_count": sum(1 for e in recent if e["action"] == "require_approval"),
            "avg_execution_time_ms": (
                sum(e.get("execution_time_ms", 0) for e in recent) / len(recent)
                if recent else 0
            )
        }


class SQLAgent:
    """
    AI-powered SQL agent with financial controls and governance.
    
    Features:
    - Natural language to SQL conversion
    - Cost controls and estimation
    - Dangerous query prevention
    - Multi-model verification (CMVK)
    - Full audit trail
    """
    
    def __init__(
        self,
        max_cost_usd: float = 100.0,
        max_rows: int = 100000,
        max_execution_time_ms: int = 30000,
        require_approval_for: list[str] = None
    ):
        self.max_cost_usd = max_cost_usd
        self.max_rows = max_rows
        self.max_execution_time_ms = max_execution_time_ms
        self.require_approval_for = require_approval_for or ["DELETE", "DROP", "TRUNCATE"]
        
        self.nl_to_sql = NLToSQL()
        self.analyzer = QueryAnalyzer()
        self.audit = AuditLogger()
        self.pending_approvals: dict[str, QueryResult] = {}
        
        # Initialize Agent OS if available
        if AGENT_OS_AVAILABLE:
            self.kernel = Kernel()
            self.kernel.load_policy(Policy.from_yaml(self._get_policy_yaml()))
        else:
            self.kernel = None
    
    def _get_policy_yaml(self) -> str:
        return f"""
version: "1.0"
name: sql-agent-policy

limits:
  max_cost_usd: {self.max_cost_usd}
  max_rows: {self.max_rows}
  max_execution_time_ms: {self.max_execution_time_ms}

rules:
  - name: block-dangerous
    trigger: query
    condition:
      risk: critical
    action: block
    
  - name: require-approval
    trigger: query
    condition:
      risk: [medium, high]
    action: require_approval
    
  - name: cost-limit
    trigger: query
    condition:
      cost_exceeds: {self.max_cost_usd}
    action: block
    message: "Query exceeds cost limit"
"""
    
    async def query(self, natural_language: str, user_id: str = "anonymous") -> QueryResult:
        """
        Process a natural language query.
        
        Args:
            natural_language: The query in plain English
            user_id: User making the query (for audit)
            
        Returns:
            QueryResult with status, data, or approval requirements
        """
        result = QueryResult(
            query_id=str(uuid.uuid4())[:8],
            natural_language=natural_language
        )
        
        # Step 1: Convert NL to SQL
        sql = self.nl_to_sql.convert(natural_language)
        if not sql:
            result.blocked = True
            result.block_reason = "Could not convert natural language to SQL"
            result.action = QueryAction.BLOCK
            result.audit_id = self.audit.log(result, user_id)
            return result
        
        result.generated_sql = sql
        
        # Step 2: Analyze risk
        risk, action, message = self.analyzer.analyze_risk(sql)
        result.risk_level = risk
        result.action = action
        
        if action == QueryAction.BLOCK:
            result.blocked = True
            result.block_reason = message
            result.audit_id = self.audit.log(result, user_id)
            return result
        
        # Step 3: Estimate cost
        cost_estimate = self.analyzer.estimate_cost(sql)
        result.cost_estimate = cost_estimate
        
        if cost_estimate.estimated_cost_usd > self.max_cost_usd:
            result.blocked = True
            result.block_reason = f"Estimated cost ${cost_estimate.estimated_cost_usd:.2f} exceeds limit ${self.max_cost_usd:.2f}"
            result.action = QueryAction.COST_EXCEEDED
            result.audit_id = self.audit.log(result, user_id)
            return result
        
        if cost_estimate.estimated_rows > self.max_rows:
            result.blocked = True
            result.block_reason = f"Estimated {cost_estimate.estimated_rows:,} rows exceeds limit {self.max_rows:,}"
            result.action = QueryAction.COST_EXCEEDED
            result.audit_id = self.audit.log(result, user_id)
            return result
        
        # Step 4: Check if approval required
        if action == QueryAction.REQUIRE_APPROVAL:
            result.requires_approval = True
            result.approval_token = str(uuid.uuid4())
            self.pending_approvals[result.approval_token] = result
            result.audit_id = self.audit.log(result, user_id)
            return result
        
        # Step 5: Execute query (simulated)
        result = await self._execute_query(result)
        result.audit_id = self.audit.log(result, user_id)
        
        return result
    
    async def execute_approved(self, approval_token: str, approver_id: str = "admin") -> QueryResult:
        """Execute a query that was pending approval."""
        if approval_token not in self.pending_approvals:
            result = QueryResult(
                query_id="invalid",
                natural_language="",
                blocked=True,
                block_reason="Invalid or expired approval token"
            )
            return result
        
        result = self.pending_approvals.pop(approval_token)
        result.requires_approval = False
        result.approval_token = None
        
        # Execute the approved query
        result = await self._execute_query(result)
        result.audit_id = self.audit.log(result, approver_id)
        
        return result
    
    async def _execute_query(self, result: QueryResult) -> QueryResult:
        """Execute the SQL query (simulated for demo)."""
        import time
        
        # Simulate execution
        start_time = time.time()
        
        # Simulated data based on query type
        if "SELECT" in result.generated_sql.upper():
            # Return mock data
            if "customers" in result.generated_sql.lower():
                result.data = [
                    {"name": "Acme Corp", "email": "acme@example.com", "revenue": 150000},
                    {"name": "TechStart", "email": "tech@example.com", "revenue": 125000},
                    {"name": "DataCo", "email": "data@example.com", "revenue": 98000},
                ]
                result.rows_returned = len(result.data)
            elif "COUNT" in result.generated_sql.upper():
                result.data = [{"count": 10547}]
                result.rows_returned = 1
            else:
                result.data = []
                result.rows_returned = 0
        
        result.execution_time_ms = int((time.time() - start_time) * 1000) + 45  # Add simulated DB time
        result.actual_cost_usd = result.cost_estimate.estimated_cost_usd if result.cost_estimate else 0.01
        result.action = QueryAction.EXECUTE
        
        return result
    
    def format_result(self, result: QueryResult) -> str:
        """Format query result for display."""
        lines = []
        
        if result.blocked:
            lines.append(f"🚫 **Query Blocked**")
            lines.append(f"Reason: {result.block_reason}")
            if result.generated_sql:
                lines.append(f"SQL: `{result.generated_sql}`")
                
        elif result.requires_approval:
            lines.append(f"⏳ **Approval Required**")
            lines.append(f"Risk Level: {result.risk_level.value.upper()}")
            lines.append(f"SQL: `{result.generated_sql}`")
            if result.cost_estimate:
                lines.append(f"Estimated Rows: {result.cost_estimate.estimated_rows:,}")
                lines.append(f"Estimated Cost: ${result.cost_estimate.estimated_cost_usd:.4f}")
            lines.append(f"Approval Token: `{result.approval_token}`")
            
        else:
            lines.append(f"✅ **Query Executed**")
            lines.append(f"SQL: `{result.generated_sql}`")
            lines.append(f"Rows: {result.rows_returned:,}")
            lines.append(f"Time: {result.execution_time_ms}ms")
            lines.append(f"Cost: ${result.actual_cost_usd:.4f}")
            
            if result.data:
                lines.append("\n**Results:**")
                for row in result.data[:5]:  # Show first 5
                    lines.append(f"  {row}")
                if result.rows_returned > 5:
                    lines.append(f"  ... and {result.rows_returned - 5} more rows")
        
        lines.append(f"\nAudit ID: {result.audit_id}")
        
        return "\n".join(lines)
    
    def get_dashboard(self, days: int = 7) -> str:
        """Get formatted dashboard stats."""
        stats = self.audit.get_stats(days)
        
        return f"""
📊 **SQL Agent Dashboard** (Last {days} Days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Queries Executed:    {stats['total_queries']:,}
Total Cost:          ${stats['total_cost_usd']:.2f}
Queries Blocked:     {stats['blocked_count']:,}  🚫
Approvals Required:  {stats['approval_count']:,}  ⏳
Avg Response Time:   {stats['avg_execution_time_ms']:.0f}ms  ⚡
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Budget: ${self.max_cost_usd:.2f} | Max Rows: {self.max_rows:,}
"""


def demo():
    """Demonstrate the SQL Agent."""
    import asyncio
    
    print("=" * 60)
    print("SQL Agent with Financial Controls - Agent OS Demo")
    print("=" * 60)
    
    async def run_demo():
        agent = SQLAgent(
            max_cost_usd=50.0,
            max_rows=50000,
            max_execution_time_ms=30000
        )
        
        test_queries = [
            "Show me top 10 customers by revenue",
            "Count all users",
            "Delete inactive users from last year",
            "Drop the users table",
            "Total revenue by region",
        ]
        
        for nl_query in test_queries:
            print(f"\n{'─' * 60}")
            print(f"📝 Query: \"{nl_query}\"")
            print('─' * 60)
            
            result = await agent.query(nl_query, user_id="analyst_jane")
            print(agent.format_result(result))
        
        print("\n" + "=" * 60)
        print(agent.get_dashboard(days=1))
        print("=" * 60)
    
    asyncio.run(run_demo())


if __name__ == "__main__":
    demo()

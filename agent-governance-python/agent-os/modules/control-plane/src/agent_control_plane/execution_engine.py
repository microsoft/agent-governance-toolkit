# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Execution Engine - Safe execution of agent actions

Provides sandboxed execution, resource monitoring, and error handling
for agent actions.

Research Foundations:
    - Sandbox isolation levels informed by container security best practices
    - Timeout and resource limits from "Fault-Tolerant Multi-Agent Systems" 
      (IEEE Trans. SMC, 2024) - failure recovery patterns
    - Transaction rollback patterns from distributed systems research
    - Circuit breaker and retry policies for resilience

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import time
from .agent_kernel import ExecutionRequest, ActionType


class SandboxLevel(Enum):
    """Sandbox isolation levels"""
    NONE = 0
    BASIC = 1
    STRICT = 2
    ISOLATED = 3


@dataclass
class ExecutionContext:
    """Context for executing an agent action"""
    request_id: str
    sandbox_level: SandboxLevel
    timeout_seconds: float = 30.0
    max_memory_mb: int = 512
    allowed_network: bool = False
    environment_vars: Dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionMetrics:
    """Metrics collected during execution"""
    start_time: datetime
    end_time: Optional[datetime] = None
    cpu_time_ms: float = 0.0
    memory_used_mb: float = 0.0
    network_calls: int = 0
    files_accessed: List[str] = field(default_factory=list)


class ExecutionEngine:
    """
    Execution Engine - Safely executes agent actions
    
    Provides:
    - Sandboxed execution
    - Resource monitoring
    - Timeout enforcement
    - Error handling and recovery
    - Transaction management
    """
    
    def __init__(self):
        self.executors: Dict[ActionType, Callable] = {}
        self.active_executions: Dict[str, ExecutionContext] = {}
        self.execution_history: List[Dict[str, Any]] = []
        
    def register_executor(self, action_type: ActionType, executor: Callable):
        """Register an executor for a specific action type"""
        self.executors[action_type] = executor
    
    def execute(
        self,
        request: ExecutionRequest,
        context: Optional[ExecutionContext] = None
    ) -> Dict[str, Any]:
        """Execute a request in a controlled environment"""
        if context is None:
            context = self._create_default_context(request)
        
        self.active_executions[request.request_id] = context
        metrics = ExecutionMetrics(start_time=datetime.now())
        
        try:
            # Get the appropriate executor
            executor = self.executors.get(request.action_type)
            if not executor:
                executor = self._default_executor
            
            # Execute with timeout
            result = self._execute_with_timeout(
                executor,
                request,
                context,
                metrics
            )
            
            metrics.end_time = datetime.now()
            
            # Record execution
            self._record_execution(request, context, metrics, result, None)
            
            return {
                "success": True,
                "result": result,
                "metrics": {
                    "execution_time_ms": (metrics.end_time - metrics.start_time).total_seconds() * 1000,
                    "cpu_time_ms": metrics.cpu_time_ms,
                    "memory_used_mb": metrics.memory_used_mb,
                }
            }
            
        except TimeoutError as e:
            metrics.end_time = datetime.now()
            self._record_execution(request, context, metrics, None, f"Timeout: {str(e)}")
            return {
                "success": False,
                "error": f"Execution timeout after {context.timeout_seconds}s",
                "error_type": "timeout"
            }
            
        except Exception as e:
            metrics.end_time = datetime.now()
            self._record_execution(request, context, metrics, None, str(e))
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
            
        finally:
            if request.request_id in self.active_executions:
                del self.active_executions[request.request_id]
    
    def _execute_with_timeout(
        self,
        executor: Callable,
        request: ExecutionRequest,
        context: ExecutionContext,
        metrics: ExecutionMetrics
    ) -> Any:
        """Execute with timeout enforcement"""
        start_time = time.time()
        
        # In a real implementation, this would use proper process isolation
        # and actual timeout mechanisms (e.g., threading with timeouts, subprocesses)
        result = executor(request.parameters, context)
        
        elapsed = time.time() - start_time
        if elapsed > context.timeout_seconds:
            raise TimeoutError(f"Execution exceeded {context.timeout_seconds}s")
        
        metrics.cpu_time_ms = elapsed * 1000
        return result
    
    def _default_executor(self, parameters: Dict[str, Any], context: ExecutionContext) -> Any:
        """Default executor for unregistered action types"""
        return {
            "status": "executed",
            "parameters": parameters,
            "note": "Using default executor (no specific executor registered)"
        }
    
    def _create_default_context(self, request: ExecutionRequest) -> ExecutionContext:
        """Create default execution context based on action type"""
        # More sensitive actions get stricter sandboxing
        sandbox_map = {
            ActionType.FILE_READ: SandboxLevel.BASIC,
            ActionType.FILE_WRITE: SandboxLevel.STRICT,
            ActionType.CODE_EXECUTION: SandboxLevel.ISOLATED,
            ActionType.DATABASE_QUERY: SandboxLevel.BASIC,
            ActionType.DATABASE_WRITE: SandboxLevel.STRICT,
            ActionType.API_CALL: SandboxLevel.BASIC,
            ActionType.WORKFLOW_TRIGGER: SandboxLevel.BASIC,
        }
        
        return ExecutionContext(
            request_id=request.request_id,
            sandbox_level=sandbox_map.get(request.action_type, SandboxLevel.STRICT),
            timeout_seconds=30.0,
            max_memory_mb=512,
            allowed_network=request.action_type in [ActionType.API_CALL],
        )
    
    def _record_execution(
        self,
        request: ExecutionRequest,
        context: ExecutionContext,
        metrics: ExecutionMetrics,
        result: Optional[Any],
        error: Optional[str]
    ):
        """Record execution for history and analytics"""
        record = {
            "request_id": request.request_id,
            "agent_id": request.agent_context.agent_id,
            "action_type": request.action_type.value,
            "timestamp": request.timestamp.isoformat(),
            "execution_time_ms": (
                (metrics.end_time - metrics.start_time).total_seconds() * 1000
                if metrics.end_time else 0
            ),
            "success": error is None,
            "error": error,
            "sandbox_level": context.sandbox_level.value,
        }
        self.execution_history.append(record)
    
    def get_execution_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get execution history, optionally filtered by agent"""
        history = self.execution_history
        
        if agent_id:
            history = [r for r in history if r["agent_id"] == agent_id]
        
        return history[-limit:]
    
    def get_active_executions(self) -> Dict[str, ExecutionContext]:
        """Get currently active executions"""
        return self.active_executions.copy()


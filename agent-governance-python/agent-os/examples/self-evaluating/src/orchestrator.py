# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Orchestration Layer - Deterministic State Machine

This module implements the "Glue" between probabilistic AI workers.
The orchestrator is NOT a fuzzy AI trying to figure things out.
It's a DETERMINISTIC STATE MACHINE that manages the flow of data 
between probabilistic workers.

Key Principles:
1. The Router (Hub & Spoke): Workers never talk to each other directly
2. The Transformer Middleware: Manages data flow between states
3. The Brain (AI) is probabilistic, but the Skeleton (Orchestrator) is deterministic

Architecture:
- State Machine: Rigid, deterministic workflow definition
- Hub: Central router that dispatches work to workers
- Workers: Probabilistic AI agents (Product Manager, Coder, Reviewer, etc.)
- Transformer: Middleware that transforms outputs between workers
"""

from typing import Dict, List, Any, Optional, Callable, Tuple
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
import json


class WorkflowState(Enum):
    """Deterministic workflow states."""
    INITIALIZED = "initialized"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class WorkerType(Enum):
    """Types of workers in the system."""
    PRODUCT_MANAGER = "product_manager"
    CODER = "coder"
    REVIEWER = "reviewer"
    TESTER = "tester"
    DEPLOYER = "deployer"
    GENERIC = "generic"


@dataclass
class WorkflowContext:
    """
    Shared context that flows through the workflow.
    This is the "data bus" between workers.
    """
    workflow_id: str
    goal: str
    state: WorkflowState
    current_step: str
    data: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_history(self, worker_type: str, input_data: Any, output_data: Any) -> None:
        """Add a step to the workflow history."""
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "worker_type": worker_type,
            "step": self.current_step,
            "input": input_data,
            "output": output_data
        })
    
    def get_last_output(self, worker_type: Optional[str] = None) -> Any:
        """Get the last output, optionally filtered by worker type."""
        if not self.history:
            return None
        
        if worker_type:
            for entry in reversed(self.history):
                if entry["worker_type"] == worker_type:
                    return entry["output"]
            return None
        
        return self.history[-1]["output"]


@dataclass
class WorkerDefinition:
    """
    Definition of a worker in the system.
    Workers are probabilistic AI agents.
    """
    worker_type: WorkerType
    name: str
    description: str
    executor: Callable[[Any, WorkflowContext], Any]
    input_transformer: Optional[Callable[[WorkflowContext], Any]] = None
    output_transformer: Optional[Callable[[Any, WorkflowContext], Any]] = None


@dataclass
class WorkflowStep:
    """
    A single step in the deterministic workflow.
    Each step specifies:
    - Which worker to use
    - What the success criteria are
    - What happens on success/failure
    """
    step_id: str
    worker_type: WorkerType
    description: str
    on_success: Optional[str] = None  # Next step ID on success
    on_failure: Optional[str] = None  # Next step ID on failure
    is_terminal: bool = False  # Is this a terminal state?
    max_retries: int = 0  # Number of retries on failure


class WorkflowDefinition:
    """
    Deterministic workflow definition.
    This is the "skeleton" - rigid and deterministic.
    """
    
    def __init__(self, name: str, description: str, goal: str):
        self.name = name
        self.description = description
        self.goal = goal
        self.steps: Dict[str, WorkflowStep] = {}
        self.initial_step: Optional[str] = None
    
    def add_step(self, step: WorkflowStep, is_initial: bool = False) -> None:
        """Add a step to the workflow."""
        self.steps[step.step_id] = step
        if is_initial:
            self.initial_step = step.step_id
    
    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        """Get a step by ID."""
        return self.steps.get(step_id)
    
    def validate(self) -> Tuple[bool, Optional[str]]:
        """
        Validate the workflow definition.
        Ensures all transitions point to valid steps.
        """
        if not self.initial_step:
            return False, "No initial step defined"
        
        if self.initial_step not in self.steps:
            return False, f"Initial step '{self.initial_step}' not found"
        
        # Check all transitions
        for step_id, step in self.steps.items():
            if step.on_success and step.on_success not in self.steps:
                return False, f"Step '{step_id}' has invalid on_success: '{step.on_success}'"
            if step.on_failure and step.on_failure not in self.steps:
                return False, f"Step '{step_id}' has invalid on_failure: '{step.on_failure}'"
        
        return True, None


class Orchestrator:
    """
    The Hub - Central deterministic orchestrator.
    
    This is the "state machine" that manages the flow between
    probabilistic workers. It's rigid, deterministic code.
    
    Key responsibilities:
    1. Route work to appropriate workers (Hub & Spoke pattern)
    2. Transform data between workers (Transformer Middleware)
    3. Track workflow state
    4. Enforce deterministic flow
    """
    
    def __init__(self):
        self.workers: Dict[WorkerType, WorkerDefinition] = {}
        self.workflows: Dict[str, WorkflowDefinition] = {}
    
    def register_worker(self, worker: WorkerDefinition) -> None:
        """Register a worker in the hub."""
        self.workers[worker.worker_type] = worker
    
    def register_workflow(self, workflow: WorkflowDefinition) -> None:
        """Register a workflow definition."""
        # Validate workflow
        valid, error = workflow.validate()
        if not valid:
            raise ValueError(f"Invalid workflow: {error}")
        
        self.workflows[workflow.name] = workflow
    
    def _transform_input(self, worker: WorkerDefinition, context: WorkflowContext) -> Any:
        """
        Transform input for a worker (Transformer Middleware).
        This is the "secret sauce" that manages data flow.
        """
        if worker.input_transformer:
            return worker.input_transformer(context)
        
        # Default: pass the last output
        return context.get_last_output()
    
    def _transform_output(self, worker: WorkerDefinition, output: Any, context: WorkflowContext) -> Any:
        """
        Transform output from a worker (Transformer Middleware).
        """
        if worker.output_transformer:
            return worker.output_transformer(output, context)
        
        # Default: pass through
        return output
    
    def _execute_step(self, step: WorkflowStep, context: WorkflowContext, 
                     verbose: bool = False) -> Tuple[bool, Any]:
        """
        Execute a single workflow step.
        Returns (success, output) tuple.
        """
        # Get the worker
        worker = self.workers.get(step.worker_type)
        if not worker:
            raise ValueError(f"Worker not found for type: {step.worker_type}")
        
        if verbose:
            print(f"\n[ORCHESTRATOR] Executing Step: {step.step_id}")
            print(f"  Worker: {worker.name}")
            print(f"  Description: {step.description}")
        
        # Transform input (Transformer Middleware)
        input_data = self._transform_input(worker, context)
        
        if verbose:
            print(f"  Input: {str(input_data)[:100]}...")
        
        # Execute worker (Probabilistic AI)
        try:
            output = worker.executor(input_data, context)
            success = True
        except Exception as e:
            if verbose:
                print(f"  ❌ Worker failed: {str(e)}")
            output = {"error": str(e)}
            success = False
        
        # Transform output (Transformer Middleware)
        transformed_output = self._transform_output(worker, output, context)
        
        if verbose:
            status = "✓" if success else "✗"
            print(f"  {status} Output: {str(transformed_output)[:100]}...")
        
        # Record in history
        context.add_history(
            worker_type=worker.worker_type.value,
            input_data=input_data,
            output_data=transformed_output
        )
        
        return success, transformed_output
    
    def execute_workflow(self, workflow_name: str, goal: str, 
                        initial_data: Optional[Dict[str, Any]] = None,
                        verbose: bool = True) -> WorkflowContext:
        """
        Execute a workflow (Deterministic State Machine).
        
        Args:
            workflow_name: Name of the workflow to execute
            goal: The goal/objective for this workflow execution
            initial_data: Optional initial data to seed the workflow
            verbose: Print execution details
        
        Returns:
            WorkflowContext with final state and results
        """
        # Get workflow definition
        workflow = self.workflows.get(workflow_name)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_name}")
        
        # Initialize context
        context = WorkflowContext(
            workflow_id=f"{workflow_name}_{datetime.now().timestamp()}",
            goal=goal,
            state=WorkflowState.INITIALIZED,
            current_step=workflow.initial_step,
            data=initial_data or {},
            metadata={"workflow_name": workflow_name}
        )
        
        if verbose:
            print("="*60)
            print(f"ORCHESTRATOR: Executing Workflow")
            print("="*60)
            print(f"Workflow: {workflow.name}")
            print(f"Goal: {goal}")
            print(f"Initial Step: {workflow.initial_step}")
            print("="*60)
        
        # State machine execution loop
        context.state = WorkflowState.IN_PROGRESS
        retry_count = 0
        max_iterations = 100  # Safety limit
        iterations = 0
        
        while context.state == WorkflowState.IN_PROGRESS and iterations < max_iterations:
            iterations += 1
            
            # Get current step
            step = workflow.get_step(context.current_step)
            if not step:
                context.state = WorkflowState.FAILED
                if verbose:
                    print(f"\n❌ FAILED: Step '{context.current_step}' not found")
                break
            
            # Execute step
            success, output = self._execute_step(step, context, verbose=verbose)
            
            # Store output in context data
            context.data[f"{step.step_id}_output"] = output
            
            # Determine next step (Deterministic State Machine)
            if success:
                retry_count = 0
                
                if step.is_terminal:
                    context.state = WorkflowState.COMPLETED
                    if verbose:
                        print(f"\n✓ COMPLETED: Workflow finished successfully")
                    break
                elif step.on_success:
                    context.current_step = step.on_success
                else:
                    context.state = WorkflowState.FAILED
                    if verbose:
                        print(f"\n❌ FAILED: No next step defined for success")
                    break
            else:
                # Handle failure
                if retry_count < step.max_retries:
                    retry_count += 1
                    if verbose:
                        print(f"  Retrying step... ({retry_count}/{step.max_retries})")
                    # Stay on current step for retry
                elif step.on_failure:
                    retry_count = 0
                    context.current_step = step.on_failure
                else:
                    context.state = WorkflowState.FAILED
                    if verbose:
                        print(f"\n❌ FAILED: Step failed and no failure path defined")
                    break
        
        if iterations >= max_iterations:
            context.state = WorkflowState.FAILED
            if verbose:
                print(f"\n❌ FAILED: Maximum iterations reached")
        
        if verbose:
            print("\n" + "="*60)
            print(f"WORKFLOW RESULT: {context.state.value.upper()}")
            print("="*60)
        
        return context


# Pre-built workflow templates
def create_build_website_workflow() -> WorkflowDefinition:
    """
    Create a "Build a Website" workflow.
    This demonstrates: Product Manager → Coder → Reviewer pipeline.
    """
    workflow = WorkflowDefinition(
        name="build_website",
        description="Build a website from requirements",
        goal="Create a functional website based on requirements"
    )
    
    # Step 1: Product Manager creates specs
    workflow.add_step(
        WorkflowStep(
            step_id="create_specs",
            worker_type=WorkerType.PRODUCT_MANAGER,
            description="Product Manager creates technical specifications",
            on_success="implement_code",
            on_failure="failed"
        ),
        is_initial=True
    )
    
    # Step 2: Coder implements
    workflow.add_step(
        WorkflowStep(
            step_id="implement_code",
            worker_type=WorkerType.CODER,
            description="Coder implements the website based on specs",
            on_success="review_code",
            on_failure="failed",
            max_retries=1
        )
    )
    
    # Step 3: Reviewer reviews
    workflow.add_step(
        WorkflowStep(
            step_id="review_code",
            worker_type=WorkerType.REVIEWER,
            description="Reviewer checks the code quality and correctness",
            on_success="completed",
            on_failure="implement_code",  # Send back to coder on failure
            max_retries=0
        )
    )
    
    # Terminal states
    workflow.add_step(
        WorkflowStep(
            step_id="completed",
            worker_type=WorkerType.GENERIC,
            description="Workflow completed successfully",
            is_terminal=True
        )
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="failed",
            worker_type=WorkerType.GENERIC,
            description="Workflow failed",
            is_terminal=True
        )
    )
    
    return workflow


def create_generic_pipeline(steps: List[Tuple[str, WorkerType, str]]) -> WorkflowDefinition:
    """
    Create a generic linear pipeline workflow.
    
    Args:
        steps: List of (step_id, worker_type, description) tuples
    
    Returns:
        WorkflowDefinition
    """
    workflow = WorkflowDefinition(
        name="_".join(s[0] for s in steps),
        description="Generic pipeline workflow",
        goal="Execute steps in sequence"
    )
    
    for i, (step_id, worker_type, description) in enumerate(steps):
        is_initial = (i == 0)
        is_terminal = (i == len(steps) - 1)
        next_step = steps[i + 1][0] if not is_terminal else None
        
        workflow.add_step(
            WorkflowStep(
                step_id=step_id,
                worker_type=worker_type,
                description=description,
                on_success=next_step,
                on_failure="failed",
                is_terminal=is_terminal
            ),
            is_initial=is_initial
        )
    
    # Add failure terminal state
    workflow.add_step(
        WorkflowStep(
            step_id="failed",
            worker_type=WorkerType.GENERIC,
            description="Workflow failed",
            is_terminal=True
        )
    )
    
    return workflow

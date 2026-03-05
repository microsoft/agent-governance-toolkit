# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for Orchestration Layer

Tests the deterministic state machine orchestrator
and its interaction with probabilistic workers.
"""

import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.orchestrator import (
    Orchestrator,
    WorkflowDefinition,
    WorkflowStep,
    WorkflowContext,
    WorkerType,
    WorkerDefinition,
    WorkflowState,
    create_build_website_workflow,
    create_generic_pipeline
)


def test_workflow_definition():
    """Test workflow definition and validation."""
    print("Testing WorkflowDefinition...")
    
    # Create a valid workflow
    workflow = WorkflowDefinition(
        name="test_workflow",
        description="Test workflow",
        goal="Test goal"
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step1",
            worker_type=WorkerType.GENERIC,
            description="First step",
            on_success="step2"
        ),
        is_initial=True
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step2",
            worker_type=WorkerType.GENERIC,
            description="Second step",
            is_terminal=True
        )
    )
    
    # Validate
    valid, error = workflow.validate()
    assert valid, f"Workflow should be valid, got error: {error}"
    assert workflow.initial_step == "step1"
    print("  ✓ Valid workflow created and validated")
    
    # Test invalid workflow (missing step reference)
    invalid_workflow = WorkflowDefinition(
        name="invalid_workflow",
        description="Invalid workflow",
        goal="Test goal"
    )
    
    invalid_workflow.add_step(
        WorkflowStep(
            step_id="step1",
            worker_type=WorkerType.GENERIC,
            description="First step",
            on_success="nonexistent_step"  # Invalid reference
        ),
        is_initial=True
    )
    
    valid, error = invalid_workflow.validate()
    assert not valid, "Workflow should be invalid"
    assert "invalid on_success" in error.lower()
    print("  ✓ Invalid workflow detected correctly")
    
    print("✓ WorkflowDefinition tests passed\n")


def test_workflow_context():
    """Test workflow context and history tracking."""
    print("Testing WorkflowContext...")
    
    context = WorkflowContext(
        workflow_id="test_123",
        goal="Test goal",
        state=WorkflowState.INITIALIZED,
        current_step="step1"
    )
    
    # Test history tracking
    context.add_history(
        worker_type="test_worker",
        input_data="input_1",
        output_data="output_1"
    )
    
    context.add_history(
        worker_type="another_worker",
        input_data="input_2",
        output_data="output_2"
    )
    
    assert len(context.history) == 2
    print("  ✓ History tracking works")
    
    # Test get_last_output
    last_output = context.get_last_output()
    assert last_output == "output_2"
    print("  ✓ get_last_output() returns latest output")
    
    # Test get_last_output with filter
    filtered_output = context.get_last_output("test_worker")
    assert filtered_output == "output_1"
    print("  ✓ get_last_output(worker_type) filters correctly")
    
    print("✓ WorkflowContext tests passed\n")


def test_orchestrator_registration():
    """Test worker and workflow registration."""
    print("Testing Orchestrator registration...")
    
    orchestrator = Orchestrator()
    
    # Register a worker
    def dummy_executor(input_data, context):
        return {"result": "success"}
    
    worker = WorkerDefinition(
        worker_type=WorkerType.GENERIC,
        name="Test Worker",
        description="A test worker",
        executor=dummy_executor
    )
    
    orchestrator.register_worker(worker)
    assert WorkerType.GENERIC in orchestrator.workers
    print("  ✓ Worker registered successfully")
    
    # Register a valid workflow
    workflow = WorkflowDefinition(
        name="test_workflow",
        description="Test workflow",
        goal="Test goal"
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step1",
            worker_type=WorkerType.GENERIC,
            description="Step 1",
            is_terminal=True
        ),
        is_initial=True
    )
    
    orchestrator.register_workflow(workflow)
    assert "test_workflow" in orchestrator.workflows
    print("  ✓ Valid workflow registered successfully")
    
    # Try to register invalid workflow
    invalid_workflow = WorkflowDefinition(
        name="invalid_workflow",
        description="Invalid workflow",
        goal="Test goal"
    )
    
    invalid_workflow.add_step(
        WorkflowStep(
            step_id="step1",
            worker_type=WorkerType.GENERIC,
            description="Step 1",
            on_success="missing_step"
        ),
        is_initial=True
    )
    
    try:
        orchestrator.register_workflow(invalid_workflow)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid workflow" in str(e)
        print("  ✓ Invalid workflow rejected")
    
    print("✓ Orchestrator registration tests passed\n")


def test_simple_workflow_execution():
    """Test execution of a simple workflow."""
    print("Testing simple workflow execution...")
    
    orchestrator = Orchestrator()
    
    # Create a simple worker
    def simple_worker(input_data, context):
        return {"message": f"Processed: {input_data}"}
    
    worker = WorkerDefinition(
        worker_type=WorkerType.GENERIC,
        name="Simple Worker",
        description="A simple worker",
        executor=simple_worker
    )
    
    orchestrator.register_worker(worker)
    
    # Create a simple single-step workflow
    workflow = WorkflowDefinition(
        name="simple_workflow",
        description="Simple workflow",
        goal="Execute one step"
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="only_step",
            worker_type=WorkerType.GENERIC,
            description="The only step",
            is_terminal=True
        ),
        is_initial=True
    )
    
    orchestrator.register_workflow(workflow)
    
    # Execute workflow
    result = orchestrator.execute_workflow(
        workflow_name="simple_workflow",
        goal="Test goal",
        verbose=False
    )
    
    assert result.state == WorkflowState.COMPLETED
    assert len(result.history) == 1
    assert "only_step_output" in result.data
    print("  ✓ Simple workflow executed successfully")
    print("✓ Simple workflow execution tests passed\n")


def test_multi_step_workflow():
    """Test execution of a multi-step workflow."""
    print("Testing multi-step workflow execution...")
    
    orchestrator = Orchestrator()
    
    # Create workers with different behaviors
    def step1_worker(input_data, context):
        return {"step": 1, "data": "Step 1 output"}
    
    def step2_worker(input_data, context):
        prev_output = context.get_last_output()
        return {"step": 2, "previous": prev_output, "data": "Step 2 output"}
    
    def step3_worker(input_data, context):
        return {"step": 3, "data": "Step 3 output"}
    
    # Register workers
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.PRODUCT_MANAGER,
            name="Worker 1",
            description="First worker",
            executor=step1_worker
        )
    )
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.CODER,
            name="Worker 2",
            description="Second worker",
            executor=step2_worker
        )
    )
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.REVIEWER,
            name="Worker 3",
            description="Third worker",
            executor=step3_worker
        )
    )
    
    # Create multi-step workflow
    workflow = WorkflowDefinition(
        name="multi_step",
        description="Multi-step workflow",
        goal="Execute three steps"
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step1",
            worker_type=WorkerType.PRODUCT_MANAGER,
            description="Step 1",
            on_success="step2"
        ),
        is_initial=True
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step2",
            worker_type=WorkerType.CODER,
            description="Step 2",
            on_success="step3"
        )
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="step3",
            worker_type=WorkerType.REVIEWER,
            description="Step 3",
            is_terminal=True
        )
    )
    
    orchestrator.register_workflow(workflow)
    
    # Execute workflow
    result = orchestrator.execute_workflow(
        workflow_name="multi_step",
        goal="Test multi-step",
        verbose=False
    )
    
    assert result.state == WorkflowState.COMPLETED
    assert len(result.history) == 3
    
    # Check history order
    assert result.history[0]["worker_type"] == "product_manager"
    assert result.history[1]["worker_type"] == "coder"
    assert result.history[2]["worker_type"] == "reviewer"
    
    # Check data flow
    step2_output = result.data["step2_output"]
    assert "previous" in step2_output
    
    print("  ✓ Multi-step workflow executed successfully")
    print("  ✓ Data flowed correctly between steps")
    print("✓ Multi-step workflow execution tests passed\n")


def test_workflow_with_failure():
    """Test workflow handling of failures."""
    print("Testing workflow failure handling...")
    
    orchestrator = Orchestrator()
    
    # Create a worker that fails
    def failing_worker(input_data, context):
        raise Exception("Simulated failure")
    
    # Create a fallback worker
    def fallback_worker(input_data, context):
        return {"status": "fallback executed"}
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.CODER,
            name="Failing Worker",
            description="Worker that fails",
            executor=failing_worker
        )
    )
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.REVIEWER,
            name="Fallback Worker",
            description="Fallback worker",
            executor=fallback_worker
        )
    )
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.GENERIC,
            name="Generic Worker",
            description="Generic worker",
            executor=lambda i, c: {"status": "ok"}
        )
    )
    
    # Create workflow with failure path
    workflow = WorkflowDefinition(
        name="failure_test",
        description="Test failure handling",
        goal="Test failure"
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="main_step",
            worker_type=WorkerType.CODER,
            description="Main step that fails",
            on_success="success_step",
            on_failure="fallback_step"
        ),
        is_initial=True
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="fallback_step",
            worker_type=WorkerType.REVIEWER,
            description="Fallback step",
            is_terminal=True
        )
    )
    
    workflow.add_step(
        WorkflowStep(
            step_id="success_step",
            worker_type=WorkerType.GENERIC,
            description="Success step",
            is_terminal=True
        )
    )
    
    orchestrator.register_workflow(workflow)
    
    # Execute workflow
    result = orchestrator.execute_workflow(
        workflow_name="failure_test",
        goal="Test failure path",
        verbose=False
    )
    
    assert result.state == WorkflowState.COMPLETED
    assert len(result.history) == 2  # Main step + fallback step
    assert result.history[1]["worker_type"] == "reviewer"  # Fallback executed
    
    print("  ✓ Workflow handled failure and took fallback path")
    print("✓ Workflow failure handling tests passed\n")


def test_pre_built_workflows():
    """Test pre-built workflow templates."""
    print("Testing pre-built workflows...")
    
    # Test build_website_workflow
    workflow = create_build_website_workflow()
    valid, error = workflow.validate()
    assert valid, f"build_website_workflow should be valid: {error}"
    assert workflow.name == "build_website"
    assert workflow.initial_step == "create_specs"
    print("  ✓ build_website_workflow is valid")
    
    # Test generic_pipeline
    pipeline = create_generic_pipeline([
        ("step1", WorkerType.PRODUCT_MANAGER, "Step 1"),
        ("step2", WorkerType.CODER, "Step 2"),
        ("step3", WorkerType.REVIEWER, "Step 3")
    ])
    valid, error = pipeline.validate()
    assert valid, f"generic_pipeline should be valid: {error}"
    print("  ✓ generic_pipeline is valid")
    
    print("✓ Pre-built workflows tests passed\n")


def run_all_tests():
    """Run all tests."""
    print("="*60)
    print("ORCHESTRATION LAYER TESTS")
    print("="*60)
    print()
    
    try:
        test_workflow_definition()
        test_workflow_context()
        test_orchestrator_registration()
        test_simple_workflow_execution()
        test_multi_step_workflow()
        test_workflow_with_failure()
        test_pre_built_workflows()
        
        print("="*60)
        print("ALL TESTS PASSED ✓")
        print("="*60)
        return True
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)

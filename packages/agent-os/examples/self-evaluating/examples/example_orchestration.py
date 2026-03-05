# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Deterministic Orchestration Layer

This demonstrates the "Glue" Problem solution:
- The Orchestrator is a DETERMINISTIC STATE MACHINE (not a fuzzy AI)
- Workers are PROBABILISTIC AI agents
- The Hub & Spoke pattern: Workers never talk directly
- Transformer Middleware manages data flow

Example: "Build a Website" Pipeline
Product Manager → Coder → Reviewer
"""

import os
from typing import Any, Dict
from dotenv import load_dotenv
from openai import OpenAI

import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.orchestrator import (
    Orchestrator,
    WorkerType,
    WorkerDefinition,
    WorkflowContext,
    create_build_website_workflow
)

# Load environment variables
load_dotenv()


# Mock workers for demonstration (in production, these would be real AI agents)
def product_manager_worker(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Product Manager: Creates technical specifications.
    This is a PROBABILISTIC AI worker.
    """
    print(f"\n[WORKER: Product Manager] Creating specifications...")
    print(f"  Goal: {context.goal}")
    
    # In a real system, this would call an LLM
    # For demo, we'll create mock specs
    specs = {
        "requirements": context.goal,
        "pages": ["Home", "About", "Contact"],
        "tech_stack": ["HTML", "CSS", "JavaScript"],
        "features": ["Responsive design", "Contact form", "Navigation menu"],
        "success_criteria": "Clean code, mobile-friendly, working contact form"
    }
    
    print(f"  ✓ Created specifications:")
    for key, value in specs.items():
        print(f"    - {key}: {value}")
    
    return specs


def coder_worker(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Coder: Implements code based on specifications.
    This is a PROBABILISTIC AI worker.
    """
    print(f"\n[WORKER: Coder] Implementing code...")
    
    # Get specs from previous step
    specs = input_data
    print(f"  Received specs: {specs.get('pages', [])} pages")
    
    # In a real system, this would call an LLM to generate code
    # For demo, we'll create mock code
    code = {
        "files": {
            "index.html": "<!DOCTYPE html><html>...",
            "style.css": "body { margin: 0; }...",
            "script.js": "document.addEventListener('DOMContentLoaded', ...);"
        },
        "pages_implemented": specs.get("pages", []),
        "features_implemented": specs.get("features", []),
        "status": "completed"
    }
    
    print(f"  ✓ Generated {len(code['files'])} files")
    for filename in code['files'].keys():
        print(f"    - {filename}")
    
    return code


def reviewer_worker(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Reviewer: Reviews code quality and correctness.
    This is a PROBABILISTIC AI worker.
    """
    print(f"\n[WORKER: Reviewer] Reviewing code...")
    
    # Get code from previous step
    code = input_data
    files = code.get("files", {})
    print(f"  Reviewing {len(files)} files...")
    
    # In a real system, this would call an LLM to review code
    # For demo, we'll create mock review
    review = {
        "approved": True,
        "quality_score": 0.85,
        "issues": [],
        "comments": [
            "Clean HTML structure",
            "CSS follows best practices",
            "JavaScript is well-organized"
        ],
        "recommendations": [
            "Consider adding comments",
            "Add error handling to contact form"
        ]
    }
    
    print(f"  ✓ Review completed:")
    print(f"    - Approved: {review['approved']}")
    print(f"    - Quality Score: {review['quality_score']}")
    print(f"    - Issues: {len(review['issues'])}")
    
    return review


def generic_worker(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Generic worker for terminal states.
    """
    return {"status": "completed"}


# Input transformers (Transformer Middleware)
def pm_input_transformer(context: WorkflowContext) -> str:
    """Transform context for Product Manager."""
    return context.goal


def coder_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    """Transform specs for Coder."""
    return context.get_last_output(WorkerType.PRODUCT_MANAGER.value)


def reviewer_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    """Transform code for Reviewer."""
    return context.get_last_output(WorkerType.CODER.value)


def main():
    """
    Demonstrate deterministic orchestration of probabilistic workers.
    """
    print("="*70)
    print("DETERMINISTIC ORCHESTRATION LAYER DEMO")
    print("="*70)
    print("\nThe Problem: How to build reliable multi-agent systems?")
    print("\nThe Solution:")
    print("  1. Orchestrator = DETERMINISTIC STATE MACHINE (rigid code)")
    print("  2. Workers = PROBABILISTIC AI AGENTS (creative)")
    print("  3. Hub & Spoke = Workers never talk directly")
    print("  4. Transformer Middleware = Manages data flow")
    print("\n" + "="*70)
    
    # Initialize orchestrator (The Hub)
    orchestrator = Orchestrator()
    
    # Register workers (Probabilistic AI Agents)
    print("\n[SETUP] Registering Workers...")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.PRODUCT_MANAGER,
            name="Product Manager",
            description="Creates technical specifications from requirements",
            executor=product_manager_worker,
            input_transformer=pm_input_transformer
        )
    )
    print("  ✓ Product Manager registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.CODER,
            name="Coder",
            description="Implements code based on specifications",
            executor=coder_worker,
            input_transformer=coder_input_transformer
        )
    )
    print("  ✓ Coder registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.REVIEWER,
            name="Reviewer",
            description="Reviews code quality and correctness",
            executor=reviewer_worker,
            input_transformer=reviewer_input_transformer
        )
    )
    print("  ✓ Reviewer registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.GENERIC,
            name="Generic",
            description="Generic worker for terminal states",
            executor=generic_worker
        )
    )
    print("  ✓ Generic worker registered")
    
    # Register workflow (Deterministic State Machine)
    print("\n[SETUP] Registering Workflow...")
    workflow = create_build_website_workflow()
    orchestrator.register_workflow(workflow)
    print(f"  ✓ Workflow registered: {workflow.name}")
    print(f"  ✓ Steps: {' → '.join(workflow.steps.keys())}")
    
    # Execute workflow
    print("\n" + "="*70)
    print("EXECUTING WORKFLOW")
    print("="*70)
    
    goal = "Build a portfolio website with home, about, and contact pages"
    result = orchestrator.execute_workflow(
        workflow_name="build_website",
        goal=goal,
        verbose=True
    )
    
    # Display results
    print("\n" + "="*70)
    print("WORKFLOW SUMMARY")
    print("="*70)
    print(f"Final State: {result.state.value.upper()}")
    print(f"Total Steps Executed: {len(result.history)}")
    print(f"\nExecution History:")
    for i, entry in enumerate(result.history, 1):
        print(f"  {i}. {entry['worker_type']} ({entry['step']})")
        print(f"     Timestamp: {entry['timestamp']}")
    
    print(f"\nFinal Output Data:")
    for key, value in result.data.items():
        print(f"  {key}: {type(value).__name__}")
    
    print("\n" + "="*70)
    print("KEY INSIGHTS")
    print("="*70)
    print("✓ The Orchestrator is DETERMINISTIC (rigid state machine)")
    print("✓ The Workers are PROBABILISTIC (AI agents)")
    print("✓ Workers communicate through the Hub (never directly)")
    print("✓ Transformer Middleware manages data flow")
    print("✓ The 'Brain' is probabilistic, the 'Skeleton' is deterministic")
    print("\nStartup Opportunity:")
    print("  This orchestration layer could be 'Orchestration-as-a-Service'")
    print("  Define a goal → Service spins up the correct pipeline automatically")
    print("="*70)


if __name__ == "__main__":
    main()

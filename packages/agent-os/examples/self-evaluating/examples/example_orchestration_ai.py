# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Advanced Example: Orchestration with Real AI Agents

This demonstrates integrating the orchestration layer with actual AI agents
(DoerAgent) to create a fully functional AI-powered workflow system.

Note: This example requires OpenAI API key to run.
"""

import os
from typing import Any, Dict
from dotenv import load_dotenv

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

# Import agent if available
try:
    from agent import DoerAgent
    AGENT_AVAILABLE = True
except ImportError:
    AGENT_AVAILABLE = False

# Load environment variables
load_dotenv()


# AI-Powered Workers (using DoerAgent)
def ai_product_manager(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Product Manager powered by AI.
    Takes requirements and creates technical specifications.
    """
    print(f"\n[AI WORKER: Product Manager] Analyzing requirements...")
    
    if not AGENT_AVAILABLE or not os.getenv("OPENAI_API_KEY"):
        # Fallback to mock if AI not available
        print("  (Using mock mode - no API key)")
        return {
            "requirements": context.goal,
            "pages": ["Home", "About", "Contact"],
            "tech_stack": ["HTML", "CSS", "JavaScript"],
            "features": ["Responsive design", "Contact form"],
        }
    
    # Use real AI agent
    doer = DoerAgent()
    
    prompt = f"""
    You are a Product Manager. Create technical specifications for this project:
    
    Requirements: {context.goal}
    
    Output a JSON object with:
    - pages: List of page names
    - tech_stack: List of technologies to use
    - features: List of features to implement
    - success_criteria: What defines success
    
    Keep it concise and practical.
    """
    
    result = doer.run(prompt, verbose=False)
    print(f"  ✓ AI generated specifications")
    
    # In a real system, you'd parse the AI response
    # For this demo, we'll return structured data
    return {
        "requirements": context.goal,
        "ai_response": result["response"],
        "pages": ["Home", "About", "Contact"],
        "tech_stack": ["HTML", "CSS", "JavaScript"],
        "features": ["Responsive design", "Contact form"],
        "success_criteria": "Clean code, mobile-friendly"
    }


def ai_coder(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Coder powered by AI.
    Implements code based on specifications.
    """
    print(f"\n[AI WORKER: Coder] Implementing code...")
    
    specs = input_data
    
    if not AGENT_AVAILABLE or not os.getenv("OPENAI_API_KEY"):
        # Fallback to mock if AI not available
        print("  (Using mock mode - no API key)")
        return {
            "files": {
                "index.html": "<!DOCTYPE html>...",
                "style.css": "body { margin: 0; }...",
            },
            "status": "completed"
        }
    
    # Use real AI agent
    doer = DoerAgent()
    
    prompt = f"""
    You are a Coder. Implement a website based on these specifications:
    
    Pages: {specs.get('pages', [])}
    Tech Stack: {specs.get('tech_stack', [])}
    Features: {specs.get('features', [])}
    
    Describe what files you would create and their key components.
    Keep it brief - just the main structure.
    """
    
    result = doer.run(prompt, verbose=False)
    print(f"  ✓ AI generated code structure")
    
    return {
        "ai_response": result["response"],
        "files": {
            "index.html": "HTML structure...",
            "style.css": "CSS styles...",
            "script.js": "JavaScript logic..."
        },
        "status": "completed"
    }


def ai_reviewer(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """
    Reviewer powered by AI.
    Reviews code quality and correctness.
    """
    print(f"\n[AI WORKER: Reviewer] Reviewing code...")
    
    code = input_data
    
    if not AGENT_AVAILABLE or not os.getenv("OPENAI_API_KEY"):
        # Fallback to mock if AI not available
        print("  (Using mock mode - no API key)")
        return {
            "approved": True,
            "quality_score": 0.85,
            "comments": ["Looks good"]
        }
    
    # Use real AI agent
    doer = DoerAgent()
    
    prompt = f"""
    You are a Code Reviewer. Review this code implementation:
    
    Files: {list(code.get('files', {}).keys())}
    Status: {code.get('status', 'unknown')}
    
    Provide:
    - Whether you approve (yes/no)
    - Quality score (0-1)
    - Brief comments
    
    Keep it concise.
    """
    
    result = doer.run(prompt, verbose=False)
    print(f"  ✓ AI completed review")
    
    return {
        "approved": True,
        "quality_score": 0.85,
        "ai_response": result["response"],
        "comments": ["AI review completed"]
    }


def generic_worker(input_data: Any, context: WorkflowContext) -> Dict[str, Any]:
    """Generic worker for terminal states."""
    return {"status": "completed"}


# Input transformers
def pm_input_transformer(context: WorkflowContext) -> str:
    return context.goal


def coder_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    return context.get_last_output(WorkerType.PRODUCT_MANAGER.value)


def reviewer_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    return context.get_last_output(WorkerType.CODER.value)


def main():
    """
    Demonstrate orchestration with AI-powered workers.
    """
    print("="*70)
    print("ORCHESTRATION WITH AI AGENTS")
    print("="*70)
    
    if not AGENT_AVAILABLE:
        print("\n⚠️  WARNING: agent.py not available")
        print("   Falling back to mock mode")
    elif not os.getenv("OPENAI_API_KEY"):
        print("\n⚠️  WARNING: OPENAI_API_KEY not found")
        print("   Falling back to mock mode")
    else:
        print("\n✓ AI agents available")
        print("✓ OpenAI API key found")
    
    print("\nThis demonstrates:")
    print("  1. Deterministic orchestration (rigid state machine)")
    print("  2. Probabilistic workers (AI-powered agents)")
    print("  3. Hub & Spoke pattern (workers through hub)")
    print("  4. Real AI integration (DoerAgent as workers)")
    print("\n" + "="*70)
    
    # Initialize orchestrator
    orchestrator = Orchestrator()
    
    # Register AI-powered workers
    print("\n[SETUP] Registering AI-Powered Workers...")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.PRODUCT_MANAGER,
            name="AI Product Manager",
            description="Creates specifications using AI",
            executor=ai_product_manager,
            input_transformer=pm_input_transformer
        )
    )
    print("  ✓ AI Product Manager registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.CODER,
            name="AI Coder",
            description="Implements code using AI",
            executor=ai_coder,
            input_transformer=coder_input_transformer
        )
    )
    print("  ✓ AI Coder registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.REVIEWER,
            name="AI Reviewer",
            description="Reviews code using AI",
            executor=ai_reviewer,
            input_transformer=reviewer_input_transformer
        )
    )
    print("  ✓ AI Reviewer registered")
    
    orchestrator.register_worker(
        WorkerDefinition(
            worker_type=WorkerType.GENERIC,
            name="Generic",
            description="Generic worker",
            executor=generic_worker
        )
    )
    print("  ✓ Generic worker registered")
    
    # Register workflow
    print("\n[SETUP] Registering Workflow...")
    workflow = create_build_website_workflow()
    orchestrator.register_workflow(workflow)
    print(f"  ✓ Workflow registered: {workflow.name}")
    
    # Execute workflow
    print("\n" + "="*70)
    print("EXECUTING AI-POWERED WORKFLOW")
    print("="*70)
    
    goal = "Build a modern e-commerce website with product catalog and checkout"
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
    print(f"Total Steps: {len(result.history)}")
    
    print("\nExecution History:")
    for i, entry in enumerate(result.history, 1):
        print(f"  {i}. {entry['worker_type']}")
        
        # Show AI responses if available
        output = entry.get('output', {})
        if isinstance(output, dict) and 'ai_response' in output:
            ai_resp = output['ai_response'][:100]
            print(f"     AI: {ai_resp}...")
    
    print("\n" + "="*70)
    print("KEY ACHIEVEMENTS")
    print("="*70)
    print("✓ Deterministic orchestration with probabilistic AI workers")
    print("✓ Hub & Spoke pattern maintained throughout")
    print("✓ Transformer middleware managed data flow")
    print("✓ AI agents integrated seamlessly into workflow")
    print("✓ Full execution history captured")
    print("\nThis demonstrates the power of combining:")
    print("  • Rigid orchestration (predictable, debuggable)")
    print("  • Creative AI workers (flexible, intelligent)")
    print("="*70)


if __name__ == "__main__":
    main()

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Model Upgrade Manager - Lifecycle Management for Wisdom Database

This module implements the "Upgrade Purge" strategy for active memory management.
When upgrading the base model (e.g., GPT-3.5 → GPT-4), it audits the wisdom database
and removes lessons that the new model can handle natively.

Philosophy:
- Lessons are often just band-aids for a model
- When you upgrade, many band-aids become redundant
- The wisdom database should get smaller and more specialized over time
- Only edge cases the new model can't handle should remain
"""

import json
import os
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

from .agent import MemorySystem, AgentTools

# Import prioritization framework
try:
    from prioritization import PrioritizationFramework
    PRIORITIZATION_AVAILABLE = True
except ImportError:
    PRIORITIZATION_AVAILABLE = False

# Load environment variables
load_dotenv()


class ModelUpgradeManager:
    """
    Manages the upgrade purge process when base models are upgraded.
    
    The workflow:
    1. Extract failure scenarios from the improvements history
    2. Test each scenario against the new model WITHOUT the learned lessons
    3. If the new model handles it natively, mark the lesson as redundant
    4. Purge redundant lessons from the wisdom database
    """
    
    # Configuration constants
    TASK_PATTERN_MAX_LENGTH = 100  # Maximum length for task pattern matching
    
    def __init__(self,
                 wisdom_file: str = "system_instructions.json",
                 upgrade_log_file: str = "model_upgrade_log.json",
                 enable_prioritization: bool = True):
        # Initialize OpenAI client only if API key is available
        api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=api_key) if api_key else None
        
        self.wisdom = MemorySystem(wisdom_file)
        self.tools = AgentTools()
        self.upgrade_log_file = upgrade_log_file
        self.enable_prioritization = enable_prioritization and PRIORITIZATION_AVAILABLE
        
        if self.enable_prioritization:
            self.prioritization = PrioritizationFramework()
        
        # Load upgrade log
        self.upgrade_log = self._load_upgrade_log()
    
    def _load_upgrade_log(self) -> Dict[str, Any]:
        """
        Load the model upgrade log from disk.
        
        Returns:
            Dict containing:
                - upgrades: List of upgrade records
                - current_model: Name of current model (or None)
        """
        if os.path.exists(self.upgrade_log_file):
            try:
                with open(self.upgrade_log_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            "upgrades": [],
            "current_model": None
        }
    
    def _save_upgrade_log(self) -> None:
        """
        Save the model upgrade log to disk.
        Persists the current upgrade history and model information.
        """
        with open(self.upgrade_log_file, 'w') as f:
            json.dump(self.upgrade_log, f, indent=2)
    
    def _extract_failure_scenarios(self) -> List[Dict[str, Any]]:
        """
        Extract failure scenarios from the improvements history.
        
        Each improvement represents a past failure that caused the system
        to learn a new lesson. We need to test if the new model can handle
        these scenarios without the learned lessons.
        
        Returns:
            List of scenario dictionaries, each containing:
                - version: Version number when lesson was learned
                - timestamp: When the lesson was learned
                - critique: The critique that prompted learning
                - query: Original query that failed
                - response: Original agent response that failed
        """
        improvements = self.wisdom.instructions.get("improvements", [])
        
        scenarios = []
        for improvement in improvements:
            scenario = {
                "version": improvement.get("version"),
                "timestamp": improvement.get("timestamp"),
                "critique": improvement.get("critique"),
                "lesson_learned": improvement.get("lesson_learned", ""),
                "query": improvement.get("query", ""),
                "response": improvement.get("response", "")
            }
            scenarios.append(scenario)
        
        return scenarios
    
    def _test_scenario_with_baseline(self,
                                     query: str,
                                     new_model: str,
                                     baseline_instructions: str) -> Tuple[str, float]:
        """
        Test a failure scenario against the new model with baseline instructions only.
        
        Args:
            query: The original query that caused the failure
            new_model: The new model to test with
            baseline_instructions: Baseline instructions (without specific lessons)
        
        Returns:
            Tuple of (response, score) where score is 0-1
        """
        if not query:
            # If we don't have the original query, we can't test
            return "", 0.0
        
        if not self.client:
            raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
        
        # Build system prompt with baseline only (no specific lessons)
        system_prompt = f"{baseline_instructions}\n\n{self.tools.get_available_tools()}"
        system_prompt += "\nIf you need to use a tool, explain which tool you would use and why."
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": query}
        ]
        
        try:
            # Execute with new model
            response = self.client.chat.completions.create(
                model=new_model,
                messages=messages,
                temperature=0.7
            )
            agent_response = response.choices[0].message.content
            
            # Evaluate the response
            score = self._evaluate_response(query, agent_response)
            
            return agent_response, score
            
        except Exception as e:
            print(f"Error testing scenario: {str(e)}")
            return f"Error: {str(e)}", 0.0
    
    def _evaluate_response(self, query: str, agent_response: str) -> float:
        """
        Evaluate how well the agent responded to a query.
        
        Returns a score from 0 to 1.
        """
        reflection_prompt = f"""You are an evaluator assessing an AI agent's response.

User Query: {query}

Agent Response: {agent_response}

Evaluate the response on the following criteria:
1. Correctness: Did the agent answer the question correctly?
2. Completeness: Did the agent provide a complete answer?
3. Clarity: Is the response clear and well-explained?
4. Tool Usage: Did the agent appropriately identify and explain tool usage when needed?

Provide your evaluation as JSON with:
- score: A number between 0 and 1 (0 = poor, 1 = excellent)
- reasoning: Brief explanation of the score

Return ONLY valid JSON in this format:
{{"score": 0.85, "reasoning": "Your brief reasoning here"}}
"""
        
        if not self.client:
            raise ValueError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
        
        try:
            response = self.client.chat.completions.create(
                model=os.getenv("REFLECTION_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": reflection_prompt}],
                temperature=0.3
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(result_text)
            return result.get("score", 0.5)
            
        except Exception as e:
            print(f"Error in evaluation: {str(e)}")
            return 0.5
    
    def audit_wisdom_database(self,
                             new_model: str,
                             baseline_instructions: str,
                             score_threshold: float = 0.8,
                             verbose: bool = True) -> Dict[str, Any]:
        """
        Audit the wisdom database against a new model.
        
        Args:
            new_model: The new model to test with (e.g., "gpt-4o", "gpt-4")
            baseline_instructions: Baseline instructions without specific lessons
            score_threshold: Score threshold to consider a scenario "solved" (default: 0.8)
            verbose: Print detailed audit information
        
        Returns:
            Audit report with redundant lessons identified
        """
        if verbose:
            print("="*60)
            print("MODEL UPGRADE AUDIT: Wisdom Database")
            print("="*60)
            print(f"New Model: {new_model}")
            print(f"Score Threshold: {score_threshold}")
            print(f"Baseline Instructions: {baseline_instructions[:100]}...")
        
        # Extract failure scenarios from improvements
        scenarios = self._extract_failure_scenarios()
        
        if verbose:
            print(f"\nFound {len(scenarios)} scenarios to audit")
        
        audit_results = {
            "new_model": new_model,
            "baseline_instructions": baseline_instructions,
            "score_threshold": score_threshold,
            "timestamp": datetime.now().isoformat(),
            "total_scenarios": len(scenarios),
            "tested_scenarios": 0,
            "redundant_lessons": [],
            "critical_lessons": [],
            "scenarios_without_query": 0
        }
        
        # Test each scenario
        for i, scenario in enumerate(scenarios, 1):
            query = scenario.get("query", "")
            
            if not query:
                audit_results["scenarios_without_query"] += 1
                if verbose:
                    print(f"\n[{i}/{len(scenarios)}] Skipping scenario (version {scenario['version']}) - no query stored")
                continue
            
            if verbose:
                print(f"\n[{i}/{len(scenarios)}] Testing scenario (version {scenario['version']})")
                print(f"  Query: {query[:80]}...")
            
            # Test with new model and baseline instructions only
            response, score = self._test_scenario_with_baseline(
                query=query,
                new_model=new_model,
                baseline_instructions=baseline_instructions
            )
            
            audit_results["tested_scenarios"] += 1
            
            if verbose:
                print(f"  Score: {score:.2f}")
                print(f"  Response: {response[:100]}...")
            
            # Determine if the lesson is redundant
            if score >= score_threshold:
                # New model handles it natively - lesson is redundant!
                if verbose:
                    print(f"  ✅ REDUNDANT: New model solves this natively (score {score:.2f} >= {score_threshold})")
                
                audit_results["redundant_lessons"].append({
                    "version": scenario["version"],
                    "timestamp": scenario["timestamp"],
                    "critique": scenario["critique"],
                    "query": query,
                    "new_model_score": score,
                    "new_model_response": response
                })
            else:
                # New model still struggles - lesson is critical!
                if verbose:
                    print(f"  ⚠️ CRITICAL: New model still needs this lesson (score {score:.2f} < {score_threshold})")
                
                audit_results["critical_lessons"].append({
                    "version": scenario["version"],
                    "timestamp": scenario["timestamp"],
                    "critique": scenario["critique"],
                    "query": query,
                    "new_model_score": score
                })
        
        if verbose:
            print("\n" + "="*60)
            print("AUDIT SUMMARY")
            print("="*60)
            print(f"Total Scenarios: {audit_results['total_scenarios']}")
            print(f"Tested: {audit_results['tested_scenarios']}")
            print(f"Skipped (no query): {audit_results['scenarios_without_query']}")
            print(f"Redundant Lessons: {len(audit_results['redundant_lessons'])}")
            print(f"Critical Lessons: {len(audit_results['critical_lessons'])}")
        
        return audit_results
    
    def purge_redundant_lessons(self,
                               audit_results: Dict[str, Any],
                               verbose: bool = True) -> Dict[str, Any]:
        """
        Purge redundant lessons from the wisdom database.
        
        Args:
            audit_results: Results from audit_wisdom_database()
            verbose: Print purge details
        
        Returns:
            Purge report
        """
        if verbose:
            print("\n" + "="*60)
            print("PURGING REDUNDANT LESSONS")
            print("="*60)
        
        redundant_versions = [lesson["version"] for lesson in audit_results["redundant_lessons"]]
        
        if not redundant_versions:
            if verbose:
                print("No redundant lessons to purge.")
            return {
                "purged_count": 0,
                "remaining_count": len(self.wisdom.instructions.get("improvements", []))
            }
        
        # Filter out redundant improvements
        original_improvements = self.wisdom.instructions.get("improvements", [])
        filtered_improvements = [
            imp for imp in original_improvements
            if imp.get("version") not in redundant_versions
        ]
        
        purged_count = len(original_improvements) - len(filtered_improvements)
        
        if verbose:
            print(f"Purging {purged_count} redundant lessons:")
            for version in redundant_versions:
                print(f"  - Version {version}")
        
        # Update wisdom database
        self.wisdom.instructions["improvements"] = filtered_improvements
        
        # Add metadata about the purge
        if "purge_history" not in self.wisdom.instructions:
            self.wisdom.instructions["purge_history"] = []
        
        self.wisdom.instructions["purge_history"].append({
            "timestamp": datetime.now().isoformat(),
            "new_model": audit_results["new_model"],
            "purged_versions": redundant_versions,
            "purged_count": purged_count,
            "remaining_count": len(filtered_improvements)
        })
        
        # Save updated wisdom
        self.wisdom.save_instructions(self.wisdom.instructions)
        
        # Also purge from prioritization framework if enabled
        if self.enable_prioritization:
            self._purge_from_prioritization(audit_results, verbose)
        
        if verbose:
            print(f"\n✅ Purged {purged_count} lessons")
            print(f"Remaining lessons: {len(filtered_improvements)}")
            print(f"Wisdom database updated to version {self.wisdom.instructions['version']}")
        
        # Log the upgrade
        self.upgrade_log["upgrades"].append({
            "timestamp": datetime.now().isoformat(),
            "new_model": audit_results["new_model"],
            "purged_count": purged_count,
            "remaining_count": len(filtered_improvements)
        })
        self.upgrade_log["current_model"] = audit_results["new_model"]
        self._save_upgrade_log()
        
        return {
            "purged_count": purged_count,
            "remaining_count": len(filtered_improvements),
            "purged_versions": redundant_versions
        }
    
    def _purge_from_prioritization(self,
                                  audit_results: Dict[str, Any],
                                  verbose: bool = False) -> None:
        """
        Purge redundant safety corrections from prioritization framework.
        
        Similar logic: if the new model handles a failure scenario natively,
        we should remove the corresponding safety correction.
        """
        if not self.enable_prioritization:
            return
        
        if verbose:
            print("\n[PRIORITIZATION] Auditing safety corrections...")
        
        # Get redundant lesson queries
        redundant_queries = set()
        for lesson in audit_results["redundant_lessons"]:
            query = lesson.get("query", "")
            if query:
                redundant_queries.add(query[:self.TASK_PATTERN_MAX_LENGTH])
        
        # Filter out redundant safety corrections
        original_corrections = self.prioritization.safety_corrections.copy()
        filtered_corrections = [
            corr for corr in original_corrections
            if isinstance(corr.task_pattern, str) and corr.task_pattern not in redundant_queries
        ]
        
        purged_corrections = len(original_corrections) - len(filtered_corrections)
        
        if purged_corrections > 0:
            self.prioritization.safety_corrections = filtered_corrections
            # Save corrections using prioritization framework's method
            try:
                self.prioritization._save_safety_corrections()
            except AttributeError:
                # If method doesn't exist or is unavailable, skip silently
                pass
            
            if verbose:
                print(f"[PRIORITIZATION] Purged {purged_corrections} redundant safety corrections")
    
    def perform_upgrade(self,
                       new_model: str,
                       baseline_instructions: str,
                       score_threshold: float = 0.8,
                       auto_purge: bool = True,
                       verbose: bool = True) -> Dict[str, Any]:
        """
        Perform a complete model upgrade with audit and purge.
        
        Args:
            new_model: The new model to upgrade to
            baseline_instructions: Baseline instructions for the new model
            score_threshold: Score threshold for redundancy detection
            auto_purge: Automatically purge redundant lessons
            verbose: Print detailed information
        
        Returns:
            Complete upgrade report
        """
        if verbose:
            print("="*60)
            print("MODEL UPGRADE: Complete Upgrade Process")
            print("="*60)
        
        # Step 1: Audit
        audit_results = self.audit_wisdom_database(
            new_model=new_model,
            baseline_instructions=baseline_instructions,
            score_threshold=score_threshold,
            verbose=verbose
        )
        
        # Step 2: Purge (if auto_purge enabled)
        purge_results = None
        if auto_purge:
            purge_results = self.purge_redundant_lessons(
                audit_results=audit_results,
                verbose=verbose
            )
        else:
            if verbose:
                print("\n⚠️ Auto-purge disabled. Run purge_redundant_lessons() manually to complete upgrade.")
        
        upgrade_report = {
            "new_model": new_model,
            "timestamp": datetime.now().isoformat(),
            "audit_results": audit_results,
            "purge_results": purge_results,
            "auto_purged": auto_purge
        }
        
        if verbose:
            print("\n" + "="*60)
            print("UPGRADE COMPLETE")
            print("="*60)
            if purge_results:
                print(f"Database Size Reduction: {purge_results['purged_count']} lessons removed")
                print(f"Remaining Lessons: {purge_results['remaining_count']} (specialized edge cases)")
        
        return upgrade_report


def main():
    """Example usage of the model upgrade manager."""
    print("Model Upgrade Manager - Example Usage")
    print("="*60)
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file with your OpenAI API key")
        return
    
    # Initialize upgrade manager
    manager = ModelUpgradeManager()
    
    # Example: Upgrade to a new model
    print("\nExample: Upgrading to GPT-4")
    print("-" * 60)
    
    # Define baseline instructions for the new model
    baseline_instructions = """You are a helpful AI assistant. Your goal is to provide accurate and useful responses to user queries. You have access to tools that you can use to help answer questions. Always think step-by-step and provide clear, concise answers."""
    
    # Perform upgrade (audit + purge)
    report = manager.perform_upgrade(
        new_model="gpt-4o",  # or "gpt-4", etc.
        baseline_instructions=baseline_instructions,
        score_threshold=0.8,
        auto_purge=False,  # Set to False to review audit before purging
        verbose=True
    )
    
    # Review audit results
    print("\n\nAudit Results:")
    print(f"  Redundant Lessons: {len(report['audit_results']['redundant_lessons'])}")
    print(f"  Critical Lessons: {len(report['audit_results']['critical_lessons'])}")
    
    # Optionally, manually purge after review
    # purge_results = manager.purge_redundant_lessons(report['audit_results'], verbose=True)


if __name__ == "__main__":
    main()

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Observer Agent - Asynchronous Learning System

The Observer is a separate process that consumes telemetry events offline,
analyzes execution traces, determines root causes of failure/success,
and updates the Wisdom Database with learned lessons.
"""

import json
import os
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

from .telemetry import EventStream, TelemetryEvent
from .agent import MemorySystem

# Import prioritization framework
try:
    from .prioritization import PrioritizationFramework
    PRIORITIZATION_AVAILABLE = True
except ImportError:
    PRIORITIZATION_AVAILABLE = False

# Import wisdom curator
try:
    from .wisdom_curator import WisdomCurator
    WISDOM_CURATOR_AVAILABLE = True
except ImportError:
    WISDOM_CURATOR_AVAILABLE = False

# Load environment variables
load_dotenv()


class ObserverAgent:
    """
    The Observer (Shadow Learner) that learns offline from execution traces.
    """
    
    def __init__(self,
                 wisdom_file: str = "system_instructions.json",
                 stream_file: str = "telemetry_events.jsonl",
                 checkpoint_file: str = "observer_checkpoint.json",
                 enable_prioritization: bool = True,
                 enable_intent_metrics: bool = True,
                 enable_wisdom_curator: bool = True):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.wisdom = MemorySystem(wisdom_file)
        self.event_stream = EventStream(stream_file)
        self.checkpoint_file = checkpoint_file
        self.enable_prioritization = enable_prioritization and PRIORITIZATION_AVAILABLE
        self.enable_intent_metrics = enable_intent_metrics
        self.enable_wisdom_curator = enable_wisdom_curator and WISDOM_CURATOR_AVAILABLE
        
        # Model configuration - can use more powerful models for learning
        self.reflection_model = os.getenv("REFLECTION_MODEL", "gpt-4o-mini")
        self.evolution_model = os.getenv("EVOLUTION_MODEL", "gpt-4o-mini")
        self.score_threshold = float(os.getenv("SCORE_THRESHOLD", "0.8"))
        
        # Initialize prioritization framework
        if self.enable_prioritization:
            self.prioritization = PrioritizationFramework()
        
        # Initialize wisdom curator
        if self.enable_wisdom_curator:
            self.wisdom_curator = WisdomCurator()
        
        # Initialize intent metrics
        if self.enable_intent_metrics:
            try:
                from intent_detection import IntentMetrics
                self.intent_metrics = IntentMetrics()
            except ImportError as e:
                print(f"Warning: Intent metrics disabled - ImportError: {e}")
                self.enable_intent_metrics = False
                self.intent_metrics = None
            except Exception as e:
                print(f"Warning: Intent metrics disabled - {type(e).__name__}: {e}")
                self.enable_intent_metrics = False
                self.intent_metrics = None
        
        # Load checkpoint
        self.checkpoint = self._load_checkpoint()
    
    def _extract_user_id(self, event: TelemetryEvent) -> Optional[str]:
        """Extract user_id from event metadata."""
        if event.metadata and isinstance(event.metadata, dict):
            return event.metadata.get("user_id")
        return None
    
    def _load_checkpoint(self) -> Dict[str, Any]:
        """Load the last processing checkpoint."""
        if os.path.exists(self.checkpoint_file):
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        return {
            "last_processed_timestamp": None,
            "lessons_learned": 0
        }
    
    def _save_checkpoint(self) -> None:
        """Save the current processing checkpoint."""
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def reflect(self, query: str, agent_response: str) -> Tuple[float, str]:
        """
        Evaluate the agent's response quality.
        Returns a score (0-1) and critique.
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
- critique: A detailed explanation of what was good and what could be improved

Return ONLY valid JSON in this format:
{{"score": 0.85, "critique": "Your detailed critique here"}}
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.reflection_model,
                messages=[{"role": "user", "content": reflection_prompt}],
                temperature=0.3
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response (handle markdown code blocks)
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(result_text)
            return result["score"], result["critique"]
        except Exception as e:
            print(f"Error in reflection: {str(e)}")
            return 0.5, f"Reflection error: {str(e)}"
    
    def evolve(self, critique: str, query: str, agent_response: str) -> str:
        """
        Generate improved system instructions based on critique.
        """
        current_instructions = self.wisdom.get_system_prompt()
        
        evolution_prompt = f"""You are a meta-learning system that improves AI agent instructions.

Current System Instructions:
{current_instructions}

Recent Query: {query}
Agent Response: {agent_response}

Evaluation Critique:
{critique}

Your task is to rewrite the system instructions to address the issues identified in the critique.
The new instructions should help the agent perform better on similar queries in the future.

Guidelines:
- Keep the instructions clear and concise
- Add specific guidance to address the critique
- Maintain the helpful and accurate nature of the agent
- Include any necessary improvements for tool usage
- Don't make the instructions overly long or complex

Return ONLY the new system instructions as plain text (no JSON, no formatting):
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.evolution_model,
                messages=[{"role": "user", "content": evolution_prompt}],
                temperature=0.7
            )
            
            new_instructions = response.choices[0].message.content.strip()
            return new_instructions
        except Exception as e:
            print(f"Error in evolution: {str(e)}")
            return current_instructions
    
    def analyze_trace(self, event: TelemetryEvent, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """
        Analyze a single execution trace and determine if learning is needed.
        Returns analysis results or None if no learning needed.
        """
        if event.event_type != "task_complete":
            return None
        
        if not event.agent_response:
            return None
        
        if verbose:
            print(f"\n[OBSERVER] Analyzing trace from {event.timestamp}")
            print(f"Query: {event.query}")
        
        # Reflect on the execution
        score, critique = self.reflect(event.query, event.agent_response)
        
        if verbose:
            print(f"Score: {score:.2f}")
            print(f"Critique: {critique}")
        
        analysis = {
            "event": event,
            "score": score,
            "critique": critique,
            "needs_learning": score < self.score_threshold
        }
        
        return analysis
    
    def evaluate_conversation_by_intent(self, conversation_id: str, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """
        Evaluate a completed conversation using intent-specific metrics.
        
        This is the key method that implements the problem statement:
        - Troubleshooting: Time-to-Resolution (flag if > 3 turns)
        - Brainstorming: Depth of Context (flag if too short)
        
        Args:
            conversation_id: The conversation identifier
            verbose: Print evaluation details
            
        Returns:
            Evaluation results with intent-specific success criteria
        """
        if not self.enable_intent_metrics:
            return None
        
        # Get all events for this conversation
        conversation_events = self.event_stream.get_conversation_events(conversation_id)
        
        if not conversation_events:
            return None
        
        # Get intent from first event
        first_event = conversation_events[0]
        intent_type = first_event.intent_type
        
        if not intent_type or intent_type == "unknown":
            if verbose:
                print(f"[INTENT EVAL] No valid intent detected for conversation {conversation_id}")
            return None
        
        # Count turns
        turn_count = self.event_stream.get_conversation_turn_count(conversation_id)
        
        if verbose:
            print(f"\n[INTENT EVAL] Evaluating conversation {conversation_id}")
            print(f"  Intent: {intent_type.upper()}")
            print(f"  Turn Count: {turn_count}")
        
        # Evaluate based on intent type
        if intent_type == "troubleshooting":
            # Check if issue was resolved (last event success status)
            last_event = conversation_events[-1]
            resolved = last_event.success if last_event.success is not None else True
            
            evaluation = self.intent_metrics.evaluate_troubleshooting(
                turn_count=turn_count,
                resolved=resolved
            )
            
            if verbose:
                print(f"  Metric: {evaluation['metric']}")
                print(f"  Success: {evaluation['success']}")
                print(f"  Reasoning: {evaluation['reasoning']}")
            
            return {
                "conversation_id": conversation_id,
                "intent_type": intent_type,
                "evaluation": evaluation,
                "needs_learning": not evaluation["success"]
            }
            
        elif intent_type == "brainstorming":
            # Calculate context depth
            conversation_history = [
                {"content": e.agent_response or ""}
                for e in conversation_events
                if e.agent_response
            ]
            
            depth_score = self.intent_metrics.calculate_context_depth(
                conversation_history,
                verbose=verbose
            )
            
            evaluation = self.intent_metrics.evaluate_brainstorming(
                turn_count=turn_count,
                context_depth_score=depth_score
            )
            
            if verbose:
                print(f"  Metric: {evaluation['metric']}")
                print(f"  Success: {evaluation['success']}")
                print(f"  Reasoning: {evaluation['reasoning']}")
            
            return {
                "conversation_id": conversation_id,
                "intent_type": intent_type,
                "evaluation": evaluation,
                "needs_learning": not evaluation["success"]
            }
        
        return None
    
    def analyze_signal(self, event: TelemetryEvent, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """
        Analyze a silent signal event and determine learning strategy.
        
        Silent signals are implicit feedback that requires immediate attention:
        - Undo: Critical failure, highest priority learning
        - Abandonment: Loss of engagement, high priority learning
        - Acceptance: Success signal, positive reinforcement
        
        Returns analysis results or None if no learning needed.
        """
        if not event.event_type.startswith("signal_"):
            return None
        
        if verbose:
            print(f"\n[OBSERVER] Analyzing {event.signal_type} signal from {event.timestamp}")
            print(f"Query: {event.query}")
        
        # Determine learning priority based on signal type
        if event.signal_type == "undo":
            # Critical failure - user reversed the action
            signal_context = event.signal_context or {}
            critique = (
                f"CRITICAL FAILURE: User immediately reversed the agent's action. "
                f"This indicates the response was fundamentally wrong or harmful. "
                f"Query: {event.query}. "
                f"Response: {event.agent_response}. "
                f"Undo action: {signal_context.get('undo_action', 'Not specified')}. "
                f"The agent MUST learn to avoid similar responses in the future."
            )
            score = 0.0  # Lowest possible score
            needs_learning = True
            priority = "critical"
            
        elif event.signal_type == "abandonment":
            # Loss of engagement - user gave up
            signal_context = event.signal_context or {}
            critique = (
                f"USER ABANDONMENT: User started the workflow but stopped responding. "
                f"This indicates the agent failed to engage effectively. "
                f"Query: {event.query}. "
                f"Last response: {event.agent_response or 'None'}. "
                f"Interactions: {signal_context.get('interaction_count', 0)}. "
                f"The agent should provide more engaging or helpful responses."
            )
            score = 0.3  # Low score
            needs_learning = True
            priority = "high"
            
        elif event.signal_type == "acceptance":
            # Success - user accepted and moved on
            signal_context = event.signal_context or {}
            critique = (
                f"SUCCESS: User accepted the output and moved to the next task. "
                f"This response pattern should be reinforced. "
                f"Query: {event.query}. "
                f"Response: {event.agent_response}. "
                f"Next task: {signal_context.get('next_task', 'Not specified')}. "
                f"The agent is performing well in this scenario."
            )
            score = 1.0  # Perfect score
            needs_learning = False  # Acceptance signals don't require correction, but can be used for reinforcement
            priority = "positive"
        else:
            return None
        
        if verbose:
            print(f"Signal Priority: {priority.upper()}")
            print(f"Score: {score:.2f}")
            print(f"Critique: {critique}")
        
        analysis = {
            "event": event,
            "score": score,
            "critique": critique,
            "needs_learning": needs_learning,
            "priority": priority,
            "signal_type": event.signal_type
        }
        
        return analysis
    
    def learn_from_analysis(self, analysis: Dict[str, Any], verbose: bool = False, 
                           results: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the wisdom database based on analysis.
        Also updates prioritization framework with safety corrections.
        
        With Wisdom Curator enabled, policy-violating updates require human approval.
        
        Args:
            analysis: Analysis dictionary with event, score, critique
            verbose: Print detailed logs
            results: Optional results dict to update statistics
        
        Returns True if wisdom was updated.
        """
        if not analysis["needs_learning"]:
            if verbose:
                print("[OBSERVER] Score meets threshold, no learning needed")
            return False
        
        event = analysis["event"]
        
        if verbose:
            print(f"[OBSERVER] Learning from low-score execution (score: {analysis['score']:.2f})")
        
        # Evolve instructions (traditional learning)
        new_instructions = self.evolve(
            analysis["critique"],
            event.query,
            event.agent_response
        )
        
        # WISDOM CURATOR: Check if this update requires human policy review
        if self.enable_wisdom_curator:
            current_instructions = self.wisdom.get_system_prompt()
            
            if self.wisdom_curator.requires_policy_review(new_instructions, analysis["critique"]):
                if verbose:
                    print("[WISDOM CURATOR] 🛡️  Policy violation detected - creating review item")
                    violations = self.wisdom_curator.detect_policy_violations(new_instructions)
                    for violation_type, pattern in violations:
                        print(f"  ⚠️  {violation_type.value}: '{pattern}'")
                
                # Create policy review instead of auto-applying
                review_item = self.wisdom_curator.create_policy_review(
                    proposed_wisdom=new_instructions,
                    current_wisdom=current_instructions,
                    critique=analysis["critique"],
                    query=event.query,
                    response=event.agent_response
                )
                
                # Track statistics
                if results is not None:
                    results["curator_stats"]["policy_reviews_created"] += 1
                
                if verbose:
                    print(f"[WISDOM CURATOR] Created review item {review_item.review_id}")
                    print("[WISDOM CURATOR] Wisdom update BLOCKED pending human approval")
                
                # Return False because we didn't update wisdom (needs approval)
                return False
        
        # No policy violation or curator disabled - proceed with update
        # Update wisdom database
        self.wisdom.update_instructions(new_instructions, analysis["critique"], 
                                       query=event.query, response=event.agent_response)
        
        # Update prioritization framework with safety correction
        if self.enable_prioritization:
            user_id = self._extract_user_id(event)
            
            self.prioritization.learn_from_failure(
                query=event.query,
                critique=analysis["critique"],
                user_id=user_id,
                verbose=verbose
            )
        
        if verbose:
            print(f"[OBSERVER] Updated wisdom database to version {self.wisdom.instructions['version']}")
            if self.enable_prioritization:
                print("[OBSERVER] Updated prioritization framework with safety correction")
        
        return True
    
    def process_events(self, verbose: bool = True) -> Dict[str, Any]:
        """
        Process all unprocessed events from the stream.
        This is the main offline learning loop.
        """
        if verbose:
            print("="*60)
            print("OBSERVER: Starting Event Processing")
            print("="*60)
            if self.enable_prioritization:
                print("[PRIORITIZATION] Enabled - learning safety corrections")
            if self.enable_intent_metrics:
                print("[INTENT METRICS] Enabled - using intent-based evaluation")
            if self.enable_wisdom_curator:
                print("[WISDOM CURATOR] Enabled - policy review and strategic sampling")
            print("[SILENT SIGNALS] Enabled - detecting implicit feedback")
        
        # Get unprocessed events
        last_timestamp = self.checkpoint.get("last_processed_timestamp")
        events = self.event_stream.read_unprocessed(last_timestamp)
        
        if not events:
            if verbose:
                print("\nNo new events to process.")
            return {
                "events_processed": 0,
                "lessons_learned": 0
            }
        
        if verbose:
            print(f"\nFound {len(events)} unprocessed events")
        
        results = {
            "events_processed": 0,
            "lessons_learned": 0,
            "analyses": [],
            "signal_stats": {
                "undo_signals": 0,
                "abandonment_signals": 0,
                "acceptance_signals": 0
            },
            "intent_evaluations": {
                "troubleshooting_conversations": 0,
                "brainstorming_conversations": 0,
                "troubleshooting_failures": 0,
                "brainstorming_failures": 0
            },
            "curator_stats": {
                "strategic_samples_created": 0,
                "policy_reviews_created": 0
            }
        }
        
        # Track conversations we've evaluated
        evaluated_conversations = set()
        
        # Process each event
        for event in events:
            # Handle silent signal events
            if event.event_type.startswith("signal_"):
                signal_analysis = self.analyze_signal(event, verbose=verbose)
                
                if signal_analysis:
                    results["analyses"].append(signal_analysis)
                    
                    # Track signal statistics
                    if event.signal_type == "undo":
                        results["signal_stats"]["undo_signals"] += 1
                    elif event.signal_type == "abandonment":
                        results["signal_stats"]["abandonment_signals"] += 1
                    elif event.signal_type == "acceptance":
                        results["signal_stats"]["acceptance_signals"] += 1
                    
                    # Learn from signal (critical and high priority signals)
                    if self.learn_from_analysis(signal_analysis, verbose=verbose, results=results):
                        results["lessons_learned"] += 1
                        self.checkpoint["lessons_learned"] += 1
                
                results["events_processed"] += 1
                continue
            
            # Learn user preferences from feedback
            if self.enable_prioritization and event.user_feedback:
                user_id = self._extract_user_id(event)
                
                if user_id:
                    self.prioritization.learn_user_preference(
                        user_id=user_id,
                        query=event.query,
                        user_feedback=event.user_feedback,
                        verbose=verbose
                    )
            
            # Evaluate conversations by intent when we see task_complete events
            if self.enable_intent_metrics and event.event_type == "task_complete" and event.conversation_id:
                # Only evaluate each conversation once (when we see its last event)
                if event.conversation_id not in evaluated_conversations:
                    intent_eval = self.evaluate_conversation_by_intent(
                        event.conversation_id,
                        verbose=verbose
                    )
                    
                    if intent_eval:
                        evaluated_conversations.add(event.conversation_id)
                        
                        # Track statistics
                        intent_type = intent_eval["intent_type"]
                        if intent_type == "troubleshooting":
                            results["intent_evaluations"]["troubleshooting_conversations"] += 1
                            if intent_eval["needs_learning"]:
                                results["intent_evaluations"]["troubleshooting_failures"] += 1
                        elif intent_type == "brainstorming":
                            results["intent_evaluations"]["brainstorming_conversations"] += 1
                            if intent_eval["needs_learning"]:
                                results["intent_evaluations"]["brainstorming_failures"] += 1
                        
                        # Flag failures for learning
                        if intent_eval["needs_learning"]:
                            evaluation = intent_eval["evaluation"]
                            
                            # Create a critique based on intent-specific failure
                            critique = f"Intent-based evaluation failure: {evaluation['reasoning']}"
                            
                            # Create analysis for learning
                            intent_analysis = {
                                "event": event,
                                "score": 0.3,  # Low score for failures
                                "critique": critique,
                                "needs_learning": True,
                                "intent_evaluation": intent_eval
                            }
                            
                            results["analyses"].append(intent_analysis)
                            
                            # Learn from intent-based failure
                            if self.learn_from_analysis(intent_analysis, verbose=verbose, results=results):
                                results["lessons_learned"] += 1
                                self.checkpoint["lessons_learned"] += 1
            
            analysis = self.analyze_trace(event, verbose=verbose)
            
            if analysis:
                results["analyses"].append(analysis)
                
                # WISDOM CURATOR: Strategic sampling for high-level review
                if self.enable_wisdom_curator and self.wisdom_curator.should_sample_interaction():
                    sample_item = self.wisdom_curator.create_strategic_sample(
                        query=event.query,
                        agent_response=event.agent_response,
                        metadata={
                            "score": analysis.get("score"),
                            "event_id": event.timestamp,
                            "instructions_version": event.instructions_version
                        }
                    )
                    results["curator_stats"]["strategic_samples_created"] += 1
                    
                    if verbose:
                        print(f"[WISDOM CURATOR] 📊 Created strategic sample {sample_item.review_id}")
                
                # Learn if needed
                if self.learn_from_analysis(analysis, verbose=verbose, results=results):
                    results["lessons_learned"] += 1
                    self.checkpoint["lessons_learned"] += 1
            
            results["events_processed"] += 1
        
        # Update checkpoint
        if events:
            self.checkpoint["last_processed_timestamp"] = events[-1].timestamp
            self._save_checkpoint()
        
        if verbose:
            print("\n" + "="*60)
            print("OBSERVER: Processing Complete")
            print("="*60)
            print(f"Events Processed: {results['events_processed']}")
            print(f"Lessons Learned: {results['lessons_learned']}")
            print(f"Wisdom Version: {self.wisdom.instructions['version']}")
            print(f"\nSilent Signal Statistics:")
            print(f"  🚨 Undo Signals (Critical): {results['signal_stats']['undo_signals']}")
            print(f"  ⚠️ Abandonment Signals (Loss): {results['signal_stats']['abandonment_signals']}")
            print(f"  ✅ Acceptance Signals (Success): {results['signal_stats']['acceptance_signals']}")
            if self.enable_intent_metrics:
                print(f"\nIntent-Based Evaluation Statistics:")
                print(f"  🔧 Troubleshooting Conversations: {results['intent_evaluations']['troubleshooting_conversations']}")
                print(f"     ❌ Failed (>3 turns): {results['intent_evaluations']['troubleshooting_failures']}")
                print(f"  💡 Brainstorming Conversations: {results['intent_evaluations']['brainstorming_conversations']}")
                print(f"     ❌ Failed (too shallow): {results['intent_evaluations']['brainstorming_failures']}")
            if self.enable_prioritization:
                stats = self.prioritization.get_stats()
                print(f"\nPrioritization Framework Stats:")
                print(f"  Safety Corrections: {stats['recent_safety_corrections']} recent / {stats['total_safety_corrections']} total")
                print(f"  User Preferences: {stats['total_preferences']} for {stats['total_users_with_preferences']} users")
            if self.enable_wisdom_curator:
                curator_stats = self.wisdom_curator.get_review_stats()
                print(f"\nWisdom Curator Stats:")
                print(f"  📊 Strategic Samples Created: {results['curator_stats']['strategic_samples_created']}")
                print(f"  🛡️  Policy Reviews Pending: {curator_stats['by_type']['policy_review']['pending']}")
                print(f"  ✅ Policy Reviews Approved: {curator_stats['by_type']['policy_review']['approved']}")
                print(f"  ❌ Policy Reviews Rejected: {curator_stats['by_type']['policy_review']['rejected']}")
                print(f"  📋 Total Reviews in Queue: {curator_stats['pending']} pending / {curator_stats['total_reviews']} total")
        
        return results


def main():
    """Run the observer to process accumulated events."""
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file with your OpenAI API key")
        return
    
    print("Observer Agent - Offline Learning System")
    print("="*60)
    
    # Initialize observer
    observer = ObserverAgent()
    
    # Process all unprocessed events
    results = observer.process_events(verbose=True)
    
    print(f"\n\nSummary:")
    print(f"- Total events processed: {results['events_processed']}")
    print(f"- New lessons learned: {results['lessons_learned']}")
    print(f"- Total lessons learned (lifetime): {observer.checkpoint['lessons_learned']}")


if __name__ == "__main__":
    main()

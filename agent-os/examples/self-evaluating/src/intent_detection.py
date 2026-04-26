# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Intent Detection System

This module detects the user's intent from their first interaction
and applies appropriate success metrics based on that intent.

Intent Types:
1. Troubleshooting (Short-Lived): Users want quick resolution
   - Metric: Time-to-Resolution (turns to complete)
   - Success: <= 3 turns
   - Failure: > 3 turns means user is trapped, not engaged

2. Brainstorming (Long-Lived): Users want deep exploration
   - Metric: Depth of Context (conversation richness)
   - Success: Multi-turn deep conversation
   - Failure: Too short means we failed to be creative enough
"""

import json
import os
from typing import Dict, Any, Optional, Literal, List
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

IntentType = Literal["troubleshooting", "brainstorming", "unknown"]


class IntentDetector:
    """
    Detects user intent from their first interaction.
    
    This helps us understand what success looks like for different
    types of conversations.
    """
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = os.getenv("INTENT_MODEL", "gpt-4o-mini")
    
    def detect_intent(self, query: str, verbose: bool = False) -> Dict[str, Any]:
        """
        Detect the user's intent from their query.
        
        Args:
            query: The user's first query
            verbose: Print detection details
            
        Returns:
            Dictionary with:
            - intent: "troubleshooting" or "brainstorming"
            - confidence: 0-1 confidence score
            - reasoning: Explanation of the classification
        """
        
        detection_prompt = f"""You are an intent classification system for a productivity AI assistant.

Analyze the following user query and classify it into one of two intent types:

1. TROUBLESHOOTING (Short-Lived Intent):
   - User has a specific problem and wants a quick solution
   - Examples: "How do I reset my password?", "Why isn't this code working?", "Fix this error"
   - Success metric: Quick resolution in <= 3 turns
   - If this takes > 3 turns, the user is trapped, not engaged

2. BRAINSTORMING (Long-Lived Intent):
   - User wants to explore ideas, design systems, or have a deep discussion
   - Examples: "Help me design a microservices architecture", "Let's explore different approaches"
   - Success metric: Deep, multi-turn conversation with rich context
   - If this is too short, we failed to be creative enough

User Query: {query}

Analyze the query and provide your classification as JSON with:
- intent: Either "troubleshooting" or "brainstorming"
- confidence: A number between 0 and 1 (how confident are you in this classification)
- reasoning: A brief explanation of why you chose this classification

Return ONLY valid JSON in this format:
{{"intent": "troubleshooting", "confidence": 0.95, "reasoning": "User is asking for a specific fix"}}
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": detection_prompt}],
                temperature=0.1  # Low temperature for consistent classification
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response (handle markdown code blocks)
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(result_text)
            
            # Validate the intent type
            if result["intent"] not in ["troubleshooting", "brainstorming"]:
                result["intent"] = "unknown"
            
            if verbose:
                print(f"\n[INTENT DETECTION]")
                print(f"  Intent: {result['intent'].upper()}")
                print(f"  Confidence: {result['confidence']:.2f}")
                print(f"  Reasoning: {result['reasoning']}")
            
            return result
            
        except Exception as e:
            if verbose:
                print(f"[INTENT DETECTION] Error: {str(e)}")
            # Default to unknown if detection fails
            return {
                "intent": "unknown",
                "confidence": 0.0,
                "reasoning": f"Intent detection failed: {type(e).__name__}: {str(e)}"
            }


class IntentMetrics:
    """
    Evaluates conversation success based on detected intent.
    
    Different intents have different success criteria:
    - Troubleshooting: Fast resolution is success
    - Brainstorming: Deep exploration is success
    """
    
    @staticmethod
    def evaluate_troubleshooting(turn_count: int, resolved: bool = True) -> Dict[str, Any]:
        """
        Evaluate a troubleshooting conversation.
        
        Args:
            turn_count: Number of turns in the conversation
            resolved: Whether the issue was resolved
            
        Returns:
            Evaluation with success status and reasoning
        """
        max_acceptable_turns = 3
        
        if turn_count <= max_acceptable_turns and resolved:
            return {
                "success": True,
                "metric": "time_to_resolution",
                "turn_count": turn_count,
                "threshold": max_acceptable_turns,
                "reasoning": f"Issue resolved quickly in {turn_count} turns (threshold: {max_acceptable_turns})"
            }
        elif turn_count > max_acceptable_turns:
            return {
                "success": False,
                "metric": "time_to_resolution",
                "turn_count": turn_count,
                "threshold": max_acceptable_turns,
                "reasoning": f"User trapped in conversation: {turn_count} turns > {max_acceptable_turns} threshold. This is failure, not engagement."
            }
        else:
            return {
                "success": False,
                "metric": "time_to_resolution",
                "turn_count": turn_count,
                "threshold": max_acceptable_turns,
                "reasoning": f"Issue not resolved after {turn_count} turns"
            }
    
    @staticmethod
    def evaluate_brainstorming(turn_count: int, context_depth_score: float = 0.5) -> Dict[str, Any]:
        """
        Evaluate a brainstorming conversation.
        
        Args:
            turn_count: Number of turns in the conversation
            context_depth_score: 0-1 score for how deep/rich the conversation was
            
        Returns:
            Evaluation with success status and reasoning
        """
        min_acceptable_turns = 5
        min_acceptable_depth = 0.6
        
        if turn_count >= min_acceptable_turns and context_depth_score >= min_acceptable_depth:
            return {
                "success": True,
                "metric": "depth_of_context",
                "turn_count": turn_count,
                "depth_score": context_depth_score,
                "min_turns": min_acceptable_turns,
                "min_depth": min_acceptable_depth,
                "reasoning": f"Deep exploration achieved: {turn_count} turns with depth score {context_depth_score:.2f}"
            }
        elif turn_count < min_acceptable_turns:
            return {
                "success": False,
                "metric": "depth_of_context",
                "turn_count": turn_count,
                "depth_score": context_depth_score,
                "min_turns": min_acceptable_turns,
                "min_depth": min_acceptable_depth,
                "reasoning": f"Conversation too short ({turn_count} < {min_acceptable_turns}). We failed to be creative enough."
            }
        else:
            return {
                "success": False,
                "metric": "depth_of_context",
                "turn_count": turn_count,
                "depth_score": context_depth_score,
                "min_turns": min_acceptable_turns,
                "min_depth": min_acceptable_depth,
                "reasoning": f"Insufficient depth (score {context_depth_score:.2f} < {min_acceptable_depth})"
            }
    
    @staticmethod
    def calculate_context_depth(conversation_history: List[Dict[str, Any]], verbose: bool = False) -> float:
        """
        Calculate context depth score for a conversation.
        
        This is a simple heuristic based on:
        - Number of distinct topics/concepts discussed
        - Average response length
        - Back-and-forth engagement
        
        Args:
            conversation_history: List of conversation turns
            verbose: Print calculation details
            
        Returns:
            Depth score between 0 and 1
        """
        if not conversation_history:
            return 0.0
        
        # Simple heuristic: average response length normalized
        total_length = sum(len(turn.get("content", "")) for turn in conversation_history)
        avg_length = total_length / len(conversation_history)
        
        # Normalize to 0-1 (assuming 500 chars per turn is "deep")
        depth_score = min(avg_length / 500.0, 1.0)
        
        if verbose:
            print(f"\n[CONTEXT DEPTH]")
            print(f"  Total turns: {len(conversation_history)}")
            print(f"  Average length: {avg_length:.0f} chars")
            print(f"  Depth score: {depth_score:.2f}")
        
        return depth_score


def main():
    """Example usage of intent detection."""
    print("="*60)
    print("Intent Detection System")
    print("="*60)
    
    detector = IntentDetector()
    
    # Test troubleshooting queries
    troubleshooting_queries = [
        "How do I reset my password?",
        "Why isn't my code compiling?",
        "Fix this error: 'NullPointerException'",
    ]
    
    print("\n\nTROUBLESHOOTING QUERIES:")
    print("-" * 60)
    for query in troubleshooting_queries:
        print(f"\nQuery: {query}")
        result = detector.detect_intent(query, verbose=True)
    
    # Test brainstorming queries
    brainstorming_queries = [
        "Help me design a microservices architecture",
        "Let's explore different approaches to data modeling",
        "I want to discuss trade-offs between SQL and NoSQL",
    ]
    
    print("\n\nBRAINSTORMING QUERIES:")
    print("-" * 60)
    for query in brainstorming_queries:
        print(f"\nQuery: {query}")
        result = detector.detect_intent(query, verbose=True)
    
    # Test metrics evaluation
    print("\n\n" + "="*60)
    print("METRICS EVALUATION")
    print("="*60)
    
    print("\n\nTroubleshooting Scenarios:")
    print("-" * 60)
    
    # Good: Quick resolution
    result = IntentMetrics.evaluate_troubleshooting(turn_count=2, resolved=True)
    print(f"\nScenario: 2 turns, resolved")
    print(f"Success: {result['success']}")
    print(f"Reasoning: {result['reasoning']}")
    
    # Bad: Too many turns (trapped)
    result = IntentMetrics.evaluate_troubleshooting(turn_count=5, resolved=True)
    print(f"\nScenario: 5 turns, resolved")
    print(f"Success: {result['success']}")
    print(f"Reasoning: {result['reasoning']}")
    
    print("\n\nBrainstorming Scenarios:")
    print("-" * 60)
    
    # Good: Deep conversation
    result = IntentMetrics.evaluate_brainstorming(turn_count=10, context_depth_score=0.8)
    print(f"\nScenario: 10 turns, depth 0.8")
    print(f"Success: {result['success']}")
    print(f"Reasoning: {result['reasoning']}")
    
    # Bad: Too short
    result = IntentMetrics.evaluate_brainstorming(turn_count=2, context_depth_score=0.5)
    print(f"\nScenario: 2 turns, depth 0.5")
    print(f"Success: {result['success']}")
    print(f"Reasoning: {result['reasoning']}")


if __name__ == "__main__":
    main()

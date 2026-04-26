# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Prioritization Framework - Graph-based Context Ranking System

This module implements a three-layer prioritization system that ranks
retrieved context based on a hierarchy of needs:

1. Safety Layer (Highest Priority): Recent failures and corrections
2. Personalization Layer (Medium Priority): User-specific preferences
3. Global Wisdom Layer (Low Priority): Generic best practices

The framework sits between the wisdom database and the agent, providing
ranked strategies that help the agent avoid past mistakes and respect
user preferences.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class SafetyCorrection:
    """Represents a correction for a past failure."""
    
    task_pattern: str  # Pattern/description of the task that failed
    failure_description: str  # What went wrong
    correction: str  # How to avoid this failure
    timestamp: str  # When this failure occurred
    user_id: Optional[str] = None  # User who experienced this failure
    occurrences: int = 1  # Number of times this failure occurred
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SafetyCorrection':
        return cls(**data)


@dataclass
class UserPreference:
    """Represents a user-specific preference or constraint."""
    
    user_id: str
    preference_key: str  # e.g., "output_format", "verbosity", "tool_preference"
    preference_value: str  # e.g., "JSON", "concise", "always_use_calculator"
    description: str  # Human-readable description
    priority: int = 5  # Priority level (1-10, higher = more important)
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserPreference':
        return cls(**data)


@dataclass
class PrioritizedContext:
    """Container for prioritized context with different layers."""
    
    safety_items: List[str]  # High priority safety corrections
    personalization_items: List[str]  # Medium priority user preferences
    global_wisdom: str  # Low priority general instructions
    
    def build_system_prompt(self) -> str:
        """Build a system prompt with prioritized context."""
        prompt_parts = []
        
        # Start with global wisdom (foundation)
        prompt_parts.append(self.global_wisdom)
        
        # Add personalization layer (medium priority)
        if self.personalization_items:
            prompt_parts.append("\n\n## USER PREFERENCES (Important)")
            prompt_parts.append("You must respect these user-specific constraints:")
            for i, pref in enumerate(self.personalization_items, 1):
                prompt_parts.append(f"{i}. {pref}")
        
        # Add safety layer (highest priority - most visible)
        if self.safety_items:
            prompt_parts.append("\n\n## ⚠️ CRITICAL SAFETY WARNINGS (Highest Priority)")
            prompt_parts.append("You MUST specifically avoid these mistakes from recent failures:")
            for i, safety in enumerate(self.safety_items, 1):
                prompt_parts.append(f"{i}. {safety}")
        
        return "\n".join(prompt_parts)


class PrioritizationFramework:
    """
    Main prioritization framework that ranks context based on:
    - Safety: Recent failures and corrections
    - Personalization: User-specific preferences
    - Global Wisdom: Generic best practices
    """
    
    # Configuration constants
    MIN_KEYWORD_OVERLAP = 2  # Minimum matching words for relevance
    
    def __init__(self,
                 safety_db_file: str = "safety_corrections.json",
                 preferences_db_file: str = "user_preferences.json",
                 failure_window_hours: int = 168):  # 7 days
        self.safety_db_file = safety_db_file
        self.preferences_db_file = preferences_db_file
        self.failure_window_hours = failure_window_hours
        
        # Load databases
        self.safety_corrections: List[SafetyCorrection] = self._load_safety_corrections()
        self.user_preferences: Dict[str, List[UserPreference]] = self._load_user_preferences()
    
    def _load_safety_corrections(self) -> List[SafetyCorrection]:
        """Load safety corrections from disk."""
        if not os.path.exists(self.safety_db_file):
            return []
        
        try:
            with open(self.safety_db_file, 'r') as f:
                data = json.load(f)
                return [SafetyCorrection.from_dict(item) for item in data.get('corrections', [])]
        except Exception as e:
            print(f"Warning: Failed to load safety corrections: {e}")
            return []
    
    def _save_safety_corrections(self) -> None:
        """Save safety corrections to disk."""
        data = {
            'corrections': [c.to_dict() for c in self.safety_corrections],
            'last_updated': datetime.now().isoformat()
        }
        with open(self.safety_db_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_user_preferences(self) -> Dict[str, List[UserPreference]]:
        """Load user preferences from disk."""
        if not os.path.exists(self.preferences_db_file):
            return {}
        
        try:
            with open(self.preferences_db_file, 'r') as f:
                data = json.load(f)
                preferences = defaultdict(list)
                for user_id, prefs in data.get('preferences', {}).items():
                    preferences[user_id] = [UserPreference.from_dict(p) for p in prefs]
                return dict(preferences)
        except Exception as e:
            print(f"Warning: Failed to load user preferences: {e}")
            return {}
    
    def _save_user_preferences(self) -> None:
        """Save user preferences to disk."""
        data = {
            'preferences': {
                user_id: [p.to_dict() for p in prefs]
                for user_id, prefs in self.user_preferences.items()
            },
            'last_updated': datetime.now().isoformat()
        }
        with open(self.preferences_db_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_safety_correction(self,
                            task_pattern: str,
                            failure_description: str,
                            correction: str,
                            user_id: Optional[str] = None) -> None:
        """
        Add a new safety correction based on a failure.
        
        Args:
            task_pattern: Description of the task that failed
            failure_description: What went wrong
            correction: How to avoid this failure
            user_id: Optional user who experienced the failure
        """
        # Check if similar correction exists
        for existing in self.safety_corrections:
            if (existing.task_pattern == task_pattern and 
                existing.user_id == user_id):
                # Update existing correction
                existing.failure_description = failure_description
                existing.correction = correction
                existing.timestamp = datetime.now().isoformat()
                existing.occurrences += 1
                self._save_safety_corrections()
                return
        
        # Add new correction
        new_correction = SafetyCorrection(
            task_pattern=task_pattern,
            failure_description=failure_description,
            correction=correction,
            timestamp=datetime.now().isoformat(),
            user_id=user_id
        )
        self.safety_corrections.append(new_correction)
        self._save_safety_corrections()
    
    def add_user_preference(self,
                           user_id: str,
                           preference_key: str,
                           preference_value: str,
                           description: str,
                           priority: int = 5) -> None:
        """
        Add or update a user preference.
        
        Args:
            user_id: User identifier
            preference_key: Type of preference (e.g., "output_format")
            preference_value: Value of preference (e.g., "JSON")
            description: Human-readable description
            priority: Priority level (1-10, higher = more important)
        """
        if user_id not in self.user_preferences:
            self.user_preferences[user_id] = []
        
        # Check if preference exists
        for pref in self.user_preferences[user_id]:
            if pref.preference_key == preference_key:
                # Update existing preference
                pref.preference_value = preference_value
                pref.description = description
                pref.priority = priority
                pref.timestamp = datetime.now().isoformat()
                self._save_user_preferences()
                return
        
        # Add new preference
        new_pref = UserPreference(
            user_id=user_id,
            preference_key=preference_key,
            preference_value=preference_value,
            description=description,
            priority=priority
        )
        self.user_preferences[user_id].append(new_pref)
        self._save_user_preferences()
    
    def _get_recent_safety_corrections(self,
                                      query: str,
                                      user_id: Optional[str] = None) -> List[str]:
        """
        Get recent safety corrections relevant to the query.
        
        Returns formatted safety warnings for high-priority injection.
        """
        cutoff_time = datetime.now() - timedelta(hours=self.failure_window_hours)
        recent_corrections = []
        
        for correction in self.safety_corrections:
            # Check if correction is recent
            correction_time = datetime.fromisoformat(correction.timestamp)
            if correction_time < cutoff_time:
                continue
            
            # Check if correction is relevant to this user
            if user_id and correction.user_id and correction.user_id != user_id:
                continue
            
            # Note: In production, use semantic similarity (e.g., embeddings) to match
            # query with task_pattern. This simple keyword matching is a placeholder.
            # See PRIORITIZATION_FRAMEWORK.md for future enhancement details.
            query_lower = query.lower()
            pattern_lower = correction.task_pattern.lower()
            
            # Simple keyword overlap check
            query_words = set(query_lower.split())
            pattern_words = set(pattern_lower.split())
            overlap = len(query_words & pattern_words)
            
            if overlap >= self.MIN_KEYWORD_OVERLAP or any(word in query_lower for word in pattern_words):
                # Format the safety warning
                urgency = "CRITICAL" if correction.occurrences > 2 else "WARNING"
                warning = (
                    f"[{urgency}] Task similar to '{correction.task_pattern}' failed recently "
                    f"({correction.occurrences}x in last {self.failure_window_hours}h). "
                    f"Issue: {correction.failure_description}. "
                    f"MUST DO: {correction.correction}"
                )
                recent_corrections.append(warning)
        
        return recent_corrections
    
    def _get_user_preferences_formatted(self, user_id: Optional[str]) -> List[str]:
        """
        Get formatted user preferences for the personalization layer.
        """
        if not user_id or user_id not in self.user_preferences:
            return []
        
        # Sort by priority (highest first)
        prefs = sorted(
            self.user_preferences[user_id],
            key=lambda p: p.priority,
            reverse=True
        )
        
        formatted = []
        for pref in prefs:
            formatted.append(
                f"[{pref.preference_key}] {pref.description} → {pref.preference_value}"
            )
        
        return formatted
    
    def get_prioritized_context(self,
                               query: str,
                               global_wisdom: str,
                               user_id: Optional[str] = None,
                               verbose: bool = False) -> PrioritizedContext:
        """
        Main method: Get prioritized context for a query.
        
        Args:
            query: User's query/task
            global_wisdom: Base system instructions
            user_id: Optional user identifier for personalization
            verbose: Print prioritization details
        
        Returns:
            PrioritizedContext with ranked strategy
        """
        # Layer 1: Safety (Highest Priority)
        safety_items = self._get_recent_safety_corrections(query, user_id)
        
        # Layer 2: Personalization (Medium Priority)
        personalization_items = self._get_user_preferences_formatted(user_id)
        
        # Layer 3: Global Wisdom (Low Priority)
        # This is passed as-is from the wisdom database
        
        if verbose:
            print(f"\n[PRIORITIZATION] Context ranking for query: {query}")
            print(f"  Safety corrections: {len(safety_items)}")
            print(f"  User preferences: {len(personalization_items)}")
            print(f"  Global wisdom: {len(global_wisdom)} chars")
        
        return PrioritizedContext(
            safety_items=safety_items,
            personalization_items=personalization_items,
            global_wisdom=global_wisdom
        )
    
    def learn_from_failure(self,
                          query: str,
                          critique: str,
                          user_id: Optional[str] = None,
                          verbose: bool = False) -> None:
        """
        Extract safety corrections from failure critique.
        
        This is called by the Observer when it detects a failure.
        
        Note: In production, use LLM to extract structured failure information.
        This simple heuristic extraction is a placeholder.
        See PRIORITIZATION_FRAMEWORK.md for future enhancement details.
        """
        if verbose:
            print(f"\n[PRIORITIZATION] Learning from failure on: {query}")
        
        # Extract key information from critique
        task_pattern = query[:100]  # Use query as task pattern
        failure_description = critique[:200]  # First part of critique
        
        # Extract correction suggestion from critique
        correction_phrases = [
            "should", "must", "need to", "ought to", "have to",
            "avoid", "don't", "ensure", "make sure"
        ]
        
        correction = "Review critique and avoid repeating this mistake"
        for phrase in correction_phrases:
            if phrase in critique.lower():
                # Find sentence containing the phrase
                sentences = critique.split('.')
                for sent in sentences:
                    if phrase in sent.lower():
                        correction = sent.strip()
                        break
                break
        
        self.add_safety_correction(
            task_pattern=task_pattern,
            failure_description=failure_description,
            correction=correction,
            user_id=user_id
        )
        
        if verbose:
            print(f"  Added safety correction for future similar tasks")
    
    def learn_user_preference(self,
                            user_id: str,
                            query: str,
                            user_feedback: str,
                            verbose: bool = False) -> None:
        """
        Extract user preferences from feedback.
        
        This is called when user provides feedback on agent behavior.
        
        Note: In production, use LLM to extract structured preferences.
        This pattern-based extraction is a placeholder for common cases.
        See PRIORITIZATION_FRAMEWORK.md for future enhancement details.
        """
        if verbose:
            print(f"\n[PRIORITIZATION] Learning user preference from feedback")
        
        feedback_lower = user_feedback.lower()
        
        # Detect output format preferences
        if "json" in feedback_lower and "format" in feedback_lower:
            self.add_user_preference(
                user_id=user_id,
                preference_key="output_format",
                preference_value="JSON",
                description="Always use JSON output format",
                priority=8
            )
        elif "concise" in feedback_lower or "brief" in feedback_lower:
            self.add_user_preference(
                user_id=user_id,
                preference_key="verbosity",
                preference_value="concise",
                description="Keep responses concise and brief",
                priority=6
            )
        elif "detailed" in feedback_lower or "verbose" in feedback_lower:
            self.add_user_preference(
                user_id=user_id,
                preference_key="verbosity",
                preference_value="detailed",
                description="Provide detailed and comprehensive responses",
                priority=6
            )
        
        # Detect tool usage preferences
        if "calculator" in feedback_lower and ("use" in feedback_lower or "always" in feedback_lower):
            self.add_user_preference(
                user_id=user_id,
                preference_key="tool_preference",
                preference_value="calculator",
                description="Always use calculator tool for mathematical operations",
                priority=7
            )
        
        if verbose:
            print(f"  Extracted and stored user preferences")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the prioritization framework."""
        recent_cutoff = datetime.now() - timedelta(hours=self.failure_window_hours)
        recent_corrections = sum(
            1 for c in self.safety_corrections
            if datetime.fromisoformat(c.timestamp) >= recent_cutoff
        )
        
        return {
            "total_safety_corrections": len(self.safety_corrections),
            "recent_safety_corrections": recent_corrections,
            "total_users_with_preferences": len(self.user_preferences),
            "total_preferences": sum(len(prefs) for prefs in self.user_preferences.values()),
            "failure_window_hours": self.failure_window_hours
        }


def main():
    """Example usage of the prioritization framework."""
    print("="*60)
    print("Prioritization Framework - Example Usage")
    print("="*60)
    
    # Initialize framework
    framework = PrioritizationFramework()
    
    # Example 1: Add a safety correction
    print("\n1. Adding safety correction from past failure...")
    framework.add_safety_correction(
        task_pattern="calculate mathematical expression",
        failure_description="Agent calculated in its head instead of using calculator tool",
        correction="MUST use the calculate() tool for any mathematical operations",
        user_id="user123"
    )
    
    # Example 2: Add user preferences
    print("\n2. Adding user preferences...")
    framework.add_user_preference(
        user_id="user123",
        preference_key="output_format",
        preference_value="JSON",
        description="Always provide output in JSON format",
        priority=9
    )
    
    framework.add_user_preference(
        user_id="user123",
        preference_key="verbosity",
        preference_value="concise",
        description="Keep responses brief and to the point",
        priority=6
    )
    
    # Example 3: Get prioritized context
    print("\n3. Getting prioritized context for query...")
    query = "What is 25 * 4 + 100?"
    global_wisdom = "You are a helpful AI assistant with access to tools."
    
    context = framework.get_prioritized_context(
        query=query,
        global_wisdom=global_wisdom,
        user_id="user123",
        verbose=True
    )
    
    print("\n4. Generated system prompt with prioritization:")
    print("-" * 60)
    print(context.build_system_prompt())
    print("-" * 60)
    
    # Example 4: Show stats
    print("\n5. Framework statistics:")
    stats = framework.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()

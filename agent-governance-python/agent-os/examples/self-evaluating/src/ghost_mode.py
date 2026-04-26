# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ghost Mode (Passive Observation) - The Observer Daemon Pattern

This module implements the "No UI" paradigm where the Interface Layer sits
in the background (Ghost Mode), consuming signal streams silently and only
surfacing when it has high-confidence value.

Key Concepts:
- Observer Daemon: Background process that watches without interfering
- Dry Run Flag: Analyzes signals without taking action
- Confidence-Based Surfacing: Only interrupts when highly confident
- Context Shadow: Learns user workflows and behavior patterns
- Behavior Model: Local, secure storage of user-specific patterns

The Setup: The Interface Layer sits in the background (Ghost Mode).
The Loop: It consumes the signal stream silently. It sends data to the Agent with a "Dry Run" flag.
The Trigger: It only surfaces when it has high-confidence value.

The Lesson:
The future interface isn't a "Destination" (a website). 
It is a Daemon (a background process). 
It is invisible until it is indispensable.
"""

import json
import os
import time
import threading
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ConfidenceLevel(Enum):
    """Confidence levels for surfacing decisions."""
    LOW = "low"           # < 0.5: Don't surface
    MEDIUM = "medium"     # 0.5-0.7: Maybe surface (depends on context)
    HIGH = "high"         # 0.7-0.9: Probably surface
    CRITICAL = "critical" # > 0.9: Always surface


@dataclass
class BehaviorPattern:
    """
    A learned behavior pattern from user workflows.
    
    Example: "How they file expenses"
    - Trigger: User opens expense report
    - Steps: [Open form, Attach receipt, Fill amount, Submit]
    - Frequency: 15 times/month
    - Last seen: 2024-01-01
    """
    pattern_id: str
    name: str
    description: str
    trigger: str  # What initiates this pattern
    steps: List[str]  # Sequence of actions
    frequency: int  # How often this pattern occurs
    last_seen: str  # ISO timestamp
    confidence: float = 0.0  # 0-1, how confident we are this is a real pattern
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger,
            "steps": self.steps,
            "frequency": self.frequency,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "metadata": self.metadata
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'BehaviorPattern':
        """Create from dictionary."""
        return BehaviorPattern(
            pattern_id=data["pattern_id"],
            name=data["name"],
            description=data["description"],
            trigger=data["trigger"],
            steps=data["steps"],
            frequency=data["frequency"],
            last_seen=data["last_seen"],
            confidence=data.get("confidence", 0.0),
            metadata=data.get("metadata", {})
        )


@dataclass
class ObservationResult:
    """
    Result of passive observation with confidence scoring.
    
    This represents what the observer learned without interfering.
    """
    timestamp: str
    signal_type: str
    observation: str  # What was observed
    confidence: float  # 0-1, how confident are we in this observation
    should_surface: bool  # Should we surface this to the user?
    recommendation: Optional[str] = None  # What to suggest (if surfacing)
    dry_run_result: Optional[Dict[str, Any]] = None  # Result of dry run analysis
    context: Dict[str, Any] = field(default_factory=dict)
    
    def get_confidence_level(self) -> ConfidenceLevel:
        """Get confidence level enum."""
        if self.confidence < 0.5:
            return ConfidenceLevel.LOW
        elif self.confidence < 0.7:
            return ConfidenceLevel.MEDIUM
        elif self.confidence < 0.9:
            return ConfidenceLevel.HIGH
        else:
            return ConfidenceLevel.CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "signal_type": self.signal_type,
            "observation": self.observation,
            "confidence": self.confidence,
            "confidence_level": self.get_confidence_level().value,
            "should_surface": self.should_surface,
            "recommendation": self.recommendation,
            "dry_run_result": self.dry_run_result,
            "context": self.context
        }


class ContextShadow:
    """
    Context Shadow: A secure local storage for user behavior patterns.
    
    This is the "Cookies of the real world" - a way to store user context
    that can be queried by other Agents.
    
    Example Use Case:
    - Learn: "User files expenses on Fridays at 4pm"
    - Store: Pattern with trigger, steps, and confidence
    - Query: "What does this user do on Friday afternoons?"
    - Answer: "High confidence they'll file expenses"
    """
    
    def __init__(self, storage_file: str = "behavior_model.json", user_id: Optional[str] = None):
        self.storage_file = storage_file
        self.user_id = user_id
        self.patterns: Dict[str, BehaviorPattern] = {}
        self._load_patterns()
    
    def _load_patterns(self) -> None:
        """Load behavior patterns from storage."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    
                    # Filter by user if user_id specified
                    patterns_data = data.get("patterns", {})
                    if self.user_id:
                        patterns_data = {
                            k: v for k, v in patterns_data.items()
                            if v.get("metadata", {}).get("user_id") == self.user_id
                        }
                    
                    self.patterns = {
                        k: BehaviorPattern.from_dict(v)
                        for k, v in patterns_data.items()
                    }
            except (json.JSONDecodeError, IOError):
                self.patterns = {}
    
    def _save_patterns(self) -> None:
        """Save behavior patterns to storage."""
        # Load existing data to preserve other users' patterns
        existing_data = {"patterns": {}}
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    existing_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Update with current user's patterns
        all_patterns = existing_data.get("patterns", {})
        for pattern_id, pattern in self.patterns.items():
            all_patterns[pattern_id] = pattern.to_dict()
        
        # Save
        with open(self.storage_file, 'w') as f:
            json.dump({"patterns": all_patterns}, f, indent=2)
    
    def learn_pattern(self, pattern: BehaviorPattern) -> None:
        """
        Learn a new behavior pattern.
        
        Args:
            pattern: Behavior pattern to learn
        """
        # Add user_id to metadata if available
        if self.user_id and "user_id" not in pattern.metadata:
            pattern.metadata["user_id"] = self.user_id
        
        # If pattern exists, update frequency
        if pattern.pattern_id in self.patterns:
            existing = self.patterns[pattern.pattern_id]
            existing.frequency += 1
            existing.last_seen = pattern.last_seen
            # Increase confidence with frequency (cap at 0.95)
            existing.confidence = min(0.95, existing.confidence + 0.05)
        else:
            self.patterns[pattern.pattern_id] = pattern
        
        self._save_patterns()
    
    def query_patterns(self, trigger: Optional[str] = None,
                      min_confidence: float = 0.5,
                      reload: bool = False) -> List[BehaviorPattern]:
        """
        Query learned behavior patterns.
        
        Args:
            trigger: Optional trigger to filter by
            min_confidence: Minimum confidence threshold
            reload: Whether to reload patterns from file first
            
        Returns:
            List of matching patterns
        """
        # Reload patterns if requested (useful for multi-user scenarios)
        if reload:
            self._load_patterns()
        
        patterns = list(self.patterns.values())
        
        # Filter by trigger if specified
        if trigger:
            patterns = [p for p in patterns if trigger.lower() in p.trigger.lower()]
        
        # Filter by confidence
        patterns = [p for p in patterns if p.confidence >= min_confidence]
        
        # Sort by confidence (highest first)
        patterns.sort(key=lambda p: p.confidence, reverse=True)
        
        return patterns
    
    def get_pattern(self, pattern_id: str) -> Optional[BehaviorPattern]:
        """Get a specific pattern by ID."""
        return self.patterns.get(pattern_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about learned patterns."""
        if not self.patterns:
            return {
                "total_patterns": 0,
                "high_confidence_patterns": 0,
                "average_confidence": 0.0
            }
        
        confidences = [p.confidence for p in self.patterns.values()]
        high_confidence_count = sum(1 for c in confidences if c >= 0.7)
        
        return {
            "total_patterns": len(self.patterns),
            "high_confidence_patterns": high_confidence_count,
            "average_confidence": sum(confidences) / len(confidences),
            "most_frequent_pattern": max(
                self.patterns.values(),
                key=lambda p: p.frequency
            ).name if self.patterns else None
        }


class GhostModeObserver:
    """
    Ghost Mode Observer: The background daemon that watches silently.
    
    This is the "No UI" paradigm - a background process that:
    1. Consumes signal streams without blocking
    2. Runs dry-run analysis without taking action
    3. Only surfaces when confidence is high
    4. Learns user behavior patterns over time
    
    The observer is invisible until indispensable.
    """
    
    def __init__(self,
                 context_shadow: Optional[ContextShadow] = None,
                 confidence_threshold: float = 0.7,
                 surfacing_callback: Optional[Callable[[ObservationResult], None]] = None):
        """
        Initialize Ghost Mode Observer.
        
        Args:
            context_shadow: Context shadow for storing behavior patterns
            confidence_threshold: Minimum confidence to surface (default 0.7, must be 0.0-1.0)
            surfacing_callback: Optional callback when surfacing is triggered
            
        Raises:
            ValueError: If confidence_threshold is not in range 0.0-1.0
        """
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError(f"confidence_threshold must be between 0.0 and 1.0, got {confidence_threshold}")
        
        self.context_shadow = context_shadow or ContextShadow()
        self.confidence_threshold = confidence_threshold
        self.surfacing_callback = surfacing_callback
        
        # Observation state
        self.is_running = False
        self.observation_thread: Optional[threading.Thread] = None
        self.observations: List[ObservationResult] = []
        self.signals_processed = 0
        self.signals_surfaced = 0
        
        # For demo purposes, track recent signals
        self._signal_buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def start_observing(self, poll_interval: float = 1.0) -> None:
        """
        Start the observer daemon in background mode.
        
        Args:
            poll_interval: How often to check for new signals (seconds)
        """
        if self.is_running:
            return
        
        self.is_running = True
        self.observation_thread = threading.Thread(
            target=self._observation_loop,
            args=(poll_interval,),
            daemon=True
        )
        self.observation_thread.start()
    
    def stop_observing(self) -> None:
        """Stop the observer daemon."""
        self.is_running = False
        if self.observation_thread:
            self.observation_thread.join(timeout=2.0)
    
    def _observation_loop(self, poll_interval: float) -> None:
        """
        Main observation loop that runs in the background.
        
        This continuously polls for signals and processes them silently.
        """
        while self.is_running:
            try:
                # Check for new signals
                with self._lock:
                    signals = self._signal_buffer.copy()
                    self._signal_buffer.clear()
                
                # Process each signal in dry-run mode
                for signal in signals:
                    observation = self._process_signal_dry_run(signal)
                    self.observations.append(observation)
                    self.signals_processed += 1
                    
                    # Check if we should surface this observation
                    if observation.should_surface:
                        self.signals_surfaced += 1
                        self._surface_observation(observation)
                
                # Sleep before next poll
                time.sleep(poll_interval)
                
            except Exception as e:
                # Log error but keep running
                logger.error(f"Error in observation loop: {e}", exc_info=True)
                time.sleep(poll_interval)
    
    def observe_signal(self, signal: Dict[str, Any]) -> None:
        """
        Observe a signal without blocking.
        
        This is the entry point for signals. The signal is queued
        and will be processed asynchronously by the daemon.
        
        Args:
            signal: Signal data to observe
        """
        with self._lock:
            self._signal_buffer.append(signal)
    
    def _process_signal_dry_run(self, signal: Dict[str, Any]) -> ObservationResult:
        """
        Process a signal in dry-run mode (no actions taken).
        
        This analyzes the signal and determines:
        1. What was observed
        2. Confidence in the observation
        3. Whether to surface to user
        4. What to recommend if surfacing
        
        Args:
            signal: Signal data
            
        Returns:
            ObservationResult with analysis
        """
        signal_type = signal.get("type", "unknown")
        timestamp = datetime.now().isoformat()
        
        # Extract context from signal
        context = signal.get("context", {})
        user_id = signal.get("user_id")
        
        # Dry-run analysis: What would we do with this signal?
        dry_run_result = self._analyze_signal(signal)
        
        # Calculate confidence based on:
        # 1. Signal clarity (do we understand it?)
        # 2. Pattern match (have we seen similar before?)
        # 3. Context completeness (do we have enough info?)
        confidence = self._calculate_confidence(signal, dry_run_result)
        
        # Determine if we should surface
        should_surface = confidence >= self.confidence_threshold
        
        # Generate observation and recommendation
        observation = dry_run_result.get("observation", f"Observed {signal_type} signal")
        recommendation = dry_run_result.get("recommendation") if should_surface else None
        
        # Learn patterns from this observation
        if dry_run_result.get("pattern"):
            self.context_shadow.learn_pattern(dry_run_result["pattern"])
        
        return ObservationResult(
            timestamp=timestamp,
            signal_type=signal_type,
            observation=observation,
            confidence=confidence,
            should_surface=should_surface,
            recommendation=recommendation,
            dry_run_result=dry_run_result,
            context=context
        )
    
    def _analyze_signal(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a signal to understand what's happening.
        
        This is where the "intelligence" of the observer lives.
        In a real system, this might use ML models or heuristics.
        
        Args:
            signal: Signal data
            
        Returns:
            Analysis results including observation and recommendations
        """
        signal_type = signal.get("type", "unknown")
        data = signal.get("data", {})
        
        # Example heuristics for different signal types
        if signal_type == "file_change":
            return self._analyze_file_change(data)
        elif signal_type == "log_stream":
            return self._analyze_log_stream(data)
        elif signal_type == "user_action":
            return self._analyze_user_action(data)
        else:
            return {
                "observation": f"Unknown signal type: {signal_type}",
                "recommendation": None,
                "pattern": None
            }
    
    def _analyze_file_change(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file change signals."""
        file_path = data.get("file_path", "")
        change_type = data.get("change_type", "")
        
        # Check for security concerns
        if "password" in file_path.lower() or "secret" in file_path.lower():
            return {
                "observation": f"Security-sensitive file modified: {file_path}",
                "recommendation": "Consider reviewing security implications of this change",
                "pattern": None
            }
        
        # Check for test files
        if "test" in file_path.lower():
            return {
                "observation": f"Test file modified: {file_path}",
                "recommendation": "Remember to run tests after changes",
                "pattern": None
            }
        
        return {
            "observation": f"File {change_type}: {file_path}",
            "recommendation": None,
            "pattern": None
        }
    
    def _analyze_log_stream(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze log stream signals."""
        level = data.get("level", "INFO")
        message = data.get("message", "")
        
        # Check for errors
        if level in ["ERROR", "CRITICAL"]:
            return {
                "observation": f"Error detected: {message[:100]}",
                "recommendation": f"Investigate {level} in logs",
                "pattern": None
            }
        
        return {
            "observation": f"Log entry: [{level}] {message[:100]}",
            "recommendation": None,
            "pattern": None
        }
    
    def _analyze_user_action(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user action signals and learn patterns."""
        action = data.get("action", "")
        sequence = data.get("sequence", [])
        
        # Check if this matches a known pattern
        matching_patterns = self.context_shadow.query_patterns(
            trigger=action,
            min_confidence=0.5
        )
        
        if matching_patterns:
            pattern = matching_patterns[0]
            return {
                "observation": f"User action matches known pattern: {pattern.name}",
                "recommendation": f"Suggest next step: {pattern.steps[-1] if pattern.steps else 'complete workflow'}",
                "pattern": None  # Don't re-learn, already exists
            }
        
        # Learn new pattern if sequence is long enough
        if len(sequence) >= 3:
            pattern = BehaviorPattern(
                pattern_id=f"pattern_{len(self.context_shadow.patterns) + 1}",
                name=f"Workflow: {action}",
                description=f"User workflow starting with {action}",
                trigger=action,
                steps=sequence,
                frequency=1,
                last_seen=datetime.now().isoformat(),
                confidence=0.5  # Start with medium confidence
            )
            
            return {
                "observation": f"Learning new workflow pattern: {action}",
                "recommendation": None,
                "pattern": pattern
            }
        
        return {
            "observation": f"User action: {action}",
            "recommendation": None,
            "pattern": None
        }
    
    def _calculate_confidence(self, signal: Dict[str, Any], 
                            analysis: Dict[str, Any]) -> float:
        """
        Calculate confidence score for the observation.
        
        Factors:
        1. Signal clarity: Do we have all required fields?
        2. Pattern match: Have we seen this before?
        3. Analysis quality: Did we extract meaningful insights?
        
        Args:
            signal: Original signal
            analysis: Analysis results
            
        Returns:
            Confidence score (0-1)
        """
        confidence = 0.5  # Start at medium
        
        # Factor 1: Signal clarity
        required_fields = ["type", "data"]
        if all(field in signal for field in required_fields):
            confidence += 0.1
        
        # Factor 2: Pattern match
        if analysis.get("pattern"):
            confidence += 0.2
        
        # Factor 3: Has recommendation
        if analysis.get("recommendation"):
            confidence += 0.2
        
        # Factor 4: Security or critical signal
        if "security" in str(analysis.get("observation", "")).lower():
            confidence += 0.3
        if "error" in str(analysis.get("observation", "")).lower():
            confidence += 0.2
        
        # Cap at 1.0
        return min(1.0, confidence)
    
    def _surface_observation(self, observation: ObservationResult) -> None:
        """
        Surface an observation to the user.
        
        This is called when confidence exceeds threshold.
        In a real system, this might show a notification, log entry,
        or trigger an action.
        
        Args:
            observation: Observation to surface
        """
        # Call the surfacing callback if provided
        if self.surfacing_callback:
            try:
                self.surfacing_callback(observation)
            except Exception as e:
                logger.error(f"Error in surfacing callback: {e}", exc_info=True)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about observation activity."""
        context_stats = self.context_shadow.get_stats()
        
        surfacing_rate = (
            self.signals_surfaced / self.signals_processed
            if self.signals_processed > 0 else 0.0
        )
        
        return {
            "is_running": self.is_running,
            "signals_processed": self.signals_processed,
            "signals_surfaced": self.signals_surfaced,
            "surfacing_rate": surfacing_rate,
            "total_observations": len(self.observations),
            "context_shadow": context_stats
        }
    
    def get_recent_observations(self, limit: int = 10) -> List[ObservationResult]:
        """Get recent observations."""
        return self.observations[-limit:]

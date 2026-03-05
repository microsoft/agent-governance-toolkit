# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Universal Signal Bus - Omni-Channel Ingestion

This module implements an "Input Agnostic" architecture where the agent
can accept signals from ANY source - not just text queries.

The Interface Layer sits above the Agent and normalizes wild, unstructured
signals into a standard Context Object.

Sources can include:
- File Change Events (VS Code, IDE)
- Log Streams (System errors, 500 errors)
- Audio Streams (Voice, Meetings)
- Traditional Text Input (backward compatibility)
- API Events, DOM Events, Clickstream, etc.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Protocol, Union
from datetime import datetime
from enum import Enum
import json


class SignalType(Enum):
    """Types of signals that can be ingested."""
    TEXT = "text"
    FILE_CHANGE = "file_change"
    LOG_STREAM = "log_stream"
    AUDIO_STREAM = "audio_stream"
    API_EVENT = "api_event"
    DOM_EVENT = "dom_event"
    CLICKSTREAM = "clickstream"
    SYSTEM_ERROR = "system_error"


@dataclass
class ContextObject:
    """
    Standard Context Object that all signals are normalized into.
    
    This is the "Intent Object" that the Agent understands.
    All signal types are converted into this standard format.
    """
    # Core fields
    signal_type: SignalType
    timestamp: str
    
    # Primary content (what the user/system wants)
    intent: str  # High-level intent extracted from the signal
    query: str  # Normalized query for the agent
    
    # Context fields
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)  # Signal-specific metadata
    
    # Source tracking
    source_id: Optional[str] = None  # ID of the signal source
    user_id: Optional[str] = None  # User identifier if applicable
    
    # Priority and urgency
    priority: str = "normal"  # "critical", "high", "normal", "low"
    urgency_score: float = 0.5  # 0-1, how urgent is this signal
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "signal_type": self.signal_type.value,
            "timestamp": self.timestamp,
            "intent": self.intent,
            "query": self.query,
            "context": self.context,
            "metadata": self.metadata,
            "source_id": self.source_id,
            "user_id": self.user_id,
            "priority": self.priority,
            "urgency_score": self.urgency_score
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class SignalNormalizer(Protocol):
    """
    Protocol (interface) for signal normalizers.
    
    Each signal type implements this protocol to convert
    its specific format into a standard ContextObject.
    """
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """
        Normalize a raw signal into a standard ContextObject.
        
        Args:
            raw_signal: Raw signal data from the source
            
        Returns:
            ContextObject: Normalized context object
        """
        ...
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """
        Validate if the raw signal has required fields.
        
        Args:
            raw_signal: Raw signal data to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        ...


class TextSignalNormalizer:
    """Normalizer for traditional text input (backward compatibility)."""
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """Convert text input to ContextObject."""
        text = raw_signal.get("text", raw_signal.get("query", ""))
        
        return ContextObject(
            signal_type=SignalType.TEXT,
            timestamp=raw_signal.get("timestamp", datetime.now().isoformat()),
            intent="user_query",
            query=text,
            context={},
            metadata=raw_signal.get("metadata", {}),
            source_id=raw_signal.get("source_id", "text_input"),
            user_id=raw_signal.get("user_id"),
            priority=raw_signal.get("priority", "normal"),
            urgency_score=raw_signal.get("urgency_score", 0.5)
        )
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """Validate text signal has required fields."""
        return "text" in raw_signal or "query" in raw_signal


class FileChangeSignalNormalizer:
    """
    Normalizer for file change events from IDEs like VS Code.
    
    The "Passive" Input: The user is coding in VS Code. The signal is the File Change Event.
    """
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """Convert file change event to ContextObject."""
        file_path = raw_signal.get("file_path", "unknown")
        change_type = raw_signal.get("change_type", "modified")  # created, modified, deleted
        content_before = raw_signal.get("content_before", "")
        content_after = raw_signal.get("content_after", "")
        
        # Extract intent from the file change
        intent = self._extract_intent(change_type, file_path, content_before, content_after)
        
        # Create a query that describes the change
        query = self._create_query(change_type, file_path, content_before, content_after)
        
        # Determine priority based on file type and change
        priority, urgency = self._assess_urgency(file_path, change_type, content_after)
        
        return ContextObject(
            signal_type=SignalType.FILE_CHANGE,
            timestamp=raw_signal.get("timestamp", datetime.now().isoformat()),
            intent=intent,
            query=query,
            context={
                "file_path": file_path,
                "change_type": change_type,
                "content_before": content_before,
                "content_after": content_after,
                "language": raw_signal.get("language", "unknown"),
                "project": raw_signal.get("project", "unknown")
            },
            metadata=raw_signal.get("metadata", {}),
            source_id=raw_signal.get("source_id", "ide_watcher"),
            user_id=raw_signal.get("user_id"),
            priority=priority,
            urgency_score=urgency
        )
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """Validate file change signal has required fields."""
        return "file_path" in raw_signal and "change_type" in raw_signal
    
    def _extract_intent(self, change_type: str, file_path: str, 
                       content_before: str, content_after: str) -> str:
        """Extract high-level intent from file change."""
        if change_type == "created":
            return "file_creation"
        elif change_type == "deleted":
            return "file_deletion"
        elif "test" in file_path.lower():
            return "test_modification"
        elif content_before and not content_after:
            return "code_removal"
        elif not content_before and content_after:
            return "code_addition"
        else:
            return "code_modification"
    
    def _create_query(self, change_type: str, file_path: str,
                     content_before: str, content_after: str) -> str:
        """Create a natural language query describing the change."""
        file_name = file_path.split("/")[-1]
        
        if change_type == "created":
            return f"New file created: {file_name}"
        elif change_type == "deleted":
            return f"File deleted: {file_name}"
        else:
            # For modifications, create a diff-like description
            lines_before = len(content_before.split("\n")) if content_before else 0
            lines_after = len(content_after.split("\n")) if content_after else 0
            diff = lines_after - lines_before
            
            if diff > 0:
                return f"File modified: {file_name} (+{diff} lines)"
            elif diff < 0:
                return f"File modified: {file_name} ({diff} lines)"
            else:
                return f"File modified: {file_name}"
    
    def _assess_urgency(self, file_path: str, change_type: str,
                       content: str) -> tuple[str, float]:
        """Assess priority and urgency of the file change."""
        # Critical files
        if any(critical in file_path.lower() for critical in ["config", "security", "auth"]):
            return "high", 0.8
        
        # Deletions are potentially dangerous
        if change_type == "deleted":
            return "high", 0.7
        
        # Large changes might need review
        if content and len(content.split("\n")) > 100:
            return "normal", 0.6
        
        return "normal", 0.5


class LogStreamSignalNormalizer:
    """
    Normalizer for system log streams.
    
    The "System" Input: The server is throwing 500 errors. The signal is the Log Stream.
    """
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """Convert log stream event to ContextObject."""
        log_level = raw_signal.get("level", "INFO")
        message = raw_signal.get("message", "")
        error_code = raw_signal.get("error_code")
        stack_trace = raw_signal.get("stack_trace")
        
        # Extract intent from log
        intent = self._extract_intent(log_level, message, error_code)
        
        # Create query
        query = self._create_query(log_level, message, error_code)
        
        # Assess urgency based on log level and content
        priority, urgency = self._assess_urgency(log_level, message, error_code)
        
        return ContextObject(
            signal_type=SignalType.LOG_STREAM,
            timestamp=raw_signal.get("timestamp", datetime.now().isoformat()),
            intent=intent,
            query=query,
            context={
                "log_level": log_level,
                "message": message,
                "error_code": error_code,
                "stack_trace": stack_trace,
                "service": raw_signal.get("service", "unknown"),
                "host": raw_signal.get("host", "unknown")
            },
            metadata=raw_signal.get("metadata", {}),
            source_id=raw_signal.get("source_id", "log_collector"),
            user_id=raw_signal.get("user_id"),
            priority=priority,
            urgency_score=urgency
        )
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """Validate log stream signal has required fields."""
        return "message" in raw_signal or "error_code" in raw_signal
    
    def _extract_intent(self, log_level: str, message: str, 
                       error_code: Optional[str]) -> str:
        """Extract intent from log entry."""
        if log_level in ["ERROR", "CRITICAL", "FATAL"]:
            if "500" in message or error_code == "500":
                return "server_error_500"
            elif "404" in message or error_code == "404":
                return "not_found_404"
            elif "timeout" in message.lower():
                return "timeout_error"
            else:
                return "system_error"
        elif log_level == "WARNING":
            return "system_warning"
        else:
            return "system_info"
    
    def _create_query(self, log_level: str, message: str,
                     error_code: Optional[str]) -> str:
        """Create query from log entry."""
        if error_code:
            return f"[{log_level}] Error {error_code}: {message[:200]}"
        else:
            return f"[{log_level}] {message[:200]}"
    
    def _assess_urgency(self, log_level: str, message: str,
                       error_code: Optional[str]) -> tuple[str, float]:
        """Assess urgency of log entry."""
        # Critical errors need immediate attention
        if log_level in ["CRITICAL", "FATAL"]:
            return "critical", 0.95
        
        # Server errors (500s) are high priority
        if "500" in message or error_code == "500":
            return "critical", 0.9
        
        # Regular errors
        if log_level == "ERROR":
            return "high", 0.75
        
        # Warnings
        if log_level == "WARNING":
            return "normal", 0.6
        
        return "low", 0.3


class AudioStreamSignalNormalizer:
    """
    Normalizer for audio/voice streams.
    
    The "Audio" Input: The user is in a meeting. The signal is the Voice Stream.
    """
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """Convert audio stream event to ContextObject."""
        transcript = raw_signal.get("transcript", "")
        speaker_id = raw_signal.get("speaker_id")
        audio_duration = raw_signal.get("duration_seconds", 0)
        
        # Extract intent from transcript
        intent = self._extract_intent(transcript)
        
        # Use transcript as query
        query = transcript if transcript else "Audio signal received"
        
        # Assess urgency
        priority, urgency = self._assess_urgency(transcript, audio_duration)
        
        return ContextObject(
            signal_type=SignalType.AUDIO_STREAM,
            timestamp=raw_signal.get("timestamp", datetime.now().isoformat()),
            intent=intent,
            query=query,
            context={
                "transcript": transcript,
                "speaker_id": speaker_id,
                "duration_seconds": audio_duration,
                "language": raw_signal.get("language", "en"),
                "confidence": raw_signal.get("confidence", 1.0)
            },
            metadata=raw_signal.get("metadata", {}),
            source_id=raw_signal.get("source_id", "audio_transcriber"),
            user_id=speaker_id or raw_signal.get("user_id"),
            priority=priority,
            urgency_score=urgency
        )
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """Validate audio signal has required fields."""
        return "transcript" in raw_signal or "audio_data" in raw_signal
    
    def _extract_intent(self, transcript: str) -> str:
        """Extract intent from audio transcript."""
        lower_transcript = transcript.lower()
        
        # Common voice commands
        if any(word in lower_transcript for word in ["help", "assist", "support"]):
            return "help_request"
        elif any(word in lower_transcript for word in ["urgent", "emergency", "critical"]):
            return "urgent_request"
        elif any(word in lower_transcript for word in ["question", "ask", "wondering"]):
            return "question"
        else:
            return "voice_input"
    
    def _assess_urgency(self, transcript: str, duration: float) -> tuple[str, float]:
        """Assess urgency of audio input."""
        lower_transcript = transcript.lower()
        
        # Urgent keywords
        if any(word in lower_transcript for word in ["urgent", "emergency", "critical", "immediately"]):
            return "critical", 0.9
        
        # Help requests
        if any(word in lower_transcript for word in ["help", "problem", "issue"]):
            return "high", 0.7
        
        return "normal", 0.5


class UniversalSignalBus:
    """
    Central orchestrator for omni-channel signal ingestion.
    
    This is the "Universal Signal Bus" - a managed service that accepts
    any stream (audio, logs, clickstream, DOM events) and normalizes them
    into a standard Context Object for AI agents.
    
    The entry point is not a UI component; it is a Signal Normalizer.
    """
    
    def __init__(self):
        self.normalizers: Dict[SignalType, SignalNormalizer] = {}
        self._register_default_normalizers()
        self.event_history: List[ContextObject] = []
    
    def _register_default_normalizers(self):
        """Register default signal normalizers."""
        self.register_normalizer(SignalType.TEXT, TextSignalNormalizer())
        self.register_normalizer(SignalType.FILE_CHANGE, FileChangeSignalNormalizer())
        self.register_normalizer(SignalType.LOG_STREAM, LogStreamSignalNormalizer())
        self.register_normalizer(SignalType.AUDIO_STREAM, AudioStreamSignalNormalizer())
    
    def register_normalizer(self, signal_type: SignalType, 
                          normalizer: SignalNormalizer) -> None:
        """
        Register a signal normalizer for a specific signal type.
        
        Args:
            signal_type: Type of signal this normalizer handles
            normalizer: Normalizer instance
        """
        self.normalizers[signal_type] = normalizer
    
    def ingest(self, raw_signal: Dict[str, Any], 
               signal_type: Optional[SignalType] = None) -> ContextObject:
        """
        Ingest a raw signal and normalize it to a ContextObject.
        
        This is the main entry point. ANY signal type can be ingested here.
        
        Args:
            raw_signal: Raw signal data from any source
            signal_type: Optional signal type hint. If not provided, will auto-detect.
            
        Returns:
            ContextObject: Normalized context object ready for the agent
            
        Raises:
            ValueError: If signal type is not supported or cannot be detected
        """
        # Auto-detect signal type if not provided
        if signal_type is None:
            signal_type = self._detect_signal_type(raw_signal)
        
        # Get appropriate normalizer
        normalizer = self.normalizers.get(signal_type)
        if normalizer is None:
            raise ValueError(f"No normalizer registered for signal type: {signal_type}")
        
        # Validate signal
        if not normalizer.validate(raw_signal):
            raise ValueError(f"Invalid signal format for type: {signal_type}")
        
        # Normalize the signal
        context_obj = normalizer.normalize(raw_signal)
        
        # Store in history
        self.event_history.append(context_obj)
        
        return context_obj
    
    def _detect_signal_type(self, raw_signal: Dict[str, Any]) -> SignalType:
        """
        Auto-detect signal type from raw signal structure.
        
        Args:
            raw_signal: Raw signal data
            
        Returns:
            SignalType: Detected signal type
            
        Raises:
            ValueError: If signal type cannot be detected
        """
        # Check for explicit signal_type field
        if "signal_type" in raw_signal:
            type_str = raw_signal["signal_type"]
            try:
                return SignalType(type_str)
            except ValueError:
                pass
        
        # Heuristic detection based on field names
        if "file_path" in raw_signal and "change_type" in raw_signal:
            return SignalType.FILE_CHANGE
        elif "log_level" in raw_signal or "level" in raw_signal or "error_code" in raw_signal or ("message" in raw_signal and any(k in raw_signal for k in ["service", "host", "stack_trace"])):
            return SignalType.LOG_STREAM
        elif "transcript" in raw_signal or "audio_data" in raw_signal:
            return SignalType.AUDIO_STREAM
        elif "text" in raw_signal or "query" in raw_signal:
            return SignalType.TEXT
        
        # Default to TEXT if we have any string content
        for value in raw_signal.values():
            if isinstance(value, str) and len(value) > 0:
                return SignalType.TEXT
        
        raise ValueError("Cannot detect signal type from raw signal")
    
    def batch_ingest(self, raw_signals: List[Dict[str, Any]]) -> List[ContextObject]:
        """
        Ingest multiple signals in batch.
        
        Args:
            raw_signals: List of raw signal data
            
        Returns:
            List[ContextObject]: List of normalized context objects
        """
        return [self.ingest(signal) for signal in raw_signals]
    
    def get_history(self, limit: Optional[int] = None,
                   signal_type: Optional[SignalType] = None) -> List[ContextObject]:
        """
        Get event history, optionally filtered.
        
        Args:
            limit: Maximum number of events to return (most recent first)
            signal_type: Filter by signal type
            
        Returns:
            List[ContextObject]: Event history
        """
        history = self.event_history
        
        # Filter by type if specified
        if signal_type:
            history = [e for e in history if e.signal_type == signal_type]
        
        # Limit if specified
        if limit:
            history = history[-limit:]
        
        return history
    
    def clear_history(self):
        """Clear event history."""
        self.event_history.clear()


def create_signal_from_text(text: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Helper: Create a text signal from a string."""
    return {
        "text": text,
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id
    }


def create_signal_from_file_change(file_path: str, change_type: str,
                                   content_before: str = "",
                                   content_after: str = "",
                                   **kwargs) -> Dict[str, Any]:
    """Helper: Create a file change signal."""
    return {
        "file_path": file_path,
        "change_type": change_type,
        "content_before": content_before,
        "content_after": content_after,
        "timestamp": datetime.now().isoformat(),
        **kwargs
    }


def create_signal_from_log(level: str, message: str,
                          error_code: Optional[str] = None,
                          **kwargs) -> Dict[str, Any]:
    """Helper: Create a log stream signal."""
    return {
        "level": level,
        "message": message,
        "error_code": error_code,
        "timestamp": datetime.now().isoformat(),
        **kwargs
    }


def create_signal_from_audio(transcript: str, speaker_id: Optional[str] = None,
                            **kwargs) -> Dict[str, Any]:
    """Helper: Create an audio stream signal."""
    return {
        "transcript": transcript,
        "speaker_id": speaker_id,
        "timestamp": datetime.now().isoformat(),
        **kwargs
    }

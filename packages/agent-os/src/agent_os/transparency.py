# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""EU AI Act Art. 13/50 transparency enforcement interceptor.

Ensures AI disclosure is delivered to users before tool execution,
supporting Art. 50(1) (AI interaction notice), Art. 50(3) (emotion
recognition notice), and Art. 13 (interpretable output documentation).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TransparencyLevel(str, Enum):
    """Disclosure level per EU AI Act risk classification."""

    NONE = "none"
    BASIC = "basic"
    ENHANCED = "enhanced"
    FULL = "full"


@dataclass
class ToolCallRequest:
    """Minimal shim — real class imported from integrations.base at runtime."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    agent_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCallResult:
    """Minimal shim — real class imported from integrations.base at runtime."""

    allowed: bool
    reason: str | None = None
    modified_arguments: dict[str, Any] | None = None
    audit_entry: dict[str, Any] | None = None


DISCLOSURE_TEXTS = {
    TransparencyLevel.BASIC: (
        "You are interacting with an AI system. Outputs are machine-generated "
        "and may contain errors. (EU AI Act Art. 50(1))"
    ),
    TransparencyLevel.ENHANCED: (
        "You are interacting with a high-risk AI system. Outputs are "
        "machine-generated, subject to governance policy enforcement, and "
        "logged for regulatory audit. Interpretability documentation is "
        "available on request. (EU AI Act Art. 13, Art. 50(1))"
    ),
    TransparencyLevel.FULL: (
        "You are interacting with a high-risk AI system under full "
        "transparency obligations. All tool calls are policy-governed, "
        "audited, and subject to human oversight. System accuracy "
        "declarations and technical documentation are available. "
        "(EU AI Act Art. 13, Art. 14, Art. 50)"
    ),
}

EMOTION_RECOGNITION_NOTICE = (
    "This system uses emotion recognition technology. You have the right "
    "to be informed when such processing takes place. (EU AI Act Art. 50(3))"
)


class TransparencyInterceptor:
    """EU AI Act Art. 13/50 transparency enforcement interceptor.

    Blocks tool execution when required AI disclosure has not been
    confirmed, and injects disclosure metadata into allowed results.

    Args:
        default_level: Transparency level applied when none is specified
            in the request context.
        require_disclosure_confirmation: If ``True``, tool calls are
            blocked until ``confirm_disclosure`` is called for the session.
        emotion_recognition_notice: If ``True``, requires emotion
            recognition acknowledgement per Art. 50(3).
    """

    def __init__(
        self,
        default_level: TransparencyLevel = TransparencyLevel.BASIC,
        require_disclosure_confirmation: bool = True,
        emotion_recognition_notice: bool = False,
    ) -> None:
        self.default_level = default_level
        self.require_disclosure_confirmation = require_disclosure_confirmation
        self.emotion_recognition_notice = emotion_recognition_notice
        self._confirmed_sessions: dict[str, float] = {}
        self._emotion_acknowledged: dict[str, float] = {}

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        """Check transparency requirements before allowing a tool call."""
        session_id = request.metadata.get("session_id", request.agent_id or "default")
        level = request.metadata.get("transparency_level", self.default_level)
        if isinstance(level, str):
            try:
                level = TransparencyLevel(level)
            except ValueError:
                level = self.default_level

        if level == TransparencyLevel.NONE:
            return ToolCallResult(allowed=True)

        # Check disclosure confirmation
        if self.require_disclosure_confirmation:
            if session_id not in self._confirmed_sessions:
                logger.warning(
                    "Blocked %s: AI disclosure not confirmed for session %s",
                    request.tool_name,
                    session_id,
                )
                return ToolCallResult(
                    allowed=False,
                    reason=(
                        f"AI disclosure must be confirmed before tool execution. "
                        f"Required level: {level.value}. "
                        f"Call confirm_disclosure(session_id) first."
                    ),
                )

        # Check emotion recognition acknowledgement
        if self.emotion_recognition_notice:
            if session_id not in self._emotion_acknowledged:
                logger.warning(
                    "Blocked %s: emotion recognition notice not acknowledged for %s",
                    request.tool_name,
                    session_id,
                )
                return ToolCallResult(
                    allowed=False,
                    reason=(
                        "Emotion recognition notice must be acknowledged "
                        "before tool execution. (Art. 50(3))"
                    ),
                )

        # Inject disclosure metadata
        disclosure = {
            "_ai_disclosure": {
                "level": level.value,
                "text": self.get_disclosure_text(level),
                "confirmed_at": self._confirmed_sessions.get(session_id),
                "emotion_recognition": self.emotion_recognition_notice,
            }
        }

        return ToolCallResult(
            allowed=True,
            audit_entry=disclosure,
        )

    def confirm_disclosure(self, session_id: str) -> None:
        """Mark AI disclosure as confirmed for a session."""
        self._confirmed_sessions[session_id] = time.time()
        logger.info("AI disclosure confirmed for session %s", session_id)

    def acknowledge_emotion_recognition(self, session_id: str) -> None:
        """Mark emotion recognition notice as acknowledged for a session."""
        self._emotion_acknowledged[session_id] = time.time()
        logger.info("Emotion recognition notice acknowledged for session %s", session_id)

    def get_disclosure_text(self, level: TransparencyLevel) -> str:
        """Get standard disclosure text for the given transparency level."""
        return DISCLOSURE_TEXTS.get(level, DISCLOSURE_TEXTS[TransparencyLevel.BASIC])

    def is_disclosure_confirmed(self, session_id: str) -> bool:
        """Check if disclosure has been confirmed for a session."""
        return session_id in self._confirmed_sessions

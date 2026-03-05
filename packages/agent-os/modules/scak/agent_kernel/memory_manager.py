# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Memory Manager — simple list-based lesson store.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any


class LessonType(Enum):
    SYNTAX = "syntax"       # Expire on model upgrade (e.g. "Output JSON")
    BUSINESS = "business"   # Never expire (e.g. "Fiscal year starts Oct")
    ONE_OFF = "one_off"     # Transient error


class MemoryManager:
    """Simple in-memory lesson store. No decay logic."""

    def __init__(self):
        self._lessons: List[Dict[str, Any]] = []

    def add_lesson(self, lesson_text: str, lesson_type: LessonType):
        """Store a lesson."""
        self._lessons.append({
            "text": lesson_text,
            "type": lesson_type,
            "created_at": datetime.now(timezone.utc),
        })

    def get_lessons_by_type(self, lesson_type: LessonType) -> List[Dict[str, Any]]:
        return [e for e in self._lessons if e["type"] == lesson_type]

    def get_all_lessons(self) -> List[Dict[str, Any]]:
        return list(self._lessons)

    def get_lesson_count(self) -> Dict[LessonType, int]:
        counts: Dict[LessonType, int] = {}
        for entry in self._lessons:
            lt = entry["type"]
            counts[lt] = counts.get(lt, 0) + 1
        return counts

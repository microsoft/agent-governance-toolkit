# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Memory Manager - Simplified reference implementation for lesson lifecycle management.

This is a reference implementation showing the core concept of the "Semantic Purge" -
tagging lessons by type so syntax lessons can be deleted on model upgrades.

The production implementation is in semantic_purge.py, which includes sophisticated
classification algorithms and decay metadata tracking.
"""

from enum import Enum
from datetime import datetime
from collections import Counter


class LessonType(Enum):
    SYNTAX = "syntax"         # Expire on model upgrade (e.g. "Output JSON")
    BUSINESS = "business"     # Never expire (e.g. "Fiscal year starts Oct")
    ONE_OFF = "one_off"       # Delete immediately (Transient error)


class MemoryManager:
    def __init__(self):
        self.vector_store = []  # Simplified in-memory storage
        
    def add_lesson(self, lesson_text, lesson_type: LessonType):
        """
        Add a lesson with lifecycle metadata.
        
        Args:
            lesson_text: The lesson content
            lesson_type: Type of lesson (SYNTAX, BUSINESS, or ONE_OFF)
        """
        entry = {
            "text": lesson_text,
            "type": lesson_type,
            "model_version": "gpt-4-0125",
            "created_at": datetime.now()
        }
        self.vector_store.append(entry)

    def run_upgrade_purge(self, new_model_version):
        """
        Called when you switch from GPT-4 to GPT-5.
        Deletes all 'SYNTAX' lessons.
        
        Args:
            new_model_version: The new model version
        """
        # Filter out SYNTAX lessons
        original_count = len(self.vector_store)
        self.vector_store = [
            entry for entry in self.vector_store 
            if entry["type"] != LessonType.SYNTAX
        ]
        purged_count = original_count - len(self.vector_store)
        
        return {
            "purged_count": purged_count,
            "retained_count": len(self.vector_store),
            "new_model_version": new_model_version
        }
    
    def get_lessons_by_type(self, lesson_type: LessonType):
        """
        Get all lessons of a specific type.
        
        Args:
            lesson_type: The type of lessons to retrieve
            
        Returns:
            list: Lessons matching the type
        """
        return [
            entry for entry in self.vector_store
            if entry["type"] == lesson_type
        ]
    
    def get_lesson_count(self):
        """Get count of lessons by type."""
        type_counts = Counter(entry["type"] for entry in self.vector_store)
        return dict(type_counts)

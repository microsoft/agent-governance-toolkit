# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Pragmatic Truth module for handling source citations and conflicts.

The Pragmatic Truth philosophy: Provide REAL answers, not just OFFICIAL ones.
When official documentation conflicts with practical reality (logs, chats, 
runbooks), present both with proper citations and transparency.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import re

from caas.models import (
    Section,
    Document,
    SourceType,
    SourceCitation,
    SourceConflict,
)


class SourceDetector:
    """Detects source types from document metadata and content."""
    
    # Patterns to detect source types
    SOURCE_PATTERNS = {
        SourceType.OFFICIAL_DOCS: [
            r'\bofficial\b',
            r'\bdocumentation\b',
            r'\bspecification\b',
            r'\bapi\s+reference\b',
            r'\buser\s+guide\b',
            r'\bmanual\b',
        ],
        SourceType.PRACTICAL_LOGS: [
            r'\blog\b',
            r'\berror\b',
            r'\bstack\s+trace\b',
            r'\bexception\b',
            r'\bwarning\b',
            r'\bdebug\b',
        ],
        SourceType.TEAM_CHAT: [
            r'\bslack\b',
            r'\bteams\b',
            r'\bchat\b',
            r'\bconversation\b',
            r'\bdiscussion\b',
            r'\bmessage\b',
        ],
        SourceType.CODE_COMMENTS: [
            r'\bcomment\b',
            r'\btodo\b',
            r'\bfixme\b',
            r'\bhack\b',
            r'\bworkaround\b',
        ],
        SourceType.TICKET_SYSTEM: [
            r'\bjira\b',
            r'\bticket\b',
            r'\bissue\b',
            r'\bbug\b',
            r'\bgithub\s+issue\b',
        ],
        SourceType.RUNBOOK: [
            r'\brunbook\b',
            r'\bplaybook\b',
            r'\btroubleshooting\b',
            r'\bincident\b',
            r'\boperational\b',
        ],
        SourceType.WIKI: [
            r'\bwiki\b',
            r'\bknowledge\s+base\b',
            r'\bconfluence\b',
            r'\binternal\s+docs\b',
        ],
        SourceType.MEETING_NOTES: [
            r'\bmeeting\b',
            r'\bnotes\b',
            r'\bminutes\b',
            r'\bdecision\b',
            r'\bagenda\b',
        ],
    }
    
    def detect_source_type(
        self,
        document: Document,
        section: Optional[Section] = None
    ) -> SourceType:
        """
        Detect source type from document/section metadata and content.
        
        Args:
            document: Document to analyze
            section: Optional specific section to analyze
            
        Returns:
            Detected source type
        """
        # Check explicit metadata first
        if section and section.source_citation:
            return section.source_citation.source_type
        if document.source_citation:
            return document.source_citation.source_type
        
        # Check metadata for hints
        metadata = document.metadata
        if 'source_type' in metadata:
            try:
                return SourceType(metadata['source_type'])
            except ValueError:
                pass
        
        # Analyze title and content
        text_to_analyze = document.title.lower()
        if section:
            text_to_analyze += " " + section.title.lower()
            text_to_analyze += " " + section.content.lower()[:500]  # First 500 chars
        else:
            text_to_analyze += " " + document.content.lower()[:500]
        
        # Score each source type
        scores = {}
        for source_type, patterns in self.SOURCE_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, text_to_analyze, re.IGNORECASE):
                    score += 1
            scores[source_type] = score
        
        # Return highest scoring type
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)
        
        return SourceType.UNKNOWN
    
    def create_citation(
        self,
        document: Document,
        section: Optional[Section] = None,
        source_type: Optional[SourceType] = None
    ) -> SourceCitation:
        """
        Create a citation for a document or section.
        
        Args:
            document: Source document
            section: Optional specific section
            source_type: Optional override for source type
            
        Returns:
            SourceCitation object
        """
        if source_type is None:
            source_type = self.detect_source_type(document, section)
        
        # Build source name
        source_name = document.title
        if section:
            source_name = f"{document.title} > {section.title}"
        
        # Extract timestamp
        timestamp = document.ingestion_timestamp
        if section and 'timestamp' in getattr(section, 'metadata', {}):
            timestamp = section.metadata['timestamp']
        
        # Extract URL from metadata
        source_url = document.metadata.get('url') or document.metadata.get('source_url')
        
        # Create excerpt
        excerpt = None
        if section:
            excerpt = section.content[:150] + "..." if len(section.content) > 150 else section.content
        
        return SourceCitation(
            source_type=source_type,
            source_name=source_name,
            source_url=source_url,
            timestamp=timestamp,
            excerpt=excerpt,
            confidence=1.0
        )


class ConflictDetector:
    """Detects conflicts between official and practical sources."""
    
    # Keywords that suggest practical/real information
    PRACTICAL_INDICATORS = [
        'actually', 'really', 'in practice', 'in reality', 'however',
        'crashes', 'fails', 'doesn\'t work', 'workaround', 'hack',
        'unstable', 'issue', 'problem', 'bug', 'limitation',
    ]
    
    # Keywords that suggest official information
    OFFICIAL_INDICATORS = [
        'officially', 'documented', 'specified', 'according to',
        'specification', 'standard', 'recommended', 'should',
        'guideline', 'policy', 'requirement',
    ]
    
    def is_official_source(self, citation: SourceCitation) -> bool:
        """Check if a source is considered official."""
        return citation.source_type == SourceType.OFFICIAL_DOCS
    
    def is_practical_source(self, citation: SourceCitation) -> bool:
        """Check if a source is considered practical/real."""
        return citation.source_type in [
            SourceType.PRACTICAL_LOGS,
            SourceType.TEAM_CHAT,
            SourceType.CODE_COMMENTS,
            SourceType.TICKET_SYSTEM,
            SourceType.RUNBOOK,
        ]
    
    def detect_conflicts(
        self,
        sections: List[Section],
        documents: Dict[str, Document]
    ) -> List[SourceConflict]:
        """
        Detect conflicts between official and practical sources.
        
        Looks for cases where:
        - Official docs say one thing
        - Practical sources (logs, chat, tickets) say another
        
        Args:
            sections: List of sections to analyze
            documents: Map of document IDs to documents
            
        Returns:
            List of detected conflicts
        """
        conflicts = []
        
        # Group sections by source type
        official_sections = []
        practical_sections = []
        
        for section in sections:
            if not section.source_citation:
                continue
            
            if self.is_official_source(section.source_citation):
                official_sections.append(section)
            elif self.is_practical_source(section.source_citation):
                practical_sections.append(section)
        
        # Look for conflicts between official and practical
        for official_sec in official_sections:
            for practical_sec in practical_sections:
                conflict = self._detect_conflict_between_sections(
                    official_sec,
                    practical_sec
                )
                if conflict:
                    conflicts.append(conflict)
        
        return conflicts
    
    def _detect_conflict_between_sections(
        self,
        official_section: Section,
        practical_section: Section
    ) -> Optional[SourceConflict]:
        """
        Detect if two sections conflict.
        
        This is a simple heuristic-based detection. In a production system,
        you might use NLP or LLM-based conflict detection.
        
        Args:
            official_section: Official source section
            practical_section: Practical source section
            
        Returns:
            SourceConflict if detected, None otherwise
        """
        # Check if sections are about similar topics
        # (simple overlap in titles or content)
        official_text = (official_section.title + " " + official_section.content).lower()
        practical_text = (practical_section.title + " " + practical_section.content).lower()
        
        # Extract key terms (simple word extraction)
        official_words = set(re.findall(r'\b\w{4,}\b', official_text))
        practical_words = set(re.findall(r'\b\w{4,}\b', practical_text))
        
        # Check for overlap
        overlap = official_words & practical_words
        if len(overlap) < 3:  # Need at least 3 common words
            return None
        
        # Check for conflicting language
        has_conflict_indicators = False
        
        # Look for practical indicators in practical section
        practical_lower = practical_section.content.lower()
        for indicator in self.PRACTICAL_INDICATORS:
            if indicator in practical_lower:
                has_conflict_indicators = True
                break
        
        if not has_conflict_indicators:
            return None
        
        # Build topic from common words
        topic = " ".join(sorted(list(overlap))[:5])
        
        # Determine severity based on keywords
        severity = "medium"
        if any(word in practical_lower for word in ['crash', 'fail', 'broken', 'bug']):
            severity = "high"
        elif any(word in practical_lower for word in ['workaround', 'hack', 'issue']):
            severity = "medium"
        else:
            severity = "low"
        
        # Create conflict
        return SourceConflict(
            topic=topic,
            official_answer=official_section.content[:200] + "...",
            official_source=official_section.source_citation,
            practical_answer=practical_section.content[:200] + "...",
            practical_source=practical_section.source_citation,
            recommendation=(
                "Consider the practical experience alongside official documentation. "
                "The practical source may reflect real-world limitations or issues "
                "not yet updated in official docs."
            ),
            conflict_severity=severity
        )


class CitationFormatter:
    """Formats citations for inclusion in context responses."""
    
    def format_citation(self, citation: SourceCitation) -> str:
        """
        Format a citation as a human-readable string.
        
        Args:
            citation: Citation to format
            
        Returns:
            Formatted citation string
        """
        parts = []
        
        # Source type label
        type_label = self._get_source_type_label(citation.source_type)
        parts.append(f"[{type_label}]")
        
        # Source name
        parts.append(citation.source_name)
        
        # Timestamp
        if citation.timestamp:
            try:
                dt = datetime.fromisoformat(citation.timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%Y-%m-%d')
                parts.append(f"({time_str})")
            except (ValueError, TypeError):
                # Skip malformed timestamps
                pass
        
        # URL
        if citation.source_url:
            parts.append(f"<{citation.source_url}>")
        
        return " ".join(parts)
    
    def _get_source_type_label(self, source_type: SourceType) -> str:
        """Get human-readable label for source type."""
        labels = {
            SourceType.OFFICIAL_DOCS: "Official Docs",
            SourceType.PRACTICAL_LOGS: "Logs",
            SourceType.TEAM_CHAT: "Team Chat",
            SourceType.CODE_COMMENTS: "Code Comments",
            SourceType.TICKET_SYSTEM: "Ticket",
            SourceType.RUNBOOK: "Runbook",
            SourceType.WIKI: "Wiki",
            SourceType.MEETING_NOTES: "Meeting Notes",
            SourceType.UNKNOWN: "Unknown",
        }
        return labels.get(source_type, str(source_type))
    
    def format_conflict(self, conflict: SourceConflict) -> str:
        """
        Format a conflict as a human-readable string.
        
        Args:
            conflict: Conflict to format
            
        Returns:
            Formatted conflict description
        """
        lines = []
        lines.append(f"⚠️  CONFLICT DETECTED: {conflict.topic}")
        lines.append("")
        lines.append("📖 Official Documentation says:")
        lines.append(f"   {conflict.official_answer}")
        lines.append(f"   Source: {self.format_citation(conflict.official_source)}")
        lines.append("")
        lines.append("🔧 Practical Experience shows:")
        lines.append(f"   {conflict.practical_answer}")
        lines.append(f"   Source: {self.format_citation(conflict.practical_source)}")
        lines.append("")
        lines.append(f"💡 Recommendation: {conflict.recommendation}")
        
        return "\n".join(lines)
    
    def enrich_context_with_citations(
        self,
        context: str,
        citations: List[SourceCitation]
    ) -> str:
        """
        Enrich context text with inline citations.
        
        Args:
            context: Original context text
            citations: List of citations to include
            
        Returns:
            Context with citations appended
        """
        if not citations:
            return context
        
        lines = [context]
        lines.append("\n\n---\n### 📚 Sources\n")
        
        for i, citation in enumerate(citations, 1):
            lines.append(f"{i}. {self.format_citation(citation)}")
            if citation.excerpt:
                lines.append(f"   > {citation.excerpt}")
        
        return "\n".join(lines)

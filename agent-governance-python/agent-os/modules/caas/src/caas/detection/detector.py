# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Auto-detection module for identifying document types and structures.
"""

import re
from typing import Dict, List, Tuple, Any

from caas.models import Document, DocumentType, Section


class DocumentTypeDetector:
    """Detects document type based on content analysis."""
    
    # Keywords and patterns for different document types
    PATTERNS = {
        DocumentType.LEGAL_CONTRACT: [
            r'\bwhereas\b',
            r'\bparty\b.*\bparty\b',
            r'\bagreement\b',
            r'\bcontract\b',
            r'\btherefore\b',
            r'\bhereby\b',
            r'\bindemnify\b',
            r'\bliability\b',
            r'\btermination\b',
            r'\bgoverning law\b',
        ],
        DocumentType.TECHNICAL_DOCUMENTATION: [
            r'\bAPI\b',
            r'\binstallation\b',
            r'\bconfiguration\b',
            r'\bparameter[s]?\b',
            r'\bmethod[s]?\b',
            r'\breturn[s]?\b',
            r'\bexample[s]?\b',
            r'\busage\b',
            r'\bsyntax\b',
        ],
        DocumentType.SOURCE_CODE: [
            r'\bfunction\b',
            r'\bclass\b',
            r'\bdef\b',
            r'\bimport\b',
            r'\breturn\b',
            r'\bif\b.*\belse\b',
            r'\bfor\b.*\bin\b',
            r'\bwhile\b',
        ],
        DocumentType.RESEARCH_PAPER: [
            r'\babstract\b',
            r'\bintroduction\b',
            r'\bmethodology\b',
            r'\bresults\b',
            r'\bconclusion\b',
            r'\breferences\b',
            r'\bcitation[s]?\b',
            r'\bhypothesis\b',
        ],
        DocumentType.TUTORIAL: [
            r'\bstep[s]?\b',
            r'\btutorial\b',
            r'\bhow to\b',
            r'\bguide\b',
            r'\bbeginners?\b',
            r'\blesson\b',
            r'\bexercise[s]?\b',
        ],
        DocumentType.API_DOCUMENTATION: [
            r'\bendpoint[s]?\b',
            r'\bGET\b.*\bPOST\b',
            r'\bHTTP\b',
            r'\brequest\b.*\bresponse\b',
            r'\bauthentication\b',
            r'\bheader[s]?\b',
            r'\bstatus code[s]?\b',
        ],
    }
    
    def detect(self, document: Document) -> DocumentType:
        """
        Detect the document type based on content analysis.
        
        Args:
            document: The document to analyze
            
        Returns:
            The detected document type
        """
        if document.format == "code":
            return DocumentType.SOURCE_CODE
        
        content = document.content.lower()
        scores: Dict[DocumentType, int] = {}
        
        # Score each document type based on pattern matches
        for doc_type, patterns in self.PATTERNS.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE))
                score += matches
            scores[doc_type] = score
        
        # Get the type with highest score
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                detected_type = max(scores, key=scores.get)
                return detected_type
        
        return DocumentType.UNKNOWN
    
    def detect_structure(self, document: Document) -> Dict[str, Any]:
        """
        Detect the structural characteristics of a document.
        
        Returns information about:
        - Section hierarchy
        - Key sections
        - Document organization
        """
        structure = {
            "has_clear_sections": len(document.sections) > 1,
            "section_count": len(document.sections),
            "section_titles": [s.title for s in document.sections],
            "key_sections": self._identify_key_sections(document),
        }
        
        return structure
    
    def _identify_key_sections(self, document: Document) -> List[str]:
        """Identify which sections are likely most important."""
        key_patterns = [
            r'definition[s]?',
            r'summary',
            r'conclusion',
            r'abstract',
            r'introduction',
            r'overview',
            r'getting started',
            r'quick start',
            r'main',
        ]
        
        key_sections = []
        for section in document.sections:
            title_lower = section.title.lower()
            for pattern in key_patterns:
                if re.search(pattern, title_lower):
                    key_sections.append(section.title)
                    break
        
        return key_sections


class StructureAnalyzer:
    """Analyzes document structure for optimization."""
    
    def analyze(self, document: Document) -> Dict[str, Any]:
        """
        Analyze document structure and return insights.
        
        Returns:
            Analysis results including section importance and relationships
        """
        analysis = {
            "document_type": document.detected_type,
            "section_analysis": [],
            "content_density": self._calculate_density(document),
            "structure_quality": self._assess_structure_quality(document),
        }
        
        # Analyze each section
        for section in document.sections:
            section_info = {
                "title": section.title,
                "length": len(section.content),
                "complexity": self._estimate_complexity(section.content),
                "keyword_density": self._calculate_keyword_density(section.content),
            }
            analysis["section_analysis"].append(section_info)
        
        return analysis
    
    def _calculate_density(self, document: Document) -> float:
        """Calculate content density (information per character)."""
        if not document.content:
            return 0.0
        
        words = len(document.content.split())
        chars = len(document.content)
        return words / chars if chars > 0 else 0.0
    
    def _assess_structure_quality(self, document: Document) -> str:
        """Assess the quality of document structure."""
        if len(document.sections) == 0:
            return "poor"
        elif len(document.sections) < 3:
            return "basic"
        elif len(document.sections) < 8:
            return "good"
        else:
            return "excellent"
    
    def _estimate_complexity(self, text: str) -> float:
        """Estimate text complexity based on various factors."""
        if not text:
            return 0.0
        
        words = text.split()
        if not words:
            return 0.0
        
        # Average word length
        avg_word_len = sum(len(w) for w in words) / len(words)
        
        # Sentence count
        sentences = len(re.split(r'[.!?]+', text))
        words_per_sentence = len(words) / sentences if sentences > 0 else 0
        
        # Complexity score (normalized 0-1)
        complexity = min(1.0, (avg_word_len / 10 + words_per_sentence / 30) / 2)
        return complexity
    
    def _calculate_keyword_density(self, text: str) -> float:
        """Calculate density of important keywords."""
        important_words = set([
            'important', 'critical', 'must', 'required', 'essential',
            'key', 'primary', 'main', 'core', 'fundamental'
        ])
        
        words = text.lower().split()
        if not words:
            return 0.0
        
        keyword_count = sum(1 for w in words if w in important_words)
        return keyword_count / len(words)

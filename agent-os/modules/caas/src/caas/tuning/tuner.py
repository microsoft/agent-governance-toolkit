# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Auto-tuning module for optimizing context weights.
"""

import re
from typing import Dict, List, Any
from collections import Counter

from caas.models import Document, DocumentType, Section, ContentTier


# Basic tier weight mapping (replaces StructureParser.get_tier_base_weight)
_TIER_WEIGHTS = {
    ContentTier.TIER_1_HIGH: 2.0,
    ContentTier.TIER_2_MEDIUM: 1.0,
    ContentTier.TIER_3_LOW: 0.5,
}


class WeightTuner:
    """Automatically tunes weights for document sections."""
    
    def __init__(self):
        """Initialize the weight tuner."""
        pass
    
    # Base weights for different document types
    TYPE_SPECIFIC_WEIGHTS = {
        DocumentType.LEGAL_CONTRACT: {
            "definitions": 2.0,
            "terms": 1.8,
            "obligations": 1.7,
            "termination": 1.5,
            "liability": 1.6,
            "governing law": 1.4,
            "default": 1.0,
        },
        DocumentType.TECHNICAL_DOCUMENTATION: {
            "api": 1.8,
            "parameters": 1.6,
            "examples": 1.7,
            "configuration": 1.5,
            "installation": 1.4,
            "quickstart": 1.9,
            "default": 1.0,
        },
        DocumentType.SOURCE_CODE: {
            "class": 1.6,
            "function": 1.5,
            "main": 1.8,
            "api": 1.7,
            "default": 1.0,
        },
        DocumentType.RESEARCH_PAPER: {
            "abstract": 2.0,
            "introduction": 1.5,
            "methodology": 1.4,
            "results": 1.7,
            "conclusion": 1.8,
            "default": 1.0,
        },
        DocumentType.TUTORIAL: {
            "getting started": 1.9,
            "step": 1.6,
            "example": 1.7,
            "exercise": 1.4,
            "default": 1.0,
        },
        DocumentType.API_DOCUMENTATION: {
            "endpoint": 1.8,
            "authentication": 1.9,
            "request": 1.6,
            "response": 1.6,
            "example": 1.7,
            "default": 1.0,
        },
    }
    
    def tune(self, document: Document) -> Document:
        """
        Auto-tune weights for document sections based on content analysis.
        
        Uses structure-aware indexing to assign tiers and calculate weights.
        Tier 1 (High): Titles, Headers, Class Definitions, API Contracts
        Tier 2 (Medium): Body text, Function logic
        Tier 3 (Low): Footnotes, Comments, Disclaimers
        
        Args:
            document: The document to tune
            
        Returns:
            Document with optimized weights
        """
        # Assign default tier to sections that don't have one
        for section in document.sections:
            if not section.tier:
                section.tier = ContentTier.TIER_2_MEDIUM
        
        # Get base weights for document type
        base_weights = self.TYPE_SPECIFIC_WEIGHTS.get(
            document.detected_type,
            {"default": 1.0}
        )
        
        # Calculate weights for each section
        for section in document.sections:
            weight = self._calculate_section_weight(
                section,
                document.detected_type,
                base_weights,
                document
            )
            section.weight = weight
            section.importance_score = self._calculate_importance_score(section)
        
        # Store overall weights in document
        document.weights = {
            section.title: section.weight
            for section in document.sections
        }
        
        return document
    
    def _calculate_section_weight(
        self,
        section: Section,
        doc_type: DocumentType,
        base_weights: Dict[str, float],
        document: Document
    ) -> float:
        """Calculate weight for a specific section using tier-based approach."""
        title_lower = section.title.lower()
        
        # Start with tier-based base weight
        if section.tier:
            weight = _TIER_WEIGHTS.get(section.tier, 1.0)
        else:
            # Fallback to default if tier not assigned
            weight = base_weights.get("default", 1.0)
        
        # Apply type-specific keyword boosts on top of tier weight (additive, not multiplicative)
        keyword_boost = 0.0
        for keyword, keyword_weight in base_weights.items():
            if keyword != "default" and keyword in title_lower:
                keyword_boost = max(keyword_boost, keyword_weight - 1.0)
                break  # Only apply one keyword boost
        
        # Add keyword boost instead of multiplying (prevents excessive amplification)
        weight = weight + keyword_boost
        
        # Adjust based on content analysis
        content_factors = self._analyze_content_factors(section)
        
        # Apply content-based adjustments
        if content_factors["has_code_examples"]:
            weight *= 1.2
        
        if content_factors["has_definitions"]:
            weight *= 1.3
        
        if content_factors["has_important_markers"]:
            weight *= 1.15
        
        # Boost weight for longer, more substantial sections (but not for Tier 3)
        if len(section.content) > 500 and section.tier != ContentTier.TIER_3_LOW:
            weight *= 1.1
        
        # Position-based adjustment (first and last sections often important)
        section_index = document.sections.index(section)
        total_sections = len(document.sections)
        
        if section_index == 0 and section.tier != ContentTier.TIER_3_LOW:
            weight *= 1.15
        elif section_index == total_sections - 1 and section.tier != ContentTier.TIER_3_LOW:
            weight *= 1.1
        
        return round(weight, 2)
    
    def _calculate_importance_score(self, section: Section) -> float:
        """Calculate an importance score for a section (0-1)."""
        factors = self._analyze_content_factors(section)
        
        score = 0.5  # Base score
        
        if factors["has_code_examples"]:
            score += 0.15
        if factors["has_definitions"]:
            score += 0.15
        if factors["has_important_markers"]:
            score += 0.1
        if factors["keyword_density"] > 0.02:
            score += 0.1
        
        # Length factor
        if len(section.content) > 300:
            score += 0.05
        
        return min(1.0, score)
    
    def _analyze_content_factors(self, section: Section) -> Dict[str, Any]:
        """Analyze content to identify important factors."""
        content = section.content.lower()
        
        # Check for code examples
        has_code = bool(
            re.search(r'```|<code>|def |function |class ', content)
        )
        
        # Check for definitions
        has_definitions = bool(
            re.search(r'defined as|definition|means|refers to', content)
        )
        
        # Check for importance markers
        has_important = bool(
            re.search(r'\b(important|critical|must|required|essential)\b', content)
        )
        
        # Calculate keyword density
        important_words = [
            'important', 'critical', 'must', 'required', 'key', 'essential'
        ]
        words = content.split()
        keyword_count = sum(1 for w in words if w in important_words)
        keyword_density = keyword_count / len(words) if words else 0
        
        return {
            "has_code_examples": has_code,
            "has_definitions": has_definitions,
            "has_important_markers": has_important,
            "keyword_density": keyword_density,
        }


class CorpusAnalyzer:
    """Analyzes corpus of documents to optimize global weights."""
    
    def __init__(self):
        self.documents: List[Document] = []
    
    def add_document(self, document: Document):
        """Add a document to the corpus."""
        self.documents.append(document)
    
    def analyze_corpus(self) -> Dict[str, Any]:
        """
        Analyze the entire corpus to identify patterns.
        
        Returns:
            Analysis results including common patterns and optimization suggestions
        """
        if not self.documents:
            return {"status": "empty_corpus"}
        
        # Count document types
        type_counts = Counter(doc.detected_type for doc in self.documents)
        
        # Analyze section patterns
        section_patterns = self._analyze_section_patterns()
        
        # Calculate average weights
        average_weights = self._calculate_average_weights()
        
        return {
            "total_documents": len(self.documents),
            "document_types": dict(type_counts),
            "common_sections": section_patterns,
            "average_weights": average_weights,
            "optimization_suggestions": self._generate_suggestions(),
        }
    
    def _analyze_section_patterns(self) -> Dict[str, int]:
        """Analyze common section patterns across documents."""
        section_counter = Counter()
        
        for doc in self.documents:
            for section in doc.sections:
                # Normalize section title
                normalized = section.title.lower().strip()
                section_counter[normalized] += 1
        
        # Return top 10 most common sections
        return dict(section_counter.most_common(10))
    
    def _calculate_average_weights(self) -> Dict[str, float]:
        """Calculate average weights across all documents."""
        weight_sums: Dict[str, List[float]] = {}
        
        for doc in self.documents:
            for section in doc.sections:
                title = section.title.lower()
                if title not in weight_sums:
                    weight_sums[title] = []
                weight_sums[title].append(section.weight)
        
        # Calculate averages
        averages = {}
        for title, weights in weight_sums.items():
            if weights:
                averages[title] = round(sum(weights) / len(weights), 2)
        
        return averages
    
    def _generate_suggestions(self) -> List[str]:
        """Generate optimization suggestions based on corpus analysis."""
        suggestions = []
        
        if len(self.documents) < 5:
            suggestions.append(
                "Add more documents to improve weight optimization accuracy"
            )
        
        # Check for document type diversity
        type_counts = Counter(doc.detected_type for doc in self.documents)
        if len(type_counts) == 1:
            suggestions.append(
                "Corpus contains only one document type; consider adding variety"
            )
        
        # Check for common patterns
        section_patterns = self._analyze_section_patterns()
        if len(section_patterns) > 20:
            suggestions.append(
                "High section diversity detected; consider standardizing section names"
            )
        
        return suggestions

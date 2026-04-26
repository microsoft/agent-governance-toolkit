# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Structure-Aware Parser for assigning content tiers.

Implements hierarchical structure parsing that assigns weights based on 
content importance tiers as described in the "Flat Chunk Fallacy".
"""

import re
from typing import List
from caas.models import Section, ContentTier, DocumentType


class StructureParser:
    """
    Parses document structure and assigns content tiers.
    
    Tier 1 (High Weight): Titles, Headers, Class Definitions, API Contracts
    Tier 2 (Medium Weight): Body text, Function logic
    Tier 3 (Low Weight): Footnotes, Comments, Disclaimers
    """
    
    # Patterns for identifying Tier 1 content (High Value)
    TIER_1_PATTERNS = {
        DocumentType.SOURCE_CODE: [
            # Matches: public class MyClass, private interface IAuth, protected enum Status
            r'^(public|private|protected)?\s*(class|interface|enum)\s+\w+',
            # Matches: public void login(...) { (Java/C-style API methods)
            r'^(public|private|protected)?\s*\w+\s+\w+\s*\([^)]*\)\s*{',
            # Matches: def login(self, username, password): (Python top-level functions)
            r'^\s*def\s+\w+\s*\([^)]*\)\s*:',
            # Matches: export function authenticate, async function getData
            r'^\s*(export\s+)?(async\s+)?function\s+\w+',
            # Matches: @api, @Api, @API decorators/annotations
            r'@(api|Api|API)',
        ],
        DocumentType.TECHNICAL_DOCUMENTATION: [
            r'^#{1,2}\s+',  # H1, H2 headers (markdown)
            r'^(API|Endpoint|Request|Response|Authentication|Authorization)',  # API sections
            r'^\s*(GET|POST|PUT|DELETE|PATCH)\s+/',  # HTTP methods
        ],
        DocumentType.LEGAL_CONTRACT: [
            r'^#{1,2}\s+',  # Main headers
            r'^(DEFINITIONS?|TERMS?|OBLIGATIONS?|LIABILITY|INDEMNITY)',  # Key legal sections
            r'^\d+\.\s+[A-Z][^:]+:',  # Numbered main clauses
        ],
        DocumentType.RESEARCH_PAPER: [
            r'^(ABSTRACT|INTRODUCTION|CONCLUSION|RESULTS)',  # Key sections
            r'^#{1,2}\s+',  # Main headers
        ],
        DocumentType.API_DOCUMENTATION: [
            r'^#{1,2}\s+',  # H1, H2 headers
            r'^\s*(GET|POST|PUT|DELETE|PATCH)\s+/',  # Endpoints
            r'^(Authentication|Authorization|Endpoint)',  # Critical API sections
        ],
    }
    
    # Patterns for identifying Tier 3 content (Low Value)
    TIER_3_PATTERNS = [
        r'^\s*#.*$',  # Comments (code)
        r'^\s*//.*$',  # Single-line comments
        r'^\s*/\*.*\*/',  # Multi-line comments
        r'TODO:|FIXME:|XXX:|HACK:',  # Comment markers
        r'^\s*\*\s+Note:',  # Footnotes
        r'^\s*\*\s+Disclaimer:',  # Disclaimers
        r'^Footnote[s]?:',  # Footnotes
        r'^Disclaimer[s]?:',  # Disclaimers
        r'^Note[s]?:',  # Notes
    ]
    
    def parse_and_assign_tiers(
        self, 
        sections: List[Section], 
        doc_type: DocumentType,
        content: str = ""
    ) -> List[Section]:
        """
        Parse sections and assign content tiers.
        
        Args:
            sections: List of document sections
            doc_type: Type of document
            content: Full document content (optional, for context)
            
        Returns:
            List of sections with assigned tiers
        """
        for section in sections:
            tier = self._determine_tier(section, doc_type)
            section.tier = tier
        
        return sections
    
    def _determine_tier(self, section: Section, doc_type: DocumentType) -> ContentTier:
        """
        Determine the content tier for a section.
        
        Args:
            section: The section to classify
            doc_type: Type of document
            
        Returns:
            The assigned content tier
        """
        content = section.content
        title = section.title
        
        # Check for Tier 3 (Low Value) first
        if self._is_tier_3_content(content, title):
            return ContentTier.TIER_3_LOW
        
        # Check for Tier 1 (High Value)
        if self._is_tier_1_content(content, title, doc_type):
            return ContentTier.TIER_1_HIGH
        
        # Default to Tier 2 (Medium Value)
        return ContentTier.TIER_2_MEDIUM
    
    def _is_tier_1_content(self, content: str, title: str, doc_type: DocumentType) -> bool:
        """Check if content is Tier 1 (High Value)."""
        combined_text = f"{title}\n{content}"
        
        # Check title for high-value indicators
        title_lower = title.lower()
        high_value_title_keywords = [
            'definition', 'api', 'class', 'interface', 'contract', 
            'authentication', 'authorization', 'endpoint', 'abstract',
            'introduction', 'conclusion', 'overview', 'summary'
        ]
        
        if any(keyword in title_lower for keyword in high_value_title_keywords):
            return True
        
        # Check doc-type specific patterns
        tier_1_patterns = self.TIER_1_PATTERNS.get(doc_type, [])
        for pattern in tier_1_patterns:
            if re.search(pattern, combined_text, re.MULTILINE | re.IGNORECASE):
                return True
        
        # Check for API contracts (general)
        if re.search(r'(contract|interface|protocol|specification)', combined_text, re.IGNORECASE):
            return True
        
        return False
    
    def _is_tier_3_content(self, content: str, title: str) -> bool:
        """Check if content is Tier 3 (Low Value)."""
        combined_text = f"{title}\n{content}"
        
        # Check title for low-value indicators
        title_lower = title.lower()
        low_value_keywords = [
            'footnote', 'disclaimer', 'note', 'comment', 'appendix',
            'acknowledgment', 'copyright', 'license'
        ]
        
        if any(keyword in title_lower for keyword in low_value_keywords):
            return True
        
        # Check patterns
        for pattern in self.TIER_3_PATTERNS:
            if re.search(pattern, combined_text, re.MULTILINE | re.IGNORECASE):
                # Make sure it's substantial (not just one comment line in a large section)
                comment_lines = len(re.findall(pattern, combined_text, re.MULTILINE | re.IGNORECASE))
                total_lines = len(combined_text.split('\n'))
                if total_lines > 0 and comment_lines / total_lines > 0.5:
                    return True
        
        return False
    
    def get_tier_base_weight(self, tier: ContentTier) -> float:
        """
        Get the base weight multiplier for a tier.
        
        Args:
            tier: The content tier
            
        Returns:
            Base weight multiplier
        """
        tier_weights = {
            ContentTier.TIER_1_HIGH: 2.0,    # High value content gets 2x base weight
            ContentTier.TIER_2_MEDIUM: 1.0,   # Medium value gets 1x base weight
            ContentTier.TIER_3_LOW: 0.5,      # Low value gets 0.5x base weight
        }
        return tier_weights.get(tier, 1.0)

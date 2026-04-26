# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Metadata enrichment module for contextual injection.

Solves the "Flat Chunk Fallacy" by enriching chunks with parent metadata.
Instead of storing isolated chunks like "It increased by 5%", we store:
"[Document: Q3 Earnings] [Chapter: Revenue] [Section: North America] It increased by 5%."

This ensures the vector carries the weight of its context.
"""

from typing import List, Optional
from caas.models import Section, Document, DocumentType


class MetadataEnricher:
    """
    Enriches sections with parent metadata for contextual awareness.
    
    Transforms isolated chunks into context-aware chunks by injecting
    hierarchical metadata (document, chapter, section).
    """
    
    def enrich_sections(self, document: Document) -> List[Section]:
        """
        Enrich all sections in a document with metadata prefixes.
        
        Args:
            document: Document with sections to enrich
            
        Returns:
            List of enriched sections
        """
        enriched_sections = []
        
        for section in document.sections:
            enriched_section = self._enrich_section(section, document)
            enriched_sections.append(enriched_section)
        
        return enriched_sections
    
    def _enrich_section(self, section: Section, document: Document) -> Section:
        """
        Enrich a single section with metadata prefix.
        
        Args:
            section: Section to enrich
            document: Parent document
            
        Returns:
            Section with enriched content
        """
        # Build metadata prefix
        metadata_parts = []
        
        # Add document title
        metadata_parts.append(f"[Document: {document.title}]")
        
        # Add document type if meaningful
        if document.detected_type and document.detected_type.value != "unknown":
            doc_type_display = document.detected_type.value.replace("_", " ").title()
            metadata_parts.append(f"[Type: {doc_type_display}]")
        
        # Add chapter/parent section if available
        if section.chapter:
            metadata_parts.append(f"[Chapter: {section.chapter}]")
        elif section.parent_section:
            metadata_parts.append(f"[Parent: {section.parent_section}]")
        
        # Add current section
        metadata_parts.append(f"[Section: {section.title}]")
        
        # Build enriched content
        metadata_prefix = " ".join(metadata_parts)
        enriched_content = f"{metadata_prefix} {section.content}"
        
        # Create a new section with enriched content
        # We preserve the original section but update the content
        # Note: Using model_copy() from Pydantic v2 (we're on v2.5.0)
        enriched_section = section.model_copy()
        enriched_section.content = enriched_content
        
        return enriched_section
    
    def get_enriched_chunk(
        self, 
        section: Section, 
        document_title: str,
        document_type: Optional[DocumentType] = None,
        include_type: bool = True
    ) -> str:
        """
        Get an enriched chunk string for a section.
        
        Useful for building enriched context on-the-fly without modifying
        the stored section.
        
        Args:
            section: Section to enrich
            document_title: Title of parent document
            document_type: Type of document (optional)
            include_type: Whether to include document type in prefix
            
        Returns:
            Enriched chunk string
        """
        metadata_parts = []
        
        # Add document title
        metadata_parts.append(f"[Document: {document_title}]")
        
        # Add document type if requested and available
        if include_type and document_type and document_type.value != "unknown":
            doc_type_display = document_type.value.replace("_", " ").title()
            metadata_parts.append(f"[Type: {doc_type_display}]")
        
        # Add hierarchical context
        if section.chapter:
            metadata_parts.append(f"[Chapter: {section.chapter}]")
        elif section.parent_section:
            metadata_parts.append(f"[Parent: {section.parent_section}]")
        
        # Add current section
        metadata_parts.append(f"[Section: {section.title}]")
        
        # Build and return enriched content
        metadata_prefix = " ".join(metadata_parts)
        return f"{metadata_prefix} {section.content}"

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Storage module for managing documents and context.
"""

import copy
import json
from typing import Dict, Optional, List, Tuple, Any
from pathlib import Path
from datetime import datetime

from caas.models import Document, DocumentType, ContentTier, SourceCitation
from caas.decay import calculate_decay_factor


class DocumentStore:
    """In-memory document store with optional persistence."""
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize document store.
        
        Args:
            storage_path: Optional path for persistent storage
        """
        self.documents: Dict[str, Document] = {}
        self.storage_path = Path(storage_path) if storage_path else None
        
        if self.storage_path and self.storage_path.exists():
            self._load_from_disk()
    
    def add(self, document: Document) -> str:
        """
        Add a document to the store.
        
        Args:
            document: The document to add
            
        Returns:
            The document ID
        """
        self.documents[document.id] = document
        
        if self.storage_path:
            self._save_to_disk()
        
        return document.id
    
    def get(self, document_id: str) -> Optional[Document]:
        """
        Retrieve a document by ID.
        
        Args:
            document_id: The document ID
            
        Returns:
            The document if found, None otherwise
        """
        return self.documents.get(document_id)
    
    def list_all(self) -> List[Document]:
        """
        List all documents in the store.
        
        Returns:
            List of all documents
        """
        return list(self.documents.values())
    
    def list_by_type(self, doc_type: DocumentType) -> List[Document]:
        """
        List documents of a specific type.
        
        Args:
            doc_type: The document type to filter by
            
        Returns:
            List of matching documents
        """
        return [
            doc for doc in self.documents.values()
            if doc.detected_type == doc_type
        ]
    
    def delete(self, document_id: str) -> bool:
        """
        Delete a document from the store.
        
        Args:
            document_id: The document ID
            
        Returns:
            True if deleted, False if not found
        """
        if document_id in self.documents:
            del self.documents[document_id]
            
            if self.storage_path:
                self._save_to_disk()
            
            return True
        return False
    
    def search(
        self, 
        query: str, 
        enable_time_decay: bool = True,
        decay_rate: float = 1.0
    ) -> List[Document]:
        """
        Search documents by content or metadata with optional time-based decay ranking.
        
        When time decay is enabled:
        - Recent documents are ranked higher than old documents
        - Formula: relevance_score = match_score * decay_factor
        - A document from Yesterday with 80% match beats Last Year with 95% match
        
        Args:
            query: The search query
            enable_time_decay: Whether to apply time-based decay to ranking (default: True)
            decay_rate: Rate of decay (default: 1.0)
            
        Returns:
            List of matching documents, sorted by time-weighted relevance
        """
        query_lower = query.lower()
        query_words = query_lower.split()
        results = []
        
        for doc in self.documents.values():
            # Calculate base match score
            match_score = 0.0
            
            # Search in content, title, and section titles
            # Check for full phrase match (best)
            if query_lower in doc.title.lower():
                match_score += 1.0  # Title match is most relevant
            
            if query_lower in doc.content.lower():
                # Count occurrences for better relevance
                occurrences = doc.content.lower().count(query_lower)
                match_score += min(occurrences * 0.1, 0.5)  # Cap at 0.5
            
            # Check for individual word matches
            title_lower = doc.title.lower()
            content_lower = doc.content.lower()
            for word in query_words:
                if len(word) > 2:  # Skip very short words
                    if word in title_lower:
                        match_score += 0.3
                    if word in content_lower:
                        occurrences = content_lower.count(word)
                        match_score += min(occurrences * 0.05, 0.2)
            
            # Check section titles and content
            for section in doc.sections:
                section_title_lower = section.title.lower()
                section_content_lower = section.content.lower()
                
                if query_lower in section_title_lower:
                    match_score += 0.4
                
                for word in query_words:
                    if len(word) > 2:
                        if word in section_title_lower:
                            match_score += 0.2
                        if word in section_content_lower:
                            occurrences = section_content_lower.count(word)
                            match_score += min(occurrences * 0.02, 0.1)
            
            # Only include documents with matches
            if match_score > 0:
                # Apply time decay if enabled
                decay_factor = 1.0  # Default to no decay
                if enable_time_decay:
                    decay_factor = calculate_decay_factor(
                        doc.ingestion_timestamp,
                        reference_time=None,
                        decay_rate=decay_rate
                    )
                    final_score = match_score * decay_factor
                else:
                    final_score = match_score
                
                # Store score for sorting
                doc.metadata['_search_score'] = final_score
                doc.metadata['_decay_factor'] = decay_factor
                results.append(doc)
        
        # Sort by final score (highest first)
        results.sort(key=lambda d: d.metadata.get('_search_score', 0), reverse=True)
        
        return results
    
    def _save_to_disk(self):
        """Save documents to disk."""
        if not self.storage_path:
            return
        
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert documents to dict for JSON serialization
        data = {
            doc_id: doc.model_dump()
            for doc_id, doc in self.documents.items()
        }
        
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_from_disk(self):
        """Load documents from disk."""
        if not self.storage_path or not self.storage_path.exists():
            return
        
        with open(self.storage_path, 'r') as f:
            data = json.load(f)
        
        # Convert dict back to Document objects
        for doc_id, doc_data in data.items():
            self.documents[doc_id] = Document(**doc_data)


class ContextExtractor:
    """Extracts relevant context from documents based on weights and time-based decay."""
    
    def __init__(
        self, 
        store: DocumentStore, 
        enrich_metadata: bool = True,
        enable_time_decay: bool = True,
        decay_rate: float = 1.0,
        enable_citations: bool = True,
        detect_conflicts: bool = True
    ):
        """
        Initialize context extractor.
        
        Args:
            store: The document store to use
            enrich_metadata: Whether to enrich chunks with metadata (default: True)
            enable_time_decay: Whether to apply time-based decay to relevance (default: True)
            decay_rate: Rate of time decay (default: 1.0). Higher = faster decay.
            enable_citations: Whether to include source citations (default: True)
            detect_conflicts: Whether to detect conflicts between sources (default: True)
        """
        self.store = store
        self.enrich_metadata = enrich_metadata
        self.enricher = None  # enrichment module removed in Public Preview
        self.enable_time_decay = enable_time_decay
        self.decay_rate = decay_rate
        self.enable_citations = False  # citations disabled
        self.detect_conflicts = False
    
    def _format_section(self, section: 'Section', document: Document) -> str:
        """
        Format a section for output.
        
        Args:
            section: Section to format
            document: Parent document for metadata
            
        Returns:
            Formatted section string
        """
        content = section.content
        return f"\n## {section.title}\n{content}\n"
    
    def extract_context(
        self,
        document_id: str,
        query: str = "",
        max_tokens: int = 2000
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Extract context from a document with structure-aware boosting and time-based decay.
        
        Now with Context scoring support:
        - Includes source citations for transparency
        - Detects conflicts between official and practical sources
        - Presents both official and real-world information
        
        Prioritizes:
        1. Tier 1 (High Value) content over Tier 2 and Tier 3
        2. Recent documents over old documents (when time decay is enabled)
        
        Formula: Final Score = Base Weight * Decay Factor
        Where Decay Factor = 1 / (1 + days_elapsed)
        
        Result: A document from Yesterday with 80% match beats a document 
                from Last Year with 95% match.
        
        Args:
            document_id: The document ID
            query: Optional query to focus context extraction
            max_tokens: Maximum tokens to return
            
        Returns:
            Tuple of (context_string, metadata)
        """
        document = self.store.get(document_id)
        if not document:
            return "", {"error": "Document not found"}
        
        # Calculate decay factor for the document if time decay is enabled
        decay_factor = 1.0
        if self.enable_time_decay:
            decay_factor = calculate_decay_factor(
                document.ingestion_timestamp,
                reference_time=None,  # Use current time
                decay_rate=self.decay_rate
            )
        
        # Create a list of sections with adjusted weights (don't mutate original)
        # This is the key: old documents get their weights reduced
        adjusted_sections = []
        for section in document.sections:
            # Create a shallow copy of the section and adjust weight
            adjusted_section = copy.copy(section)
            adjusted_section.weight = section.weight * decay_factor
            adjusted_sections.append(adjusted_section)
        
        # Sort sections by weight (highest first)
        # Now sections from recent documents will rank higher
        sorted_sections = sorted(
            adjusted_sections,
            key=lambda s: s.weight,
            reverse=True
        )
        
        # If query provided, boost sections matching the query
        if query:
            query_lower = query.lower()
            for section in sorted_sections:
                if query_lower in section.content.lower():
                    # Query boost: 50% increase
                    section.weight *= 1.5
            
            # Re-sort after query boosting
            sorted_sections.sort(key=lambda s: s.weight, reverse=True)
        
        # Build context string within token limit
        context_parts = []
        sections_used = []
        total_chars = 0
        char_limit = max_tokens * 4  # Approximate: 4 chars per token
        
        for section in sorted_sections:
            # Format section
            section_text = self._format_section(section, document)
            
            if total_chars + len(section_text) > char_limit:
                # Add partial section if there's room
                remaining = char_limit - total_chars
                if remaining > 100:
                    section_text = section_text[:remaining] + "..."
                    context_parts.append(section_text)
                    sections_used.append(section.title)
                break
            
            context_parts.append(section_text)
            sections_used.append(section.title)
            total_chars += len(section_text)
        
        context = "".join(context_parts)
        
        metadata = {
            "document_id": document_id,
            "document_type": document.detected_type,
            "sections_used": sections_used,
            "weights_applied": {s.title: s.weight for s in sorted_sections},
            "tiers_applied": {
                s.title: s.tier.value if s.tier else "unknown" 
                for s in sorted_sections
            },
            "total_sections": len(document.sections),
            "sections_included": len(sections_used),
            "metadata_enriched": self.enrich_metadata,
            "time_decay_enabled": self.enable_time_decay,
            "decay_factor": decay_factor,
            "ingestion_timestamp": document.ingestion_timestamp,
            "citations": [],
            "conflicts": [],
        }
        
        return context, metadata
    


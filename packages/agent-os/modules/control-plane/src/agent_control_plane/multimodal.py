# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Multimodal Capabilities - Vision, Audio, and RAG Integration

This module extends agent capabilities beyond text to support vision (image analysis),
audio processing, and Retrieval-Augmented Generation (RAG) with vector stores.

Research Foundations:
    - "Multimodal Agents: A Survey" (arXiv:2404.12390, 2024)
    - GPT-4V vision capabilities and safety considerations
    - "AudioLM: Language Modeling Approach to Audio" (arXiv:2209.03143)
    - RAG patterns from "Retrieval-Augmented Generation for Large Language Models" 
      (arXiv:2312.10997, 2023)
    - Vector database integration patterns from Pinecone, Weaviate, ChromaDB docs

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import base64
import hashlib
import json


class ModalityType(Enum):
    """Types of modalities supported"""
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    MULTIMODAL = "multimodal"


class ImageFormat(Enum):
    """Supported image formats"""
    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"
    BASE64 = "base64"


class AudioFormat(Enum):
    """Supported audio formats"""
    MP3 = "mp3"
    WAV = "wav"
    OGG = "ogg"
    FLAC = "flac"


class VectorStoreType(Enum):
    """Supported vector store backends"""
    PINECONE = "pinecone"
    WEAVIATE = "weaviate"
    CHROMA = "chroma"
    QDRANT = "qdrant"
    MILVUS = "milvus"
    IN_MEMORY = "in_memory"


@dataclass
class ImageInput:
    """
    Image input for vision capabilities.
    
    Attributes:
        image_data: Base64-encoded image or file path
        format: Image format
        url: Optional URL if image is remote
        metadata: Additional metadata (size, dimensions, etc.)
    """
    image_data: str
    format: ImageFormat
    url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_hash(self) -> str:
        """Get hash of image for caching/deduplication"""
        return hashlib.sha256(self.image_data.encode()).hexdigest()[:16]


@dataclass
class AudioInput:
    """
    Audio input for audio processing.
    
    Attributes:
        audio_data: Base64-encoded audio or file path
        format: Audio format
        duration_seconds: Optional duration
        sample_rate: Optional sample rate
        metadata: Additional metadata
    """
    audio_data: str
    format: AudioFormat
    duration_seconds: Optional[float] = None
    sample_rate: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MultimodalInput:
    """
    Combined multimodal input.
    
    Attributes:
        text: Optional text component
        images: List of images
        audio: List of audio inputs
        metadata: Additional metadata
    """
    text: Optional[str] = None
    images: List[ImageInput] = field(default_factory=list)
    audio: List[AudioInput] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_modalities(self) -> List[ModalityType]:
        """Get list of modalities present"""
        modalities = []
        if self.text:
            modalities.append(ModalityType.TEXT)
        if self.images:
            modalities.append(ModalityType.IMAGE)
        if self.audio:
            modalities.append(ModalityType.AUDIO)
        return modalities


@dataclass
class VectorDocument:
    """
    Document with vector embedding for RAG.
    
    Attributes:
        doc_id: Unique document identifier
        content: Document content (text)
        embedding: Vector embedding (simplified as list)
        metadata: Document metadata (source, timestamp, etc.)
    """
    doc_id: str
    content: str
    embedding: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class VisionCapability:
    """
    Vision capabilities for image analysis.
    
    Features:
    - Image understanding and description
    - Object detection and recognition
    - Safety filtering for inappropriate content
    - Content moderation
    
    Note: This is a governance wrapper. Actual vision processing
    would integrate with GPT-4V, Claude Vision, or similar models.
    
    Usage:
        vision = VisionCapability()
        
        # Analyze image
        result = vision.analyze_image(
            image=ImageInput(image_data=base64_img, format=ImageFormat.PNG),
            prompt="Describe this image"
        )
        
        # Check safety
        safety_check = vision.check_image_safety(image)
    """
    
    def __init__(self):
        self._analysis_history: List[Dict[str, Any]] = []
        self._blocked_content_types = ["explicit", "violence", "harmful"]
    
    def analyze_image(
        self,
        image: ImageInput,
        prompt: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze an image with a text prompt.
        
        Args:
            image: Image to analyze
            prompt: Text prompt for analysis
            context: Additional context
            
        Returns:
            Analysis results
        """
        # Safety check first
        safety_result = self.check_image_safety(image)
        
        if not safety_result["safe"]:
            return {
                "success": False,
                "error": "Image failed safety check",
                "safety_violations": safety_result["violations"],
                "blocked": True
            }
        
        # In production, would call vision model API here
        # For now, return governance metadata
        analysis = {
            "success": True,
            "image_hash": image.get_hash(),
            "prompt": prompt,
            "analysis": "Image analysis would be performed by vision model",
            "safety_checked": True,
            "timestamp": datetime.now().isoformat()
        }
        
        self._analysis_history.append({
            "image_hash": image.get_hash(),
            "prompt": prompt,
            "timestamp": datetime.now().isoformat(),
            "safe": True
        })
        
        return analysis
    
    def check_image_safety(
        self,
        image: ImageInput
    ) -> Dict[str, Any]:
        """
        Check if an image is safe for processing.
        
        This is a governance hook. In production, would integrate
        with content moderation APIs.
        
        Args:
            image: Image to check
            
        Returns:
            Safety check results
        """
        # In production, would use actual content moderation
        # For now, implement basic checks
        
        violations = []
        
        # Check metadata for warnings
        if image.metadata.get("nsfw", False):
            violations.append("explicit")
        
        # Check file size (prevent abuse)
        image_size = len(image.image_data)
        if image_size > 10 * 1024 * 1024:  # 10MB limit
            violations.append("file_too_large")
        
        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "image_hash": image.get_hash(),
            "checked_at": datetime.now().isoformat()
        }
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported image formats"""
        return [fmt.value for fmt in ImageFormat]
    
    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get history of image analyses"""
        return self._analysis_history.copy()


class AudioCapability:
    """
    Audio processing capabilities.
    
    Features:
    - Audio transcription
    - Audio generation
    - Voice activity detection
    - Content moderation for audio
    
    Note: This is a governance wrapper. Actual audio processing
    would integrate with Whisper, ElevenLabs, or similar services.
    
    Usage:
        audio = AudioCapability()
        
        # Transcribe audio
        result = audio.transcribe(
            audio=AudioInput(audio_data=base64_audio, format=AudioFormat.MP3)
        )
        
        # Check safety
        safety_check = audio.check_audio_safety(audio_input)
    """
    
    def __init__(self):
        self._transcription_history: List[Dict[str, Any]] = []
    
    def transcribe(
        self,
        audio: AudioInput,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Transcribe audio to text.
        
        Args:
            audio: Audio to transcribe
            language: Optional language hint
            
        Returns:
            Transcription results
        """
        # Safety check
        safety_result = self.check_audio_safety(audio)
        
        if not safety_result["safe"]:
            return {
                "success": False,
                "error": "Audio failed safety check",
                "blocked": True
            }
        
        # In production, would call transcription API (e.g., Whisper)
        result = {
            "success": True,
            "transcription": "Audio transcription would be performed by speech model",
            "language": language or "auto-detect",
            "duration": audio.duration_seconds,
            "timestamp": datetime.now().isoformat()
        }
        
        self._transcription_history.append({
            "audio_format": audio.format.value,
            "language": language,
            "timestamp": datetime.now().isoformat()
        })
        
        return result
    
    def check_audio_safety(
        self,
        audio: AudioInput
    ) -> Dict[str, Any]:
        """
        Check if audio is safe for processing.
        
        Args:
            audio: Audio to check
            
        Returns:
            Safety check results
        """
        violations = []
        
        # Check file size
        audio_size = len(audio.audio_data)
        if audio_size > 25 * 1024 * 1024:  # 25MB limit
            violations.append("file_too_large")
        
        # Check duration
        if audio.duration_seconds and audio.duration_seconds > 300:  # 5 min limit
            violations.append("duration_too_long")
        
        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "checked_at": datetime.now().isoformat()
        }
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported audio formats"""
        return [fmt.value for fmt in AudioFormat]


class VectorStoreIntegration:
    """
    Integration with vector databases for RAG (Retrieval-Augmented Generation).
    
    Features:
    - Vector storage and retrieval
    - Semantic search
    - Hybrid search (vector + keyword)
    - Multiple backend support (Pinecone, Weaviate, ChromaDB, etc.)
    
    Usage:
        vector_store = VectorStoreIntegration(
            store_type=VectorStoreType.CHROMA,
            collection_name="knowledge_base"
        )
        
        # Add documents
        vector_store.add_documents([
            VectorDocument(
                doc_id="doc1",
                content="AI safety is important",
                embedding=[0.1, 0.2, 0.3, ...]
            )
        ])
        
        # Search
        results = vector_store.search(
            query_embedding=[0.1, 0.2, 0.3, ...],
            top_k=5
        )
    """
    
    def __init__(
        self,
        store_type: VectorStoreType = VectorStoreType.IN_MEMORY,
        collection_name: str = "default",
        config: Optional[Dict[str, Any]] = None
    ):
        self.store_type = store_type
        self.collection_name = collection_name
        self.config = config or {}
        
        # In-memory storage for simplified implementation
        self._documents: Dict[str, VectorDocument] = {}
        self._index_built = False
    
    def add_documents(
        self,
        documents: List[VectorDocument]
    ) -> Dict[str, Any]:
        """
        Add documents to vector store.
        
        Args:
            documents: List of documents with embeddings
            
        Returns:
            Result with added document IDs
        """
        added_ids = []
        
        for doc in documents:
            self._documents[doc.doc_id] = doc
            added_ids.append(doc.doc_id)
        
        self._index_built = False  # Mark for reindexing
        
        return {
            "success": True,
            "added_count": len(added_ids),
            "document_ids": added_ids
        }
    
    def search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar documents.
        
        Args:
            query_embedding: Query vector
            top_k: Number of results to return
            filter_metadata: Optional metadata filters
            
        Returns:
            List of similar documents with scores
        """
        if not self._documents:
            return []
        
        # Calculate similarities (simplified cosine similarity)
        results = []
        
        for doc_id, doc in self._documents.items():
            # Apply metadata filters if provided
            if filter_metadata:
                if not self._matches_filters(doc.metadata, filter_metadata):
                    continue
            
            # Simplified similarity calculation
            similarity = self._calculate_similarity(query_embedding, doc.embedding)
            
            results.append({
                "doc_id": doc_id,
                "content": doc.content,
                "similarity": similarity,
                "metadata": doc.metadata
            })
        
        # Sort by similarity and return top k
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]
    
    def delete_documents(
        self,
        doc_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Delete documents from vector store.
        
        Args:
            doc_ids: List of document IDs to delete
            
        Returns:
            Deletion results
        """
        deleted = []
        not_found = []
        
        for doc_id in doc_ids:
            if doc_id in self._documents:
                del self._documents[doc_id]
                deleted.append(doc_id)
            else:
                not_found.append(doc_id)
        
        return {
            "success": True,
            "deleted_count": len(deleted),
            "deleted_ids": deleted,
            "not_found": not_found
        }
    
    def get_document(self, doc_id: str) -> Optional[VectorDocument]:
        """Get a document by ID"""
        return self._documents.get(doc_id)
    
    def list_documents(
        self,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        List documents in the collection.
        
        Args:
            limit: Optional limit on number of documents
            
        Returns:
            List of document metadata
        """
        docs = list(self._documents.values())
        
        if limit:
            docs = docs[:limit]
        
        return [
            {
                "doc_id": doc.doc_id,
                "content_preview": doc.content[:100] + "..." if len(doc.content) > 100 else doc.content,
                "metadata": doc.metadata,
                "timestamp": doc.timestamp.isoformat()
            }
            for doc in docs
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            "store_type": self.store_type.value,
            "collection_name": self.collection_name,
            "document_count": len(self._documents),
            "index_built": self._index_built
        }
    
    def _calculate_similarity(
        self,
        vec1: List[float],
        vec2: List[float]
    ) -> float:
        """
        Calculate cosine similarity between two vectors.
        Simplified implementation.
        """
        if len(vec1) != len(vec2):
            return 0.0
        
        # Dot product
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        
        # Magnitudes
        mag1 = sum(a * a for a in vec1) ** 0.5
        mag2 = sum(b * b for b in vec2) ** 0.5
        
        if mag1 == 0 or mag2 == 0:
            return 0.0
        
        return dot_product / (mag1 * mag2)
    
    def _matches_filters(
        self,
        metadata: Dict[str, Any],
        filters: Dict[str, Any]
    ) -> bool:
        """Check if metadata matches filters"""
        for key, value in filters.items():
            if key not in metadata or metadata[key] != value:
                return False
        return True


class RAGPipeline:
    """
    Complete RAG (Retrieval-Augmented Generation) pipeline.
    
    Combines vector store retrieval with generation for knowledge-grounded responses.
    
    Features:
    - Document retrieval
    - Context assembly
    - Prompt engineering for RAG
    - Citation tracking
    
    Usage:
        rag = RAGPipeline(vector_store)
        
        # Query with RAG
        response = rag.query(
            "What is AI safety?",
            query_embedding=[...],
            top_k=3
        )
    """
    
    def __init__(self, vector_store: VectorStoreIntegration):
        self.vector_store = vector_store
        self._query_history: List[Dict[str, Any]] = []
    
    def query(
        self,
        query_text: str,
        query_embedding: List[float],
        top_k: int = 3,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Query with RAG pipeline.
        
        Args:
            query_text: Query text
            query_embedding: Query vector embedding
            top_k: Number of documents to retrieve
            context: Additional context
            
        Returns:
            RAG response with retrieved documents and citations
        """
        # Retrieve relevant documents
        retrieved_docs = self.vector_store.search(
            query_embedding=query_embedding,
            top_k=top_k
        )
        
        # Assemble context from retrieved documents
        context_text = self._assemble_context(retrieved_docs)
        
        # Create RAG prompt
        rag_prompt = self._create_rag_prompt(query_text, context_text)
        
        # Track query
        self._query_history.append({
            "query": query_text,
            "retrieved_count": len(retrieved_docs),
            "timestamp": datetime.now().isoformat()
        })
        
        return {
            "success": True,
            "query": query_text,
            "retrieved_documents": retrieved_docs,
            "context": context_text,
            "rag_prompt": rag_prompt,
            "citations": [doc["doc_id"] for doc in retrieved_docs]
        }
    
    def _assemble_context(
        self,
        retrieved_docs: List[Dict[str, Any]]
    ) -> str:
        """Assemble context from retrieved documents"""
        context_parts = []
        
        for i, doc in enumerate(retrieved_docs, 1):
            context_parts.append(f"[{i}] {doc['content']}")
        
        return "\n\n".join(context_parts)
    
    def _create_rag_prompt(
        self,
        query: str,
        context: str
    ) -> str:
        """Create RAG-style prompt"""
        return f"""Use the following context to answer the question. Cite sources using [1], [2], etc.

Context:
{context}

Question: {query}

Answer:"""
    
    def get_query_history(self) -> List[Dict[str, Any]]:
        """Get query history"""
        return self._query_history.copy()


def create_multimodal_suite() -> Dict[str, Any]:
    """
    Create a complete multimodal capabilities suite.
    
    Returns:
        Dictionary with vision, audio, and RAG capabilities
    """
    vector_store = VectorStoreIntegration(
        store_type=VectorStoreType.IN_MEMORY,
        collection_name="knowledge_base"
    )
    
    return {
        "vision": VisionCapability(),
        "audio": AudioCapability(),
        "vector_store": vector_store,
        "rag_pipeline": RAGPipeline(vector_store)
    }

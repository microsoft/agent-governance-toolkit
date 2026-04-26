# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multimodal and RAG Examples

This demonstrates vision, audio, and RAG capabilities for multimodal agents.
"""

from agent_control_plane import (
    VisionCapability,
    AudioCapability,
    VectorStoreIntegration,
    RAGPipeline,
    ImageInput,
    AudioInput,
    VectorDocument,
    ImageFormat,
    AudioFormat,
    VectorStoreType,
    create_multimodal_suite
)
import base64


def example_vision_analysis():
    """Example: Analyzing images with vision capability"""
    print("=== Vision Capability Example ===\n")
    
    vision = VisionCapability()
    
    # Simulated image (in production, would be actual base64-encoded image)
    image = ImageInput(
        image_data="simulated_base64_encoded_image_data",
        format=ImageFormat.PNG,
        metadata={"source": "user_upload", "size": 1024}
    )
    
    # Analyze image
    result = vision.analyze_image(
        image=image,
        prompt="Describe what you see in this image"
    )
    
    print("Image Analysis:")
    print(f"  Success: {result['success']}")
    print(f"  Safety checked: {result['safety_checked']}")
    print(f"  Image hash: {result['image_hash']}")
    print()
    
    # Check image safety
    safety = vision.check_image_safety(image)
    print("Image Safety Check:")
    print(f"  Safe: {safety['safe']}")
    print(f"  Violations: {safety['violations']}")
    print()
    
    print(f"Supported formats: {', '.join(vision.get_supported_formats())}")
    print()


def example_audio_processing():
    """Example: Processing audio with transcription"""
    print("=== Audio Capability Example ===\n")
    
    audio_cap = AudioCapability()
    
    # Simulated audio input
    audio = AudioInput(
        audio_data="simulated_base64_encoded_audio_data",
        format=AudioFormat.MP3,
        duration_seconds=45.0,
        sample_rate=44100
    )
    
    # Transcribe audio
    result = audio_cap.transcribe(audio, language="en")
    
    print("Audio Transcription:")
    print(f"  Success: {result['success']}")
    print(f"  Duration: {result['duration']} seconds")
    print(f"  Language: {result['language']}")
    print()
    
    # Check audio safety
    safety = audio_cap.check_audio_safety(audio)
    print("Audio Safety Check:")
    print(f"  Safe: {safety['safe']}")
    print(f"  Violations: {safety['violations']}")
    print()
    
    print(f"Supported formats: {', '.join(audio_cap.get_supported_formats())}")
    print()


def example_vector_store():
    """Example: Using vector store for document storage"""
    print("=== Vector Store Example ===\n")
    
    vector_store = VectorStoreIntegration(
        store_type=VectorStoreType.IN_MEMORY,
        collection_name="knowledge_base"
    )
    
    # Add documents
    documents = [
        VectorDocument(
            doc_id="doc1",
            content="Agent Control Plane provides governance for AI agents",
            embedding=[0.1, 0.2, 0.3, 0.4, 0.5],
            metadata={"source": "documentation", "category": "overview"}
        ),
        VectorDocument(
            doc_id="doc2",
            content="Constitutional AI helps align agent behavior with values",
            embedding=[0.2, 0.3, 0.4, 0.5, 0.6],
            metadata={"source": "documentation", "category": "safety"}
        ),
        VectorDocument(
            doc_id="doc3",
            content="RAG enables knowledge-grounded generation",
            embedding=[0.3, 0.4, 0.5, 0.6, 0.7],
            metadata={"source": "documentation", "category": "features"}
        )
    ]
    
    result = vector_store.add_documents(documents)
    print(f"Added Documents:")
    print(f"  Count: {result['added_count']}")
    print(f"  IDs: {', '.join(result['document_ids'])}")
    print()
    
    # Search for similar documents
    query_embedding = [0.15, 0.25, 0.35, 0.45, 0.55]
    results = vector_store.search(
        query_embedding=query_embedding,
        top_k=2
    )
    
    print(f"Search Results (top 2):")
    for i, doc in enumerate(results, 1):
        print(f"  {i}. {doc['content']}")
        print(f"     Similarity: {doc['similarity']:.3f}")
        print(f"     Metadata: {doc['metadata']}")
    print()
    
    # Get stats
    stats = vector_store.get_stats()
    print(f"Vector Store Stats:")
    print(f"  Type: {stats['store_type']}")
    print(f"  Collection: {stats['collection_name']}")
    print(f"  Documents: {stats['document_count']}")
    print()


def example_rag_pipeline():
    """Example: RAG (Retrieval-Augmented Generation) pipeline"""
    print("=== RAG Pipeline Example ===\n")
    
    # Set up vector store with knowledge
    vector_store = VectorStoreIntegration(
        store_type=VectorStoreType.IN_MEMORY,
        collection_name="ai_knowledge"
    )
    
    knowledge_docs = [
        VectorDocument(
            doc_id="safety1",
            content="AI safety focuses on ensuring AI systems behave as intended and don't cause unintended harm. Key approaches include alignment, robustness, and interpretability.",
            embedding=[0.8, 0.7, 0.6, 0.5, 0.4]
        ),
        VectorDocument(
            doc_id="governance1",
            content="AI governance involves establishing policies, standards, and oversight mechanisms to ensure responsible AI development and deployment.",
            embedding=[0.7, 0.8, 0.5, 0.6, 0.3]
        ),
        VectorDocument(
            doc_id="agents1",
            content="Autonomous agents are AI systems that can perceive their environment and take actions to achieve goals with minimal human intervention.",
            embedding=[0.6, 0.5, 0.8, 0.7, 0.2]
        )
    ]
    
    vector_store.add_documents(knowledge_docs)
    
    # Create RAG pipeline
    rag = RAGPipeline(vector_store)
    
    # Query with RAG
    query = "What is AI safety?"
    query_embedding = [0.75, 0.65, 0.55, 0.45, 0.35]
    
    result = rag.query(
        query_text=query,
        query_embedding=query_embedding,
        top_k=2
    )
    
    print(f"RAG Query: {query}")
    print(f"  Retrieved: {len(result['retrieved_documents'])} documents")
    print()
    
    print("Retrieved Context:")
    for i, doc in enumerate(result['retrieved_documents'], 1):
        print(f"  [{i}] {doc['content'][:80]}...")
    print()
    
    print("RAG Prompt (for LLM):")
    print(result['rag_prompt'][:200] + "...")
    print()
    
    print(f"Citations: {result['citations']}")
    print()


def example_multimodal_input():
    """Example: Processing multimodal input (text + image + audio)"""
    print("=== Multimodal Input Example ===\n")
    
    from agent_control_plane.multimodal import MultimodalInput, ModalityType
    
    # Create multimodal input
    mm_input = MultimodalInput(
        text="Analyze this medical scan and audio recording",
        images=[
            ImageInput(
                image_data="medical_scan_image",
                format=ImageFormat.PNG,
                metadata={"type": "x-ray"}
            )
        ],
        audio=[
            AudioInput(
                audio_data="doctor_notes_audio",
                format=AudioFormat.WAV,
                duration_seconds=120.0
            )
        ]
    )
    
    modalities = mm_input.get_modalities()
    print("Multimodal Input:")
    print(f"  Text: {mm_input.text[:50]}...")
    print(f"  Images: {len(mm_input.images)}")
    print(f"  Audio: {len(mm_input.audio)}")
    print(f"  Modalities: {[m.value for m in modalities]}")
    print()


def example_rag_with_metadata_filtering():
    """Example: RAG with metadata filtering"""
    print("=== RAG with Metadata Filtering ===\n")
    
    vector_store = VectorStoreIntegration(
        store_type=VectorStoreType.IN_MEMORY
    )
    
    # Add documents with metadata
    docs = [
        VectorDocument(
            doc_id="tech1",
            content="Machine learning algorithms learn from data",
            embedding=[0.5, 0.5, 0.5, 0.5, 0.5],
            metadata={"category": "technical", "difficulty": "beginner"}
        ),
        VectorDocument(
            doc_id="tech2",
            content="Neural networks consist of interconnected layers",
            embedding=[0.6, 0.5, 0.5, 0.5, 0.4],
            metadata={"category": "technical", "difficulty": "advanced"}
        ),
        VectorDocument(
            doc_id="business1",
            content="AI can improve business efficiency and decision-making",
            embedding=[0.5, 0.6, 0.5, 0.4, 0.5],
            metadata={"category": "business", "difficulty": "beginner"}
        )
    ]
    
    vector_store.add_documents(docs)
    
    # Search with metadata filter
    query_embedding = [0.55, 0.55, 0.5, 0.5, 0.45]
    
    # Filter for technical content only
    results = vector_store.search(
        query_embedding=query_embedding,
        top_k=5,
        filter_metadata={"category": "technical"}
    )
    
    print("Search Results (technical only):")
    for doc in results:
        print(f"  - {doc['content']}")
        print(f"    Category: {doc['metadata']['category']}")
        print(f"    Difficulty: {doc['metadata']['difficulty']}")
    print()


def example_integrated_multimodal():
    """Example: Using complete multimodal suite"""
    print("=== Integrated Multimodal Suite ===\n")
    
    suite = create_multimodal_suite()
    
    vision = suite["vision"]
    audio = suite["audio"]
    vector_store = suite["vector_store"]
    rag = suite["rag_pipeline"]
    
    print("Multimodal Suite Components:")
    print(f"  ✅ Vision Capability")
    print(f"  ✅ Audio Capability")
    print(f"  ✅ Vector Store ({vector_store.store_type.value})")
    print(f"  ✅ RAG Pipeline")
    print()
    
    # Example workflow
    print("Example Workflow:")
    print("  1. Process image with vision capability")
    print("  2. Transcribe audio with audio capability")
    print("  3. Store results in vector store")
    print("  4. Use RAG to answer questions about the content")
    print()


if __name__ == "__main__":
    print("Agent Control Plane - Multimodal & RAG Examples")
    print("=" * 70)
    print()
    
    example_vision_analysis()
    print("\n" + "=" * 70 + "\n")
    
    example_audio_processing()
    print("\n" + "=" * 70 + "\n")
    
    example_vector_store()
    print("\n" + "=" * 70 + "\n")
    
    example_rag_pipeline()
    print("\n" + "=" * 70 + "\n")
    
    example_multimodal_input()
    print("\n" + "=" * 70 + "\n")
    
    example_rag_with_metadata_filtering()
    print("\n" + "=" * 70 + "\n")
    
    example_integrated_multimodal()

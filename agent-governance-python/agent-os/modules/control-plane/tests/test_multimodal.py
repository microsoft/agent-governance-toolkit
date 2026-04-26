# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Multimodal capabilities
"""

import unittest
from src.agent_control_plane.multimodal import (
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


class TestVisionCapability(unittest.TestCase):
    """Test vision capability functionality"""
    
    def setUp(self):
        self.vision = VisionCapability()
    
    def test_analyze_safe_image(self):
        """Test analyzing a safe image"""
        image = ImageInput(
            image_data="base64_encoded_image_data",
            format=ImageFormat.PNG
        )
        
        result = self.vision.analyze_image(
            image=image,
            prompt="Describe this image"
        )
        
        self.assertTrue(result["success"])
        self.assertTrue(result["safety_checked"])
    
    def test_check_image_safety_pass(self):
        """Test image safety check that passes"""
        image = ImageInput(
            image_data="small_image_data",
            format=ImageFormat.JPEG
        )
        
        result = self.vision.check_image_safety(image)
        
        self.assertTrue(result["safe"])
        self.assertEqual(len(result["violations"]), 0)
    
    def test_check_image_safety_nsfw(self):
        """Test image safety check for NSFW content"""
        image = ImageInput(
            image_data="image_data",
            format=ImageFormat.PNG,
            metadata={"nsfw": True}
        )
        
        result = self.vision.check_image_safety(image)
        
        self.assertFalse(result["safe"])
        self.assertIn("explicit", result["violations"])
    
    def test_get_supported_formats(self):
        """Test getting supported image formats"""
        formats = self.vision.get_supported_formats()
        
        self.assertIn("jpeg", formats)
        self.assertIn("png", formats)


class TestAudioCapability(unittest.TestCase):
    """Test audio capability functionality"""
    
    def setUp(self):
        self.audio = AudioCapability()
    
    def test_transcribe_audio(self):
        """Test audio transcription"""
        audio = AudioInput(
            audio_data="base64_encoded_audio",
            format=AudioFormat.MP3,
            duration_seconds=30.0
        )
        
        result = self.audio.transcribe(audio)
        
        self.assertTrue(result["success"])
        self.assertIn("transcription", result)
    
    def test_check_audio_safety_pass(self):
        """Test audio safety check that passes"""
        audio = AudioInput(
            audio_data="small_audio_data",
            format=AudioFormat.WAV,
            duration_seconds=60.0
        )
        
        result = self.audio.check_audio_safety(audio)
        
        self.assertTrue(result["safe"])
    
    def test_check_audio_safety_too_long(self):
        """Test audio safety check for too long audio"""
        audio = AudioInput(
            audio_data="audio_data",
            format=AudioFormat.MP3,
            duration_seconds=400.0
        )
        
        result = self.audio.check_audio_safety(audio)
        
        self.assertFalse(result["safe"])
        self.assertIn("duration_too_long", result["violations"])
    
    def test_get_supported_formats(self):
        """Test getting supported audio formats"""
        formats = self.audio.get_supported_formats()
        
        self.assertIn("mp3", formats)
        self.assertIn("wav", formats)


class TestVectorStoreIntegration(unittest.TestCase):
    """Test vector store integration"""
    
    def setUp(self):
        self.vector_store = VectorStoreIntegration(
            store_type=VectorStoreType.IN_MEMORY,
            collection_name="test_collection"
        )
    
    def test_add_documents(self):
        """Test adding documents to vector store"""
        docs = [
            VectorDocument(
                doc_id="doc1",
                content="AI safety is important",
                embedding=[0.1, 0.2, 0.3]
            ),
            VectorDocument(
                doc_id="doc2",
                content="Governance is crucial",
                embedding=[0.4, 0.5, 0.6]
            )
        ]
        
        result = self.vector_store.add_documents(docs)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["added_count"], 2)
    
    def test_search_documents(self):
        """Test searching for similar documents"""
        # Add documents
        docs = [
            VectorDocument(
                doc_id="doc1",
                content="AI safety",
                embedding=[0.1, 0.2, 0.3]
            ),
            VectorDocument(
                doc_id="doc2",
                content="Machine learning",
                embedding=[0.9, 0.8, 0.7]
            )
        ]
        self.vector_store.add_documents(docs)
        
        # Search
        results = self.vector_store.search(
            query_embedding=[0.1, 0.2, 0.3],
            top_k=2
        )
        
        self.assertEqual(len(results), 2)
        # First result should be most similar
        self.assertEqual(results[0]["doc_id"], "doc1")
    
    def test_delete_documents(self):
        """Test deleting documents"""
        docs = [
            VectorDocument(
                doc_id="doc1",
                content="Test",
                embedding=[0.1, 0.2, 0.3]
            )
        ]
        self.vector_store.add_documents(docs)
        
        result = self.vector_store.delete_documents(["doc1"])
        
        self.assertTrue(result["success"])
        self.assertEqual(result["deleted_count"], 1)
    
    def test_get_document(self):
        """Test getting a document by ID"""
        doc = VectorDocument(
            doc_id="doc1",
            content="Test content",
            embedding=[0.1, 0.2, 0.3]
        )
        self.vector_store.add_documents([doc])
        
        retrieved = self.vector_store.get_document("doc1")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.content, "Test content")
    
    def test_list_documents(self):
        """Test listing documents"""
        docs = [
            VectorDocument(
                doc_id=f"doc{i}",
                content=f"Content {i}",
                embedding=[0.1, 0.2, 0.3]
            )
            for i in range(5)
        ]
        self.vector_store.add_documents(docs)
        
        listed = self.vector_store.list_documents(limit=3)
        
        self.assertEqual(len(listed), 3)
    
    def test_get_stats(self):
        """Test getting collection statistics"""
        stats = self.vector_store.get_stats()
        
        self.assertIn("store_type", stats)
        self.assertIn("collection_name", stats)
        self.assertIn("document_count", stats)


class TestRAGPipeline(unittest.TestCase):
    """Test RAG pipeline functionality"""
    
    def setUp(self):
        self.vector_store = VectorStoreIntegration(
            store_type=VectorStoreType.IN_MEMORY
        )
        self.rag = RAGPipeline(self.vector_store)
    
    def test_query_with_retrieval(self):
        """Test RAG query with document retrieval"""
        # Add documents
        docs = [
            VectorDocument(
                doc_id="doc1",
                content="AI safety focuses on making AI systems safe and beneficial",
                embedding=[0.1, 0.2, 0.3]
            ),
            VectorDocument(
                doc_id="doc2",
                content="Machine learning is a subset of artificial intelligence",
                embedding=[0.4, 0.5, 0.6]
            )
        ]
        self.vector_store.add_documents(docs)
        
        # Query
        result = self.rag.query(
            query_text="What is AI safety?",
            query_embedding=[0.1, 0.2, 0.3],
            top_k=2
        )
        
        self.assertTrue(result["success"])
        self.assertGreater(len(result["retrieved_documents"]), 0)
        self.assertIn("rag_prompt", result)
        self.assertIn("citations", result)
    
    def test_rag_prompt_format(self):
        """Test RAG prompt formatting"""
        docs = [
            VectorDocument(
                doc_id="doc1",
                content="Test content",
                embedding=[0.1, 0.2, 0.3]
            )
        ]
        self.vector_store.add_documents(docs)
        
        result = self.rag.query(
            query_text="Test query",
            query_embedding=[0.1, 0.2, 0.3]
        )
        
        prompt = result["rag_prompt"]
        self.assertIn("Context:", prompt)
        self.assertIn("Question:", prompt)
        self.assertIn("Test query", prompt)


class TestMultimodalSuite(unittest.TestCase):
    """Test multimodal suite creation"""
    
    def test_create_suite(self):
        """Test creating complete multimodal suite"""
        suite = create_multimodal_suite()
        
        self.assertIn("vision", suite)
        self.assertIn("audio", suite)
        self.assertIn("vector_store", suite)
        self.assertIn("rag_pipeline", suite)
        
        self.assertIsInstance(suite["vision"], VisionCapability)
        self.assertIsInstance(suite["audio"], AudioCapability)
        self.assertIsInstance(suite["vector_store"], VectorStoreIntegration)
        self.assertIsInstance(suite["rag_pipeline"], RAGPipeline)


if __name__ == '__main__':
    unittest.main()

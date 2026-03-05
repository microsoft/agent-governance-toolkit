# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Simple test to verify Context-as-a-Service functionality.
"""

import uuid
from caas.models import ContentFormat, DocumentType
from caas.ingestion import ProcessorFactory
from caas.detection import DocumentTypeDetector
from caas.tuning import WeightTuner
from caas.storage import DocumentStore, ContextExtractor


def test_html_processing():
    """Test HTML document processing pipeline."""
    print("\n=== Testing HTML Processing ===")
    
    # Sample HTML content
    html_content = b"""
    <html>
    <head><title>API Documentation</title></head>
    <body>
        <h1>User API Documentation</h1>
        <h2>Authentication</h2>
        <p>All requests must include an API key in the Authorization header.</p>
        
        <h2>Endpoints</h2>
        <h3>GET /users</h3>
        <p>Retrieve a list of users. This is a critical endpoint for user management.</p>
        
        <h3>POST /users</h3>
        <p>Create a new user. Required fields: name, email.</p>
        
        <h2>Examples</h2>
        <pre>curl -X GET https://api.example.com/users</pre>
    </body>
    </html>
    """
    
    # Process
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "API Documentation"}
    document = processor.process(html_content, metadata)
    
    print(f"✓ Processed document: {document.title}")
    print(f"✓ Found {len(document.sections)} sections")
    for section in document.sections:
        print(f"  - {section.title}")
    
    # Detect type
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    print(f"✓ Detected type: {document.detected_type}")
    
    # Tune weights
    tuner = WeightTuner()
    document = tuner.tune(document)
    print(f"✓ Applied weights:")
    for section in sorted(document.sections, key=lambda s: s.weight, reverse=True):
        print(f"  - {section.title}: {section.weight}x (importance: {section.importance_score:.2f})")
    
    return document


def test_code_processing():
    """Test code document processing pipeline."""
    print("\n=== Testing Code Processing ===")
    
    # Sample Python code
    code_content = b"""
def authenticate_user(username: str, password: str):
    '''Authenticate a user with username and password.'''
    # This is a critical function for security
    return verify_credentials(username, password)

class UserService:
    '''Main service for user operations.'''
    
    def create_user(self, name: str):
        '''Create a new user.'''
        pass
    
    def get_user(self, user_id: str):
        '''Retrieve user by ID.'''
        pass
"""
    
    # Process
    processor = ProcessorFactory.get_processor(ContentFormat.CODE)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "User Service", "language": "python"}
    document = processor.process(code_content, metadata)
    
    print(f"✓ Processed document: {document.title}")
    print(f"✓ Language: {document.metadata.get('language')}")
    print(f"✓ Found {len(document.sections)} sections")
    
    # Detect and tune
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    print(f"✓ Detected type: {document.detected_type}")
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    print(f"✓ Applied weights")
    
    return document


def test_context_extraction():
    """Test context extraction."""
    print("\n=== Testing Context Extraction ===")
    
    # Create a test document
    html_content = b"""
    <html>
    <body>
        <h1>Contract</h1>
        <h2>Definitions</h2>
        <p>This agreement defines the terms between parties.</p>
        
        <h2>Terms of Service</h2>
        <p>The service shall be provided as described herein.</p>
        
        <h2>Termination</h2>
        <p>Either party may terminate this agreement with 30 days notice.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "Service Contract"}
    document = processor.process(html_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    # Store and extract
    store = DocumentStore()
    store.add(document)
    
    extractor = ContextExtractor(store)
    context, metadata = extractor.extract_context(doc_id, query="termination", max_tokens=500)
    
    print(f"✓ Extracted context for query 'termination'")
    print(f"✓ Sections used: {metadata['sections_used']}")
    print(f"✓ Context length: {len(context)} chars")
    print(f"\n--- Context Preview ---")
    print(context[:300])
    
    return context


def test_corpus_analysis():
    """Test corpus analysis."""
    print("\n=== Testing Corpus Analysis ===")
    
    from caas.tuning import CorpusAnalyzer
    
    analyzer = CorpusAnalyzer()
    
    # Add test documents
    for i in range(3):
        html = b"<html><body><h1>Doc</h1><h2>Section</h2><p>Content</p></body></html>"
        processor = ProcessorFactory.get_processor(ContentFormat.HTML)
        doc = processor.process(html, {"id": str(i), "title": f"Doc {i}"})
        
        detector = DocumentTypeDetector()
        doc.detected_type = detector.detect(doc)
        
        tuner = WeightTuner()
        doc = tuner.tune(doc)
        
        analyzer.add_document(doc)
    
    analysis = analyzer.analyze_corpus()
    print(f"✓ Analyzed corpus")
    print(f"  Total documents: {analysis['total_documents']}")
    print(f"  Document types: {analysis['document_types']}")
    print(f"  Suggestions: {len(analysis['optimization_suggestions'])}")
    
    return analysis


def main():
    """Run all tests."""
    print("=" * 60)
    print("Context-as-a-Service Functionality Test")
    print("=" * 60)
    
    try:
        test_html_processing()
        test_code_processing()
        test_context_extraction()
        test_corpus_analysis()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

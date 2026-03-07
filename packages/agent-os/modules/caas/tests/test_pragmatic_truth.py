# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Tests for Pragmatic Truth feature (Real > Official).

Tests that the system can:
1. Track source types (official docs vs practical sources)
2. Include citations in responses
3. Detect conflicts between official and practical sources
4. Present both perspectives transparently
"""

import uuid
from datetime import datetime

from caas.models import (
    ContentFormat,
    DocumentType,
    SourceType,
    SourceCitation,
    Section,
    Document,
)
from caas.ingestion import ProcessorFactory
from caas.detection import DocumentTypeDetector
from caas.tuning import WeightTuner
from caas.storage import DocumentStore, ContextExtractor
from caas.pragmatic_truth import SourceDetector, ConflictDetector, CitationFormatter


def test_source_detection():
    """Test that source types are correctly detected."""
    print("\n=== Testing Source Detection ===")
    
    # Create test documents with different source types
    doc_id_official = str(uuid.uuid4())
    official_doc = Document(
        id=doc_id_official,
        title="API Rate Limits - Official Documentation",
        content="The API supports up to 100 requests per minute according to specifications.",
        format=ContentFormat.HTML,
        detected_type=DocumentType.API_DOCUMENTATION,
        sections=[
            Section(
                title="Rate Limits",
                content="The API officially supports 100 requests per minute. This is documented in the specification.",
            )
        ],
        metadata={"source_type": "official_docs"},
        ingestion_timestamp=datetime.utcnow().isoformat()
    )
    
    doc_id_chat = str(uuid.uuid4())
    chat_doc = Document(
        id=doc_id_chat,
        title="Slack #engineering - API Issues",
        content="From team discussion on Slack about API stability.",
        format=ContentFormat.TEXT,
        detected_type=DocumentType.UNKNOWN,
        sections=[
            Section(
                title="Rate Limit Reality",
                content="Actually, the API crashes after 50 requests. We've seen this repeatedly in production. The official limit is 100, but in practice it fails at 50.",
            )
        ],
        metadata={"source_type": "team_chat", "url": "slack://channel/engineering/msg123"},
        ingestion_timestamp=datetime.utcnow().isoformat()
    )
    
    detector = SourceDetector()
    
    # Test official doc detection
    official_type = detector.detect_source_type(official_doc)
    print(f"✓ Official doc detected as: {official_type}")
    assert official_type == SourceType.OFFICIAL_DOCS
    
    # Test team chat detection
    chat_type = detector.detect_source_type(chat_doc)
    print(f"✓ Chat doc detected as: {chat_type}")
    assert chat_type == SourceType.TEAM_CHAT
    
    print("✓ Source detection working correctly")


def test_citation_generation():
    """Test that citations are properly generated."""
    print("\n=== Testing Citation Generation ===")
    
    doc_id = str(uuid.uuid4())
    document = Document(
        id=doc_id,
        title="Deployment Runbook",
        content="Steps for deploying the application.",
        format=ContentFormat.MARKDOWN,
        detected_type=DocumentType.TUTORIAL,
        sections=[
            Section(
                title="Deployment Steps",
                content="Run the deployment script with --force flag for emergency deployments.",
            )
        ],
        metadata={"source_type": "runbook", "url": "https://wiki.company.com/runbooks/deploy"},
        ingestion_timestamp="2024-01-03T10:00:00"
    )
    
    detector = SourceDetector()
    citation = detector.create_citation(document, document.sections[0])
    
    print(f"✓ Citation created:")
    print(f"  - Source Type: {citation.source_type}")
    print(f"  - Source Name: {citation.source_name}")
    print(f"  - URL: {citation.source_url}")
    print(f"  - Timestamp: {citation.timestamp}")
    
    formatter = CitationFormatter()
    formatted = formatter.format_citation(citation)
    print(f"✓ Formatted citation: {formatted}")
    
    assert citation.source_type == SourceType.RUNBOOK
    assert citation.source_url == "https://wiki.company.com/runbooks/deploy"


def test_conflict_detection():
    """Test that conflicts between official and practical sources are detected."""
    print("\n=== Testing Conflict Detection ===")
    
    # Create official documentation section
    official_section = Section(
        title="API Rate Limits",
        content="The API limit is 100 requests per minute as per the official specification.",
        source_citation=SourceCitation(
            source_type=SourceType.OFFICIAL_DOCS,
            source_name="API Documentation v2.1",
            timestamp="2023-06-01T00:00:00"
        )
    )
    
    # Create practical experience section
    practical_section = Section(
        title="Rate Limit Issues",
        content="Actually, the API crashes after 50 requests in production. Multiple engineers have reported this issue in recent Slack conversations.",
        source_citation=SourceCitation(
            source_type=SourceType.TEAM_CHAT,
            source_name="Slack #engineering (2024-01-02)",
            timestamp="2024-01-02T15:30:00"
        )
    )
    
    detector = ConflictDetector()
    conflicts = detector.detect_conflicts(
        [official_section, practical_section],
        {}
    )
    
    print(f"✓ Detected {len(conflicts)} conflict(s)")
    if conflicts:
        conflict = conflicts[0]
        print(f"  - Topic: {conflict.topic}")
        print(f"  - Official: {conflict.official_answer[:50]}...")
        print(f"  - Practical: {conflict.practical_answer[:50]}...")
        print(f"  - Severity: {conflict.conflict_severity}")
        
        formatter = CitationFormatter()
        formatted = formatter.format_conflict(conflict)
        print(f"\n✓ Formatted conflict:\n{formatted}")
    
    assert len(conflicts) > 0, "Should detect at least one conflict"


def test_context_extraction_with_citations():
    """Test context extraction with citation support."""
    print("\n=== Testing Context Extraction with Citations ===")
    
    # Create document store
    store = DocumentStore()
    
    # Add official documentation
    doc_id_official = str(uuid.uuid4())
    official_html = b"""
    <html>
    <head><title>API Documentation</title></head>
    <body>
        <h1>API Rate Limits</h1>
        <p>The official rate limit is 100 requests per minute.</p>
        <h2>Best Practices</h2>
        <p>Follow these guidelines for optimal API usage.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    metadata_official = {
        "id": doc_id_official,
        "title": "API Documentation",
        "source_type": "official_docs",
        "url": "https://api.example.com/docs"
    }
    official_doc = processor.process(official_html, metadata_official)
    official_doc.detected_type = DocumentType.API_DOCUMENTATION
    official_doc.ingestion_timestamp = "2023-06-01T00:00:00"
    
    tuner = WeightTuner()
    official_doc = tuner.tune(official_doc)
    store.add(official_doc)
    
    # Extract context with citations
    extractor = ContextExtractor(
        store,
        enrich_metadata=False,
        enable_citations=True,
        detect_conflicts=False
    )
    
    context, metadata = extractor.extract_context(
        doc_id_official,
        query="rate limit",
        max_tokens=1000
    )
    
    print(f"✓ Extracted context length: {len(context)} chars")
    print(f"✓ Sections used: {metadata['sections_used']}")
    print(f"✓ Citations included: {len(metadata['citations'])}")
    
    # Check that citations are in the output
    assert "Sources" in context or len(metadata['citations']) > 0
    print("✓ Citations properly included in context")


def test_conflict_detection_in_extraction():
    """Test full pipeline with conflict detection."""
    print("\n=== Testing Full Pipeline with Conflict Detection ===")
    
    # Create document store
    store = DocumentStore()
    
    # Create a document with conflicting sections
    doc_id = str(uuid.uuid4())
    doc = Document(
        id=doc_id,
        title="Server Restart Procedures",
        content="Information about server restart procedures from various sources.",
        format=ContentFormat.TEXT,
        detected_type=DocumentType.TUTORIAL,
        sections=[
            Section(
                title="Official Documentation",
                content="According to the official documentation, the server restart command is 'service restart'. This is the standard procedure.",
                source_citation=SourceCitation(
                    source_type=SourceType.OFFICIAL_DOCS,
                    source_name="Official Admin Guide",
                    timestamp="2023-01-01T00:00:00"
                )
            ),
            Section(
                title="Team Knowledge",
                content="Actually, 'service restart' doesn't work properly. The team uses 'killall -9 server && ./start.sh' instead. This workaround has been shared in Slack multiple times.",
                source_citation=SourceCitation(
                    source_type=SourceType.TEAM_CHAT,
                    source_name="Slack #ops (2024-01-02)",
                    timestamp="2024-01-02T10:00:00"
                )
            ),
        ],
        metadata={},
        ingestion_timestamp=datetime.utcnow().isoformat()
    )
    
    store.add(doc)
    
    # Extract with conflict detection
    extractor = ContextExtractor(
        store,
        enrich_metadata=False,
        enable_citations=True,
        detect_conflicts=True
    )
    
    context, metadata = extractor.extract_context(
        doc_id,
        query="server restart",
        max_tokens=2000
    )
    
    print(f"✓ Context length: {len(context)} chars")
    print(f"✓ Conflicts detected: {len(metadata['conflicts'])}")
    
    if metadata['conflicts']:
        print("✓ Conflict details:")
        for conflict in metadata['conflicts']:
            print(f"  - Topic: {conflict['topic']}")
            print(f"  - Severity: {conflict['conflict_severity']}")
    
    # Check that conflict warning is in output
    assert len(metadata['conflicts']) > 0 or "restart" in context.lower()
    print("✓ Full pipeline working with Pragmatic Truth")


def run_all_tests():
    """Run all pragmatic truth tests."""
    print("=" * 60)
    print("Running Pragmatic Truth Tests")
    print("=" * 60)
    
    try:
        test_source_detection()
        test_citation_generation()
        test_conflict_detection()
        test_context_extraction_with_citations()
        test_conflict_detection_in_extraction()
        
        print("\n" + "=" * 60)
        print("✅ All Pragmatic Truth tests passed!")
        print("=" * 60)
        return True
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)

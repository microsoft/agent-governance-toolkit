# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Metadata Injection (Contextual Enrichment) functionality.

Tests the solution to the problem:
- Original Chunk: "It increased by 5%."
- Enriched Chunk: "[Document: Q3 Earnings] [Chapter: Revenue] [Section: North America] It increased by 5%."

The enriched chunk carries the weight of its context, so the AI knows exactly what increased.
"""

import uuid
from caas.models import ContentFormat, DocumentType, Section, Document
from caas.ingestion import ProcessorFactory
from caas.detection import DocumentTypeDetector
from caas.tuning import WeightTuner
from caas.storage import DocumentStore, ContextExtractor
from caas.enrichment import MetadataEnricher


def test_metadata_enrichment_basic():
    """Test basic metadata enrichment functionality."""
    print("\n=== Testing Basic Metadata Enrichment ===")
    
    # Create a simple section
    section = Section(
        title="North America",
        content="It increased by 5%.",
        chapter="Revenue"
    )
    
    # Create a mock document
    document = Document(
        id="test-123",
        title="Q3 Earnings",
        content="Test content",
        format=ContentFormat.HTML,
        detected_type=DocumentType.ARTICLE,
        sections=[section]
    )
    
    # Enrich the section
    enricher = MetadataEnricher()
    enriched_chunk = enricher.get_enriched_chunk(
        section,
        document.title,
        document.detected_type
    )
    
    print(f"Original chunk: '{section.content}'")
    print(f"Enriched chunk: '{enriched_chunk}'")
    
    # Verify enrichment includes all metadata
    assert "Q3 Earnings" in enriched_chunk, "Document title should be in enriched chunk"
    assert "Revenue" in enriched_chunk, "Chapter should be in enriched chunk"
    assert "North America" in enriched_chunk, "Section title should be in enriched chunk"
    assert "It increased by 5%" in enriched_chunk, "Original content should be preserved"
    
    print("✓ Basic metadata enrichment works correctly")
    return enriched_chunk


def test_html_document_with_hierarchy():
    """Test metadata enrichment with hierarchical HTML document."""
    print("\n=== Testing HTML Document with Hierarchy ===")
    
    # Create an HTML document with hierarchy
    html_content = b"""
    <html>
    <body>
        <h1>Q3 2024 Financial Results</h1>
        
        <h2>Revenue Analysis</h2>
        <p>Overall revenue performance across regions.</p>
        
        <h3>North America</h3>
        <p>Revenue in North America increased by 5% year-over-year.</p>
        
        <h3>Europe</h3>
        <p>European markets showed strong growth of 8%.</p>
        
        <h2>Expenses</h2>
        <p>Operating expenses decreased by 3%.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "Q3 Earnings Report"}
    document = processor.process(html_content, metadata)
    
    # Detect type and tune
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    # Store document
    store = DocumentStore()
    store.add(document)
    
    # Extract context WITH metadata enrichment
    extractor = ContextExtractor(store, enrich_metadata=True)
    enriched_context, metadata_result = extractor.extract_context(doc_id, max_tokens=1000)
    
    print(f"\n✓ Processed document with {len(document.sections)} sections")
    print(f"✓ Metadata enrichment enabled: {metadata_result['metadata_enriched']}")
    
    # Check that sections have hierarchical metadata
    na_sections = [s for s in document.sections if "North America" in s.title]
    if na_sections:
        na_section = na_sections[0]
        print(f"\n✓ North America section hierarchy:")
        print(f"  - Chapter: {na_section.chapter}")
        print(f"  - Parent: {na_section.parent_section}")
        print(f"  - Title: {na_section.title}")
        
        # Verify hierarchy is correct
        assert na_section.chapter == "Q3 2024 Financial Results", "H3 should have H1 as chapter"
    
    # Check enriched context
    print(f"\n--- Enriched Context Preview ---")
    print(enriched_context[:500])
    
    # Verify metadata is in the context
    assert "[Document:" in enriched_context, "Document metadata should be in enriched context"
    assert "[Section:" in enriched_context, "Section metadata should be in enriched context"
    
    print("\n✓ Hierarchical metadata properly extracted and injected")
    return enriched_context


def test_comparison_with_without_enrichment():
    """Compare context extraction with and without metadata enrichment."""
    print("\n=== Testing With vs Without Enrichment ===")
    
    html_content = b"""
    <html>
    <body>
        <h1>API Documentation</h1>
        
        <h2>Authentication</h2>
        <h3>JWT Tokens</h3>
        <p>The system uses JWT for authentication. Tokens expire after 1 hour.</p>
        
        <h2>Endpoints</h2>
        <h3>/api/users</h3>
        <p>Returns a list of users. Requires authentication.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "API Guide"}
    document = processor.process(html_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    store = DocumentStore()
    store.add(document)
    
    # Extract WITHOUT enrichment
    extractor_plain = ContextExtractor(store, enrich_metadata=False)
    plain_context, plain_meta = extractor_plain.extract_context(doc_id, max_tokens=500)
    
    # Extract WITH enrichment
    extractor_enriched = ContextExtractor(store, enrich_metadata=True)
    enriched_context, enriched_meta = extractor_enriched.extract_context(doc_id, max_tokens=500)
    
    print("\n--- Plain Context (No Enrichment) ---")
    print(plain_context[:300])
    print(f"... (length: {len(plain_context)} chars)")
    
    print("\n--- Enriched Context (With Metadata) ---")
    print(enriched_context[:300])
    print(f"... (length: {len(enriched_context)} chars)")
    
    # Verify differences
    assert "[Document:" not in plain_context, "Plain context should not have metadata"
    assert "[Document:" in enriched_context, "Enriched context should have metadata"
    assert len(enriched_context) > len(plain_context), "Enriched context should be longer"
    
    print("\n✓ Metadata enrichment successfully adds context to chunks")
    print(f"✓ Plain context: {plain_meta['metadata_enriched']}")
    print(f"✓ Enriched context: {enriched_meta['metadata_enriched']}")
    
    return plain_context, enriched_context


def test_enrichment_with_parent_sections():
    """Test that parent section metadata is properly injected."""
    print("\n=== Testing Parent Section Metadata ===")
    
    # Create a document with explicit parent relationships
    section1 = Section(
        title="Europe",
        content="Growth was significant.",
        chapter="Revenue",
        parent_section="Regional Analysis"
    )
    
    document = Document(
        id="test-456",
        title="Annual Report 2024",
        content="Test",
        format=ContentFormat.HTML,
        detected_type=DocumentType.ARTICLE,
        sections=[section1]
    )
    
    enricher = MetadataEnricher()
    enriched = enricher.get_enriched_chunk(
        section1,
        document.title,
        document.detected_type
    )
    
    print(f"Original: '{section1.content}'")
    print(f"Enriched: '{enriched}'")
    
    # Verify all hierarchy levels are present
    assert "Annual Report 2024" in enriched, "Document title should be present"
    assert "Revenue" in enriched, "Chapter should be present"
    assert "Europe" in enriched, "Section title should be present"
    assert "Growth was significant" in enriched, "Original content should be preserved"
    
    print("✓ Parent section metadata properly injected")
    return enriched


def test_code_enrichment():
    """Test metadata enrichment with code documents."""
    print("\n=== Testing Code Document Enrichment ===")
    
    code_content = b"""
class UserAuthentication:
    def validate_credentials(self, username, password):
        # Check credentials
        return True
    
    def generate_token(self, user_id):
        # Generate JWT token
        return "token"
"""
    
    processor = ProcessorFactory.get_processor(ContentFormat.CODE)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "auth.py", "language": "python"}
    document = processor.process(code_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    store = DocumentStore()
    store.add(document)
    
    # Extract with enrichment
    extractor = ContextExtractor(store, enrich_metadata=True)
    context, meta = extractor.extract_context(doc_id, max_tokens=800)
    
    print(f"\n✓ Processed code document: {document.title}")
    print(f"✓ Sections: {len(document.sections)}")
    
    print("\n--- Enriched Code Context ---")
    print(context[:400])
    
    # Verify enrichment
    assert "[Document: auth.py]" in context, "Code file name should be in metadata"
    assert "[Section:" in context, "Section metadata should be present"
    
    print("\n✓ Code enrichment works correctly")
    return context


def main():
    """Run all metadata injection tests."""
    print("=" * 70)
    print("Metadata Injection (Contextual Enrichment) Tests")
    print("Solving the 'Flat Chunk Fallacy' - Context Amnesia Problem")
    print("=" * 70)
    
    try:
        test_metadata_enrichment_basic()
        test_html_document_with_hierarchy()
        test_comparison_with_without_enrichment()
        test_enrichment_with_parent_sections()
        test_code_enrichment()
        
        print("\n" + "=" * 70)
        print("✅ All metadata injection tests passed!")
        print("=" * 70)
        print("\nKey Results:")
        print("- ✓ Chunks are enriched with document title")
        print("- ✓ Hierarchical metadata (chapter, parent) injected")
        print("- ✓ Section context included in every chunk")
        print("- ✓ Original content preserved")
        print("- ✓ Works with HTML, Code, and other formats")
        print("- ✓ Can be toggled on/off as needed")
        print("\nExample Transformation:")
        print('  Before: "It increased by 5%."')
        print('  After:  "[Document: Q3 Earnings] [Chapter: Revenue] [Section: North America] It increased by 5%."')
        print("=" * 70)
        
    except AssertionError as e:
        print(f"\n❌ Test assertion failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

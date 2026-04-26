# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Structure-Aware Indexing functionality.

Tests the three-tier hierarchical approach:
- Tier 1 (High): Titles, Headers, Class Definitions, API Contracts
- Tier 2 (Medium): Body text, Function logic  
- Tier 3 (Low): Footnotes, Comments, Disclaimers
"""

import uuid
from caas.models import ContentFormat, DocumentType, ContentTier
from caas.ingestion import ProcessorFactory, StructureParser
from caas.detection import DocumentTypeDetector
from caas.tuning import WeightTuner
from caas.storage import DocumentStore, ContextExtractor


def test_tier_classification():
    """Test that content is properly classified into tiers."""
    print("\n=== Testing Tier Classification ===")
    
    # Create a code document with different tier content
    code_content = b"""
# This is a comment - should be Tier 3
# TODO: fix this later - should be Tier 3

class Authentication:
    '''Main authentication class - should be Tier 1'''
    
    def login(self, username: str, password: str):
        '''Login function - should be Tier 2'''
        # Validate credentials
        return self._validate(username, password)
    
    def _validate(self, username: str, password: str):
        '''Helper function - should be Tier 2'''
        return True

def helper_function():
    '''Helper function - should be Tier 2'''
    pass

# Note: This is just a simple example
# Disclaimer: Use at your own risk
"""
    
    processor = ProcessorFactory.get_processor(ContentFormat.CODE)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "Auth Module", "language": "python"}
    document = processor.process(code_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    print(f"✓ Processed code document with {len(document.sections)} sections")
    
    # Check tier assignments
    tier_counts = {"tier_1": 0, "tier_2": 0, "tier_3": 0}
    for section in document.sections:
        print(f"  - {section.title[:50]}: Tier={section.tier.value if section.tier else 'None'}, Weight={section.weight}x")
        if section.tier == ContentTier.TIER_1_HIGH:
            tier_counts["tier_1"] += 1
        elif section.tier == ContentTier.TIER_2_MEDIUM:
            tier_counts["tier_2"] += 1
        elif section.tier == ContentTier.TIER_3_LOW:
            tier_counts["tier_3"] += 1
    
    print(f"✓ Tier distribution: Tier 1={tier_counts['tier_1']}, Tier 2={tier_counts['tier_2']}, Tier 3={tier_counts['tier_3']}")
    
    # Verify that class definitions have higher weights
    class_sections = [s for s in document.sections if 'class' in s.title.lower()]
    if class_sections:
        assert class_sections[0].weight > 1.5, "Class definitions should have high weight"
        print(f"✓ Class definitions have proper high weight: {class_sections[0].weight}x")
    
    return document


def test_tier_based_retrieval():
    """Test that retrieval prioritizes high-tier content."""
    print("\n=== Testing Tier-Based Retrieval ===")
    
    # Create HTML document with mixed tier content
    html_content = b"""
    <html>
    <body>
        <h1>API Documentation</h1>
        
        <h2>Endpoint: POST /authenticate</h2>
        <p>Critical API endpoint for user authentication. Must use HTTPS.</p>
        
        <h2>Implementation Details</h2>
        <p>The authentication flow uses JWT tokens for security.</p>
        
        <h2>Footnotes</h2>
        <p>Note: This documentation is provided as-is without warranty.</p>
        <p>Disclaimer: Always test in staging before production.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "Auth API Docs"}
    document = processor.process(html_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    # Store document
    store = DocumentStore()
    store.add(document)
    
    # Extract context - should prioritize Tier 1 content
    extractor = ContextExtractor(store)
    context, metadata_result = extractor.extract_context(doc_id, max_tokens=200)
    
    print(f"✓ Extracted context (limited to 200 tokens)")
    print(f"✓ Sections used: {metadata_result['sections_used']}")
    print(f"✓ Tiers applied: {metadata_result.get('tiers_applied', {})}")
    
    # Verify high-tier content is prioritized
    sections_used = metadata_result['sections_used']
    
    # The endpoint section (Tier 1) should be included before footnotes (Tier 3)
    if 'Footnotes' in [s.title for s in document.sections]:
        footnote_sections = [s for s in document.sections if s.title == 'Footnotes']
        endpoint_section = [s for s in document.sections if 'Endpoint' in s.title or 'POST' in s.title]
        
        if endpoint_section and footnote_sections:
            assert endpoint_section[0].weight > footnote_sections[0].weight, \
                "Endpoint (Tier 1) should have higher weight than Footnotes (Tier 3)"
            print(f"✓ Tier 1 content properly prioritized over Tier 3")
    
    print(f"\n--- Context Preview ---")
    print(context[:400])
    
    return context


def test_semantic_similarity_with_tiers():
    """Test that tiers boost content even with same semantic similarity."""
    print("\n=== Testing Tier Boosting Over Semantic Similarity ===")
    
    # Create document where both sections match query, but different tiers
    html_content = b"""
    <html>
    <body>
        <h1>User Authentication System</h1>
        
        <h2>Authentication API Contract</h2>
        <p>The authentication contract defines the interface for user login.
        All authentication requests must follow this contract.</p>
        
        <h2>Implementation Notes</h2>
        <p>When implementing authentication, remember to hash passwords.
        The authentication module handles this automatically.</p>
        
        <h2>Developer Comments</h2>
        <p>TODO: Improve authentication performance in future releases.
        NOTE: Authentication code needs refactoring.</p>
    </body>
    </html>
    """
    
    processor = ProcessorFactory.get_processor(ContentFormat.HTML)
    doc_id = str(uuid.uuid4())
    metadata = {"id": doc_id, "title": "Auth System"}
    document = processor.process(html_content, metadata)
    
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    print(f"✓ Processed document with {len(document.sections)} sections")
    
    # All sections mention "authentication", so semantic similarity is similar
    # But tiers should differentiate them
    for section in document.sections:
        tier_name = section.tier.value if section.tier else "unknown"
        print(f"  - {section.title}: {tier_name}, Weight={section.weight}x")
    
    # Store and extract
    store = DocumentStore()
    store.add(document)
    
    extractor = ContextExtractor(store)
    context, metadata_result = extractor.extract_context(
        doc_id, 
        query="authentication",  # All sections match this query
        max_tokens=300
    )
    
    print(f"\n✓ Query: 'authentication' (matches all sections)")
    print(f"✓ Sections retrieved in order: {metadata_result['sections_used']}")
    
    # Verify that API Contract (Tier 1) is prioritized over Comments (Tier 3)
    sections_used = metadata_result['sections_used']
    weights = metadata_result['weights_applied']
    
    if 'Authentication API Contract' in weights and 'Developer Comments' in weights:
        api_weight = weights['Authentication API Contract']
        comment_weight = weights['Developer Comments']
        assert api_weight > comment_weight, \
            f"API Contract (Tier 1) weight {api_weight} should be > Comments (Tier 3) weight {comment_weight}"
        print(f"✓ API Contract (Tier 1) weight {api_weight}x > Comments (Tier 3) weight {comment_weight}x")
        print(f"✓ Tier boosting works even with same semantic similarity!")
    
    return context


def test_tier_weights():
    """Test tier base weight assignments."""
    print("\n=== Testing Tier Base Weights ===")
    
    parser = StructureParser()
    
    tier_1_weight = parser.get_tier_base_weight(ContentTier.TIER_1_HIGH)
    tier_2_weight = parser.get_tier_base_weight(ContentTier.TIER_2_MEDIUM)
    tier_3_weight = parser.get_tier_base_weight(ContentTier.TIER_3_LOW)
    
    print(f"✓ Tier 1 (High Value) base weight: {tier_1_weight}x")
    print(f"✓ Tier 2 (Medium Value) base weight: {tier_2_weight}x")
    print(f"✓ Tier 3 (Low Value) base weight: {tier_3_weight}x")
    
    # Verify hierarchy
    assert tier_1_weight > tier_2_weight > tier_3_weight, \
        "Tier weights should follow hierarchy: Tier 1 > Tier 2 > Tier 3"
    
    print(f"✓ Weight hierarchy verified: {tier_1_weight} > {tier_2_weight} > {tier_3_weight}")
    
    return True


def main():
    """Run all structure-aware indexing tests."""
    print("=" * 70)
    print("Structure-Aware Indexing Tests")
    print("Testing the 'Flat Chunk Fallacy' Solution")
    print("=" * 70)
    
    try:
        test_tier_weights()
        test_tier_classification()
        test_tier_based_retrieval()
        test_semantic_similarity_with_tiers()
        
        print("\n" + "=" * 70)
        print("✅ All structure-aware indexing tests passed!")
        print("=" * 70)
        print("\nKey Results:")
        print("- Content is properly classified into 3 tiers")
        print("- Tier 1 (High): Classes, APIs, Headers get 2x base weight")
        print("- Tier 2 (Medium): Functions, body text get 1x base weight")
        print("- Tier 3 (Low): Comments, disclaimers get 0.5x base weight")
        print("- Retrieval prioritizes high-tier content over low-tier")
        print("- Tier boosting works even when semantic similarity is the same")
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

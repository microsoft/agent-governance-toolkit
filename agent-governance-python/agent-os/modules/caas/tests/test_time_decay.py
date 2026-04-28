# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test time-based decay function for relevance scoring.

Demonstrates "The Half-Life of Truth" - mathematical gravity for old data.
"""

import uuid
from datetime import datetime, timedelta, timezone
from caas.models import Document, ContentFormat, DocumentType, Section
from caas.storage import DocumentStore
from caas.decay import calculate_decay_factor, get_time_weighted_score


def test_decay_factor_calculation():
    """Test decay factor calculation for different time periods."""
    print("\n=== Testing Decay Factor Calculation ===")
    
    reference_time = datetime(2024, 1, 10, 12, 0, 0)
    
    # Document from today (0 days ago)
    today = reference_time.isoformat()
    decay_today = calculate_decay_factor(today, reference_time, decay_rate=1.0)
    print(f"✓ Today (0 days): decay_factor = {decay_today:.3f} (should be ~1.0)")
    
    # Document from yesterday (1 day ago)
    yesterday = (reference_time - timedelta(days=1)).isoformat()
    decay_yesterday = calculate_decay_factor(yesterday, reference_time, decay_rate=1.0)
    print(f"✓ Yesterday (1 day): decay_factor = {decay_yesterday:.3f} (should be ~0.5)")
    
    # Document from a week ago (7 days)
    week_ago = (reference_time - timedelta(days=7)).isoformat()
    decay_week = calculate_decay_factor(week_ago, reference_time, decay_rate=1.0)
    print(f"✓ Week ago (7 days): decay_factor = {decay_week:.3f} (should be ~0.125)")
    
    # Document from a month ago (30 days)
    month_ago = (reference_time - timedelta(days=30)).isoformat()
    decay_month = calculate_decay_factor(month_ago, reference_time, decay_rate=1.0)
    print(f"✓ Month ago (30 days): decay_factor = {decay_month:.3f} (should be ~0.032)")
    
    # Document from a year ago (365 days)
    year_ago = (reference_time - timedelta(days=366)).isoformat()
    decay_year = calculate_decay_factor(year_ago, reference_time, decay_rate=1.0)
    print(f"✓ Year ago (365 days): decay_factor = {decay_year:.3f} (should be ~0.003)")
    
    # Verify decay factors are in expected ranges
    assert 0.9 <= decay_today <= 1.0, "Today should have minimal decay"
    assert 0.45 <= decay_yesterday <= 0.55, "Yesterday should be ~0.5"
    assert 0.11 <= decay_week <= 0.14, "Week should be ~0.125"
    assert decay_year < 0.01, "Year old should be very small"
    
    print("✓ All decay factor calculations are correct!")


def test_the_half_life_of_truth():
    """
    Test the core principle: Yesterday's 80% match beats Last Year's 95% match.
    
    This demonstrates "The Half-Life of Truth" - recency is relevance.
    """
    print("\n=== Testing 'The Half-Life of Truth' ===")
    print("Scenario: Yesterday's 80% match should beat Last Year's 95% match")
    
    reference_time = datetime(2024, 1, 10, 12, 0, 0)
    
    # Recent document with 80% similarity
    recent_doc_time = (reference_time - timedelta(days=1)).isoformat()  # Yesterday
    recent_similarity = 0.80
    recent_score = get_time_weighted_score(
        base_score=recent_similarity,
        ingestion_timestamp=recent_doc_time,
        reference_time=reference_time,
        decay_rate=1.0
    )
    
    # Old document with 95% similarity
    old_doc_time = (reference_time - timedelta(days=366)).isoformat()  # Last year
    old_similarity = 0.95
    old_score = get_time_weighted_score(
        base_score=old_similarity,
        ingestion_timestamp=old_doc_time,
        reference_time=reference_time,
        decay_rate=1.0
    )
    
    print(f"\nRecent Document (Yesterday):")
    print(f"  - Base similarity: {recent_similarity:.2%}")
    print(f"  - Decay factor: {calculate_decay_factor(recent_doc_time, reference_time):.3f}")
    print(f"  - Final score: {recent_score:.3f}")
    
    print(f"\nOld Document (Last Year):")
    print(f"  - Base similarity: {old_similarity:.2%}")
    print(f"  - Decay factor: {calculate_decay_factor(old_doc_time, reference_time):.3f}")
    print(f"  - Final score: {old_score:.3f}")
    
    print(f"\n{'='*50}")
    if recent_score > old_score:
        print("✓ SUCCESS: Recent document (80%) beats old document (95%)!")
        print(f"  Recent score ({recent_score:.3f}) > Old score ({old_score:.3f})")
    else:
        print("✗ FAILED: Old document still ranks higher")
        print(f"  Recent score ({recent_score:.3f}) <= Old score ({old_score:.3f})")
    
    assert recent_score > old_score, "Recent document should rank higher!"
    print("✓ The Half-Life of Truth is working correctly!")


def test_search_with_time_decay():
    """Test document search with time-based decay."""
    print("\n=== Testing Search with Time Decay ===")
    
    # Create a document store
    store = DocumentStore()
    
    # Use current actual time for realistic testing
    current_time = datetime.now(timezone.utc)
    
    # Create documents with different ages but same content match quality
    # Document 1: Recent (yesterday)
    doc1 = Document(
        id=str(uuid.uuid4()),
        title="Recent Server Reset Guide",
        content="How to reset the server using the new method. Updated for 2024.",
        format=ContentFormat.TEXT,
        detected_type=DocumentType.TECHNICAL_DOCUMENTATION,
        sections=[
            Section(title="Introduction", content="How to reset the server using the new method.", weight=1.0)
        ],
        ingestion_timestamp=(current_time - timedelta(days=1)).isoformat()
    )
    
    # Document 2: Old (last year) but with more matches
    doc2 = Document(
        id=str(uuid.uuid4()),
        title="Server Reset Guide (2021)",
        content="How to reset the server. Old method from 2021. Server reset procedures. Server reset steps.",
        format=ContentFormat.TEXT,
        detected_type=DocumentType.TECHNICAL_DOCUMENTATION,
        sections=[
            Section(title="Introduction", content="How to reset the server. Old method.", weight=1.0)
        ],
        ingestion_timestamp=(current_time - timedelta(days=366)).isoformat()
    )
    
    # Document 3: Very old (3 years)
    doc3 = Document(
        id=str(uuid.uuid4()),
        title="Server Reset Guide (2020)",
        content="Server reset guide from 2020. How to reset the server.",
        format=ContentFormat.TEXT,
        detected_type=DocumentType.TECHNICAL_DOCUMENTATION,
        sections=[
            Section(title="Introduction", content="Server reset from 2020.", weight=1.0)
        ],
        ingestion_timestamp=(current_time - timedelta(days=365*3)).isoformat()
    )
    
    # Add documents to store
    store.add(doc1)
    store.add(doc2)
    store.add(doc3)
    
    # Search without time decay
    print("\nSearch results WITHOUT time decay:")
    results_no_decay = store.search("reset server", enable_time_decay=False)
    for i, doc in enumerate(results_no_decay, 1):
        score = doc.metadata.get('_search_score', 0)
        print(f"  {i}. {doc.title}: score={score:.3f}")
    
    # Search with time decay (default)
    print("\nSearch results WITH time decay:")
    results_with_decay = store.search("reset server", enable_time_decay=True)
    for i, doc in enumerate(results_with_decay, 1):
        score = doc.metadata.get('_search_score', 0)
        decay = doc.metadata.get('_decay_factor', 1.0)
        age_days = (current_time - datetime.fromisoformat(doc.ingestion_timestamp)).days
        print(f"  {i}. {doc.title}: score={score:.3f}, decay={decay:.3f}, age={age_days}d")
    
    # Verify recent document ranks higher with decay
    assert results_with_decay[0].id == doc1.id, "Recent document should rank first with decay!"
    print("\n✓ Recent document correctly ranks first with time decay!")
    print("✓ 'Recency is Relevance' principle is working!")


def test_context_extraction_with_decay():
    """Test context extraction with time-based decay applied."""
    print("\n=== Testing Context Extraction with Time Decay ===")
    
    from caas.storage import ContextExtractor
    
    store = DocumentStore()
    current_time = datetime.now(timezone.utc)
    
    # Create a recent document
    doc = Document(
        id=str(uuid.uuid4()),
        title="API Documentation 2024",
        content="Authentication endpoint details for 2024.",
        format=ContentFormat.HTML,
        detected_type=DocumentType.API_DOCUMENTATION,
        sections=[
            Section(
                title="Authentication",
                content="Use JWT tokens for authentication in 2024.",
                weight=2.0,
                importance_score=0.9
            ),
            Section(
                title="Endpoints",
                content="GET /api/users endpoint details.",
                weight=1.5,
                importance_score=0.7
            )
        ],
        ingestion_timestamp=(current_time - timedelta(days=2)).isoformat()
    )
    
    store.add(doc)
    
    # Extract context with decay enabled
    extractor_with_decay = ContextExtractor(store, enable_time_decay=True, decay_rate=1.0)
    context_decay, metadata_decay = extractor_with_decay.extract_context(doc.id, "authentication")
    
    # Extract context without decay
    extractor_no_decay = ContextExtractor(store, enable_time_decay=False)
    context_no_decay, metadata_no_decay = extractor_no_decay.extract_context(doc.id, "authentication")
    
    print(f"\nWith time decay:")
    print(f"  - Decay factor: {metadata_decay['decay_factor']:.3f}")
    print(f"  - Sections included: {metadata_decay['sections_included']}")
    print(f"  - Weights applied: {metadata_decay['weights_applied']}")
    
    print(f"\nWithout time decay:")
    print(f"  - Decay factor: {metadata_no_decay['decay_factor']:.3f}")
    print(f"  - Weights applied: {metadata_no_decay['weights_applied']}")
    
    # Verify decay was applied
    assert metadata_decay['time_decay_enabled'] == True
    assert metadata_decay['decay_factor'] < 1.0, "Decay factor should be < 1.0 for 2-day old doc"
    assert metadata_no_decay['decay_factor'] == 1.0, "No decay should have factor = 1.0"
    
    print("\n✓ Time decay is correctly applied to context extraction!")


if __name__ == "__main__":
    print("="*60)
    print("TIME-BASED DECAY FUNCTION TEST SUITE")
    print("'The Half-Life of Truth' - Mathematical Gravity for Old Data")
    print("="*60)
    
    try:
        test_decay_factor_calculation()
        test_the_half_life_of_truth()
        test_search_with_time_decay()
        test_context_extraction_with_decay()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        print("\nKey Findings:")
        print("  ✓ Decay function correctly applies time-based gravity")
        print("  ✓ Yesterday's 80% match beats Last Year's 95% match")
        print("  ✓ Search results prioritize recent documents")
        print("  ✓ Context extraction applies decay factor")
        print("  ✓ Recency is Relevance!")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise

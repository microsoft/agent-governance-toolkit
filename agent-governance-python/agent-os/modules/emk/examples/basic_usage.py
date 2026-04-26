# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating basic emk usage.
"""

from emk import Episode, FileAdapter, Indexer
import tempfile
import os


def main():
    """Demonstrate basic emk functionality."""
    
    print("=" * 60)
    print("emk (Episodic Memory Kernel) - Basic Example")
    print("=" * 60)
    print()
    
    # Create a temporary file for storage using secure method
    with tempfile.NamedTemporaryFile(mode='w', suffix=".jsonl", delete=False) as tf:
        temp_file = tf.name
    
    try:
        # 1. Create a FileAdapter
        print("1. Creating FileAdapter...")
        store = FileAdapter(temp_file)
        print(f"   ✓ Store created at: {temp_file}")
        print()
        
        # 2. Create and store some episodes
        print("2. Creating and storing episodes...")
        
        episode1 = Episode(
            goal="Retrieve user preferences",
            action="Query database for user_id=123",
            result="Successfully retrieved preferences",
            reflection="Database query was efficient",
            metadata={"user_id": "123", "query_time_ms": 45}
        )
        
        episode2 = Episode(
            goal="Process payment transaction",
            action="Called payment API",
            result="Payment successful",
            reflection="API responded quickly, good performance",
            metadata={"user_id": "123", "amount": 99.99}
        )
        
        episode3 = Episode(
            goal="Send notification email",
            action="Queued email to notification service",
            result="Email sent successfully",
            reflection="Consider adding retry logic for failures",
            metadata={"user_id": "456", "email_type": "confirmation"}
        )
        
        # Store episodes
        id1 = store.store(episode1)
        id2 = store.store(episode2)
        id3 = store.store(episode3)
        
        print(f"   ✓ Stored episode 1: {id1[:16]}...")
        print(f"   ✓ Stored episode 2: {id2[:16]}...")
        print(f"   ✓ Stored episode 3: {id3[:16]}...")
        print()
        
        # 3. Retrieve all episodes
        print("3. Retrieving all episodes...")
        all_episodes = store.retrieve(limit=10)
        print(f"   ✓ Retrieved {len(all_episodes)} episodes")
        for i, ep in enumerate(all_episodes, 1):
            print(f"      {i}. {ep.goal[:40]}...")
        print()
        
        # 4. Filter by metadata
        print("4. Filtering episodes by metadata (user_id=123)...")
        user_episodes = store.retrieve(filters={"user_id": "123"})
        print(f"   ✓ Found {len(user_episodes)} episodes for user_id=123")
        for i, ep in enumerate(user_episodes, 1):
            print(f"      {i}. {ep.goal}")
        print()
        
        # 5. Retrieve specific episode by ID
        print("5. Retrieving specific episode by ID...")
        specific = store.get_by_id(id2)
        if specific:
            print(f"   ✓ Retrieved episode: {specific.goal}")
            print(f"      Action: {specific.action}")
            print(f"      Result: {specific.result}")
        print()
        
        # 6. Use Indexer to generate tags
        print("6. Using Indexer to generate searchable tags...")
        tags = Indexer.generate_episode_tags(episode1)
        print(f"   ✓ Generated {len(tags)} tags: {', '.join(tags[:10])}")
        print()
        
        # 7. Create search text
        print("7. Creating search text for embedding...")
        search_text = Indexer.create_search_text(episode1)
        print(f"   ✓ Search text: {search_text[:100]}...")
        print()
        
        # 8. Enrich metadata
        print("8. Enriching metadata with indexing info...")
        enriched = Indexer.enrich_metadata(episode1, auto_tags=True)
        print(f"   ✓ Enriched metadata keys: {', '.join(enriched.keys())}")
        print(f"      Goal length: {enriched['goal_length']} chars")
        print(f"      Auto-generated tags: {len(enriched['tags'])} tags")
        print()
        
        print("=" * 60)
        print("Example completed successfully!")
        print("=" * 60)
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"\nCleaned up temporary file: {temp_file}")


if __name__ == "__main__":
    main()

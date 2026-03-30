# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
Indexer — simple tag-based filtering for episodes.
"""

from typing import List, Set, Dict, Any
import hashlib
import re

from emk.schema import Episode


class Indexer:
    """Tag extraction and simple metadata-based filtering for episodes."""

    @staticmethod
    def extract_tags(text: str, min_length: int = 3) -> Set[str]:
        """Extract potential search tags from *text*."""
        words = re.findall(r'\b\w+\b', text.lower())
        stop_words = {
            'the', 'is', 'at', 'which', 'on', 'and', 'a', 'an',
            'as', 'are', 'was', 'were', 'been', 'be', 'have', 'has',
            'had', 'do', 'does', 'did', 'will', 'would', 'should',
            'could', 'may', 'might', 'must', 'can', 'to', 'from',
            'in', 'out', 'up', 'down', 'for', 'with', 'by', 'of',
        }
        return {w for w in words if len(w) >= min_length and w not in stop_words}

    @staticmethod
    def generate_episode_tags(episode: Episode) -> List[str]:
        """Generate searchable tags from an episode."""
        combined = f"{episode.goal} {episode.action} {episode.result} {episode.reflection}"
        tags = Indexer.extract_tags(combined)
        for key in episode.metadata.keys():
            tags.add(key.lower())
        return sorted(tags)

    @staticmethod
    def compute_content_hash(episode: Episode) -> str:
        """Return the content hash (episode_id) of the episode."""
        return episode.episode_id

    @staticmethod
    def enrich_metadata(episode: Episode, auto_tags: bool = True) -> Dict[str, Any]:
        """Enrich episode metadata with tags and length metrics."""
        enriched = episode.metadata.copy()
        if auto_tags and 'tags' not in enriched:
            enriched['tags'] = Indexer.generate_episode_tags(episode)
        enriched['goal_length'] = len(episode.goal)
        enriched['action_length'] = len(episode.action)
        enriched['result_length'] = len(episode.result)
        enriched['reflection_length'] = len(episode.reflection)
        return enriched

    @staticmethod
    def create_search_text(episode: Episode) -> str:
        """Create a concatenated search text from an episode."""
        parts = [
            f"Goal: {episode.goal}",
            f"Action: {episode.action}",
            f"Result: {episode.result}",
            f"Reflection: {episode.reflection}",
        ]
        if episode.metadata:
            metadata_str = ", ".join(f"{k}: {v}" for k, v in episode.metadata.items())
            parts.append(f"Context: {metadata_str}")
        return " | ".join(parts)

    @staticmethod
    def filter_by_tags(
        episodes: List[Episode],
        required_tags: Set[str],
    ) -> List[Episode]:
        """Return episodes whose auto-generated tags include all *required_tags*."""
        required_lower = {t.lower() for t in required_tags}
        results: List[Episode] = []
        for ep in episodes:
            ep_tags = set(Indexer.generate_episode_tags(ep))
            if required_lower.issubset(ep_tags):
                results.append(ep)
        return results

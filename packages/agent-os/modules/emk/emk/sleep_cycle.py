# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Sleep Cycle - Memory decay and compression utilities.

This module implements the "sleep cycle" for agent memory management,
where old episodes are summarized into semantic rules and raw logs are archived.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Callable
from pathlib import Path

from emk.schema import Episode, SemanticRule
from emk.store import VectorStoreAdapter


class MemoryCompressor:
    """
    Handles memory decay and compression through sleep cycles.
    
    The compressor identifies old episodes, summarizes them into semantic rules,
    and optionally archives/deletes the raw episodes to reduce memory overhead.
    """
    
    def __init__(
        self,
        store: VectorStoreAdapter,
        age_threshold_days: int = 30,
        compression_batch_size: int = 50,
        rules_filepath: Optional[str] = None
    ):
        """
        Initialize the memory compressor.
        
        Args:
            store: The vector store containing episodes
            age_threshold_days: Episodes older than this are candidates for compression
            compression_batch_size: Number of episodes to compress at once
            rules_filepath: Path to store compressed semantic rules (JSONL format)
        """
        self.store = store
        self.age_threshold_days = age_threshold_days
        self.compression_batch_size = compression_batch_size
        self.rules_filepath = Path(rules_filepath or "semantic_rules.jsonl")
        
        # Ensure rules file parent directory exists
        self.rules_filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.rules_filepath.exists():
            self.rules_filepath.touch()
    
    def identify_old_episodes(self, episodes: List[Episode]) -> List[Episode]:
        """
        Identify episodes that are candidates for compression based on age.
        
        Args:
            episodes: List of episodes to filter
            
        Returns:
            List of old episodes that should be compressed
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=self.age_threshold_days)
        old_episodes = [
            ep for ep in episodes 
            if ep.timestamp < threshold
        ]
        return old_episodes
    
    def summarize_episodes(
        self, 
        episodes: List[Episode],
        summarizer: Optional[Callable[[List[Episode]], str]] = None
    ) -> SemanticRule:
        """
        Summarize a batch of episodes into a semantic rule.
        
        Args:
            episodes: List of episodes to summarize
            summarizer: Optional custom summarization function
            
        Returns:
            A SemanticRule representing the compressed knowledge
        """
        if not episodes:
            raise ValueError("Cannot summarize empty episode list")
        
        # Default summarization: extract common patterns
        if summarizer is None:
            rule_text = self._default_summarize(episodes)
        else:
            rule_text = summarizer(episodes)
        
        # Create semantic rule
        source_ids = [ep.episode_id for ep in episodes]
        
        # Calculate confidence based on episode count
        confidence = min(1.0, len(episodes) / 10.0)  # More episodes = higher confidence
        
        # Extract common metadata
        common_metadata = self._extract_common_metadata(episodes)
        
        semantic_rule = SemanticRule(
            rule=rule_text,
            source_episode_ids=source_ids,
            context=self._extract_context(episodes),
            confidence=confidence,
            metadata=common_metadata
        )
        
        return semantic_rule
    
    def _default_summarize(self, episodes: List[Episode]) -> str:
        """
        Default summarization strategy: extract common patterns.
        
        Args:
            episodes: List of episodes
            
        Returns:
            A summary string
        """
        # Group episodes by similar goals
        goal_patterns = {}
        action_patterns = {}
        
        for ep in episodes:
            # Simple word-based grouping
            goal_words = set(ep.goal.lower().split())
            action_words = set(ep.action.lower().split())
            
            # Track patterns
            for word in goal_words:
                goal_patterns[word] = goal_patterns.get(word, 0) + 1
            for word in action_words:
                action_patterns[word] = action_patterns.get(word, 0) + 1
        
        # Find most common patterns
        top_goals = sorted(goal_patterns.items(), key=lambda x: x[1], reverse=True)[:3]
        top_actions = sorted(action_patterns.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Build summary
        summary_parts = []
        
        if top_goals:
            goal_words = [word for word, _ in top_goals]
            summary_parts.append(f"Common goals involve: {', '.join(goal_words)}")
        
        if top_actions:
            action_words = [word for word, _ in top_actions]
            summary_parts.append(f"Typical actions include: {', '.join(action_words)}")
        
        # Check for failures
        failures = [ep for ep in episodes if ep.is_failure()]
        if failures:
            summary_parts.append(
                f"Warning: {len(failures)}/{len(episodes)} attempts failed"
            )
        
        return ". ".join(summary_parts) if summary_parts else "General agent activity"
    
    def _extract_context(self, episodes: List[Episode]) -> str:
        """Extract context from episodes."""
        if not episodes:
            return "General"
        
        # Use metadata tags if available
        all_tags = set()
        for ep in episodes:
            if "tags" in ep.metadata:
                tags = ep.metadata["tags"]
                if isinstance(tags, list):
                    all_tags.update(tags)
        
        if all_tags:
            return f"Context: {', '.join(list(all_tags)[:5])}"
        
        return "General agent activity"
    
    def _extract_common_metadata(self, episodes: List[Episode]) -> Dict[str, Any]:
        """Extract common metadata patterns from episodes."""
        metadata = {
            "episode_count": len(episodes),
            "time_span_days": self._calculate_time_span(episodes),
        }
        
        # Count failures
        failures = [ep for ep in episodes if ep.is_failure()]
        if failures:
            metadata["failure_count"] = len(failures)
            metadata["success_rate"] = (len(episodes) - len(failures)) / len(episodes)
        
        return metadata
    
    def _calculate_time_span(self, episodes: List[Episode]) -> int:
        """Calculate the time span covered by episodes in days."""
        if not episodes:
            return 0
        
        timestamps = [ep.timestamp for ep in episodes]
        min_time = min(timestamps)
        max_time = max(timestamps)
        
        return (max_time - min_time).days
    
    def store_rule(self, rule: SemanticRule) -> str:
        """
        Store a semantic rule to the rules file.
        
        Args:
            rule: The semantic rule to store
            
        Returns:
            The rule_id of the stored rule
        """
        with open(self.rules_filepath, 'a') as f:
            f.write(rule.to_json() + '\n')
        
        return rule.rule_id
    
    def retrieve_rules(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[SemanticRule]:
        """
        Retrieve semantic rules from storage.
        
        Args:
            filters: Optional metadata filters
            limit: Maximum number of rules to return
            
        Returns:
            List of matching semantic rules (most recent first)
        """
        rules = []
        
        if not self.rules_filepath.exists() or self.rules_filepath.stat().st_size == 0:
            return rules
        
        with open(self.rules_filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    rule = SemanticRule.from_json(line)
                    
                    # Apply filters if provided
                    if filters:
                        match = all(
                            rule.metadata.get(key) == value
                            for key, value in filters.items()
                        )
                        if not match:
                            continue
                    
                    rules.append(rule)
                except (ValueError, KeyError) as e:
                    # Skip invalid lines but log the issue
                    import logging
                    logging.debug(f"Skipping invalid rule line: {e}")
                    continue
        
        # Return most recent rules first
        rules.reverse()
        return rules[:limit]
    
    def compress_old_episodes(
        self,
        summarizer: Optional[Callable[[List[Episode]], str]] = None,
        dry_run: bool = False,
        max_episodes: int = 10000
    ) -> Dict[str, Any]:
        """
        Execute a compression cycle: identify old episodes, summarize, and optionally archive.
        
        Args:
            summarizer: Optional custom summarization function
            dry_run: If True, only report what would be compressed without making changes
            max_episodes: Maximum number of episodes to process (default: 10000)
            
        Returns:
            Dictionary with compression statistics
        """
        # Retrieve episodes up to max limit
        all_episodes = self.store.retrieve(limit=max_episodes)
        
        if len(all_episodes) == max_episodes:
            # Log warning that we may have hit the limit
            import logging
            logging.warning(
                f"Retrieved {max_episodes} episodes (limit reached). "
                "Some episodes may not be processed. Consider increasing max_episodes."
            )
        
        # Identify old episodes
        old_episodes = self.identify_old_episodes(all_episodes)
        
        if not old_episodes:
            return {
                "compressed_count": 0,
                "rules_created": 0,
                "message": "No old episodes found for compression"
            }
        
        # Batch compress
        rules_created = 0
        compressed_count = 0
        errors = []
        
        for i in range(0, len(old_episodes), self.compression_batch_size):
            batch = old_episodes[i:i + self.compression_batch_size]
            
            # Summarize batch
            try:
                rule = self.summarize_episodes(batch, summarizer)
                
                if not dry_run:
                    self.store_rule(rule)
                
                rules_created += 1
                compressed_count += len(batch)
            except Exception as e:
                # Collect errors but continue with next batch
                import logging
                logging.error(f"Error compressing batch starting at index {i}: {e}")
                errors.append(str(e))
                continue
        
        result = {
            "compressed_count": compressed_count,
            "rules_created": rules_created,
            "total_episodes": len(all_episodes),
            "old_episodes": len(old_episodes),
            "dry_run": dry_run
        }
        
        if errors:
            result["errors"] = errors
            result["message"] = f"Completed with {len(errors)} error(s)"
        elif dry_run:
            result["message"] = f"Dry run: Would compress {compressed_count} episodes into {rules_created} rules"
        else:
            result["message"] = f"Compressed {compressed_count} episodes into {rules_created} rules"
        
        return result

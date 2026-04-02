# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
emk - Episodic Memory Kernel.

A mutable ledger of agent experiences for AI systems with causal reasoning
and sleep-cycle memory compression.

Example:
    >>> from emk import Episode, FileAdapter
    >>> store = FileAdapter("memories.jsonl")
    >>> episode = Episode(
    ...     goal="Retrieve user data",
    ...     action="Query database",
    ...     result="Success",
    ...     reflection="Efficient query"
    ... )
    >>> episode_id = store.store(episode)
"""

from typing import TYPE_CHECKING, List

__version__ = "3.0.2"
__author__ = "Microsoft Corporation"
__license__ = "MIT"

# Core exports - always available
from emk.schema import Episode, SemanticRule
from emk.store import VectorStoreAdapter, FileAdapter
from emk.indexer import Indexer
from emk.sleep_cycle import MemoryCompressor

# Define explicit public API
__all__: List[str] = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    # Core classes
    "Episode",
    "SemanticRule",
    "VectorStoreAdapter",
    "FileAdapter",
    "Indexer",
    "MemoryCompressor",
]

# Optional ChromaDB adapter - only import if chromadb is installed
try:
    from emk.store import ChromaDBAdapter
    __all__.append("ChromaDBAdapter")
except ImportError:
    if TYPE_CHECKING:
        from emk.store import ChromaDBAdapter  # noqa: F401

# Causal memory (requires sqlite3, always available in stdlib)
from emk.causal import CausalEpisode, CausalMemoryStore
__all__.extend(["CausalEpisode", "CausalMemoryStore"])

# Optional Hugging Face utilities - only import if huggingface_hub is installed
try:
    from emk.hf_utils import (
        upload_episodes_to_hub,
        download_episodes_from_hub,
        push_experiment_results,
    )
    __all__.extend([
        "upload_episodes_to_hub",
        "download_episodes_from_hub",
        "push_experiment_results",
    ])
except ImportError:
    pass


def get_version_info() -> dict:
    """Get detailed version information about the emk package."""
    features = {
        "chromadb": "ChromaDBAdapter" in __all__,
        "huggingface": "upload_episodes_to_hub" in __all__,
        "causal": True,
    }
    return {
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "features": features,
    }

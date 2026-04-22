# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
CaaS Core: Layer 1 Primitive for Context Management.

A pure, logic-only library for routing context and managing context windows.
"""

from typing import TYPE_CHECKING

__version__ = "3.2.2"
__author__ = "Microsoft Corporation"
__email__ = "agentgovtoolkit@microsoft.com"
__license__ = "MIT"

# Core data models - always available
from caas.models import (
    # Enums
    ContentTier,
    ContextLayer,
    DocumentType,
    ContentFormat,
    SourceType,
    ModelTier,
    FileType,
    # Data classes
    Section,
    Document,
    SourceCitation,
    ContextRequest,
    ContextResponse,
    RoutingDecision,
    ContextTriadItem,
    ContextTriadState,
    FileNode,
    FileEdit,
    VFSState,
    FileResponse,
    FileListResponse,
)

# Tiered context - single-tier context management
from caas.triad import ContextTriadManager

# Decay functions for time-based retrieval
from caas.decay import calculate_decay_factor, apply_decay_to_score, get_time_weighted_score

# Conversation management
from caas.conversation import ConversationManager

# Heuristic Router - default-route query routing
from caas.routing import HeuristicRouter

# Document Detection
from caas.detection import DocumentTypeDetector, StructureAnalyzer

# Ingestion & Processing
from caas.ingestion import (
    BaseProcessor,
    PDFProcessor,
    HTMLProcessor,
    CodeProcessor,
    ProcessorFactory,
)

# Storage & Extraction
from caas.storage import DocumentStore, ContextExtractor

# Tuning
from caas.tuning import WeightTuner, CorpusAnalyzer

# Virtual File System - Project state management for SDLC agents
from caas.vfs import VirtualFileSystem

# Context Caching - Cost optimization for LLM APIs (CAAS-008)
from caas.caching import (
    ContextCache,
    CacheConfig,
    CacheStrategy,
    AnthropicCacheStrategy,
    OpenAICacheStrategy,
    LocalCacheStrategy,
    CacheProvider,
    CacheType,
    CacheResult,
    CacheStats,
    create_cache,
)

# Public API - explicit exports for `from caas import *`
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    # Enums
    "ContentTier",
    "ContextLayer",
    "DocumentType",
    "ContentFormat",
    "SourceType",
    "ModelTier",
    "FileType",
    # Data Models
    "Section",
    "Document",
    "SourceCitation",
    "ContextRequest",
    "ContextResponse",
    "RoutingDecision",
    "ContextTriadItem",
    "ContextTriadState",
    "FileNode",
    "FileEdit",
    "VFSState",
    "FileResponse",
    "FileListResponse",
    # Core Managers
    "ContextTriadManager",
    "calculate_decay_factor",
    "apply_decay_to_score",
    "get_time_weighted_score",
    "ConversationManager",
    # Routing
    "HeuristicRouter",
    # Detection
    "DocumentTypeDetector",
    "StructureAnalyzer",
    # Ingestion
    "BaseProcessor",
    "PDFProcessor",
    "HTMLProcessor",
    "CodeProcessor",
    "ProcessorFactory",
    # Storage
    "DocumentStore",
    "ContextExtractor",
    # Tuning
    "WeightTuner",
    "CorpusAnalyzer",
    # Virtual File System
    "VirtualFileSystem",
    # Context Caching
    "ContextCache",
    "CacheConfig",
    "CacheStrategy",
    "AnthropicCacheStrategy",
    "OpenAICacheStrategy",
    "LocalCacheStrategy",
    "CacheProvider",
    "CacheType",
    "CacheResult",
    "CacheStats",
    "create_cache",
]


def get_version() -> str:
    """Return the current version of CaaS."""
    return __version__

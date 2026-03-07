# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for package initialization and imports."""

import pytest


def test_import_main_package():
    """Test that the main package can be imported."""
    import emk
    assert hasattr(emk, '__version__')
    assert emk.__version__ == "0.2.0"


def test_import_episode():
    """Test that Episode can be imported."""
    from emk import Episode
    
    episode = Episode(
        goal="Test",
        action="Test",
        result="Test",
        reflection="Test"
    )
    assert episode.goal == "Test"


def test_import_file_adapter():
    """Test that FileAdapter can be imported."""
    from emk import FileAdapter
    
    assert FileAdapter is not None


def test_import_vector_store_adapter():
    """Test that VectorStoreAdapter can be imported."""
    from emk import VectorStoreAdapter
    
    assert VectorStoreAdapter is not None


def test_import_indexer():
    """Test that Indexer can be imported."""
    from emk import Indexer
    
    assert Indexer is not None


def test_chromadb_adapter_optional():
    """Test that ChromaDBAdapter import is optional."""
    try:
        from emk import ChromaDBAdapter
        # If import succeeds, chromadb is installed
        assert ChromaDBAdapter is not None
    except ImportError:
        # If import fails, chromadb is not installed - this is expected
        pytest.skip("chromadb not installed")

#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Command-line interface for Context-as-a-Service.
"""

import sys
import json
from pathlib import Path

from caas.models import ContentFormat
from caas.ingestion import ProcessorFactory
from caas.detection import DocumentTypeDetector, StructureAnalyzer
from caas.tuning import WeightTuner
from caas.storage import DocumentStore, ContextExtractor


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print_usage()
        return
    
    command = sys.argv[1]
    
    if command == "ingest":
        ingest_command()
    elif command == "analyze":
        analyze_command()
    elif command == "context":
        context_command()
    elif command == "list":
        list_command()
    else:
        print(f"Unknown command: {command}")
        print_usage()


def print_usage():
    """Print CLI usage information."""
    print("""
Context-as-a-Service CLI

Usage:
    caas ingest <file> <format> [title]    Ingest a document
    caas analyze <document_id>             Analyze a document
    caas context <document_id> [query]     Extract context
    caas list                              List all documents

Formats: pdf, html, code

Examples:
    caas ingest contract.pdf pdf "Employment Contract"
    caas analyze abc-123
    caas context abc-123 "termination clause"
    """)


def ingest_command():
    """Handle ingest command."""
    if len(sys.argv) < 4:
        print("Usage: caas ingest <file> <format> [title]")
        return
    
    file_path = Path(sys.argv[2])
    format_str = sys.argv[3]
    title = sys.argv[4] if len(sys.argv) > 4 else file_path.stem
    
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        return
    
    # Map format string to enum
    format_map = {
        "pdf": ContentFormat.PDF,
        "html": ContentFormat.HTML,
        "code": ContentFormat.CODE,
    }
    
    format_enum = format_map.get(format_str.lower())
    if not format_enum:
        print(f"Error: Invalid format: {format_str}")
        print("Valid formats: pdf, html, code")
        return
    
    # Process document
    print(f"Ingesting {file_path}...")
    
    content = file_path.read_bytes()
    processor = ProcessorFactory.get_processor(format_enum)
    
    import uuid
    doc_id = str(uuid.uuid4())
    
    metadata = {
        "id": doc_id,
        "title": title,
        "filename": file_path.name,
    }
    
    document = processor.process(content, metadata)
    
    # Auto-detect and tune
    detector = DocumentTypeDetector()
    document.detected_type = detector.detect(document)
    
    tuner = WeightTuner()
    document = tuner.tune(document)
    
    # Store
    store = DocumentStore("caas_data.json")
    store.add(document)
    
    print(f"\n✓ Document ingested successfully!")
    print(f"  ID: {document.id}")
    print(f"  Title: {document.title}")
    print(f"  Detected Type: {document.detected_type}")
    print(f"  Sections: {len(document.sections)}")
    print(f"\nTop weighted sections:")
    sorted_sections = sorted(document.sections, key=lambda s: s.weight, reverse=True)
    for section in sorted_sections[:5]:
        print(f"  - {section.title}: {section.weight}x")


def analyze_command():
    """Handle analyze command."""
    if len(sys.argv) < 3:
        print("Usage: caas analyze <document_id>")
        return
    
    doc_id = sys.argv[2]
    
    store = DocumentStore("caas_data.json")
    document = store.get(doc_id)
    
    if not document:
        print(f"Error: Document not found: {doc_id}")
        return
    
    analyzer = StructureAnalyzer()
    detector = DocumentTypeDetector()
    
    structure = detector.detect_structure(document)
    analysis = analyzer.analyze(document)
    
    print(f"\n=== Document Analysis ===")
    print(f"ID: {document.id}")
    print(f"Title: {document.title}")
    print(f"Type: {document.detected_type}")
    print(f"\nStructure:")
    print(f"  Sections: {structure['section_count']}")
    print(f"  Clear Structure: {'Yes' if structure['has_clear_sections'] else 'No'}")
    print(f"  Quality: {analysis['structure_quality']}")
    print(f"\nKey Sections:")
    for section in structure['key_sections']:
        print(f"  - {section}")


def context_command():
    """Handle context command."""
    if len(sys.argv) < 3:
        print("Usage: caas context <document_id> [query]")
        return
    
    doc_id = sys.argv[2]
    query = sys.argv[3] if len(sys.argv) > 3 else ""
    
    store = DocumentStore("caas_data.json")
    document = store.get(doc_id)
    
    if not document:
        print(f"Error: Document not found: {doc_id}")
        return
    
    extractor = ContextExtractor(store)
    context, metadata = extractor.extract_context(doc_id, query, max_tokens=500)
    
    print(f"\n=== Context Extraction ===")
    print(f"Document: {document.title}")
    print(f"Type: {document.detected_type}")
    if query:
        print(f"Query: {query}")
    print(f"\nSections used: {len(metadata['sections_used'])}/{metadata['total_sections']}")
    for section in metadata['sections_used']:
        print(f"  - {section}")
    print(f"\n--- Context ---")
    print(context[:1000] + ("..." if len(context) > 1000 else ""))


def list_command():
    """Handle list command."""
    store = DocumentStore("caas_data.json")
    documents = store.list_all()
    
    if not documents:
        print("No documents found.")
        return
    
    print(f"\n=== Documents ({len(documents)}) ===")
    for doc in documents:
        print(f"\n{doc.id}")
        print(f"  Title: {doc.title}")
        print(f"  Type: {doc.detected_type}")
        print(f"  Format: {doc.format}")
        print(f"  Sections: {len(doc.sections)}")


if __name__ == "__main__":
    main()

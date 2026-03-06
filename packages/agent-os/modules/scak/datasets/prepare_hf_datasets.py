#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Prepare datasets for Hugging Face upload

This script converts local datasets to Hugging Face format and prepares them for upload.

Usage:
    python datasets/prepare_hf_datasets.py
"""

import json
import os
from pathlib import Path
from typing import Dict, List


def create_vague_queries_dataset() -> List[Dict]:
    """Create GAIA vague queries dataset."""
    queries = [
        {
            "id": "q001",
            "query": "Find the Q3 report",
            "category": "archived_resource",
            "ground_truth": {
                "exists": True,
                "location": "archive/2025-Q3-Final.pdf",
                "requires": ["check_archives"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        },
        {
            "id": "q002",
            "query": "Get logs for error 500",
            "category": "archived_resource",
            "ground_truth": {
                "exists": True,
                "location": "/var/log/archive/2024-01/error_500_logs.json",
                "requires": ["check_archives", "search_partitions"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        },
        {
            "id": "q003",
            "query": "Show project Alpha status",
            "category": "renamed_entity",
            "ground_truth": {
                "exists": True,
                "location": "projects/Project_Artemis",
                "requires": ["check_rename_history"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        },
        {
            "id": "q004",
            "query": "Find customer feedback from last quarter",
            "category": "time_based_confusion",
            "ground_truth": {
                "exists": True,
                "location": "database.customer_surveys_q4_2024",
                "requires": ["translate_relative_time", "query_database"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        },
        {
            "id": "q005",
            "query": "Get the latest deployment config",
            "category": "synonym_issue",
            "ground_truth": {
                "exists": True,
                "location": "configs/deploy_config_v2.3.1_prod.yaml",
                "requires": ["check_versioned_configs", "identify_latest"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        }
    ]
    
    # Extend with more synthetic examples to reach 50
    categories = ["archived_resource", "renamed_entity", "time_based_confusion", "synonym_issue"]
    for i in range(6, 51):
        category = categories[i % len(categories)]
        queries.append({
            "id": f"q{i:03d}",
            "query": f"Synthetic query {i} for {category}",
            "category": category,
            "ground_truth": {
                "exists": True,
                "location": f"data/{category}/item_{i}",
                "requires": [f"capability_{category}"]
            },
            "expected_agent_behavior": "give_up",
            "expected_teacher_behavior": "find_it"
        })
    
    return queries


def save_dataset(data: List[Dict], output_path: Path):
    """Save dataset as JSONL."""
    with open(output_path, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')
    print(f"✅ Saved {len(data)} examples to {output_path}")


def main():
    print("=" * 60)
    print("Preparing Datasets for Hugging Face")
    print("=" * 60)
    
    # Create output directory
    output_dir = Path("datasets/hf_upload")
    output_dir.mkdir(exist_ok=True)
    
    # 1. GAIA Vague Queries Dataset
    print("\n1. Creating GAIA Vague Queries dataset...")
    vague_queries = create_vague_queries_dataset()
    save_dataset(vague_queries, output_dir / "scak_gaia_laziness.jsonl")
    
    # 2. Copy dataset card
    import shutil
    shutil.copy("datasets/DATASET_CARD.md", output_dir / "README.md")
    print("✅ Copied dataset card to README.md")
    
    print("\n" + "=" * 60)
    print("Dataset Preparation Complete!")
    print("=" * 60)
    print(f"\nFiles created in: {output_dir}/")
    print("  - scak_gaia_laziness.jsonl (50 examples)")
    print("  - README.md (dataset card)")
    print("\nNext steps:")
    print("1. Install Hugging Face CLI: pip install huggingface_hub")
    print("2. Login: huggingface-cli login")
    print("3. Create repo: huggingface-cli repo create scak-gaia-laziness --type dataset")
    print("4. Upload files:")
    print(f"   huggingface-cli upload microsoft/scak-gaia-laziness {output_dir}/")
    print("\nOr use the web interface at: https://huggingface.co/new-dataset")


if __name__ == "__main__":
    main()

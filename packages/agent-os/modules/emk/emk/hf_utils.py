# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hugging Face Hub utilities for EMK.

This module provides functions to push and pull episode data and experiment
results to/from the Hugging Face Hub for sharing and reproducibility.

Requirements:
    pip install emk[huggingface]

Example:
    >>> from emk.hf_utils import upload_episodes_to_hub
    >>> upload_episodes_to_hub(
    ...     episodes=my_episodes,
    ...     repo_id="microsoft/emk-experiments",
    ...     filename="episodes.jsonl"
    ... )

Note:
    You must be logged in to Hugging Face Hub to push data:
    >>> huggingface_hub.login()
    or set the HF_TOKEN environment variable.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from emk.schema import Episode

# Lazy import to avoid requiring huggingface_hub at import time
_HF_HUB_AVAILABLE = None


def _check_hf_hub() -> None:
    """Check if huggingface_hub is available and raise helpful error if not."""
    global _HF_HUB_AVAILABLE
    
    if _HF_HUB_AVAILABLE is None:
        try:
            import huggingface_hub  # noqa: F401
            _HF_HUB_AVAILABLE = True
        except ImportError:
            _HF_HUB_AVAILABLE = False
    
    if not _HF_HUB_AVAILABLE:
        raise ImportError(
            "huggingface_hub is required for this functionality. "
            "Install it with: pip install emk[huggingface]"
        )


def upload_episodes_to_hub(
    episodes: List["Episode"],
    repo_id: str,
    filename: str = "episodes.jsonl",
    *,
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
    branch: Optional[str] = None,
) -> str:
    """
    Upload episodes to a Hugging Face Hub dataset repository.
    
    This function serializes episodes to JSONL format and uploads them
    to the specified Hugging Face Hub repository.
    
    Args:
        episodes: List of Episode objects to upload.
        repo_id: The Hugging Face Hub repository ID (e.g., "username/repo-name").
        filename: Name of the file in the repository (default: "episodes.jsonl").
        commit_message: Custom commit message (auto-generated if not provided).
        private: Whether the repository should be private (default: False).
        token: Hugging Face API token (uses cached token if not provided).
        branch: Branch to upload to (default: main).
    
    Returns:
        str: URL of the uploaded file.
    
    Raises:
        ImportError: If huggingface_hub is not installed.
        ValueError: If episodes list is empty.
    
    Example:
        >>> from emk import Episode
        >>> from emk.hf_utils import upload_episodes_to_hub
        >>> episodes = [Episode(goal="Test", action="Run", result="Pass", reflection="Good")]
        >>> url = upload_episodes_to_hub(
        ...     episodes=episodes,
        ...     repo_id="microsoft/emk-test-data"
        ... )
        >>> print(f"Uploaded to: {url}")
    """
    _check_hf_hub()
    from huggingface_hub import HfApi
    
    if not episodes:
        raise ValueError("Episodes list cannot be empty")
    
    api = HfApi(token=token)
    
    # Create repository if it doesn't exist
    api.create_repo(
        repo_id=repo_id,
        repo_type="dataset",
        private=private,
        exist_ok=True,
    )
    
    # Serialize episodes to JSONL
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for episode in episodes:
            f.write(episode.to_json() + "\n")
        temp_path = f.name
    
    try:
        # Generate commit message if not provided
        if commit_message is None:
            commit_message = f"Upload {len(episodes)} episodes via emk"
        
        # Upload file
        result = api.upload_file(
            path_or_fileobj=temp_path,
            path_in_repo=filename,
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=commit_message,
            revision=branch,
        )
        
        return result
    finally:
        # Cleanup temp file
        Path(temp_path).unlink(missing_ok=True)


def download_episodes_from_hub(
    repo_id: str,
    filename: str = "episodes.jsonl",
    *,
    token: Optional[str] = None,
    revision: Optional[str] = None,
) -> List["Episode"]:
    """
    Download episodes from a Hugging Face Hub dataset repository.
    
    Args:
        repo_id: The Hugging Face Hub repository ID (e.g., "username/repo-name").
        filename: Name of the file in the repository (default: "episodes.jsonl").
        token: Hugging Face API token (uses cached token if not provided).
        revision: Git revision (branch, tag, or commit) to download from.
    
    Returns:
        List[Episode]: List of Episode objects loaded from the repository.
    
    Raises:
        ImportError: If huggingface_hub is not installed.
        FileNotFoundError: If the file doesn't exist in the repository.
    
    Example:
        >>> from emk.hf_utils import download_episodes_from_hub
        >>> episodes = download_episodes_from_hub(
        ...     repo_id="microsoft/emk-test-data"
        ... )
        >>> print(f"Downloaded {len(episodes)} episodes")
    """
    _check_hf_hub()
    from huggingface_hub import hf_hub_download
    
    # Import Episode here to avoid circular imports
    from emk.schema import Episode
    
    # Download file
    local_path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        repo_type="dataset",
        token=token,
        revision=revision,
    )
    
    # Parse episodes
    episodes = []
    with open(local_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                episodes.append(Episode.from_json(line))
    
    return episodes


def push_experiment_results(
    results: Dict[str, Any],
    repo_id: str,
    filename: str = "results.json",
    *,
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
    append_timestamp: bool = True,
) -> str:
    """
    Push experiment results to Hugging Face Hub.
    
    This is useful for tracking experiment runs and sharing reproducible
    results with the research community.
    
    Args:
        results: Dictionary of experiment results to upload.
        repo_id: The Hugging Face Hub repository ID.
        filename: Name of the results file (default: "results.json").
        commit_message: Custom commit message.
        private: Whether the repository should be private.
        token: Hugging Face API token.
        append_timestamp: Whether to append timestamp to filename (default: True).
    
    Returns:
        str: URL of the uploaded file.
    
    Example:
        >>> from emk.hf_utils import push_experiment_results
        >>> results = {
        ...     "accuracy": 0.95,
        ...     "latency_ms": 12.5,
        ...     "episodes_processed": 1000
        ... }
        >>> url = push_experiment_results(
        ...     results=results,
        ...     repo_id="microsoft/emk-experiments"
        ... )
    """
    _check_hf_hub()
    from huggingface_hub import HfApi
    
    api = HfApi(token=token)
    
    # Create repository if it doesn't exist
    api.create_repo(
        repo_id=repo_id,
        repo_type="dataset",
        private=private,
        exist_ok=True,
    )
    
    # Add metadata to results
    results_with_meta = {
        "_uploaded_at": datetime.now(timezone.utc).isoformat(),
        "_emk_version": _get_emk_version(),
        **results,
    }
    
    # Modify filename with timestamp if requested
    if append_timestamp:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = Path(filename).stem
        suffix = Path(filename).suffix or ".json"
        filename = f"{stem}_{timestamp}{suffix}"
    
    # Serialize to JSON
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(results_with_meta, f, indent=2, default=str)
        temp_path = f.name
    
    try:
        if commit_message is None:
            commit_message = f"Upload experiment results via emk"
        
        result = api.upload_file(
            path_or_fileobj=temp_path,
            path_in_repo=filename,
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=commit_message,
        )
        
        return result
    finally:
        Path(temp_path).unlink(missing_ok=True)


def create_dataset_card(
    repo_id: str,
    description: str,
    *,
    num_episodes: Optional[int] = None,
    tags: Optional[List[str]] = None,
    license: str = "mit",
    token: Optional[str] = None,
) -> str:
    """
    Create or update a dataset card (README.md) for an EMK dataset.
    
    Args:
        repo_id: The Hugging Face Hub repository ID.
        description: Description of the dataset.
        num_episodes: Number of episodes in the dataset (optional).
        tags: List of tags for the dataset (optional).
        license: License identifier (default: "mit").
        token: Hugging Face API token.
    
    Returns:
        str: URL of the dataset card.
    
    Example:
        >>> from emk.hf_utils import create_dataset_card
        >>> url = create_dataset_card(
        ...     repo_id="microsoft/emk-agent-logs",
        ...     description="Agent experience logs from production system",
        ...     num_episodes=10000,
        ...     tags=["agents", "episodic-memory", "nlp"]
        ... )
    """
    _check_hf_hub()
    from huggingface_hub import HfApi
    
    api = HfApi(token=token)
    
    # Build tags list
    all_tags = ["emk", "episodic-memory", "agent-experiences"]
    if tags:
        all_tags.extend(tags)
    tags_yaml = "\n".join(f"- {tag}" for tag in all_tags)
    
    # Build dataset card content
    card_content = f"""---
license: {license}
tags:
{tags_yaml}
library_name: emk
---

# {repo_id.split('/')[-1]}

{description}

## Dataset Information

- **Format**: JSONL (newline-delimited JSON)
- **Schema**: EMK Episode (Goal → Action → Result → Reflection)
- **Library**: [emk](https://github.com/microsoft/agent-governance-toolkit)
"""

    if num_episodes:
        card_content += f"- **Episodes**: {num_episodes:,}\n"
    
    card_content += """
## Usage

```python
from emk.hf_utils import download_episodes_from_hub

episodes = download_episodes_from_hub(
    repo_id="{repo_id}"
)

for episode in episodes[:5]:
    print(f"Goal: {episode.goal}")
    print(f"Result: {episode.result}")
    print("---")
```

## Episode Schema

Each episode contains:

| Field | Type | Description |
|-------|------|-------------|
| `goal` | string | The agent's intended objective |
| `action` | string | The action taken |
| `result` | string | The outcome |
| `reflection` | string | Agent's analysis or learning |
| `timestamp` | datetime | When the episode was created |
| `metadata` | object | Additional context |
| `episode_id` | string | Unique SHA-256 identifier |

## License

This dataset is released under the {license.upper()} license.
""".format(repo_id=repo_id, license=license)
    
    # Upload README
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(card_content)
        temp_path = f.name
    
    try:
        result = api.upload_file(
            path_or_fileobj=temp_path,
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="dataset",
            commit_message="Create/update dataset card via emk",
        )
        return result
    finally:
        Path(temp_path).unlink(missing_ok=True)


def _get_emk_version() -> str:
    """Get the current emk version."""
    try:
        from emk import __version__
        return __version__
    except ImportError:
        return "unknown"


__all__ = [
    "upload_episodes_to_hub",
    "download_episodes_from_hub",
    "push_experiment_results",
    "create_dataset_card",
]

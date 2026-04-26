# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hugging Face Hub Utilities for AMB
==================================

This module provides utilities for uploading and downloading experiment results,
datasets, and logs to/from the Hugging Face Hub.

Features:
    - Upload experiment results and benchmarks
    - Push/pull message log datasets
    - Version control for research artifacts

Requirements:
    pip install huggingface_hub

Usage:
    from amb_core.hf_utils import upload_experiment_logs, download_dataset

    # Upload benchmark results
    upload_experiment_logs(
        file_path="experiments/results.json",
        repo_id="microsoft/amb-benchmarks"
    )

    # Download existing dataset
    df = download_dataset("microsoft/amb-message-logs")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from huggingface_hub import (
        DatasetCard,
        DatasetCardData,
        HfApi,
        Repository,
        create_repo,
        hf_hub_download,
        list_repo_files,
        upload_file,
    )
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False


__all__ = [
    "upload_experiment_logs",
    "download_dataset",
    "push_message_logs",
    "create_dataset_card",
    "HFDatasetManager",
]


def _check_hf_available() -> None:
    """Check if huggingface_hub is installed."""
    if not HF_AVAILABLE:
        raise ImportError(
            "huggingface_hub is required for HF utilities. "
            "Install it with: pip install huggingface_hub"
        )


def upload_experiment_logs(
    file_path: Union[str, Path],
    repo_id: str,
    *,
    path_in_repo: Optional[str] = None,
    commit_message: Optional[str] = None,
    token: Optional[str] = None,
    private: bool = False,
) -> str:
    """
    Upload experiment logs or benchmark results to Hugging Face Hub.

    This function uploads a single file (typically JSON results from experiments)
    to a dataset repository on the Hugging Face Hub.

    Args:
        file_path: Local path to the file to upload.
        repo_id: Repository ID on HF Hub (e.g., "microsoft/amb-benchmarks").
        path_in_repo: Destination path in the repository. Defaults to filename
            with timestamp prefix.
        commit_message: Git commit message. Auto-generated if not provided.
        token: HF API token. Uses HF_TOKEN env var or cached token if not provided.
        private: Whether to create a private repository if it doesn't exist.

    Returns:
        URL to the uploaded file on Hugging Face Hub.

    Raises:
        ImportError: If huggingface_hub is not installed.
        FileNotFoundError: If the file_path doesn't exist.

    Example:
        >>> url = upload_experiment_logs(
        ...     "experiments/results.json",
        ...     "microsoft/amb-benchmarks"
        ... )
        >>> print(f"Uploaded to: {url}")
    """
    _check_hf_available()

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    api = HfApi(token=token)

    # Create repo if it doesn't exist
    try:
        create_repo(
            repo_id=repo_id,
            repo_type="dataset",
            private=private,
            exist_ok=True,
            token=token,
        )
    except Exception:
        # Repo might already exist
        pass

    # Generate path in repo with timestamp
    if path_in_repo is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path_in_repo = f"runs/{timestamp}_{file_path.name}"

    # Generate commit message
    if commit_message is None:
        commit_message = f"Upload experiment results: {file_path.name}"

    # Upload file
    url = api.upload_file(
        path_or_fileobj=str(file_path),
        path_in_repo=path_in_repo,
        repo_id=repo_id,
        repo_type="dataset",
        commit_message=commit_message,
    )

    return url


def download_dataset(
    repo_id: str,
    filename: str = "latest",
    *,
    local_dir: Optional[Union[str, Path]] = None,
    token: Optional[str] = None,
) -> Path:
    """
    Download a dataset file from Hugging Face Hub.

    Args:
        repo_id: Repository ID on HF Hub (e.g., "microsoft/amb-benchmarks").
        filename: Specific file to download, or "latest" to get most recent.
        local_dir: Local directory to save the file. Defaults to HF cache.
        token: HF API token. Uses HF_TOKEN env var or cached token if not provided.

    Returns:
        Path to the downloaded file.

    Raises:
        ImportError: If huggingface_hub is not installed.

    Example:
        >>> path = download_dataset(
        ...     "microsoft/amb-benchmarks",
        ...     filename="latest"
        ... )
        >>> with open(path) as f:
        ...     data = json.load(f)
    """
    _check_hf_available()

    api = HfApi(token=token)

    # If "latest", find most recent file
    if filename == "latest":
        files = list_repo_files(repo_id, repo_type="dataset", token=token)
        # Filter to JSON files in runs directory
        run_files = [f for f in files if f.startswith("runs/") and f.endswith(".json")]
        if not run_files:
            raise FileNotFoundError(f"No run files found in {repo_id}")
        filename = sorted(run_files)[-1]  # Most recent by timestamp

    # Download file
    local_path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        repo_type="dataset",
        local_dir=local_dir,
        token=token,
    )

    return Path(local_path)


def push_message_logs(
    messages: List[Dict[str, Any]],
    repo_id: str,
    *,
    split: str = "train",
    token: Optional[str] = None,
    private: bool = False,
) -> str:
    """
    Push a list of message logs as a dataset to Hugging Face Hub.

    This is useful for collecting agent communication patterns for research.

    Args:
        messages: List of message dictionaries to push.
        repo_id: Repository ID on HF Hub.
        split: Dataset split name (train, test, validation).
        token: HF API token.
        private: Whether to create a private repository.

    Returns:
        URL to the dataset on Hugging Face Hub.

    Example:
        >>> messages = [
        ...     {"topic": "agent.thoughts", "payload": {"thought": "analyzing..."}, "timestamp": "2024-01-01T00:00:00Z"},
        ...     {"topic": "agent.actions", "payload": {"action": "search"}, "timestamp": "2024-01-01T00:00:01Z"},
        ... ]
        >>> url = push_message_logs(messages, "microsoft/amb-message-logs")
    """
    _check_hf_available()

    api = HfApi(token=token)

    # Create repo
    create_repo(
        repo_id=repo_id,
        repo_type="dataset",
        private=private,
        exist_ok=True,
        token=token,
    )

    # Convert to JSONL format
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"data/{split}_{timestamp}.jsonl"

    # Create temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for msg in messages:
            f.write(json.dumps(msg, default=str) + "\n")
        temp_path = f.name

    try:
        # Upload
        url = api.upload_file(
            path_or_fileobj=temp_path,
            path_in_repo=filename,
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=f"Add {len(messages)} message logs",
        )
    finally:
        os.unlink(temp_path)

    return url


def create_dataset_card(
    repo_id: str,
    *,
    description: str = "Agent Message Bus communication logs and experiment results.",
    license: str = "mit",
    language: str = "en",
    tags: Optional[List[str]] = None,
    token: Optional[str] = None,
) -> None:
    """
    Create or update the dataset card (README.md) for a HF dataset.

    Args:
        repo_id: Repository ID on HF Hub.
        description: Dataset description.
        license: License identifier.
        language: Language code.
        tags: List of tags for the dataset.
        token: HF API token.

    Example:
        >>> create_dataset_card(
        ...     "microsoft/amb-benchmarks",
        ...     description="AMB performance benchmarks across different configurations.",
        ...     tags=["message-bus", "agents", "benchmarks"]
        ... )
    """
    _check_hf_available()

    if tags is None:
        tags = ["agent-communication", "message-bus", "benchmarks", "async"]

    card_data = DatasetCardData(
        license=license,
        language=language,
        tags=tags,
    )

    card_content = f"""---
{card_data.to_yaml()}
---

# {repo_id.split('/')[-1]}

{description}

## Dataset Description

This dataset contains experiment results and message logs from the 
[AMB (Agent Message Bus)](https://github.com/microsoft/agent-governance-toolkit) project.

### Supported Tasks

- Performance benchmarking analysis
- Agent communication pattern research
- Message latency studies

### Data Format

Results are stored in JSON/JSONL format with the following schema:

```json
{{
    "metadata": {{
        "experiment_name": "string",
        "timestamp": "ISO8601",
        "seed": "int"
    }},
    "results": [
        {{
            "name": "benchmark_name",
            "mean_latency_ms": "float",
            "throughput_msg_per_sec": "float"
        }}
    ]
}}
```

## Usage

```python
from amb_core.hf_utils import download_dataset
import json

# Download latest results
path = download_dataset("{repo_id}", filename="latest")
with open(path) as f:
    data = json.load(f)
```

## Citation

```bibtex
@software{{amb2024,
  author = {{Siddique, Imran}},
  title = {{AMB: Agent Message Bus}},
  year = {{2024}},
  url = {{https://github.com/microsoft/agent-governance-toolkit}}
}}
```

## License

This dataset is released under the {license.upper()} License.
"""

    api = HfApi(token=token)

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(card_content)
        temp_path = f.name

    try:
        api.upload_file(
            path_or_fileobj=temp_path,
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="dataset",
            commit_message="Update dataset card",
            token=token,
        )
    finally:
        os.unlink(temp_path)


class HFDatasetManager:
    """
    High-level manager for Hugging Face dataset operations.

    This class provides a convenient interface for managing experiment
    results and message logs on Hugging Face Hub.

    Attributes:
        repo_id: Repository ID on HF Hub.
        token: HF API token.

    Example:
        >>> manager = HFDatasetManager("microsoft/amb-benchmarks")
        >>> manager.upload_results("experiments/results.json")
        >>> latest = manager.get_latest_results()
    """

    def __init__(
        self,
        repo_id: str,
        *,
        token: Optional[str] = None,
        auto_create: bool = True,
        private: bool = False,
    ) -> None:
        """
        Initialize the dataset manager.

        Args:
            repo_id: Repository ID on HF Hub (e.g., "username/dataset-name").
            token: HF API token. Uses HF_TOKEN env var if not provided.
            auto_create: Whether to automatically create the repo if it doesn't exist.
            private: Whether to create a private repository.
        """
        _check_hf_available()

        self.repo_id = repo_id
        self.token = token or os.environ.get("HF_TOKEN")
        self._api = HfApi(token=self.token)

        if auto_create:
            try:
                create_repo(
                    repo_id=repo_id,
                    repo_type="dataset",
                    private=private,
                    exist_ok=True,
                    token=self.token,
                )
            except Exception:
                pass  # Repo might already exist

    def upload_results(
        self,
        file_path: Union[str, Path],
        *,
        commit_message: Optional[str] = None,
    ) -> str:
        """
        Upload experiment results to the repository.

        Args:
            file_path: Path to the results file (JSON).
            commit_message: Git commit message.

        Returns:
            URL to the uploaded file.
        """
        return upload_experiment_logs(
            file_path=file_path,
            repo_id=self.repo_id,
            token=self.token,
            commit_message=commit_message,
        )

    def get_latest_results(
        self,
        local_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Download and parse the latest results file.

        Args:
            local_dir: Local directory to save the file.

        Returns:
            Parsed JSON data from the latest results file.
        """
        path = download_dataset(
            repo_id=self.repo_id,
            filename="latest",
            local_dir=local_dir,
            token=self.token,
        )

        with open(path) as f:
            return json.load(f)

    def list_runs(self) -> List[str]:
        """
        List all experiment runs in the repository.

        Returns:
            List of run file paths.
        """
        files = list_repo_files(
            self.repo_id,
            repo_type="dataset",
            token=self.token,
        )
        return [f for f in files if f.startswith("runs/") and f.endswith(".json")]

    def push_logs(
        self,
        messages: List[Dict[str, Any]],
        *,
        split: str = "train",
    ) -> str:
        """
        Push message logs to the repository.

        Args:
            messages: List of message dictionaries.
            split: Dataset split name.

        Returns:
            URL to the uploaded data.
        """
        return push_message_logs(
            messages=messages,
            repo_id=self.repo_id,
            split=split,
            token=self.token,
        )

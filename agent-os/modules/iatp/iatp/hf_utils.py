# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Hugging Face Hub Integration Utilities for IATP.

This module provides utilities for uploading and downloading IATP experiment
results, datasets, and model artifacts to/from the Hugging Face Hub.

Usage:
    from iatp.hf_utils import IATPHubClient

    client = IATPHubClient()
    client.upload_experiment_logs("experiments/results.json")
    client.download_benchmark_dataset()

Requirements:
    pip install inter-agent-trust-protocol[hf]
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from huggingface_hub import (
        DatasetCard,
        DatasetCardData,
        HfApi,
        HfFolder,
        Repository,
        create_repo,
        hf_hub_download,
        upload_file,
        upload_folder,
    )
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False


__all__ = [
    "IATPHubClient",
    "upload_experiment_logs",
    "download_benchmark_dataset",
    "create_iatp_dataset_card",
]


# =============================================================================
# Constants
# =============================================================================

DEFAULT_REPO_ID = "microsoft/iatp-experiments"
DEFAULT_DATASET_REPO = "microsoft/iatp-benchmark"
IATP_VERSION = "0.3.1"


# =============================================================================
# Hub Client
# =============================================================================

class IATPHubClient:
    """
    Client for interacting with Hugging Face Hub for IATP artifacts.

    This client provides methods to:
    - Upload experiment results and logs
    - Download benchmark datasets
    - Manage IATP model/dataset repositories

    Attributes:
        repo_id: The Hugging Face repository ID (e.g., "username/repo-name")
        token: HF API token (uses cached token if not provided)

    Example:
        >>> client = IATPHubClient(repo_id="microsoft/iatp-experiments")
        >>> client.upload_experiment_logs("experiments/results.json")
        >>> dataset = client.download_benchmark_dataset()
    """

    def __init__(
        self,
        repo_id: str = DEFAULT_REPO_ID,
        token: str | None = None,
        repo_type: str = "dataset",
    ) -> None:
        """
        Initialize the Hugging Face Hub client.

        Args:
            repo_id: The repository ID on Hugging Face Hub
            token: HF API token. If None, uses cached token from `huggingface-cli login`
            repo_type: Type of repository ("dataset", "model", or "space")

        Raises:
            ImportError: If huggingface_hub is not installed
        """
        if not HF_AVAILABLE:
            raise ImportError(
                "huggingface_hub is required for HF integration. "
                "Install with: pip install inter-agent-trust-protocol[hf]"
            )

        self.repo_id = repo_id
        self.token = token or os.getenv("HF_TOKEN") or HfFolder.get_token()
        self.repo_type = repo_type
        self.api = HfApi(token=self.token)

    def upload_experiment_logs(
        self,
        file_path: str | Path,
        path_in_repo: str | None = None,
        commit_message: str | None = None,
        create_if_missing: bool = True,
    ) -> str:
        """
        Upload experiment results to Hugging Face Hub.

        Args:
            file_path: Local path to the experiment results file (JSON/JSONL)
            path_in_repo: Path within the repository. If None, uses filename with timestamp
            commit_message: Git commit message
            create_if_missing: Create the repository if it doesn't exist

        Returns:
            URL of the uploaded file

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file format is not supported

        Example:
            >>> client.upload_experiment_logs(
            ...     "experiments/results.json",
            ...     commit_message="Add cascading failure experiment results"
            ... )
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if file_path.suffix not in [".json", ".jsonl", ".csv", ".parquet"]:
            raise ValueError(
                f"Unsupported file format: {file_path.suffix}. "
                "Supported: .json, .jsonl, .csv, .parquet"
            )

        # Generate path in repo if not provided
        if path_in_repo is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path_in_repo = f"experiments/{timestamp}_{file_path.name}"

        # Create repo if needed
        if create_if_missing:
            try:
                create_repo(
                    repo_id=self.repo_id,
                    repo_type=self.repo_type,
                    exist_ok=True,
                    token=self.token,
                )
            except Exception:
                pass  # Repo already exists

        # Generate commit message
        if commit_message is None:
            commit_message = f"Upload experiment results: {file_path.name}"

        # Upload the file
        url = upload_file(
            path_or_fileobj=str(file_path),
            path_in_repo=path_in_repo,
            repo_id=self.repo_id,
            repo_type=self.repo_type,
            commit_message=commit_message,
            token=self.token,
        )

        return url

    def upload_experiment_folder(
        self,
        folder_path: str | Path,
        path_in_repo: str = "experiments",
        commit_message: str | None = None,
    ) -> str:
        """
        Upload an entire experiments folder to Hugging Face Hub.

        Args:
            folder_path: Local path to the experiments folder
            path_in_repo: Path within the repository
            commit_message: Git commit message

        Returns:
            URL of the repository
        """
        folder_path = Path(folder_path)

        if not folder_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {folder_path}")

        if commit_message is None:
            commit_message = f"Upload experiments folder: {folder_path.name}"

        url = upload_folder(
            folder_path=str(folder_path),
            path_in_repo=path_in_repo,
            repo_id=self.repo_id,
            repo_type=self.repo_type,
            commit_message=commit_message,
            token=self.token,
        )

        return url

    def download_benchmark_dataset(
        self,
        filename: str = "benchmark.json",
        repo_id: str | None = None,
        local_dir: str | Path | None = None,
    ) -> Path:
        """
        Download the IATP benchmark dataset.

        Args:
            filename: Name of the file to download
            repo_id: Repository ID. Defaults to the benchmark repo
            local_dir: Local directory to save the file

        Returns:
            Path to the downloaded file

        Example:
            >>> dataset_path = client.download_benchmark_dataset()
            >>> with open(dataset_path) as f:
            ...     data = json.load(f)
        """
        repo_id = repo_id or DEFAULT_DATASET_REPO

        file_path = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            repo_type="dataset",
            token=self.token,
            local_dir=str(local_dir) if local_dir else None,
        )

        return Path(file_path)

    def list_experiments(self) -> list[dict[str, Any]]:
        """
        List all experiment files in the repository.

        Returns:
            List of file metadata dictionaries
        """
        files = self.api.list_repo_files(
            repo_id=self.repo_id,
            repo_type=self.repo_type,
            token=self.token,
        )

        experiment_files = [
            {"path": f, "type": "experiment"}
            for f in files
            if f.startswith("experiments/") and f.endswith((".json", ".jsonl"))
        ]

        return experiment_files


# =============================================================================
# Convenience Functions
# =============================================================================

def upload_experiment_logs(
    file_path: str | Path,
    repo_id: str = DEFAULT_REPO_ID,
    token: str | None = None,
) -> str:
    """
    Convenience function to upload experiment logs.

    Args:
        file_path: Path to the experiment results file
        repo_id: Hugging Face repository ID
        token: HF API token

    Returns:
        URL of the uploaded file

    Example:
        >>> from iatp.hf_utils import upload_experiment_logs
        >>> url = upload_experiment_logs("experiments/results.json")
        >>> print(f"Uploaded to: {url}")
    """
    client = IATPHubClient(repo_id=repo_id, token=token)
    return client.upload_experiment_logs(file_path)


def download_benchmark_dataset(
    local_dir: str | Path | None = None,
    repo_id: str = DEFAULT_DATASET_REPO,
    token: str | None = None,
) -> Path:
    """
    Convenience function to download the benchmark dataset.

    Args:
        local_dir: Local directory to save the dataset
        repo_id: Hugging Face repository ID
        token: HF API token

    Returns:
        Path to the downloaded file

    Example:
        >>> from iatp.hf_utils import download_benchmark_dataset
        >>> path = download_benchmark_dataset(local_dir="./data")
    """
    client = IATPHubClient(repo_id=repo_id, token=token, repo_type="dataset")
    return client.download_benchmark_dataset(local_dir=local_dir)


def create_iatp_dataset_card(
    repo_id: str = DEFAULT_DATASET_REPO,
    output_path: str | Path | None = None,
) -> str:
    """
    Generate a Hugging Face Dataset Card for IATP datasets.

    Args:
        repo_id: Repository ID for the dataset
        output_path: Optional path to save the README.md

    Returns:
        The dataset card content as a string

    Example:
        >>> card = create_iatp_dataset_card()
        >>> print(card)
    """
    card_content = '''---
license: mit
task_categories:
  - text-classification
language:
  - en
tags:
  - iatp
  - agent-trust
  - security
  - multi-agent-systems
  - llm-safety
pretty_name: IATP Benchmark Dataset
size_categories:
  - 1K<n<10K
---

# IATP Benchmark Dataset

## Dataset Description

This dataset contains experiment results and benchmark data for the
**Inter-Agent Trust Protocol (IATP)** - a sidecar architecture for
preventing cascading hallucinations in autonomous agent networks.

### Dataset Summary

The IATP benchmark dataset includes:

- **Capability Manifests**: Sample agent capability declarations
- **Trust Scenarios**: Test cases for trust score calculation
- **Cascading Failure Tests**: Data for evaluating failure prevention
- **Policy Decisions**: Ground truth for policy engine validation

### Supported Tasks

- Agent Trust Classification
- Cascading Failure Detection
- Privacy Policy Validation

### Languages

English (en)

## Dataset Structure

### Data Instances

```json
{
  "agent_id": "secure-bank-agent",
  "trust_level": "verified_partner",
  "capabilities": {
    "reversibility": "full",
    "idempotency": true
  },
  "expected_trust_score": 10,
  "expected_decision": "allow"
}
```

### Data Fields

- `agent_id`: Unique identifier for the agent
- `trust_level`: One of ["verified_partner", "trusted", "standard", "unknown", "untrusted"]
- `capabilities`: Object containing reversibility, idempotency, etc.
- `privacy_contract`: Object containing retention policy, encryption settings
- `expected_trust_score`: Ground truth trust score (0-10)
- `expected_decision`: Expected policy decision ["allow", "warn", "deny"]

## Dataset Creation

### Curation Rationale

This dataset was created to enable reproducible evaluation of agent trust
mechanisms and to provide a benchmark for multi-agent security research.

### Source Data

Generated from IATP experiment runs using controlled agent configurations.

## Considerations for Using the Data

### Intended Use

- Evaluating agent trust mechanisms
- Benchmarking multi-agent security systems
- Research in LLM safety and governance

### Limitations

- Synthetic data based on defined scenarios
- May not cover all edge cases in production environments
- Trust scores are calculated using IATP's specific algorithm

## Additional Information

### Licensing Information

MIT License

### Citation Information

```bibtex
@software{iatp2024,
  title = {Inter-Agent Trust Protocol},
  author = {Siddique, Imran},
  year = {2024},
  url = {https://github.com/microsoft/agent-governance-toolkit}
}
```

### Contributions

Contributions are welcome! Please see the
[GitHub repository](https://github.com/microsoft/agent-governance-toolkit)
for contribution guidelines.
'''

    if output_path:
        output_path = Path(output_path)
        output_path.write_text(card_content)

    return card_content

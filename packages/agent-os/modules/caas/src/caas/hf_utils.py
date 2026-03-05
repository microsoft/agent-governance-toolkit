# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hugging Face Hub Utilities for CaaS.

This module provides utilities for uploading and downloading datasets,
experiment results, and model artifacts to/from Hugging Face Hub.

Example:
    Upload experiment results to Hugging Face::

        from caas.hf_utils import CaaSHubClient

        client = CaaSHubClient(repo_id="microsoft/caas-benchmark")
        client.upload_experiment_logs(
            results_path="experiments/results.json",
            commit_message="Add benchmark results v0.2.0"
        )

    Download the benchmark corpus::

        client = CaaSHubClient(repo_id="microsoft/caas-benchmark")
        corpus_path = client.download_benchmark_corpus()
        print(f"Corpus downloaded to: {corpus_path}")

Note:
    Requires the `huggingface_hub` package: ``pip install huggingface_hub``

    For uploads, you must be authenticated. Run ``huggingface-cli login``
    or set the ``HF_TOKEN`` environment variable.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Lazy import to avoid hard dependency
try:
    from huggingface_hub import (
        HfApi,
        hf_hub_download,
        snapshot_download,
        upload_file,
        upload_folder,
        create_repo,
        RepoUrl,
    )

    HF_HUB_AVAILABLE = True
except ImportError:
    HF_HUB_AVAILABLE = False


__all__ = [
    "CaaSHubClient",
    "ExperimentMetadata",
    "upload_experiment_logs",
    "download_benchmark_corpus",
    "push_dataset_to_hub",
]


# Default repository IDs
DEFAULT_BENCHMARK_REPO = "microsoft/caas-benchmark"
DEFAULT_DATASET_REPO = "microsoft/caas-enterprise-docs"


@dataclass
class ExperimentMetadata:
    """Metadata for an experiment run.

    Attributes:
        experiment_name: Human-readable name for the experiment.
        caas_version: Version of CaaS used.
        timestamp: ISO format timestamp of the experiment.
        python_version: Python version used.
        metrics: Dictionary of metric names to values.
        config: Configuration parameters used.
        tags: List of tags for categorization.
    """

    experiment_name: str
    caas_version: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    python_version: str = ""
    metrics: Dict[str, float] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary.

        Returns:
            Dict containing all metadata fields.
        """
        return {
            "experiment_name": self.experiment_name,
            "caas_version": self.caas_version,
            "timestamp": self.timestamp,
            "python_version": self.python_version,
            "metrics": self.metrics,
            "config": self.config,
            "tags": self.tags,
        }


class CaaSHubClient:
    """Client for interacting with Hugging Face Hub for CaaS artifacts.

    This client provides methods to upload and download datasets,
    experiment results, and benchmark corpora.

    Attributes:
        repo_id: The Hugging Face repository ID (format: "username/repo-name").
        token: Optional Hugging Face API token. If not provided, uses cached token.
        repo_type: Type of repository ("dataset", "model", or "space").

    Example:
        Initialize and download benchmark corpus::

            client = CaaSHubClient(repo_id="microsoft/caas-benchmark")
            corpus_path = client.download_benchmark_corpus()

        Upload experiment results::

            client = CaaSHubClient(repo_id="microsoft/caas-results")
            client.upload_experiment_logs("results/experiment_001.json")
    """

    def __init__(
        self,
        repo_id: str = DEFAULT_BENCHMARK_REPO,
        token: Optional[str] = None,
        repo_type: str = "dataset",
    ) -> None:
        """Initialize the Hugging Face Hub client.

        Args:
            repo_id: The Hugging Face repository ID.
            token: Optional API token. Falls back to HF_TOKEN env var or cached login.
            repo_type: Type of repository ("dataset", "model", or "space").

        Raises:
            ImportError: If huggingface_hub is not installed.
        """
        if not HF_HUB_AVAILABLE:
            raise ImportError(
                "huggingface_hub is required for Hugging Face integration. "
                "Install it with: pip install huggingface_hub"
            )

        self.repo_id = repo_id
        self.token = token or os.environ.get("HF_TOKEN")
        self.repo_type = repo_type
        self._api = HfApi(token=self.token)

    def download_benchmark_corpus(
        self,
        local_dir: Optional[Union[str, Path]] = None,
        revision: str = "main",
    ) -> Path:
        """Download the CaaS benchmark corpus from Hugging Face.

        Args:
            local_dir: Local directory to download to. Defaults to cache.
            revision: Git revision (branch, tag, or commit hash).

        Returns:
            Path to the downloaded corpus directory.

        Example:
            Download to custom directory::

                client = CaaSHubClient()
                path = client.download_benchmark_corpus(local_dir="./data/corpus")
        """
        if local_dir:
            local_dir = Path(local_dir)
            local_dir.mkdir(parents=True, exist_ok=True)

        downloaded_path = snapshot_download(
            repo_id=self.repo_id,
            repo_type=self.repo_type,
            revision=revision,
            local_dir=str(local_dir) if local_dir else None,
            token=self.token,
        )

        return Path(downloaded_path)

    def download_file(
        self,
        filename: str,
        local_dir: Optional[Union[str, Path]] = None,
        revision: str = "main",
    ) -> Path:
        """Download a specific file from the repository.

        Args:
            filename: Path to the file within the repository.
            local_dir: Local directory to save the file.
            revision: Git revision.

        Returns:
            Path to the downloaded file.

        Example:
            Download specific results file::

                client = CaaSHubClient()
                path = client.download_file("results/evaluation_results.json")
        """
        downloaded_path = hf_hub_download(
            repo_id=self.repo_id,
            filename=filename,
            repo_type=self.repo_type,
            revision=revision,
            local_dir=str(local_dir) if local_dir else None,
            token=self.token,
        )

        return Path(downloaded_path)

    def upload_experiment_logs(
        self,
        results_path: Union[str, Path],
        path_in_repo: Optional[str] = None,
        commit_message: Optional[str] = None,
        metadata: Optional[ExperimentMetadata] = None,
    ) -> str:
        """Upload experiment results to Hugging Face Hub.

        Args:
            results_path: Local path to the results file (JSON or folder).
            path_in_repo: Path within the repository. Defaults to filename.
            commit_message: Git commit message.
            metadata: Optional experiment metadata to include.

        Returns:
            URL of the uploaded file.

        Example:
            Upload with metadata::

                metadata = ExperimentMetadata(
                    experiment_name="ablation_study_v1",
                    caas_version="0.2.0",
                    metrics={"precision_at_5": 0.847}
                )
                url = client.upload_experiment_logs(
                    "results.json",
                    metadata=metadata
                )
        """
        results_path = Path(results_path)

        if path_in_repo is None:
            path_in_repo = f"results/{results_path.name}"

        if commit_message is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            commit_message = f"Upload experiment results: {timestamp}"

        # If metadata provided, merge it into the results
        if metadata and results_path.suffix == ".json":
            with open(results_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data["_metadata"] = metadata.to_dict()

            # Write to temp file
            temp_path = results_path.parent / f"_upload_{results_path.name}"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            upload_path = temp_path
        else:
            upload_path = results_path

        try:
            url = upload_file(
                path_or_fileobj=str(upload_path),
                path_in_repo=path_in_repo,
                repo_id=self.repo_id,
                repo_type=self.repo_type,
                commit_message=commit_message,
                token=self.token,
            )
            return url
        finally:
            # Clean up temp file
            if metadata and results_path.suffix == ".json":
                temp_path.unlink(missing_ok=True)

    def upload_folder(
        self,
        folder_path: Union[str, Path],
        path_in_repo: str = "",
        commit_message: Optional[str] = None,
        ignore_patterns: Optional[List[str]] = None,
    ) -> str:
        """Upload a folder to Hugging Face Hub.

        Args:
            folder_path: Local folder path.
            path_in_repo: Target path within the repository.
            commit_message: Git commit message.
            ignore_patterns: Patterns to ignore (e.g., ["*.pyc", "__pycache__"]).

        Returns:
            URL of the repository.

        Example:
            Upload entire results folder::

                url = client.upload_folder(
                    "experiments/results/",
                    path_in_repo="benchmark_results/v0.2.0"
                )
        """
        folder_path = Path(folder_path)

        if commit_message is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            commit_message = f"Upload folder: {folder_path.name} at {timestamp}"

        if ignore_patterns is None:
            ignore_patterns = ["*.pyc", "__pycache__", ".git", ".DS_Store"]

        return upload_folder(
            folder_path=str(folder_path),
            path_in_repo=path_in_repo,
            repo_id=self.repo_id,
            repo_type=self.repo_type,
            commit_message=commit_message,
            ignore_patterns=ignore_patterns,
            token=self.token,
        )

    def create_dataset_repo(
        self,
        repo_name: Optional[str] = None,
        private: bool = False,
        exist_ok: bool = True,
    ) -> str:
        """Create a new dataset repository on Hugging Face Hub.

        Args:
            repo_name: Name for the new repository. Uses self.repo_id if None.
            private: Whether the repository should be private.
            exist_ok: Don't raise error if repo already exists.

        Returns:
            URL of the created repository.

        Example:
            Create a new private dataset repo::

                client = CaaSHubClient(repo_id="myuser/my-caas-experiments")
                url = client.create_dataset_repo(private=True)
        """
        repo_id = repo_name or self.repo_id

        result: RepoUrl = create_repo(
            repo_id=repo_id,
            repo_type="dataset",
            private=private,
            exist_ok=exist_ok,
            token=self.token,
        )

        return str(result)


# Convenience functions for quick access
def upload_experiment_logs(
    results_path: Union[str, Path],
    repo_id: str = DEFAULT_BENCHMARK_REPO,
    commit_message: Optional[str] = None,
    token: Optional[str] = None,
) -> str:
    """Upload experiment results to Hugging Face Hub.

    Convenience function that creates a client and uploads results.

    Args:
        results_path: Path to the results file.
        repo_id: Target repository ID.
        commit_message: Git commit message.
        token: Optional API token.

    Returns:
        URL of the uploaded file.

    Example:
        Quick upload::

            from caas.hf_utils import upload_experiment_logs
            url = upload_experiment_logs("results/eval.json")
    """
    client = CaaSHubClient(repo_id=repo_id, token=token)
    return client.upload_experiment_logs(
        results_path=results_path,
        commit_message=commit_message,
    )


def download_benchmark_corpus(
    local_dir: Optional[Union[str, Path]] = None,
    repo_id: str = DEFAULT_BENCHMARK_REPO,
    token: Optional[str] = None,
) -> Path:
    """Download the CaaS benchmark corpus.

    Convenience function for downloading the official benchmark corpus.

    Args:
        local_dir: Local directory to download to.
        repo_id: Source repository ID.
        token: Optional API token.

    Returns:
        Path to the downloaded corpus.

    Example:
        Quick download::

            from caas.hf_utils import download_benchmark_corpus
            corpus_path = download_benchmark_corpus("./data")
    """
    client = CaaSHubClient(repo_id=repo_id, token=token)
    return client.download_benchmark_corpus(local_dir=local_dir)


def push_dataset_to_hub(
    data_path: Union[str, Path],
    repo_id: str,
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
) -> str:
    """Push a dataset folder to Hugging Face Hub.

    Creates the repository if it doesn't exist and uploads the data.

    Args:
        data_path: Path to the dataset folder.
        repo_id: Target repository ID (format: "username/dataset-name").
        commit_message: Git commit message.
        private: Whether to create a private repository.
        token: Optional API token.

    Returns:
        URL of the repository.

    Example:
        Push local dataset::

            from caas.hf_utils import push_dataset_to_hub
            url = push_dataset_to_hub(
                data_path="./benchmarks/data/sample_corpus",
                repo_id="myuser/enterprise-docs-benchmark"
            )
    """
    client = CaaSHubClient(repo_id=repo_id, token=token)

    # Create repo if needed
    client.create_dataset_repo(private=private, exist_ok=True)

    # Upload the folder
    return client.upload_folder(
        folder_path=data_path,
        commit_message=commit_message,
    )

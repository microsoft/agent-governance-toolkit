# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hugging Face Hub Utilities for CMVK

Lightweight utilities for pushing/pulling datasets and experiment results
to the Hugging Face Hub. Designed for research reproducibility.

Usage:
    from cmvk.hf_utils import upload_experiment_logs, download_dataset

    # Upload experiment results
    upload_experiment_logs(
        results_path="experiments/results.json",
        repo_id="microsoft/cmvk-benchmark-data"
    )

    # Download shared datasets
    download_dataset(
        repo_id="microsoft/cmvk-benchmark-data",
        filename="datasets/humaneval_50.json",
        local_path="experiments/datasets/"
    )

Requirements:
    pip install huggingface_hub
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from huggingface_hub import HfApi

logger = logging.getLogger(__name__)

# Default repository configuration
DEFAULT_REPO_ID = "microsoft/cmvk-benchmark-data"
DEFAULT_REPO_TYPE = "dataset"


class HuggingFaceHubError(Exception):
    """Raised when Hugging Face Hub operations fail."""

    pass


def _get_api() -> HfApi:
    """Get HfApi instance, raising helpful error if not installed."""
    try:
        from huggingface_hub import HfApi

        return HfApi()
    except ImportError as e:
        raise HuggingFaceHubError(
            "huggingface_hub is required for HF integration. "
            "Install with: pip install huggingface_hub"
        ) from e


def check_auth() -> bool:
    """
    Check if Hugging Face authentication is configured.

    Returns:
        True if authenticated, False otherwise.

    Example:
        >>> if check_auth():
        ...     upload_experiment_logs("results.json")
    """
    try:
        api = _get_api()
        api.whoami()
        return True
    except Exception:
        return False


def upload_experiment_logs(
    results_path: str | Path,
    repo_id: str = DEFAULT_REPO_ID,
    path_in_repo: str | None = None,
    commit_message: str | None = None,
    private: bool = False,
) -> str:
    """
    Upload experiment results/logs to Hugging Face Hub.

    Args:
        results_path: Path to local results file (JSON, CSV, etc.)
        repo_id: Hugging Face repository ID (e.g., "username/repo-name")
        path_in_repo: Path within the repository. If None, uses filename.
        commit_message: Custom commit message. Auto-generated if None.
        private: Whether to make the repository private.

    Returns:
        URL of the uploaded file.

    Raises:
        HuggingFaceHubError: If upload fails or file not found.
        FileNotFoundError: If results_path doesn't exist.

    Example:
        >>> url = upload_experiment_logs(
        ...     "experiments/results.json",
        ...     repo_id="microsoft/cmvk-benchmark-data"
        ... )
        >>> print(f"Uploaded to: {url}")
    """
    from huggingface_hub import create_repo

    results_path = Path(results_path)
    if not results_path.exists():
        raise FileNotFoundError(f"Results file not found: {results_path}")

    api = _get_api()

    # Create repo if needed
    try:
        create_repo(
            repo_id,
            repo_type=DEFAULT_REPO_TYPE,
            private=private,
            exist_ok=True,
        )
    except Exception as e:
        logger.debug(f"Repository creation skipped: {e}")

    # Determine path in repo
    if path_in_repo is None:
        path_in_repo = f"results/{results_path.name}"

    # Auto-generate commit message
    if commit_message is None:
        commit_message = f"Upload experiment results: {results_path.name}"

    try:
        url: str = api.upload_file(
            path_or_fileobj=str(results_path),
            path_in_repo=path_in_repo,
            repo_id=repo_id,
            repo_type=DEFAULT_REPO_TYPE,
            commit_message=commit_message,
        )
        logger.info(f"Uploaded {results_path.name} to {url}")
        return url
    except Exception as e:
        raise HuggingFaceHubError(f"Failed to upload {results_path}: {e}") from e


def upload_traces(
    trace_dir: str | Path,
    repo_id: str = DEFAULT_REPO_ID,
    max_files: int = 100,
) -> list[str]:
    """
    Upload execution traces directory to Hugging Face Hub.

    Args:
        trace_dir: Directory containing trace JSON files.
        repo_id: Hugging Face repository ID.
        max_files: Maximum number of files to upload.

    Returns:
        List of uploaded file URLs.

    Example:
        >>> urls = upload_traces("logs/traces/")
        >>> print(f"Uploaded {len(urls)} trace files")
    """
    trace_path = Path(trace_dir)
    if not trace_path.exists():
        raise FileNotFoundError(f"Trace directory not found: {trace_path}")

    api = _get_api()
    trace_files = sorted(trace_path.glob("*.json"))[:max_files]

    urls = []
    for trace_file in trace_files:
        try:
            url = api.upload_file(
                path_or_fileobj=str(trace_file),
                path_in_repo=f"traces/{trace_file.name}",
                repo_id=repo_id,
                repo_type=DEFAULT_REPO_TYPE,
                commit_message=f"Upload trace: {trace_file.name}",
            )
            urls.append(url)
        except Exception as e:
            logger.warning(f"Failed to upload {trace_file.name}: {e}")

    logger.info(f"Uploaded {len(urls)}/{len(trace_files)} trace files")
    return urls


def download_dataset(
    repo_id: str = DEFAULT_REPO_ID,
    filename: str = "datasets/humaneval_50.json",
    local_path: str | Path = "experiments/datasets/",
    revision: str = "main",
) -> Path:
    """
    Download a dataset file from Hugging Face Hub.

    Args:
        repo_id: Hugging Face repository ID.
        filename: Path to file within the repository.
        local_path: Local directory to save the file.
        revision: Git revision (branch, tag, or commit).

    Returns:
        Path to the downloaded file.

    Example:
        >>> path = download_dataset(
        ...     filename="datasets/humaneval_50.json",
        ...     local_path="experiments/datasets/"
        ... )
        >>> with open(path) as f:
        ...     data = json.load(f)
    """
    from huggingface_hub import hf_hub_download

    local_path = Path(local_path)
    local_path.mkdir(parents=True, exist_ok=True)

    try:
        downloaded = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            repo_type=DEFAULT_REPO_TYPE,
            revision=revision,
            local_dir=str(local_path),
        )
        result_path = Path(downloaded)
        logger.info(f"Downloaded {filename} to {result_path}")
        return result_path
    except Exception as e:
        raise HuggingFaceHubError(f"Failed to download {filename}: {e}") from e


def upload_verification_dataset(
    data: list[dict[str, Any]],
    dataset_name: str,
    repo_id: str = DEFAULT_REPO_ID,
    description: str | None = None,
) -> str:
    """
    Upload a verification dataset (list of problems/results) to HF Hub.

    Args:
        data: List of problem dictionaries with verification results.
        dataset_name: Name for the dataset file.
        repo_id: Hugging Face repository ID.
        description: Optional description to include in metadata.

    Returns:
        URL of the uploaded dataset.

    Example:
        >>> results = [
        ...     {"task_id": "HE/1", "success": True, "drift_score": 0.15},
        ...     {"task_id": "HE/2", "success": False, "drift_score": 0.89},
        ... ]
        >>> upload_verification_dataset(results, "humaneval_run_001")
    """
    import tempfile
    from datetime import datetime

    # Create metadata wrapper
    dataset = {
        "name": dataset_name,
        "created_at": datetime.now().isoformat(),
        "description": description or f"CMVK verification dataset: {dataset_name}",
        "count": len(data),
        "data": data,
    }

    # Write to temp file and upload
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
    ) as f:
        json.dump(dataset, f, indent=2)
        temp_path = Path(f.name)

    try:
        return upload_experiment_logs(
            temp_path,
            repo_id=repo_id,
            path_in_repo=f"datasets/{dataset_name}.json",
            commit_message=f"Upload verification dataset: {dataset_name}",
        )
    finally:
        temp_path.unlink(missing_ok=True)

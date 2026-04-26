# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hugging Face Hub utilities for ATR.

This module provides utilities for integrating ATR with the Hugging Face ecosystem,
including uploading/downloading datasets, experiment logs, and tool specifications.

Example:
    Upload experiment results to Hugging Face Hub::

        from atr.hf_utils import upload_experiment_logs

        upload_experiment_logs(
            repo_id="microsoft/atr-experiments",
            results_path="experiments/results/results.json"
        )

Note:
    Requires the `huggingface-hub` package. Install with::

        pip install agent-tool-registry[hf]

    You must be authenticated with Hugging Face. Run::

        huggingface-cli login
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from atr import Registry, ToolSpec

logger = logging.getLogger(__name__)

# Default repository namespace
DEFAULT_NAMESPACE = "microsoft"


def _check_hf_hub_installed() -> None:
    """Check if huggingface_hub is installed.

    Raises:
        ImportError: If huggingface_hub is not installed.
    """
    try:
        import huggingface_hub  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "huggingface_hub is required for HF integration. "
            "Install it with: pip install agent-tool-registry[hf]"
        ) from e


def upload_experiment_logs(
    repo_id: str,
    results_path: Union[str, Path],
    *,
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
) -> str:
    """Upload experiment results to Hugging Face Hub.

    Creates or updates a dataset repository with experiment logs.

    Args:
        repo_id: The Hugging Face repo ID (e.g., "microsoft/atr-experiments").
        results_path: Path to the results JSON file.
        commit_message: Custom commit message. Auto-generated if None.
        private: Whether the repository should be private.
        token: Hugging Face API token. Uses cached token if None.

    Returns:
        URL of the uploaded file on Hugging Face Hub.

    Raises:
        ImportError: If huggingface_hub is not installed.
        FileNotFoundError: If results file doesn't exist.
        ValueError: If results file is not valid JSON.

    Example:
        >>> url = upload_experiment_logs(
        ...     repo_id="microsoft/atr-experiments",
        ...     results_path="experiments/results/results.json"
        ... )
        >>> print(f"Uploaded to: {url}")
    """
    _check_hf_hub_installed()

    from huggingface_hub import HfApi, create_repo

    results_path = Path(results_path)
    if not results_path.exists():
        raise FileNotFoundError(f"Results file not found: {results_path}")

    # Validate JSON
    try:
        with open(results_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in results file: {e}") from e

    api = HfApi(token=token)

    # Create repo if it doesn't exist
    try:
        create_repo(
            repo_id=repo_id,
            repo_type="dataset",
            private=private,
            token=token,
            exist_ok=True,
        )
    except Exception as e:
        logger.warning(f"Could not create/verify repo: {e}")

    # Generate filename with timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    remote_path = f"experiments/results_{timestamp}.json"

    # Generate commit message
    if commit_message is None:
        atr_version = data.get("metadata", {}).get("atr_version", "unknown")
        commit_message = f"Add experiment results (ATR v{atr_version})"

    # Upload file
    url = api.upload_file(
        path_or_fileobj=str(results_path),
        path_in_repo=remote_path,
        repo_id=repo_id,
        repo_type="dataset",
        commit_message=commit_message,
        token=token,
    )

    logger.info(f"Uploaded experiment logs to: {url}")
    return url


def download_experiment_logs(
    repo_id: str,
    output_dir: Union[str, Path] = ".",
    *,
    filename: Optional[str] = None,
    token: Optional[str] = None,
) -> Path:
    """Download experiment results from Hugging Face Hub.

    Args:
        repo_id: The Hugging Face repo ID.
        output_dir: Directory to save downloaded files.
        filename: Specific file to download. Downloads latest if None.
        token: Hugging Face API token.

    Returns:
        Path to the downloaded file.

    Raises:
        ImportError: If huggingface_hub is not installed.

    Example:
        >>> path = download_experiment_logs(
        ...     repo_id="microsoft/atr-experiments",
        ...     output_dir="./downloaded"
        ... )
    """
    _check_hf_hub_installed()

    from huggingface_hub import hf_hub_download, list_repo_files

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # If no specific file, find the latest
    if filename is None:
        files = list_repo_files(repo_id=repo_id, repo_type="dataset", token=token)
        experiment_files = sorted(
            [f for f in files if f.startswith("experiments/") and f.endswith(".json")],
            reverse=True,
        )
        if not experiment_files:
            raise FileNotFoundError(f"No experiment files found in {repo_id}")
        filename = experiment_files[0]

    downloaded_path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        repo_type="dataset",
        local_dir=str(output_dir),
        token=token,
    )

    return Path(downloaded_path)


def upload_tool_registry(
    repo_id: str,
    registry: Registry,
    *,
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
) -> str:
    """Upload a tool registry snapshot to Hugging Face Hub.

    Serializes all tool specifications and uploads as a dataset.

    Args:
        repo_id: The Hugging Face repo ID.
        registry: The ATR Registry instance to upload.
        commit_message: Custom commit message.
        private: Whether the repository should be private.
        token: Hugging Face API token.

    Returns:
        URL of the uploaded file.

    Example:
        >>> import atr
        >>> url = upload_tool_registry(
        ...     repo_id="microsoft/atr-tools",
        ...     registry=atr._global_registry
        ... )
    """
    _check_hf_hub_installed()

    from huggingface_hub import HfApi, create_repo

    api = HfApi(token=token)

    # Create repo
    create_repo(
        repo_id=repo_id,
        repo_type="dataset",
        private=private,
        token=token,
        exist_ok=True,
    )

    # Serialize registry
    tools = registry.list_tools()
    registry_data = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_count": len(tools),
        },
        "tools": [
            {
                "name": tool.metadata.name,
                "description": tool.metadata.description,
                "version": tool.metadata.version,
                "author": tool.metadata.author,
                "cost": tool.metadata.cost.value,
                "tags": tool.metadata.tags,
                "parameters": [p.model_dump() for p in tool.parameters],
                "openai_schema": tool.to_openai_function_schema(),
            }
            for tool in tools
        ],
    }

    # Write to temp file and upload
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(registry_data, f, indent=2, default=str)
        temp_path = f.name

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    remote_path = f"registry/tools_{timestamp}.json"

    if commit_message is None:
        commit_message = f"Upload tool registry ({len(tools)} tools)"

    url = api.upload_file(
        path_or_fileobj=temp_path,
        path_in_repo=remote_path,
        repo_id=repo_id,
        repo_type="dataset",
        commit_message=commit_message,
        token=token,
    )

    # Cleanup
    Path(temp_path).unlink()

    logger.info(f"Uploaded tool registry to: {url}")
    return url


def create_model_card_snippet(
    tools: List[ToolSpec],
    model_name: str = "ATR Tool Registry",
) -> str:
    """Generate a Hugging Face Model Card snippet for ATR tools.

    Creates a markdown snippet suitable for a Model Card README.

    Args:
        tools: List of tool specifications to document.
        model_name: Name to use in the model card header.

    Returns:
        Markdown string for the model card.

    Example:
        >>> import atr
        >>> tools = atr.list_tools()
        >>> snippet = create_model_card_snippet(tools)
        >>> print(snippet)
    """
    tool_list = "\n".join(f"- **{t.metadata.name}**: {t.metadata.description}" for t in tools[:10])

    if len(tools) > 10:
        tool_list += f"\n- ... and {len(tools) - 10} more tools"

    return f"""---
license: mit
language:
- en
library_name: atr
tags:
- agent-tools
- function-calling
- llm
---

# {model_name}

## Model Description

This repository contains tool specifications for the Agent Tool Registry (ATR),
a decentralized marketplace for agent capabilities.

## Intended Use

These tool specifications are intended for:
- **LLM Function Calling**: Convert to OpenAI/Anthropic function schemas
- **Agent Development**: Discover and integrate tools into AI agents
- **Research**: Benchmark and evaluate agent tool usage

### Primary Use Cases

1. Tool discovery for autonomous agents
2. Schema generation for LLM function calling
3. Standardized tool interfaces across different agent frameworks

## Tools Included

{tool_list}

## Limitations

- **No Execution**: ATR stores specifications only; execution is handled by the agent runtime
- **Schema Only**: The callable functions are not included in this dataset
- **Version Dependent**: Tool specifications may change between versions

## How to Use

```python
import atr
from atr.hf_utils import download_experiment_logs

# Download tool specifications
# (implementation depends on your use case)
```

## Citation

```bibtex
@software{{atr2026,
  author = {{Siddique, Imran}},
  title = {{ATR: Agent Tool Registry}},
  year = {{2026}},
  url = {{https://github.com/microsoft/agent-governance-toolkit}}
}}
```

## Contact

For questions or issues, please open an issue on the
[GitHub repository](https://github.com/microsoft/agent-governance-toolkit).
"""


def push_to_hub(
    repo_id: str,
    data: Dict[str, Any],
    filename: str,
    *,
    repo_type: str = "dataset",
    commit_message: Optional[str] = None,
    private: bool = False,
    token: Optional[str] = None,
) -> str:
    """Generic utility to push JSON data to Hugging Face Hub.

    Args:
        repo_id: The Hugging Face repo ID.
        data: Dictionary to serialize as JSON.
        filename: Remote filename (e.g., "data/results.json").
        repo_type: Type of repository ("dataset", "model", "space").
        commit_message: Commit message.
        private: Whether repository should be private.
        token: Hugging Face API token.

    Returns:
        URL of the uploaded file.
    """
    _check_hf_hub_installed()

    from huggingface_hub import HfApi, create_repo

    api = HfApi(token=token)

    create_repo(
        repo_id=repo_id,
        repo_type=repo_type,
        private=private,
        token=token,
        exist_ok=True,
    )

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
        temp_path = f.name

    if commit_message is None:
        commit_message = f"Upload {filename}"

    url = api.upload_file(
        path_or_fileobj=temp_path,
        path_in_repo=filename,
        repo_id=repo_id,
        repo_type=repo_type,
        commit_message=commit_message,
        token=token,
    )

    Path(temp_path).unlink()
    return url

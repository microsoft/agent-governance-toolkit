# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hugging Face Hub Utilities for Agent Control Plane

This module provides utilities for interacting with Hugging Face Hub, including:
    - Uploading experiment logs and results
    - Downloading/uploading datasets
    - Model card generation
    - Dataset versioning and management

Installation:
    pip install huggingface_hub datasets

Usage:
    from agent_control_plane.hf_utils import (
        upload_experiment_logs,
        download_red_team_dataset,
        create_model_card,
    )
    
    # Upload experiment results
    upload_experiment_logs(
        results_path="experiments/results.json",
        repo_id="microsoft/acp-experiment-logs",
    )

Configuration:
    Set HF_TOKEN environment variable or use `huggingface-cli login`
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class HFConfig:
    """Configuration for Hugging Face Hub operations.
    
    Attributes:
        default_org: Default organization/user for uploads.
        red_team_dataset: Repository ID for the red team benchmark dataset.
        experiment_logs_repo: Repository ID for experiment logs.
        token: HF API token (if not set, uses HF_TOKEN env var).
    """
    
    default_org: str = "microsoft"
    red_team_dataset: str = "microsoft/agent-control-redteam-60"
    experiment_logs_repo: str = "microsoft/acp-experiment-logs"
    token: Optional[str] = None
    
    def get_token(self) -> Optional[str]:
        """Get the HF token from config or environment."""
        return self.token or os.environ.get("HF_TOKEN")


DEFAULT_CONFIG = HFConfig()


# =============================================================================
# Dataset Operations
# =============================================================================


def download_red_team_dataset(
    config: Optional[HFConfig] = None,
    split: str = "train",
    streaming: bool = False,
) -> Any:
    """
    Download the Agent Control Plane red team benchmark dataset.
    
    This dataset contains 60 adversarial prompts across categories:
    - Direct attacks
    - Prompt injection
    - Privilege escalation
    - Data exfiltration
    
    Args:
        config: HF configuration (uses default if not provided).
        split: Dataset split to load ("train").
        streaming: If True, return an iterable dataset for memory efficiency.
    
    Returns:
        Hugging Face Dataset object.
    
    Raises:
        ImportError: If datasets library is not installed.
        
    Example:
        >>> from agent_control_plane.hf_utils import download_red_team_dataset
        >>> dataset = download_red_team_dataset()
        >>> print(f"Loaded {len(dataset)} prompts")
        >>> for item in dataset:
        ...     print(f"Category: {item['category']}, Blocked: {item['expected_blocked']}")
    """
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError(
            "datasets library required. Install with: pip install datasets"
        )
    
    config = config or DEFAULT_CONFIG
    
    logger.info(f"Downloading red team dataset from: {config.red_team_dataset}")
    
    dataset = load_dataset(
        config.red_team_dataset,
        split=split,
        streaming=streaming,
        token=config.get_token(),
    )
    
    logger.info(f"Successfully loaded dataset with {len(dataset)} entries")
    return dataset


def upload_dataset(
    data: Union[Dict[str, List[Any]], List[Dict[str, Any]], Any],
    repo_id: str,
    config: Optional[HFConfig] = None,
    private: bool = False,
    commit_message: Optional[str] = None,
) -> str:
    """
    Upload a dataset to Hugging Face Hub.
    
    Args:
        data: Dataset to upload. Can be:
            - Dict mapping column names to lists
            - List of dicts (one per row)
            - Existing HF Dataset object
        repo_id: Target repository ID (e.g., "username/dataset-name").
        config: HF configuration (uses default if not provided).
        private: If True, create a private repository.
        commit_message: Custom commit message.
    
    Returns:
        URL of the uploaded dataset.
    
    Raises:
        ImportError: If datasets/huggingface_hub libraries not installed.
        
    Example:
        >>> from agent_control_plane.hf_utils import upload_dataset
        >>> data = {
        ...     "prompt": ["attack 1", "attack 2"],
        ...     "category": ["injection", "exfil"],
        ...     "blocked": [True, True],
        ... }
        >>> url = upload_dataset(data, "my-user/my-dataset")
        >>> print(f"Uploaded to: {url}")
    """
    try:
        from datasets import Dataset
        from huggingface_hub import HfApi
    except ImportError:
        raise ImportError(
            "Required libraries not installed. "
            "Install with: pip install datasets huggingface_hub"
        )
    
    config = config or DEFAULT_CONFIG
    token = config.get_token()
    
    # Convert to Dataset if needed
    if isinstance(data, dict):
        dataset = Dataset.from_dict(data)
    elif isinstance(data, list):
        dataset = Dataset.from_list(data)
    else:
        dataset = data  # Assume it's already a Dataset
    
    # Generate commit message
    if commit_message is None:
        commit_message = f"Upload dataset - {datetime.now().isoformat()}"
    
    logger.info(f"Uploading dataset to: {repo_id}")
    logger.info(f"Dataset size: {len(dataset)} rows")
    
    # Push to hub
    dataset.push_to_hub(
        repo_id,
        token=token,
        private=private,
        commit_message=commit_message,
    )
    
    url = f"https://huggingface.co/datasets/{repo_id}"
    logger.info(f"Successfully uploaded to: {url}")
    return url


# =============================================================================
# Experiment Log Operations
# =============================================================================


def upload_experiment_logs(
    results_path: Union[str, Path],
    repo_id: Optional[str] = None,
    config: Optional[HFConfig] = None,
    experiment_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Upload experiment results/logs to Hugging Face Hub.
    
    This function uploads experiment results for reproducibility tracking.
    Results are stored in a structured format with metadata.
    
    Args:
        results_path: Path to results JSON file or directory.
        repo_id: Target repository ID. Uses config default if not provided.
        config: HF configuration (uses default if not provided).
        experiment_name: Optional name for the experiment run.
        metadata: Additional metadata to include.
    
    Returns:
        URL of the uploaded file.
    
    Raises:
        FileNotFoundError: If results_path doesn't exist.
        ImportError: If huggingface_hub library not installed.
        
    Example:
        >>> from agent_control_plane.hf_utils import upload_experiment_logs
        >>> url = upload_experiment_logs(
        ...     results_path="experiments/results.json",
        ...     experiment_name="ablation_study_v2",
        ...     metadata={"gpu": "A100", "seed": 42},
        ... )
        >>> print(f"Logs uploaded to: {url}")
    """
    try:
        from huggingface_hub import HfApi, upload_file
    except ImportError:
        raise ImportError(
            "huggingface_hub library required. Install with: pip install huggingface_hub"
        )
    
    config = config or DEFAULT_CONFIG
    repo_id = repo_id or config.experiment_logs_repo
    token = config.get_token()
    
    results_path = Path(results_path)
    if not results_path.exists():
        raise FileNotFoundError(f"Results file not found: {results_path}")
    
    # Load and enrich results
    with open(results_path, "r") as f:
        results = json.load(f)
    
    # Add metadata
    enriched_results = {
        "upload_timestamp": datetime.now().isoformat(),
        "experiment_name": experiment_name or results_path.stem,
        "source_file": str(results_path),
        "custom_metadata": metadata or {},
        "results": results,
    }
    
    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_name = experiment_name or "experiment"
    filename = f"logs/{exp_name}_{timestamp}.json"
    
    # Create temp file with enriched data
    temp_path = results_path.parent / f"_upload_{timestamp}.json"
    try:
        with open(temp_path, "w") as f:
            json.dump(enriched_results, f, indent=2)
        
        logger.info(f"Uploading experiment logs to: {repo_id}/{filename}")
        
        # Upload to hub
        api = HfApi(token=token)
        
        # Ensure repo exists
        try:
            api.create_repo(repo_id, repo_type="dataset", exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create repo (may already exist): {e}")
        
        url = api.upload_file(
            path_or_fileobj=str(temp_path),
            path_in_repo=filename,
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=f"Upload experiment: {exp_name}",
        )
        
        logger.info(f"Successfully uploaded to: {url}")
        return url
        
    finally:
        # Cleanup temp file
        if temp_path.exists():
            temp_path.unlink()


def list_experiment_logs(
    repo_id: Optional[str] = None,
    config: Optional[HFConfig] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    List available experiment logs in the repository.
    
    Args:
        repo_id: Repository ID to list from.
        config: HF configuration (uses default if not provided).
        limit: Maximum number of files to list.
    
    Returns:
        List of file metadata dicts with name, size, and last_modified.
        
    Example:
        >>> from agent_control_plane.hf_utils import list_experiment_logs
        >>> logs = list_experiment_logs()
        >>> for log in logs[:5]:
        ...     print(f"{log['name']} - {log['size']} bytes")
    """
    try:
        from huggingface_hub import HfApi
    except ImportError:
        raise ImportError(
            "huggingface_hub library required. Install with: pip install huggingface_hub"
        )
    
    config = config or DEFAULT_CONFIG
    repo_id = repo_id or config.experiment_logs_repo
    token = config.get_token()
    
    api = HfApi(token=token)
    
    try:
        files = api.list_repo_files(repo_id, repo_type="dataset")
        
        # Filter for log files
        log_files = [f for f in files if f.startswith("logs/") and f.endswith(".json")]
        
        return [{"name": f, "path": f} for f in log_files[:limit]]
        
    except Exception as e:
        logger.error(f"Failed to list experiment logs: {e}")
        return []


# =============================================================================
# Model Card Generation
# =============================================================================


@dataclass
class ModelCardInfo:
    """Information for generating a Hugging Face Model Card.
    
    Attributes:
        model_name: Name of the model/system.
        description: Brief description.
        intended_use: Primary intended use cases.
        limitations: Known limitations and out-of-scope uses.
        training_data: Description of training data (if applicable).
        metrics: Evaluation metrics and results.
        citation: BibTeX citation.
    """
    
    model_name: str = "Agent Control Plane"
    description: str = ""
    intended_use: List[str] = field(default_factory=list)
    out_of_scope_use: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    training_data: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)
    citation: str = ""
    license: str = "MIT"
    authors: List[str] = field(default_factory=lambda: ["Imran Siddique"])


def create_model_card(info: Optional[ModelCardInfo] = None) -> str:
    """
    Generate a Hugging Face Model Card README.md content.
    
    Args:
        info: ModelCardInfo with details. Uses defaults if not provided.
    
    Returns:
        Markdown string for the model card.
        
    Example:
        >>> from agent_control_plane.hf_utils import create_model_card, ModelCardInfo
        >>> info = ModelCardInfo(
        ...     model_name="My ACP Instance",
        ...     intended_use=["Enterprise AI governance"],
        ...     limitations=["Requires policy configuration"],
        ... )
        >>> card = create_model_card(info)
        >>> print(card)
    """
    if info is None:
        info = ModelCardInfo(
            model_name="Agent Control Plane (ACP)",
            description=(
                "A deterministic kernel for zero-violation governance in agentic AI systems. "
                "ACP interposes between LLM intent and action execution, providing "
                "ABAC-based policy enforcement and constraint graphs."
            ),
            intended_use=[
                "Enterprise AI agent governance and safety enforcement",
                "Multi-agent orchestration with policy-based access control",
                "Research into deterministic AI safety mechanisms",
                "Integration with OpenAI, LangChain, and MCP-based agents",
            ],
            out_of_scope_use=[
                "Direct use as an LLM or chat model",
                "Content moderation (this is action-level, not content-level)",
                "Replacing human oversight in critical systems",
            ],
            limitations=[
                "Requires explicit policy configuration for each deployment",
                "Does not prevent all possible adversarial attacks",
                "Shadow mode simulation does not guarantee real-world behavior",
                "Performance overhead scales with policy complexity",
            ],
            metrics={
                "Safety Violation Rate": "0.00% (60-prompt red team benchmark)",
                "False Positive Rate": "0.00%",
                "Token Reduction": "98.1% (Scale by Subtraction)",
                "Latency Overhead": "<5ms per policy check",
            },
            citation="""@article{siddique2026acp,
  title={Agent Control Plane: A Deterministic Kernel for Zero-Violation Governance in Agentic AI},
  author={Siddique, Imran},
  journal={arXiv preprint},
  year={2026}
}""",
        )
    
    # Generate markdown
    card = f"""---
license: {info.license}
tags:
  - ai-safety
  - agents
  - governance
  - control-plane
  - deterministic
language:
  - en
library_name: agent-control-plane
---

# {info.model_name}

{info.description}

## Intended Use

**Primary Use Cases:**
"""
    
    for use in info.intended_use:
        card += f"- {use}\n"
    
    if info.out_of_scope_use:
        card += "\n**Out-of-Scope Uses:**\n"
        for use in info.out_of_scope_use:
            card += f"- ⚠️ {use}\n"
    
    card += "\n## Limitations\n\n"
    for limitation in info.limitations:
        card += f"- {limitation}\n"
    
    if info.metrics:
        card += "\n## Evaluation Results\n\n"
        card += "| Metric | Value |\n|--------|-------|\n"
        for metric, value in info.metrics.items():
            card += f"| {metric} | {value} |\n"
    
    card += f"""
## Installation

```bash
pip install agent-control-plane
```

## Quick Start

```python
from agent_control_plane import AgentControlPlane, create_governed_client

# Create a governed OpenAI client
client = create_governed_client(
    openai_client,
    permission_level="read_only"
)

# All tool calls are now governed by the control plane
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{{"role": "user", "content": "Read the sales report"}}],
    tools=[...]
)
```

## Citation

If you use this work, please cite:

```bibtex
{info.citation}
```

## Authors

"""
    for author in info.authors:
        card += f"- {author}\n"
    
    card += f"""
## License

This project is licensed under the {info.license} License.
"""
    
    return card


# =============================================================================
# Convenience Exports
# =============================================================================


__all__ = [
    # Configuration
    "HFConfig",
    "DEFAULT_CONFIG",
    # Dataset operations
    "download_red_team_dataset",
    "upload_dataset",
    # Experiment logs
    "upload_experiment_logs",
    "list_experiment_logs",
    # Model card
    "ModelCardInfo",
    "create_model_card",
]

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Benchmark module for comparative safety studies.
"""

from .red_team_dataset import (
    RedTeamPrompt,
    PromptCategory,
    get_all_prompts,
    get_prompts_by_category,
    get_dataset_stats
)

__all__ = [
    'RedTeamPrompt',
    'PromptCategory',
    'get_all_prompts',
    'get_prompts_by_category',
    'get_dataset_stats'
]

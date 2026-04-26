# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Type Definitions

Core types used throughout the verification library.
All types are immutable where possible for purity.
"""

from .verification import DriftExplanation, DriftType, VerificationScore

__all__ = ["DriftType", "VerificationScore", "DriftExplanation"]

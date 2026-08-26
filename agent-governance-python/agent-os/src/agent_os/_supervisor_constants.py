# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared constants for the supervisor hierarchy.

This leaf module exists so that both ``supervisor`` and ``trust_root`` can
import ``MAX_SUPERVISOR_LEVEL`` without a circular dependency (``supervisor``
imports ``TrustDecision`` and ``TrustRoot`` from ``trust_root``).
"""

# Real supervision hierarchies rarely exceed single digits; 1 000 is generous
# enough to never constrain legitimate use.  Without this bound, Python's
# unbounded integers allow a pathologically large level (e.g. ``10**100``)
# that makes ``validate_hierarchy`` hang if it ever tries to iterate the
# numeric range.
MAX_SUPERVISOR_LEVEL: int = 1_000

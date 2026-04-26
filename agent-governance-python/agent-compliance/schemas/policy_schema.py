# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class PolicySchema(BaseModel):
    """
    JSON Schema for governance policies.
    Addresses request for better validation (#305).
    """

    id: str = Field(..., description="Unique policy identifier")
    name: str = Field(..., description="Human-readable policy name")
    version: str = Field("1.0.0")
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = None


class PolicyValidationError(Exception):
    """Raised when a governance policy fails schema validation."""

    pass


def validate_policy(data: Dict[str, Any]) -> PolicySchema:
    """Validate a governance policy dict against the schema.

    Args:
        data: Policy data dictionary.

    Returns:
        Validated PolicySchema instance.

    Raises:
        PolicyValidationError: If validation fails with field-level details.
    """
    try:
        return PolicySchema(**data)
    except Exception as e:
        raise PolicyValidationError(f"Policy validation failed: {e}") from e

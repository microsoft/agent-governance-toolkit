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

def validate_policy(data: Dict[str, Any]):
    return PolicySchema(**data)

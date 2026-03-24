from pydantic import BaseModel
from typing import List, Optional

class OrgPolicy(BaseModel):
    """
    Policy model scoped to organization boundaries.
    Enables bilateral policy agreements and federated trust.
    """
    org_id: str
    trusted_orgs: List[str]
    PII_redaction_required: bool = True
    delegated_categories: List[str] = []

class FederatedEnforcement:
    def __init__(self, local_policy: OrgPolicy):
        self.local_policy = local_policy

    def evaluate_request(self, caller_org: str, category: str) -> bool:
        if caller_org not in self.local_policy.trusted_orgs:
            return False
        if category in self.local_policy.delegated_categories:
            return True
        return True # Default allow for trusted orgs in non-delegated categories

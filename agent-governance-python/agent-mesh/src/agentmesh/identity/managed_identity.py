# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Managed Identity Adapters for Enterprise Identity Providers.

Maps AGT agent DIDs to enterprise identity providers (Entra ID, AWS IAM,
GCP Workload Identity) so that governed agents can acquire cloud tokens
using their mesh identity.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from agentmesh.exceptions import IdentityError

logger = logging.getLogger(__name__)

# Default IMDS / metadata endpoints (overridable for testing)
_AZURE_IMDS_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
)
_AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/iam"
_AWS_TOKEN_URL = "http://169.254.169.254/latest/api/token"  # noqa: S105 — not a password, AWS metadata token endpoint URL constant
_GCP_METADATA_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts"
)


class ManagedIdentityAdapter(ABC):
    """Abstract adapter for enterprise identity providers.

    Subclasses implement cloud-specific token acquisition and validation
    while maintaining a mapping between the agent's DID and the cloud
    identity principal.
    """

    def __init__(self, agent_did: str) -> None:
        if not agent_did or not agent_did.startswith("did:mesh:"):
            raise IdentityError(
                f"Invalid agent DID format: {agent_did!r}. "
                "Expected 'did:mesh:<unique-id>'."
            )
        self.agent_did = agent_did
        self._token_cache: dict[str, tuple[str, float]] = {}

    @abstractmethod
    def get_token(self, scope: str) -> str:
        """Acquire an access token for the given scope."""

    def validate_token(self, token: str) -> dict:
        """Validate a token and return its claims.

        The base implementation performs structural validation only.
        Subclasses may override with provider-specific introspection.
        """
        if not token or not isinstance(token, str):
            raise IdentityError("Token must be a non-empty string")
        parts = token.split(".")
        if len(parts) != 3:
            raise IdentityError(
                "Token does not appear to be a valid JWT (expected 3 parts)"
            )
        return {"valid": True, "agent_did": self.agent_did}

    def get_agent_mapping(self) -> dict:
        """Return a mapping between the agent DID and the cloud principal."""
        return {
            "agent_did": self.agent_did,
            "provider": self.__class__.__name__,
        }

    def _cache_token(self, scope: str, token: str, ttl: float = 300.0) -> None:
        """Cache a token with an expiry timestamp."""
        self._token_cache[scope] = (token, time.monotonic() + ttl)

    def _get_cached_token(self, scope: str) -> Optional[str]:
        """Return a cached token if still valid, else ``None``."""
        entry = self._token_cache.get(scope)
        if entry is None:
            return None
        token, expiry = entry
        if time.monotonic() >= expiry:
            del self._token_cache[scope]
            return None
        return token


# ---------------------------------------------------------------------------
# Azure Entra Managed Identity
# ---------------------------------------------------------------------------

class EntraManagedIdentity(ManagedIdentityAdapter):
    """Azure Managed Identity adapter using the Instance Metadata Service."""

    DEFAULT_SCOPE = "https://management.azure.com/.default"

    def __init__(
        self,
        agent_did: str,
        client_id: Optional[str] = None,
        *,
        imds_url: str = _AZURE_IMDS_URL,
    ) -> None:
        super().__init__(agent_did)
        self.client_id = client_id
        self._imds_url = imds_url

    def get_token(self, scope: str = DEFAULT_SCOPE) -> str:
        """Acquire a token from the Azure IMDS endpoint."""
        cached = self._get_cached_token(scope)
        if cached is not None:
            return cached

        params = (
            f"?api-version=2018-02-01&resource={scope}"
        )
        if self.client_id:
            params += f"&client_id={self.client_id}"

        url = self._imds_url + params
        request = Request(url, headers={"Metadata": "true"})  # noqa: S310 — cloud metadata endpoint URL

        try:
            with urlopen(request, timeout=5) as resp:  # noqa: S310 — cloud metadata endpoint URL
                data = json.loads(resp.read().decode())
        except (URLError, OSError, json.JSONDecodeError) as exc:
            raise IdentityError(
                f"Failed to acquire Azure token for DID {self.agent_did}: {exc}"
            ) from exc

        token = data.get("access_token")
        if not token:
            raise IdentityError(
                "Azure IMDS response did not contain an access_token"
            )

        expires_in = float(data.get("expires_in", 300))
        self._cache_token(scope, token, ttl=max(expires_in - 30, 0))
        return token

    def validate_token(self, token: str) -> dict:
        """Validate an Azure JWT token (structural check)."""
        base = super().validate_token(token)
        base["provider"] = "azure"
        if self.client_id:
            base["client_id"] = self.client_id
        return base

    def get_agent_mapping(self) -> dict:
        mapping = super().get_agent_mapping()
        mapping["client_id"] = self.client_id
        mapping["provider"] = "azure_managed_identity"
        return mapping


# ---------------------------------------------------------------------------
# AWS IAM Role
# ---------------------------------------------------------------------------

class AWSIAMIdentity(ManagedIdentityAdapter):
    """AWS IAM Role adapter using the EC2 instance metadata service."""

    DEFAULT_SCOPE = "sts"

    def __init__(
        self,
        agent_did: str,
        role_arn: Optional[str] = None,
        *,
        metadata_url: str = _AWS_METADATA_URL,
        token_url: str = _AWS_TOKEN_URL,
    ) -> None:
        super().__init__(agent_did)
        self.role_arn = role_arn
        self._metadata_url = metadata_url
        self._token_url = token_url

    def _get_imds_token(self) -> str:
        """Acquire an IMDSv2 session token."""
        request = Request(  # noqa: S310 — cloud metadata endpoint URL
            self._token_url,
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        try:
            with urlopen(request, timeout=5) as resp:  # noqa: S310 — cloud metadata endpoint URL
                return resp.read().decode()
        except (URLError, OSError) as exc:
            raise IdentityError(
                f"Failed to acquire AWS IMDSv2 token: {exc}"
            ) from exc

    def get_token(self, scope: str = DEFAULT_SCOPE) -> str:
        """Acquire temporary credentials from the EC2 metadata service."""
        cached = self._get_cached_token(scope)
        if cached is not None:
            return cached

        imds_token = self._get_imds_token()

        # Discover role name
        role_url = f"{self._metadata_url}/security-credentials/"
        request = Request(  # noqa: S310 — cloud metadata endpoint URL
            role_url,
            headers={"X-aws-ec2-metadata-token": imds_token},
        )
        try:
            with urlopen(request, timeout=5) as resp:  # noqa: S310 — cloud metadata endpoint URL
                role_name = resp.read().decode().strip()
        except (URLError, OSError) as exc:
            raise IdentityError(
                f"Failed to discover AWS IAM role: {exc}"
            ) from exc

        # Fetch credentials for role
        creds_url = f"{self._metadata_url}/security-credentials/{role_name}"
        request = Request(  # noqa: S310 — cloud metadata endpoint URL
            creds_url,
            headers={"X-aws-ec2-metadata-token": imds_token},
        )
        try:
            with urlopen(request, timeout=5) as resp:  # noqa: S310 — cloud metadata endpoint URL
                data = json.loads(resp.read().decode())
        except (URLError, OSError, json.JSONDecodeError) as exc:
            raise IdentityError(
                f"Failed to acquire AWS credentials: {exc}"
            ) from exc

        token = data.get("Token") or data.get("AccessKeyId")
        if not token:
            raise IdentityError(
                "AWS metadata response did not contain credentials"
            )

        self._cache_token(scope, token, ttl=300)
        return token

    def validate_token(self, token: str) -> dict:
        """Structural validation for AWS tokens."""
        if not token or not isinstance(token, str):
            raise IdentityError("Token must be a non-empty string")
        return {
            "valid": True,
            "agent_did": self.agent_did,
            "provider": "aws",
            "role_arn": self.role_arn,
        }

    def get_agent_mapping(self) -> dict:
        mapping = super().get_agent_mapping()
        mapping["role_arn"] = self.role_arn
        mapping["provider"] = "aws_iam"
        return mapping


# ---------------------------------------------------------------------------
# GCP Workload Identity
# ---------------------------------------------------------------------------

class GCPWorkloadIdentity(ManagedIdentityAdapter):
    """GCP Workload Identity adapter using the GCE metadata server."""

    DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

    def __init__(
        self,
        agent_did: str,
        service_account: Optional[str] = None,
        *,
        metadata_url: str = _GCP_METADATA_URL,
    ) -> None:
        super().__init__(agent_did)
        self.service_account = service_account or "default"
        self._metadata_url = metadata_url

    def get_token(
        self, scope: str = DEFAULT_SCOPE
    ) -> str:
        """Acquire an access token from the GCE metadata server."""
        cached = self._get_cached_token(scope)
        if cached is not None:
            return cached

        url = (
            f"{self._metadata_url}/{self.service_account}"
            f"/token?scopes={scope}"
        )
        request = Request(url, headers={"Metadata-Flavor": "Google"})  # noqa: S310 — cloud metadata endpoint URL

        try:
            with urlopen(request, timeout=5) as resp:  # noqa: S310 — cloud metadata endpoint URL
                data = json.loads(resp.read().decode())
        except (URLError, OSError, json.JSONDecodeError) as exc:
            raise IdentityError(
                f"Failed to acquire GCP token for DID {self.agent_did}: {exc}"
            ) from exc

        token = data.get("access_token")
        if not token:
            raise IdentityError(
                "GCP metadata response did not contain an access_token"
            )

        expires_in = float(data.get("expires_in", 3600))
        self._cache_token(scope, token, ttl=max(expires_in - 30, 0))
        return token

    def validate_token(self, token: str) -> dict:
        """Structural validation for GCP tokens."""
        base = super().validate_token(token)
        base["provider"] = "gcp"
        base["service_account"] = self.service_account
        return base

    def get_agent_mapping(self) -> dict:
        mapping = super().get_agent_mapping()
        mapping["service_account"] = self.service_account
        mapping["provider"] = "gcp_workload_identity"
        return mapping

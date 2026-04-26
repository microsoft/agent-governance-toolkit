# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Native Entra Agent ID integration for AgentMesh.

Maps AGT agent identities (DIDs) to Microsoft Entra application
registrations or managed identities, enabling token acquisition
and validation using only the Python standard library.
"""

from __future__ import annotations

import base64
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class EntraAgentID:
    """Maps an AGT agent identity to a Microsoft Entra application/managed identity."""

    IMDS_URL = "http://169.254.169.254/metadata"
    IMDS_API_VERSION = "2021-02-01"
    IMDS_IDENTITY_VERSION = "2018-02-01"

    def __init__(self, agent_did: str, tenant_id: str, client_id: str) -> None:
        if not agent_did:
            raise ValueError("agent_did must not be empty")
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        if not client_id:
            raise ValueError("client_id must not be empty")
        self.agent_did = agent_did
        self.tenant_id = tenant_id
        self.client_id = client_id

    # -- factory methods -------------------------------------------------------

    @classmethod
    def from_managed_identity(cls, agent_did: str) -> "EntraAgentID":
        """Auto-discover from Azure IMDS (Instance Metadata Service)."""
        # Step 1: retrieve tenant ID from instance metadata
        instance_url = (
            f"{cls.IMDS_URL}/instance/compute"
            f"?api-version={cls.IMDS_API_VERSION}"
        )
        req = Request(instance_url, headers={"Metadata": "true"})  # noqa: S310 — Entra ID endpoint URL
        try:
            with urlopen(req, timeout=2) as resp:  # noqa: S310 — Entra ID endpoint URL
                compute = json.loads(resp.read().decode())
        except (URLError, HTTPError) as exc:
            raise RuntimeError(
                "Failed to contact Azure IMDS. "
                "Ensure code runs on an Azure resource with managed identity."
            ) from exc

        tenant_id = compute.get("tenantId", "")
        if not tenant_id:
            raise RuntimeError("Could not determine tenant ID from IMDS")

        # Step 2: acquire a bootstrap token and extract client_id (appid claim)
        token_url = (
            f"{cls.IMDS_URL}/identity/oauth2/token"
            f"?api-version={cls.IMDS_IDENTITY_VERSION}"
            f"&resource=https://management.azure.com/"
        )
        tok_req = Request(token_url, headers={"Metadata": "true"})  # noqa: S310 — Entra ID endpoint URL
        try:
            with urlopen(tok_req, timeout=5) as resp:  # noqa: S310 — Entra ID endpoint URL
                token_data = json.loads(resp.read().decode())
        except (URLError, HTTPError) as exc:
            raise RuntimeError(
                "Failed to acquire bootstrap token from IMDS"
            ) from exc

        access_token = token_data.get("access_token", "")
        claims = cls._decode_jwt_claims(access_token)
        client_id = claims.get("appid", claims.get("azp", ""))
        if not client_id:
            raise RuntimeError("Could not determine client_id from IMDS token")

        return cls(agent_did=agent_did, tenant_id=tenant_id, client_id=client_id)

    @classmethod
    def from_environment(cls, agent_did: str) -> "EntraAgentID":
        """Create from AZURE_TENANT_ID + AZURE_CLIENT_ID env vars."""
        tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        if not tenant_id:
            raise EnvironmentError(
                "AZURE_TENANT_ID environment variable is not set"
            )
        if not client_id:
            raise EnvironmentError(
                "AZURE_CLIENT_ID environment variable is not set"
            )
        return cls(agent_did=agent_did, tenant_id=tenant_id, client_id=client_id)

    # -- token operations ------------------------------------------------------

    def validate_token(self, token: str) -> dict:
        """Validate a JWT token issued by Entra ID for this agent.

        Performs structural and claim-level validation (expiry, issuer,
        audience).  Cryptographic signature verification requires the
        Entra JWKS and is intentionally left to callers with
        ``azure-identity`` or equivalent.
        """
        claims = self._decode_jwt_claims(token)

        # Expiry
        exp = claims.get("exp")
        if exp is not None and time.time() > float(exp):
            raise ValueError("Token has expired")

        # Not-before
        nbf = claims.get("nbf")
        if nbf is not None and time.time() < float(nbf):
            raise ValueError("Token is not yet valid")

        # Issuer — accept both v1 and v2 Entra endpoints
        iss = claims.get("iss", "")
        valid_issuers = (
            f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
            f"https://sts.windows.net/{self.tenant_id}/",
        )
        if iss not in valid_issuers:
            raise ValueError(
                f"Token issuer mismatch: got '{iss}', "
                f"expected tenant {self.tenant_id}"
            )

        # Audience
        aud = claims.get("aud", "")
        if isinstance(aud, list):
            if self.client_id not in aud:
                raise ValueError(
                    "Token audience does not include this agent's client_id"
                )
        elif aud != self.client_id:
            raise ValueError(
                "Token audience does not match this agent's client_id"
            )

        return claims

    def get_agent_token(
        self, scope: str = "https://governance.azure.com/.default"
    ) -> str:
        """Get a token for this agent using managed identity or client credentials."""
        resource = scope.replace("/.default", "")
        token_url = (
            f"{self.IMDS_URL}/identity/oauth2/token"
            f"?api-version={self.IMDS_IDENTITY_VERSION}"
            f"&resource={resource}"
            f"&client_id={self.client_id}"
        )
        req = Request(token_url, headers={"Metadata": "true"})  # noqa: S310 — Entra ID endpoint URL
        try:
            with urlopen(req, timeout=5) as resp:  # noqa: S310 — Entra ID endpoint URL
                data = json.loads(resp.read().decode())
            return data["access_token"]
        except (URLError, HTTPError, KeyError) as exc:
            raise RuntimeError(
                f"Failed to acquire token for scope '{scope}'. "
                "Ensure managed identity is configured or use azure-identity "
                "for client-credential flows."
            ) from exc

    # -- mapping ---------------------------------------------------------------

    def to_did_mapping(self) -> dict:
        """Return mapping between AGT DID and Entra object IDs."""
        return {
            "agent_did": self.agent_did,
            "entra": {
                "tenant_id": self.tenant_id,
                "client_id": self.client_id,
            },
            "mapping_version": "1.0",
        }

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _decode_jwt_claims(token: str) -> dict:
        """Decode the payload section of a JWT without signature verification."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT: expected 3 dot-separated parts")
        payload = parts[1]
        # Restore base64url padding
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    def __repr__(self) -> str:
        return (
            f"EntraAgentID(agent_did={self.agent_did!r}, "
            f"tenant_id={self.tenant_id!r}, client_id={self.client_id!r})"
        )

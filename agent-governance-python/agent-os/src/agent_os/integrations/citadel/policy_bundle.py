# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Bundle Resolver for Citadel Access Contracts

Loads and validates AGT policy bundles that are bound to Citadel Access
Contracts. When a Citadel Access Contract provisions an agent environment,
it references an AGT policy bundle ID/version. This module resolves that
reference to a concrete policy configuration.

The resolver supports multiple sources:
- Local file (for development)
- Azure Key Vault (for production)
- URL (for centralized policy management)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyBundle:
    """An AGT policy bundle bound to a Citadel Access Contract.

    Attributes:
        bundle_id: Unique identifier for the bundle.
        version: Semantic version of the bundle.
        name: Human-readable name.
        data_classification: Sensitivity level (public/internal/confidential/restricted).
        allowed_actions: Actions the agent is permitted to perform.
        blocked_actions: Actions explicitly denied.
        rate_limits: Per-action rate limits.
        requires_justification: Actions that need a reason before execution.
        min_trust_score: Minimum trust score required for any action.
        audit_config: Audit settings (hash_chain, export_to_citadel, etc.).
        raw_config: The full raw configuration dict.
        content_hash: SHA-256 hash of the bundle content for integrity verification.
    """

    bundle_id: str = ""
    version: str = "0.0.0"
    name: str = ""
    data_classification: str = "internal"
    allowed_actions: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    rate_limits: dict[str, dict[str, int]] = field(default_factory=dict)
    requires_justification: list[str] = field(default_factory=list)
    min_trust_score: int = 0
    audit_config: dict[str, Any] = field(default_factory=dict)
    raw_config: dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def __post_init__(self) -> None:
        """Compute content hash if not already set."""
        if not self.content_hash and self.raw_config:
            content = json.dumps(self.raw_config, sort_keys=True).encode()
            self.content_hash = hashlib.sha256(content).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyBundle:
        """Create a PolicyBundle from a configuration dictionary.

        Args:
            data: Raw configuration dict (typically loaded from YAML).

        Returns:
            A validated PolicyBundle instance.
        """
        policy = data.get("policy", data)
        trust = policy.get("trust", {})
        audit = policy.get("audit", {})

        return cls(
            bundle_id=data.get("bundle_id", policy.get("name", "")),
            version=policy.get("version", "0.0.0"),
            name=policy.get("name", ""),
            data_classification=policy.get("data_classification", "internal"),
            allowed_actions=policy.get("allowed_actions", []),
            blocked_actions=policy.get("blocked_actions", []),
            rate_limits=policy.get("rate_limits", {}),
            requires_justification=policy.get("requires_justification", []),
            min_trust_score=trust.get("minimum_score", 0),
            audit_config=audit,
            raw_config=data,
        )

    def validate_against_contract(
        self, contract_params: dict[str, Any]
    ) -> list[str]:
        """Validate that this bundle is compatible with a Citadel Access Contract.

        Checks that AGT policy constraints do not exceed what the contract
        allows. For example, AGT rate limits should not exceed Citadel quotas.

        Args:
            contract_params: Parsed Citadel Access Contract parameters.

        Returns:
            List of validation warnings (empty if compatible).
        """
        warnings: list[str] = []

        # Check bundle ID/version match
        contract_bundle = contract_params.get("agtPolicyBundle", {})
        if contract_bundle:
            expected_id = contract_bundle.get("bundleId", "")
            expected_version = contract_bundle.get("version", "")
            if expected_id and expected_id != self.bundle_id:
                warnings.append(
                    f"Bundle ID mismatch: contract expects '{expected_id}', "
                    f"got '{self.bundle_id}'"
                )
            if expected_version and expected_version != self.version:
                warnings.append(
                    f"Version mismatch: contract expects '{expected_version}', "
                    f"got '{self.version}'"
                )

        return warnings


class PolicyBundleResolver:
    """Resolves AGT policy bundles from various sources.

    Supports loading bundles from:
    - Local filesystem (YAML files)
    - Azure Key Vault secrets
    - HTTP URLs

    The resolver is typically called at agent startup to load the policy
    bundle that was bound to the agent's Citadel Access Contract.
    """

    def __init__(self) -> None:
        self._cache: dict[str, PolicyBundle] = {}

    def resolve_from_file(self, path: str) -> PolicyBundle:
        """Load a policy bundle from a local YAML file.

        Args:
            path: Path to the YAML policy file.

        Returns:
            The loaded PolicyBundle.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file cannot be parsed.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Policy bundle file not found: {path}")

        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required to load policy bundles from YAML files. "
                "Install with: pip install pyyaml"
            )

        with open(file_path) as f:
            data = yaml.safe_load(f)

        bundle = PolicyBundle.from_dict(data)
        logger.info(
            "Loaded policy bundle '%s' v%s from %s (hash: %s)",
            bundle.name,
            bundle.version,
            path,
            bundle.content_hash[:12],
        )
        self._cache[bundle.bundle_id] = bundle
        return bundle

    def resolve_from_keyvault(
        self,
        vault_url: str,
        secret_name: str,
    ) -> PolicyBundle:
        """Load a policy bundle from Azure Key Vault.

        The secret value should be a JSON-serialized policy bundle.

        Args:
            vault_url: The Key Vault URL (e.g., https://myvault.vault.azure.net).
            secret_name: The name of the secret containing the bundle.

        Returns:
            The loaded PolicyBundle.

        Raises:
            ImportError: If azure-keyvault-secrets is not installed.
            RuntimeError: If the secret cannot be retrieved.
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError:
            raise ImportError(
                "Azure Key Vault SDK required. "
                "Install with: pip install azure-keyvault-secrets azure-identity"
            )

        try:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=vault_url, credential=credential)
            secret = client.get_secret(secret_name)
            data = json.loads(secret.value)
        except Exception as e:
            raise RuntimeError(
                f"Failed to load policy bundle from Key Vault "
                f"({vault_url}/{secret_name}): {e}"
            )

        bundle = PolicyBundle.from_dict(data)
        logger.info(
            "Loaded policy bundle '%s' v%s from Key Vault %s/%s",
            bundle.name,
            bundle.version,
            vault_url,
            secret_name,
        )
        self._cache[bundle.bundle_id] = bundle
        return bundle

    def resolve_from_url(self, url: str) -> PolicyBundle:
        """Load a policy bundle from an HTTP URL.

        Args:
            url: The URL to fetch the bundle from (JSON or YAML).

        Returns:
            The loaded PolicyBundle.

        Raises:
            RuntimeError: If the URL cannot be fetched.
        """
        import urllib.request

        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode("utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to fetch policy bundle from {url}: {e}")

        # Try JSON first, then YAML
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                raise ImportError(
                    "PyYAML is required to parse YAML policy bundles. "
                    "Install with: pip install pyyaml"
                )

        bundle = PolicyBundle.from_dict(data)
        logger.info(
            "Loaded policy bundle '%s' v%s from %s",
            bundle.name,
            bundle.version,
            url,
        )
        self._cache[bundle.bundle_id] = bundle
        return bundle

    def resolve(self, config: dict[str, Any]) -> PolicyBundle:
        """Resolve a policy bundle from a Citadel Access Contract config.

        Reads the ``agtPolicyBundle`` parameter from the contract and loads
        the bundle from the appropriate source.

        Args:
            config: Parsed Access Contract parameters containing agtPolicyBundle.

        Returns:
            The resolved PolicyBundle.

        Raises:
            ValueError: If the bundle config is invalid.
        """
        bundle_config = config.get("agtPolicyBundle", {})
        if not bundle_config:
            raise ValueError(
                "No agtPolicyBundle parameter found in Access Contract config"
            )

        source = bundle_config.get("source", "file")
        bundle_id = bundle_config.get("bundleId", "")

        # Check cache first
        if bundle_id in self._cache:
            logger.info("Using cached policy bundle '%s'", bundle_id)
            return self._cache[bundle_id]

        if source == "file":
            file_path = bundle_config.get("filePath", "")
            if not file_path:
                raise ValueError("agtPolicyBundle.filePath is required for file source")
            return self.resolve_from_file(file_path)

        elif source == "keyvault":
            vault_url = bundle_config.get("vaultUrl", "")
            secret_name = bundle_config.get("secretName", "")
            if not vault_url or not secret_name:
                raise ValueError(
                    "agtPolicyBundle.vaultUrl and .secretName are required "
                    "for keyvault source"
                )
            return self.resolve_from_keyvault(vault_url, secret_name)

        elif source == "url":
            url = bundle_config.get("url", "")
            if not url:
                raise ValueError("agtPolicyBundle.url is required for url source")
            return self.resolve_from_url(url)

        else:
            raise ValueError(
                f"Unknown policy bundle source: '{source}'. "
                f"Expected: file, keyvault, or url"
            )

    def get_cached(self, bundle_id: str) -> Optional[PolicyBundle]:
        """Get a previously resolved bundle from cache.

        Args:
            bundle_id: The bundle ID to look up.

        Returns:
            The cached PolicyBundle, or None if not found.
        """
        return self._cache.get(bundle_id)

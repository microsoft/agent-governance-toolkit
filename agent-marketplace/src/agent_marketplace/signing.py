# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Signing & Verification

Ed25519-based signing and verification for AgentMesh plugin packages,
integrating with the existing identity/keystore infrastructure.
"""

from __future__ import annotations

import base64
import logging

from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_marketplace.manifest import MarketplaceError, PluginManifest

logger = logging.getLogger(__name__)


class PluginSigner:
    """Sign and verify plugin manifests using Ed25519 keys.

    Args:
        private_key: Ed25519 private key for signing operations.

    Example:
        >>> private_key = ed25519.Ed25519PrivateKey.generate()
        >>> signer = PluginSigner(private_key)
        >>> signed = signer.sign(manifest)
        >>> assert signed.signature is not None
    """

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        """Return the public key corresponding to the signing key."""
        return self._private_key.public_key()

    def sign(self, manifest: PluginManifest) -> PluginManifest:
        """Sign a plugin manifest in place.

        Args:
            manifest: Manifest to sign.

        Returns:
            A copy of the manifest with the ``signature`` field populated.
        """
        data = manifest.signable_bytes()
        sig = self._private_key.sign(data)
        signed = manifest.model_copy(update={"signature": base64.b64encode(sig).decode()})
        logger.info("Signed plugin %s@%s", manifest.name, manifest.version)
        return signed


def verify_signature(
    manifest: PluginManifest,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify the Ed25519 signature of a plugin manifest.

    Args:
        manifest: The manifest to verify (must include a ``signature``).
        public_key: The publisher's Ed25519 public key.

    Returns:
        ``True`` if the signature is valid.

    Raises:
        MarketplaceError: If the signature is missing or invalid.
    """
    if not manifest.signature:
        raise MarketplaceError("Manifest has no signature")
    try:
        sig_bytes = base64.b64decode(manifest.signature)
        data = manifest.signable_bytes()
        public_key.verify(sig_bytes, data)
        logger.info("Signature verified for %s@%s", manifest.name, manifest.version)
        return True
    except Exception as exc:
        raise MarketplaceError(f"Signature verification failed: {exc}") from exc

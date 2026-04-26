# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
``agentos sign`` — Sign and verify plugin manifests.

Wraps :class:`agentmesh.marketplace.signing.PluginSigner` for CLI use.

Usage::

    # Generate a signing keypair
    agentos sign keygen --out keys/

    # Sign a plugin manifest
    agentos sign plugin ./my-plugin/ --key keys/signing.key

    # Verify a signed manifest
    agentos sign verify ./my-plugin/ --pubkey keys/signing.pub
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.marketplace.manifest import MANIFEST_FILENAME, PluginManifest
from agentmesh.marketplace.signing import PluginSigner, verify_signature

logger = logging.getLogger(__name__)


def _load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SystemExit(f"Key at {path} is not Ed25519")
    return key


def _load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SystemExit(f"Key at {path} is not Ed25519")
    return key


def _load_manifest(plugin_dir: Path) -> PluginManifest:
    """Load agent-plugin.yaml from a plugin directory."""
    manifest_path = plugin_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        raise SystemExit(
            f"No {MANIFEST_FILENAME} found in {plugin_dir}. "
            "Run 'agentos sign init' in your plugin directory first."
        )
    import yaml

    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    return PluginManifest(**raw)


def _save_manifest(manifest: PluginManifest, plugin_dir: Path) -> None:
    """Write the signed manifest back to disk."""
    import yaml

    manifest_path = plugin_dir / MANIFEST_FILENAME
    data = json.loads(manifest.model_dump_json(exclude_none=True))
    manifest_path.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def cmd_sign_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 signing keypair."""
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = out_dir / "signing.key"
    pub_path = out_dir / "signing.pub"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o600)

    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Also output the public key fingerprint for easy identification
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = base64.b64encode(raw_pub).decode()[:16]

    print(f"✅ Keypair generated:")
    print(f"   Private key: {priv_path}")
    print(f"   Public key:  {pub_path}")
    print(f"   Fingerprint: {fingerprint}...")
    print()
    print(f"⚠️  Keep {priv_path} secret. Share {pub_path} with verifiers.")
    return 0


def cmd_sign_plugin(args: argparse.Namespace) -> int:
    """Sign a plugin's agent-plugin.yaml manifest."""
    plugin_dir = Path(args.plugin_dir)
    key_path = Path(args.key)

    if not key_path.exists():
        raise SystemExit(f"Private key not found: {key_path}")

    private_key = _load_private_key(key_path)
    manifest = _load_manifest(plugin_dir)
    signer = PluginSigner(private_key)
    signed = signer.sign(manifest)
    _save_manifest(signed, plugin_dir)

    print(f"✅ Signed {manifest.name}@{manifest.version}")
    print(f"   Manifest: {plugin_dir / MANIFEST_FILENAME}")
    print(f"   Signature: {signed.signature[:32]}...")
    return 0


def cmd_sign_verify(args: argparse.Namespace) -> int:
    """Verify a signed plugin manifest."""
    plugin_dir = Path(args.plugin_dir)
    pub_path = Path(args.pubkey)

    if not pub_path.exists():
        raise SystemExit(f"Public key not found: {pub_path}")

    public_key = _load_public_key(pub_path)
    manifest = _load_manifest(plugin_dir)

    try:
        verify_signature(manifest, public_key)
        print(f"✅ Signature valid: {manifest.name}@{manifest.version}")

        if args.json:
            result = {
                "valid": True,
                "plugin": manifest.name,
                "version": manifest.version,
                "author": manifest.author,
            }
            print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"❌ Signature invalid: {exc}", file=sys.stderr)
        if args.json:
            result = {"valid": False, "error": str(exc)}
            print(json.dumps(result, indent=2))
        return 1


def register_sign_subcommands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'sign' subcommand and its sub-subcommands on the main parser."""
    sign_parser = subparsers.add_parser(
        "sign",
        help="Sign and verify plugin manifests",
    )
    sign_sub = sign_parser.add_subparsers(dest="sign_command")

    # keygen
    keygen_p = sign_sub.add_parser("keygen", help="Generate Ed25519 signing keypair")
    keygen_p.add_argument(
        "--out", default=".", help="Output directory for keypair (default: current dir)"
    )

    # plugin (sign a manifest)
    plugin_p = sign_sub.add_parser("plugin", help="Sign a plugin manifest")
    plugin_p.add_argument("plugin_dir", help="Path to plugin directory")
    plugin_p.add_argument("--key", required=True, help="Path to Ed25519 private key (.key)")

    # verify
    verify_p = sign_sub.add_parser("verify", help="Verify a signed plugin manifest")
    verify_p.add_argument("plugin_dir", help="Path to plugin directory")
    verify_p.add_argument("--pubkey", required=True, help="Path to Ed25519 public key (.pub)")
    verify_p.add_argument("--json", action="store_true", help="Output in JSON format")


def cmd_sign(args: argparse.Namespace) -> int:
    """Route sign subcommands."""
    handlers = {
        "keygen": cmd_sign_keygen,
        "plugin": cmd_sign_plugin,
        "verify": cmd_sign_verify,
    }

    handler = handlers.get(args.sign_command)
    if handler is None:
        print("Usage: agentos sign {keygen|plugin|verify}")
        print()
        print("Commands:")
        print("  keygen   Generate Ed25519 signing keypair")
        print("  plugin   Sign a plugin manifest")
        print("  verify   Verify a signed plugin manifest")
        return 0

    return handler(args)

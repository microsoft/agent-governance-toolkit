# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Smoke tests for the agent-marketplace package."""

from __future__ import annotations

import pytest


def test_signable_bytes_is_canonical_json():
    """Regression: signable_bytes used to be yaml.dump(sort_keys=True),
    which is not stable across Python builds or PyYAML versions and
    embeds Python-specific tags. A signature produced on one machine
    could fail to verify on another even with identical manifest
    content. Use JSON with sort_keys / ascii / no-nan instead.
    """
    import json
    from agent_marketplace.manifest import PluginManifest, PluginType

    m = PluginManifest(
        name="x",
        version="1.0.0",
        plugin_type=PluginType.POLICY_TEMPLATE,
        author="a@example.com",
        description="desc",
    )
    encoded = m.signable_bytes()

    # Decodable as JSON (would NOT be true for yaml.dump output).
    decoded = json.loads(encoded.decode("ascii"))
    assert decoded["name"] == "x"
    assert decoded["version"] == "1.0.0"
    # signature field must be excluded.
    assert "signature" not in decoded


def test_signable_bytes_independent_of_field_order():
    """Two manifests with the same logical content but different
    Python field insertion order must produce byte-identical signable
    output. ``sort_keys=True`` is the load-bearing primitive.
    """
    from agent_marketplace.manifest import PluginManifest, PluginType

    a = PluginManifest(
        name="x",
        version="1.0.0",
        plugin_type=PluginType.POLICY_TEMPLATE,
        author="a@example.com",
        description="desc",
    )
    # Construct b via dict to vary insertion order; pydantic will
    # canonicalise it, and signable_bytes should produce the same
    # output as a.
    b = PluginManifest.model_validate({
        "description": "desc",
        "plugin_type": PluginType.POLICY_TEMPLATE.value,
        "version": "1.0.0",
        "author": "a@example.com",
        "name": "x",
    })
    assert a.signable_bytes() == b.signable_bytes()


def test_signable_bytes_omits_signature_field():
    """The signature field is set AFTER signing; it must not be part
    of the signable representation, or verification would have to
    strip it back out and bugs in that path would silently invalidate
    every signature.
    """
    from agent_marketplace.manifest import PluginManifest, PluginType

    m = PluginManifest(
        name="x",
        version="1.0.0",
        plugin_type=PluginType.POLICY_TEMPLATE,
        author="a@example.com",
        description="desc",
    )
    unsigned = m.signable_bytes()
    m.signature = "deadbeef" * 16
    signed = m.signable_bytes()
    assert unsigned == signed


def test_top_level_imports():
    """All public symbols are importable from the top-level package."""
    from agent_marketplace import (
        MANIFEST_FILENAME,
        MarketplaceError,
        PluginInstaller,
        PluginManifest,
        PluginRegistry,
        PluginSigner,
        PluginType,
        load_manifest,
        save_manifest,
        verify_signature,
    )
    assert MarketplaceError is not None
    assert callable(load_manifest)
    assert callable(save_manifest)
    assert callable(verify_signature)


def test_marketplace_error_standalone():
    """MarketplaceError no longer requires agentmesh."""
    from agent_marketplace.exceptions import MarketplaceError

    err = MarketplaceError("test error")
    assert str(err) == "test error"
    assert isinstance(err, Exception)


def test_backward_compat_shim():
    """Importing from agentmesh.marketplace still works."""
    from agentmesh.marketplace import PluginManifest, PluginRegistry

    assert PluginManifest is not None
    assert PluginRegistry is not None


def test_plugin_type_enum():
    from agent_marketplace import PluginType

    assert hasattr(PluginType, "POLICY_TEMPLATE")
    assert hasattr(PluginType, "INTEGRATION")
    assert hasattr(PluginType, "AGENT")
    assert hasattr(PluginType, "VALIDATOR")


class TestTrustedKeysImmutability:
    """Verify that PluginInstaller.trusted_keys is frozen at construction."""

    def test_trusted_keys_cannot_be_mutated(self, tmp_path):
        """Attempting to add a key after construction must raise TypeError."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from agent_marketplace import PluginInstaller, PluginRegistry

        registry = PluginRegistry()
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys={"author": ed25519.Ed25519PrivateKey.generate().public_key()},
        )
        with pytest.raises(TypeError):
            installer._trusted_keys["evil"] = "injected"  # type: ignore[index]

    def test_original_dict_mutation_does_not_affect_installer(self, tmp_path):
        """Mutating the original dict after construction must not change installer state."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from agent_marketplace import PluginInstaller, PluginRegistry

        registry = PluginRegistry()
        original = {"author": ed25519.Ed25519PrivateKey.generate().public_key()}
        installer = PluginInstaller(
            plugins_dir=tmp_path / "plugins",
            registry=registry,
            trusted_keys=original,
        )
        original["evil"] = "injected"
        assert "evil" not in installer._trusted_keys


# ---------------------------------------------------------------------------
# Version-validator and registry-sort regression tests
# ---------------------------------------------------------------------------
#
# `PluginManifest.validate_version` previously used `part.isdigit()` which
# returns True for many Unicode digit-like characters that `int()` cannot
# parse — superscripts, circled numerals, etc. A version like "1.0.²" passed
# the validator and then crashed `_semver_tuple` on every registry sort,
# DoSing every consumer of `get_plugin`, `search`, or `list_plugins`.
# Tightening the validator to ASCII-only digits closes the bypass; making
# `_semver_tuple` defensive ensures a tampered storage file can never crash
# the registry.


from agent_marketplace.manifest import (  # noqa: E402
    MarketplaceError,
    PluginManifest,
    PluginType,
)
from agent_marketplace.registry import _semver_tuple  # noqa: E402


class TestVersionValidatorRejectsUnicodeDigits:
    """isdigit() lets through values int() cannot parse; the validator
    must use an ASCII-only check to keep registry sorts safe."""

    @pytest.mark.parametrize(
        "bad_version",
        [
            "1.0.²",         # superscript 2 — isdigit() True, int() fails
            "1.0.⒈",         # digit-one-full-stop — same
            "1.0.⓵",         # circled digit one — same
            "¹.0.0",         # superscript in major
            "1.²⁰.0",        # superscripts in minor
        ],
    )
    def test_unicode_digit_components_rejected(self, bad_version: str):
        with pytest.raises(MarketplaceError, match="Invalid version"):
            PluginManifest(
                name="test",
                version=bad_version,
                description="x",
                author="alice",
                plugin_type=PluginType.INTEGRATION,
            )

    def test_legitimate_ascii_versions_still_accepted(self):
        for good_version in ("1.0.0", "0.1.2", "10.20.30", "1.0", "999.999.999"):
            m = PluginManifest(
                name="test",
                version=good_version,
                description="x",
                author="alice",
                plugin_type=PluginType.INTEGRATION,
            )
            assert m.version == good_version

    def test_empty_component_rejected(self):
        with pytest.raises(MarketplaceError, match="Invalid version"):
            PluginManifest(
                name="test",
                version="1..0",
                description="x",
                author="alice",
                plugin_type=PluginType.INTEGRATION,
            )

    def test_signed_or_hex_components_rejected(self):
        for bad in ("1.-1.0", "1.+1.0", "1.0x1.0"):
            with pytest.raises(MarketplaceError, match="Invalid version"):
                PluginManifest(
                    name="test",
                    version=bad,
                    description="x",
                    author="alice",
                    plugin_type=PluginType.INTEGRATION,
                )


class TestSemverTupleDefensive:
    """_semver_tuple must never crash, even on values that slipped past
    the validator (e.g. via a tampered storage file or a future schema
    change)."""

    def test_well_formed_version_parses(self):
        assert _semver_tuple("1.2.3") == (1, 2, 3)
        assert _semver_tuple("0.0.1") == (0, 0, 1)
        assert _semver_tuple("10.20") == (10, 20)

    def test_unicode_digit_falls_back_to_zero_tuple(self):
        # "1.0.²" — passed the old isdigit() validator pre-fix and would
        # raise ValueError under int(); under the defensive helper it
        # sorts as (0,) and the registry stays operational.
        assert _semver_tuple("1.0.²") == (0,)

    def test_garbage_version_falls_back_to_zero_tuple(self):
        for garbage in ("not-a-version", "1.x.0", "abc", "", "1.0.0-rc1"):
            assert _semver_tuple(garbage) == (0,)

    def test_max_over_mixed_versions_does_not_crash(self):
        # Simulates `get_plugin(name)` against a registry whose storage
        # contains one tampered version. Pre-fix this raised; post-fix
        # the legitimate "1.0.0" wins.
        versions = ["1.0.0", "0.5.0", "1.0.²"]
        latest = max(versions, key=_semver_tuple)
        assert latest == "1.0.0"

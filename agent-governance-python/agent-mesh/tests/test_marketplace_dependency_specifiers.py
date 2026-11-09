# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Dependency specifier parsing in the agentmesh marketplace fallbacks.

``agentmesh.marketplace`` re-exports ``agent_marketplace`` when it is
installed and otherwise falls back to ``_marketplace_impl``; the
``installer`` module is a second standalone copy. Both must parse plugin
dependency specifiers the way ``agent_marketplace`` does, so these tests
import the fallback modules directly instead of going through the shim.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentmesh.marketplace import _marketplace_impl
from agentmesh.marketplace import installer as installer_module
from agentmesh.marketplace import manifest as manifest_module
from agentmesh.marketplace import registry as registry_module
from agentmesh.marketplace import signing as signing_module

PARSERS = [
    pytest.param(installer_module._parse_dependency, id="installer"),
    pytest.param(_marketplace_impl._parse_dependency, id="marketplace_impl"),
]


@pytest.mark.parametrize("parse", PARSERS)
@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("plugin-name", ("plugin-name", None)),
        ("plugin-name==1.2.3", ("plugin-name", "1.2.3")),
        ("plugin-name == 1.2.3", ("plugin-name", "1.2.3")),
        ("plugin-name>=1.0", ("plugin-name", None)),
        ("plugin-name>=1.0,<2.0", ("plugin-name", None)),
        ("plugin-name>=1.0,==1.5", ("plugin-name", "1.5")),
        ("plugin-name<=2.0", ("plugin-name", None)),
        ("plugin-name!=1.0", ("plugin-name", None)),
        ("plugin-name~=1.0", ("plugin-name", None)),
        ("plugin-name===1.0", ("plugin-name", None)),
        ("plugin-name[extra]>=1.0", ("plugin-name", None)),
        ('plugin-name>=1.0; python_version >= "3.11"', ("plugin-name", None)),
    ],
)
def test_parse_dependency(parse, spec: str, expected: tuple[str, str | None]) -> None:
    assert parse(spec) == expected


def _install_with_dependency(
    module: ModuleType,
    *,
    manifest_cls: type,
    registry_cls: type,
    signer_cls: type,
    installer_cls: type,
    plugins_dir: Path,
    dep_spec: str,
) -> str:
    private_key = ed25519.Ed25519PrivateKey.generate()
    signer = signer_cls(private_key)
    registry = registry_cls()

    def manifest(name: str, version: str, dependencies: list[str]) -> object:
        return signer.sign(
            manifest_cls(
                name=name,
                version=version,
                description=f"{name} plugin",
                author="tester@example.com",
                plugin_type=module.PluginType.INTEGRATION,
                dependencies=dependencies,
            )
        )

    for version in ("1.0.0", "1.5.0", "2.0.0"):
        registry.register(manifest("dep-plugin", version, []))
    registry.register(manifest("main-plugin", "1.0.0", [dep_spec]))
    installer = installer_cls(
        plugins_dir=plugins_dir,
        registry=registry,
        trusted_keys={"tester@example.com": private_key.public_key()},
    )
    installer.install("main-plugin")
    return {p.name: p.version for p in installer.list_installed()}["dep-plugin"]


INSTALLERS = [
    pytest.param(
        {
            "module": manifest_module,
            "manifest_cls": manifest_module.PluginManifest,
            "registry_cls": registry_module.PluginRegistry,
            "signer_cls": signing_module.PluginSigner,
            "installer_cls": installer_module.PluginInstaller,
        },
        id="installer",
    ),
    pytest.param(
        {
            "module": _marketplace_impl,
            "manifest_cls": _marketplace_impl.PluginManifest,
            "registry_cls": _marketplace_impl.PluginRegistry,
            "signer_cls": _marketplace_impl.PluginSigner,
            "installer_cls": _marketplace_impl.PluginInstaller,
        },
        id="marketplace_impl",
    ),
]


@pytest.mark.parametrize("parts", INSTALLERS)
@pytest.mark.parametrize(
    ("dep_spec", "expected_version"),
    [
        ("dep-plugin>=1.0.0", "2.0.0"),
        ("dep-plugin~=1.0", "2.0.0"),
        ("dep-plugin!=1.5.0", "2.0.0"),
        ("dep-plugin>=1.0.0,==1.5.0", "1.5.0"),
    ],
)
def test_install_resolves_dependency_specifiers(
    tmp_path: Path, parts: dict[str, object], dep_spec: str, expected_version: str
) -> None:
    installed = _install_with_dependency(
        plugins_dir=tmp_path / "plugins", dep_spec=dep_spec, **parts
    )
    assert installed == expected_version

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Guard the ACS core shim's crates.io identity after the retarget.

``0.3.1-beta.0`` is already the pre-retarget embedded engine on crates.io.
Publishing the compatibility shim under that version would collide with a
different artifact. The shim's ``#[deprecated(since = "0.3.2-beta.0")]``
attributes name the intended next identity. Consumer lockfiles must record
this path crate, not the published cedar-policy/ureq engine.

These checks are the runnable equivalent of
``policy-engine/core/tests/crate_version.rs`` on toolchains that cannot
compile the crate (``rust-version = "1.85"``).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
COLLIDING_VERSION = "0.3.1-beta.0"
SHIM_VERSION = "0.3.2-beta.0"
CORE_PACKAGE = "agent_control_specification_core"
CONSUMER_LOCKFILES = (
    "policy-engine/Cargo.lock",
    "agent-governance-rust/Cargo.lock",
    "policy-engine/examples/coding_agent/app/Cargo.lock",
    "benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.lock",
)
SHIM_SOURCES = (
    "policy-engine/core/src/lib.rs",
    "policy-engine/core/src/identity.rs",
)
DEPRECATED_SINCE = f'since = "{SHIM_VERSION}"'


def _package_stanzas(lockfile: str, package: str) -> list[str]:
    header = f'name = "{package}"\n'
    stanzas: list[str] = []
    start = 0
    while True:
        found = lockfile.find(header, start)
        if found == -1:
            return stanzas
        rest = lockfile[found:]
        end = rest.find("\n[[package]]")
        stanzas.append(rest if end == -1 else rest[:end])
        start = found + len(header)


def test_core_shim_version_does_not_collide_with_published_embedded_engine() -> None:
    cargo = tomllib.loads(
        (REPO_ROOT / "policy-engine/core/Cargo.toml").read_text(encoding="utf-8")
    )["package"]
    assert cargo["name"] == CORE_PACKAGE
    assert cargo["version"] != COLLIDING_VERSION
    assert cargo["version"] == SHIM_VERSION


def test_sdk_and_deprecation_attrs_name_the_shim_version() -> None:
    sdk = (REPO_ROOT / "policy-engine/sdk/rust/Cargo.toml").read_text(encoding="utf-8")
    assert (
        f'{CORE_PACKAGE} = {{ version = "={SHIM_VERSION}", path = "../../core"' in sdk
    )
    assert f'version = "={COLLIDING_VERSION}"' not in sdk

    rust_test = (REPO_ROOT / "policy-engine/core/tests/crate_version.rs").read_text(
        encoding="utf-8"
    )
    assert f'const COLLIDING_VERSION: &str = "{COLLIDING_VERSION}";' in rust_test
    assert f'const SHIM_VERSION: &str = "{SHIM_VERSION}";' in rust_test

    for rel in SHIM_SOURCES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert DEPRECATED_SINCE in text, rel
        assert f'since = "{COLLIDING_VERSION}"' not in text, rel
        assert len(re.findall(r"since = \"[^\"]+\"", text)) == text.count(
            DEPRECATED_SINCE
        ), rel


def test_consumer_lockfiles_record_the_path_shim_not_the_published_engine() -> None:
    for rel in CONSUMER_LOCKFILES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        stanzas = _package_stanzas(text, CORE_PACKAGE)
        assert len(stanzas) == 1, f"{rel} must lock exactly one {CORE_PACKAGE}"
        stanza = stanzas[0]
        assert f'version = "{SHIM_VERSION}"' in stanza, rel
        assert f'version = "{COLLIDING_VERSION}"' not in stanza, rel
        assert "agent-control-spec" in stanza, rel
        assert "cedar-policy" not in stanza, rel
        assert "source =" not in stanza, f"{rel} must record the path crate, not crates.io"

#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Synchronise every package manifest in the repo to the version in ./VERSION.

Usage:
    python scripts/sync-version.py          # apply the version from VERSION
    python scripts/sync-version.py --check  # exit non-zero if any file differs
    python scripts/sync-version.py 3.5.0    # override: set everything to 3.5.0

Supported manifest types:
    - Python   pyproject.toml   [project].version
    - Node     package.json     top-level "version"
    - Rust     Cargo.toml       [workspace.package].version
    - .NET     Directory.Build.props  <Version> property
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO_ROOT / "VERSION"

# Directories to skip during recursive traversal
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".hypothesis",
    ".tox", "egg-info",
}


def read_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def find_files(name: str, root: Path | None = None) -> list[Path]:
    """Recursively find files by name, skipping junk directories."""
    results: list[Path] = []
    for p in (root or REPO_ROOT).rglob(name):
        if any(skip in p.parts for skip in SKIP_DIRS):
            continue
        results.append(p)
    return sorted(results)


# --- Python pyproject.toml ---------------------------------------------------

_TOML_VERSION_RE = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)


def sync_pyproject(path: Path, version: str, check: bool) -> bool:
    """Update [project].version in a pyproject.toml file."""
    text = path.read_text(encoding="utf-8")
    m = _TOML_VERSION_RE.search(text)
    if not m:
        return True
    current = text[m.start():m.end()]
    expected = f'{m.group(1)}"{version}"'
    if current == expected:
        return True
    if check:
        print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (has {current})")
        return False
    new_text = text[:m.start()] + expected + text[m.end():]
    path.write_text(new_text, encoding="utf-8")
    print(f"  UPDATED {path.relative_to(REPO_ROOT)}")
    return True


# --- Node package.json -------------------------------------------------------

def sync_package_json(path: Path, version: str, check: bool) -> bool:
    """Update the top-level 'version' key in a package.json file."""
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if data.get("version") == version:
        return True
    if check:
        print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (has {data.get('version')})")
        return False
    data["version"] = version
    # Preserve original indent (detect from first line)
    indent = 2
    for line in text.splitlines()[1:3]:
        stripped = line.lstrip()
        if stripped:
            indent = len(line) - len(stripped)
            break
    path.write_text(
        json.dumps(data, indent=indent, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"  UPDATED {path.relative_to(REPO_ROOT)}")
    return True


# --- Rust Cargo.toml (workspace only) ----------------------------------------

_CARGO_WS_VERSION_RE = re.compile(
    r'^(version\s*=\s*)"[^"]*"',
    re.MULTILINE,
)


def sync_cargo_workspace(path: Path, version: str, check: bool) -> bool:
    """Update [workspace.package].version in the root Cargo.toml."""
    text = path.read_text(encoding="utf-8")
    # Only update the workspace-level version (appears after [workspace.package])
    ws_match = re.search(r'\[workspace\.package\]', text)
    if not ws_match:
        return True
    section_text = text[ws_match.end():]
    m = _CARGO_WS_VERSION_RE.search(section_text)
    if not m:
        return True
    abs_start = ws_match.end() + m.start()
    abs_end = ws_match.end() + m.end()
    current = text[abs_start:abs_end]
    expected = f'{m.group(1)}"{version}"'
    if current == expected:
        return True
    if check:
        print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (has {current})")
        return False
    new_text = text[:abs_start] + expected + text[abs_end:]
    path.write_text(new_text, encoding="utf-8")
    print(f"  UPDATED {path.relative_to(REPO_ROOT)}")
    return True


# --- .NET Directory.Build.props -----------------------------------------------

_DOTNET_VERSION_RE = re.compile(r'<Version>[^<]*</Version>')


def sync_dotnet_props(path: Path, version: str, check: bool) -> bool:
    """Ensure <Version> is set in Directory.Build.props."""
    text = path.read_text(encoding="utf-8")
    expected_tag = f"<Version>{version}</Version>"

    m = _DOTNET_VERSION_RE.search(text)
    if m:
        if m.group(0) == expected_tag:
            return True
        if check:
            print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (has {m.group(0)})")
            return False
        new_text = text[:m.start()] + expected_tag + text[m.end():]
        path.write_text(new_text, encoding="utf-8")
        print(f"  UPDATED {path.relative_to(REPO_ROOT)}")
        return True

    # <Version> not present yet: insert after first <PropertyGroup>
    if check:
        print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (no <Version> tag)")
        return False
    insert_after = "<PropertyGroup>"
    idx = text.find(insert_after)
    if idx == -1:
        print(f"  SKIP {path.relative_to(REPO_ROOT)}  (no <PropertyGroup> found)")
        return True
    insert_pos = idx + len(insert_after)
    indent = "\n    "
    new_text = text[:insert_pos] + f"{indent}{expected_tag}" + text[insert_pos:]
    path.write_text(new_text, encoding="utf-8")
    print(f"  UPDATED {path.relative_to(REPO_ROOT)}  (added <Version>)")
    return True


# --- .NET .csproj: remove individual <Version> tags --------------------------

def strip_csproj_version(path: Path, check: bool) -> bool:
    """Remove <Version> from individual .csproj files (they inherit from props)."""
    text = path.read_text(encoding="utf-8")
    m = _DOTNET_VERSION_RE.search(text)
    if not m:
        return True
    if check:
        print(f"  DRIFT {path.relative_to(REPO_ROOT)}  (has individual {m.group(0)})")
        return False
    # Remove the entire line containing <Version>
    lines = text.splitlines(keepends=True)
    new_lines = [ln for ln in lines if "<Version>" not in ln or "</Version>" not in ln]
    path.write_text("".join(new_lines), encoding="utf-8")
    print(f"  UPDATED {path.relative_to(REPO_ROOT)}  (removed individual <Version>)")
    return True


# --- Main ---------------------------------------------------------------------

def main() -> int:
    check = "--check" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--check"]

    if args:
        version = args[0]
        VERSION_FILE.write_text(version + "\n", encoding="utf-8")
        print(f"VERSION file set to {version}")
    else:
        version = read_version()

    mode = "CHECK" if check else "SYNC"
    print(f"\n=== {mode} all packages to version {version} ===\n")

    ok = True

    # Python
    print("Python (pyproject.toml):")
    for p in find_files("pyproject.toml"):
        ok &= sync_pyproject(p, version, check)

    # Node / TypeScript
    print("\nNode/TypeScript (package.json):")
    for p in find_files("package.json"):
        ok &= sync_package_json(p, version, check)

    # Rust
    print("\nRust (Cargo.toml workspace):")
    rust_root = REPO_ROOT / "agent-governance-rust" / "Cargo.toml"
    if rust_root.exists():
        ok &= sync_cargo_workspace(rust_root, version, check)

    # .NET
    print("\n.NET (Directory.Build.props):")
    dotnet_props = REPO_ROOT / "agent-governance-dotnet" / "Directory.Build.props"
    if dotnet_props.exists():
        ok &= sync_dotnet_props(dotnet_props, version, check)

    # Remove individual <Version> from SDK .csproj files
    print("\n.NET (remove individual <Version> from SDK .csproj):")
    sdk_src = REPO_ROOT / "agent-governance-dotnet" / "src"
    if sdk_src.exists():
        for p in find_files("*.csproj", sdk_src):
            ok &= strip_csproj_version(p, check)

    print()
    if not ok:
        print("FAIL: version drift detected. Run `python scripts/sync-version.py` to fix.")
        return 1
    print(f"OK: all packages are at version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

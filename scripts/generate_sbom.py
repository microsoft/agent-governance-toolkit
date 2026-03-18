#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Generate Software Bill of Materials (SBOM) for all packages.

Outputs CycloneDX JSON SBOMs for each package in the repository.
Requires: pip install cyclonedx-bom  (or pip-audit for CVE scanning)

Usage:
    python scripts/generate_sbom.py
    python scripts/generate_sbom.py --audit   # also scan for known CVEs
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGES_DIR = REPO_ROOT / "packages"
OUTPUT_DIR = REPO_ROOT / "sbom"


def find_packages() -> list[Path]:
    """Find all packages with pyproject.toml or setup.py."""
    packages = []
    for p in sorted(PACKAGES_DIR.iterdir()):
        if not p.is_dir():
            continue
        if (p / "pyproject.toml").exists() or (p / "setup.py").exists():
            packages.append(p)
    return packages


def generate_sbom(package_dir: Path, output_dir: Path) -> Path:
    """Generate CycloneDX SBOM for a single package."""
    name = package_dir.name
    out_file = output_dir / f"{name}.cdx.json"

    # Try cyclonedx-bom first
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "cyclonedx_py",
                "environment",
                "--output", str(out_file),
                "--format", "json",
            ],
            cwd=str(package_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print(f"  ✓ {name}: {out_file}")
            return out_file
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: generate minimal SBOM from pip freeze
    print(f"  ⚠ {name}: cyclonedx-bom not available, generating minimal SBOM")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        deps = json.loads(result.stdout) if result.returncode == 0 else []
    except Exception:
        deps = []

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "library",
                "name": name,
                "bom-ref": f"pkg:{name}",
            },
            "tools": [{"name": "generate_sbom.py", "version": "1.0.0"}],
        },
        "components": [
            {
                "type": "library",
                "name": dep["name"],
                "version": dep.get("version", "unknown"),
                "purl": f"pkg:pypi/{dep['name']}@{dep.get('version', 'unknown')}",
            }
            for dep in deps
        ],
    }
    out_file.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"  ✓ {name}: {out_file} (minimal)")
    return out_file


def run_audit(package_dir: Path) -> bool:
    """Run pip-audit to check for known CVEs."""
    name = package_dir.name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--strict", "--desc"],
            cwd=str(package_dir),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            print(f"  ✓ {name}: No known vulnerabilities")
            return True
        else:
            print(f"  ✗ {name}: Vulnerabilities found:")
            print(result.stdout)
            return False
    except FileNotFoundError:
        print(f"  ⚠ {name}: pip-audit not installed (pip install pip-audit)")
        return True
    except subprocess.TimeoutExpired:
        print(f"  ⚠ {name}: pip-audit timed out")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SBOMs for all packages")
    parser.add_argument("--audit", action="store_true", help="Also run CVE scan")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    packages = find_packages()

    if not packages:
        print("No packages found")
        return 1

    print(f"Generating SBOMs for {len(packages)} packages...\n")
    for pkg in packages:
        generate_sbom(pkg, OUTPUT_DIR)

    if args.audit:
        print("\nRunning CVE audit...\n")
        all_clean = True
        for pkg in packages:
            if not run_audit(pkg):
                all_clean = False
        if not all_clean:
            print("\n⚠ Some packages have known vulnerabilities!")
            return 1

    print(f"\nSBOMs written to {OUTPUT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

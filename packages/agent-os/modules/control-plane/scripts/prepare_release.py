#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Release preparation script for Agent Control Plane

This script helps prepare a new release by:
1. Validating version consistency across files
2. Running tests and checks
3. Building the package
4. Creating the git tag

Usage:
    python scripts/prepare_release.py --version 1.2.0
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description, check=True):
    """Run a shell command and handle errors"""
    print(f"\n{'='*60}")
    print(f"📋 {description}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    if check and result.returncode != 0:
        print(f"❌ Failed: {description}")
        sys.exit(1)
    
    print(f"✅ Completed: {description}")
    return result


def validate_version_format(version):
    """Validate semantic version format"""
    pattern = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$'
    if not re.match(pattern, version):
        print(f"❌ Invalid version format: {version}")
        print("   Expected format: MAJOR.MINOR.PATCH (e.g., 1.2.0)")
        sys.exit(1)


def check_version_in_file(file_path, version, pattern):
    """Check if version is present in a file"""
    content = Path(file_path).read_text()
    if version not in content:
        print(f"❌ Version {version} not found in {file_path}")
        print(f"   Please update the version using pattern: {pattern}")
        return False
    print(f"✅ Version {version} found in {file_path}")
    return True


def check_changelog(version):
    """Check if CHANGELOG.md has an entry for this version"""
    changelog = Path("CHANGELOG.md").read_text()
    version_header = f"## [{version}]"
    if version_header not in changelog:
        print(f"❌ CHANGELOG.md missing entry for version {version}")
        print(f"   Please add a section: {version_header} - YYYY-MM-DD")
        return False
    print(f"✅ CHANGELOG.md has entry for version {version}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Prepare a new release")
    parser.add_argument("--version", required=True, help="Version to release (e.g., 1.2.0)")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--dry-run", action="store_true", help="Don't create git tag")
    args = parser.parse_args()
    
    version = args.version
    validate_version_format(version)
    
    print(f"\n🚀 Preparing release for version {version}\n")
    
    # Check version consistency
    print("Step 1: Checking version consistency...")
    checks_passed = True
    checks_passed &= check_version_in_file("pyproject.toml", version, 'version = "X.Y.Z"')
    checks_passed &= check_version_in_file("setup.py", version, 'version="X.Y.Z"')
    checks_passed &= check_changelog(version)
    
    if not checks_passed:
        print("\n❌ Version checks failed. Please fix the issues above.")
        sys.exit(1)
    
    print("\n✅ All version checks passed!")
    
    # Run tests
    if not args.skip_tests:
        print("\nStep 2: Running tests...")
        run_command(
            "python -m unittest discover -s tests -p 'test_*.py' -v",
            "Running test suite"
        )
    else:
        print("\nStep 2: Skipping tests (--skip-tests flag)")
    
    # Run linting
    print("\nStep 3: Running linting...")
    run_command(
        "flake8 src/ --count --select=E9,F63,F7,F82 --show-source --statistics",
        "Linting code for critical errors",
        check=False  # Don't fail on linting errors
    )
    
    # Clean previous builds
    print("\nStep 4: Cleaning previous builds...")
    run_command("rm -rf dist/ build/ *.egg-info", "Cleaning build artifacts")
    
    # Build package
    print("\nStep 5: Building package...")
    run_command("pip install --upgrade build twine", "Installing build tools")
    run_command("python -m build", "Building distribution packages")
    run_command("twine check dist/*", "Checking package metadata")
    
    # Create git tag
    if not args.dry_run:
        print("\nStep 6: Creating git tag...")
        tag_name = f"v{version}"
        
        # Check if tag already exists
        result = subprocess.run(
            f"git tag -l {tag_name}",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip():
            print(f"⚠️  Tag {tag_name} already exists. Skipping tag creation.")
        else:
            run_command(
                f'git tag -a {tag_name} -m "Release version {version}"',
                f"Creating git tag {tag_name}"
            )
            print(f"\n📌 Tag {tag_name} created successfully!")
            print(f"\nTo push the tag and trigger the release:")
            print(f"   git push origin {tag_name}")
    else:
        print("\nStep 6: Skipping git tag creation (--dry-run mode)")
    
    # Summary
    print("\n" + "="*60)
    print("✅ Release preparation complete!")
    print("="*60)
    print(f"\nVersion: {version}")
    print(f"Tag: v{version}")
    print("\nNext steps:")
    if not args.dry_run:
        print("1. Push the tag to trigger the release workflow:")
        print(f"   git push origin v{version}")
    else:
        print("1. Create and push the tag:")
        print(f"   git tag -a v{version} -m 'Release version {version}'")
        print(f"   git push origin v{version}")
    print("2. Monitor GitHub Actions for release creation")
    print("3. Verify the release on GitHub and PyPI")
    print("4. Announce in GitHub Discussions")
    print("\nRelease URLs:")
    print(f"- GitHub: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v{version}")
    print(f"- PyPI: https://pypi.org/project/agent-control-plane/{version}/")


if __name__ == "__main__":
    main()

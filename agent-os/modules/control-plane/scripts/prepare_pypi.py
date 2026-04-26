#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Setup script for PyPI package preparation

This script prepares the Agent Control Plane package for PyPI release.
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and report results"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(e.stderr)
        return False


def main():
    """Prepare package for PyPI release"""
    print("=" * 70)
    print("Agent Control Plane - PyPI Release Preparation")
    print("=" * 70)
    
    print("\nNext steps for PyPI release:")
    print("1. Review dist/ files after build")
    print("2. Test locally: pip install dist/*.whl")
    print("3. Upload to Test PyPI: python -m twine upload --repository testpypi dist/*")
    print("4. Upload to PyPI: python -m twine upload dist/*")


if __name__ == "__main__":
    main()

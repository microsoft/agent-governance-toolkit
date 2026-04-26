#!/bin/bash
# Build and publish script for SCAK PyPI package
# This script helps prepare the package for PyPI publication
# For Windows users, use build_and_publish.ps1 instead

set -e  # Exit on error

echo "======================================"
echo "SCAK Package Build & Publish Script"
echo "======================================"
echo ""

# Check if we're in the right directory
if [ ! -f "setup.py" ]; then
    echo "Error: setup.py not found. Run this script from the repository root."
    exit 1
fi

# Clean previous builds
echo "1. Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info
echo "   ✓ Cleaned"
echo ""

# Install build dependencies
echo "2. Installing build dependencies..."
pip install --no-cache-dir --upgrade "build==1.2.2" "twine==6.0.1"
echo "   ✓ Dependencies installed"
echo ""

# Build the package
echo "3. Building package..."
python -m build
echo "   ✓ Package built successfully"
echo ""

# Check the distribution
echo "4. Checking package with twine..."
python -m twine check dist/*
echo "   ✓ Package check passed"
echo ""

# Display package info
echo "5. Package information:"
echo "   Contents of dist/:"
ls -lh dist/
echo ""

# Instructions for publishing
echo "======================================"
echo "Package is ready for publication!"
echo "======================================"
echo ""
echo "To test on TestPyPI:"
echo "  python -m twine upload --repository testpypi dist/*"
echo ""
echo "To publish to PyPI (using .pypirc):"
echo "  python -m twine upload --config-file .pypirc dist/*"
echo ""
echo "To publish to PyPI (using environment variables):"
echo "  export TWINE_USERNAME=__token__"
echo "  export TWINE_PASSWORD=<your-pypi-token>"
echo "  python -m twine upload dist/*"
echo ""
echo "To install locally and test:"
echo "  pip install dist/*.whl"
echo ""
echo "To verify installation:"
echo "  python -c \"from agent_kernel import SelfCorrectingKernel; print('Success!')\""
echo ""
echo "To create git tags:"
echo "  git tag -a v1.1.0 -m 'Release v1.1.0 - Production features'"
echo "  git push origin --tags"
echo ""

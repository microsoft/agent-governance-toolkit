#!/bin/bash
#
# Build and Publish Script for Agent Control Plane
# Usage:
#   ./build_and_publish.sh         - Build only
#   ./build_and_publish.sh test    - Build and upload to Test PyPI
#   ./build_and_publish.sh prod    - Build and upload to PyPI
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}   Agent Control Plane - Build and Publish Script${NC}"
echo -e "${BLUE}=====================================================================${NC}"

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

# Check for required tools
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

# Find Python executable (check venv first, then system)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
if [ -f "$SCRIPT_DIR/../.venv/Scripts/python.exe" ]; then
    PYTHON="$SCRIPT_DIR/../.venv/Scripts/python.exe"
elif [ -f ".venv/Scripts/python.exe" ]; then
    PYTHON=".venv/Scripts/python.exe"
elif [ -f ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
elif command -v python3 &> /dev/null; then
    PYTHON="python3"
elif command -v python &> /dev/null; then
    PYTHON="python"
else
    print_error "Python is not installed"
    exit 1
fi
print_status "Python found: $($PYTHON --version)"

# Ensure pip is up to date
$PYTHON -m pip install --upgrade pip --quiet

# Install build tools if not present
echo -e "\n${YELLOW}Installing/updating build tools...${NC}"
$PYTHON -m pip install --upgrade build twine --quiet
print_status "Build tools installed (build, twine)"

# Clean previous builds
echo -e "\n${YELLOW}Cleaning previous builds...${NC}"
rm -rf dist/ build/ *.egg-info src/*.egg-info
print_status "Cleaned dist/, build/, and egg-info directories"

# Build the package
echo -e "\n${YELLOW}Building package...${NC}"
$PYTHON -m build

if [ -d "dist" ]; then
    print_status "Package built successfully"
    echo -e "\n${BLUE}Built files:${NC}"
    ls -la dist/
else
    print_error "Build failed - no dist/ directory created"
    exit 1
fi

# Check the built package
echo -e "\n${YELLOW}Checking package with twine...${NC}"
$PYTHON -m twine check dist/*
print_status "Package check passed"

# Check for local .pypirc file
PYPIRC_FILE=""
if [ -f ".pypirc" ]; then
    PYPIRC_FILE="--config-file .pypirc"
    print_status "Found local .pypirc file"
elif [ -f "$HOME/.pypirc" ]; then
    print_status "Using ~/.pypirc"
fi

# Handle upload based on argument
case "${1:-}" in
    test)
        echo -e "\n${YELLOW}Uploading to Test PyPI...${NC}"
        $PYTHON -m twine upload --repository testpypi $PYPIRC_FILE dist/*
        print_status "Uploaded to Test PyPI"
        echo -e "\n${BLUE}Install from Test PyPI with:${NC}"
        echo "pip install --index-url https://test.pypi.org/simple/ agent-control-plane"
        ;;
    prod)
        echo -e "\n${RED}WARNING: You are about to upload to PyPI (production)!${NC}"
        read -p "Are you sure? (y/N): " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            echo -e "\n${YELLOW}Uploading to PyPI...${NC}"
            $PYTHON -m twine upload $PYPIRC_FILE dist/*
            print_status "Uploaded to PyPI"
            echo -e "\n${BLUE}Install with:${NC}"
            echo "pip install agent-control-plane"
        else
            print_warning "Upload cancelled"
        fi
        ;;
    *)
        echo -e "\n${GREEN}Build complete!${NC}"
        echo -e "\n${BLUE}Next steps:${NC}"
        echo "  1. Test locally:        pip install dist/*.whl"
        echo "  2. Upload to Test PyPI: ./build_and_publish.sh test"
        echo "  3. Upload to PyPI:      ./build_and_publish.sh prod"
        ;;
esac

echo -e "\n${BLUE}=====================================================================${NC}"
echo -e "${GREEN}Done!${NC}"

# Contributing to Agent Control Plane

Thank you for your interest in contributing to the Agent Control Plane! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project is committed to providing a welcoming and inclusive environment. Please be respectful and considerate in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/agent-control-plane.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip

### Installation

1. Install the package in development mode:
```bash
pip install -e .
```

2. Install development dependencies:
```bash
pip install -e ".[dev]"
```

## Project Structure

```
agent-control-plane/
├── src/
│   └── agent_control_plane/     # Main package source code
│       ├── __init__.py
│       ├── agent_kernel.py
│       ├── control_plane.py
│       ├── policy_engine.py
│       ├── execution_engine.py
│       ├── constraint_graphs.py
│       ├── shadow_mode.py
│       ├── mute_agent.py
│       ├── supervisor_agents.py
│       └── example_executors.py
├── tests/                        # Test files
│   ├── test_control_plane.py
│   └── test_advanced_features.py
├── examples/                     # Example scripts
│   ├── basic_usage.py
│   ├── advanced_features.py
│   └── configuration.py
├── docs/                         # Documentation
│   ├── guides/
│   ├── api/
│   └── architecture/
├── setup.py                      # Package setup
├── pyproject.toml               # Project configuration
└── README.md                    # Main documentation
```

## Making Changes

### Guidelines

1. **Keep changes focused**: One feature or bug fix per pull request
2. **Write clear commit messages**: Use descriptive commit messages that explain what and why
3. **Add tests**: All new features should include tests
4. **Update documentation**: Update relevant documentation for new features or changes
5. **Follow existing patterns**: Maintain consistency with existing code

### Code Organization

- **Core modules**: Place core functionality in `src/agent_control_plane/`
- **Tests**: Place tests in `tests/` directory
- **Examples**: Place examples in `examples/` directory
- **Documentation**: Place documentation in `docs/` directory

## Testing

### Running Tests

Run all tests:
```bash
python -m pytest tests/
```

Run tests with coverage:
```bash
python -m pytest --cov=agent_control_plane tests/
```

Run specific test file:
```bash
python -m pytest tests/test_control_plane.py
```

Run specific test:
```bash
python -m pytest tests/test_control_plane.py::TestAgentKernel::test_create_agent_session
```

### Writing Tests

- Use unittest framework (consistent with existing tests)
- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Write descriptive test names that explain what is being tested
- Include both positive and negative test cases
- Test edge cases and error conditions

Example:
```python
import unittest
from agent_control_plane import AgentControlPlane, create_standard_agent

class TestMyFeature(unittest.TestCase):
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_feature_success_case(self):
        """Test that feature works in normal conditions"""
        # Test implementation
        pass
    
    def test_feature_error_case(self):
        """Test that feature handles errors properly"""
        # Test implementation
        pass
```

## Code Style

### Python Style Guidelines

- Follow PEP 8 style guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings to all public classes and functions
- Add type hints where appropriate

### Formatting

Use Black for code formatting:
```bash
black src/ tests/ examples/
```

### Linting

Use flake8 for linting:
```bash
flake8 src/ tests/ examples/
```

### Type Checking

Use mypy for type checking:
```bash
mypy src/
```

## Submitting Changes

### Pull Request Process

1. **Update your branch**: Ensure your branch is up to date with the main branch
   ```bash
   git checkout main
   git pull upstream main
   git checkout your-feature-branch
   git rebase main
   ```

2. **Run tests**: Ensure all tests pass
   ```bash
   python -m pytest tests/
   ```

3. **Update documentation**: Update relevant documentation

4. **Commit your changes**: Use clear, descriptive commit messages
   ```bash
   git add .
   git commit -m "Add feature: description of your feature"
   ```

5. **Push to your fork**:
   ```bash
   git push origin your-feature-branch
   ```

6. **Create a Pull Request**: 
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Provide a clear description of your changes
   - Reference any related issues

### Pull Request Guidelines

- **Title**: Use a clear, descriptive title
- **Description**: Explain what changes you made and why
- **Tests**: Ensure all tests pass
- **Documentation**: Include documentation updates if needed
- **Review**: Be responsive to feedback and questions

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `style`: Code style changes (formatting, etc.)
- `chore`: Maintenance tasks

Example:
```
feat: add conditional permission capability

Implement conditional permissions that allow agents to have
fine-grained access control based on context attributes.

Closes #123
```

## Questions?

If you have questions or need help, please:
- Check [GitHub Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions)
- Open an issue on GitHub
- Check existing documentation in the `docs/` directory
- Review [SUPPORT.md](SUPPORT.md) for detailed support options
- Look at existing code and tests for examples

## Release Process

### For Maintainers

The release process is mostly automated through GitHub Actions. Here's how to create a new release:

1. **Update Version Numbers**
   - Update version in `pyproject.toml` (line 7)
   - Update version in `setup.py` (line 16)
   - Follow [Semantic Versioning](https://semver.org/): MAJOR.MINOR.PATCH

2. **Update CHANGELOG.md**
   - Add a new section at the top with the version and date
   - List all changes under appropriate categories (Added, Changed, Fixed, etc.)
   - Follow [Keep a Changelog](https://keepachangelog.com/) format

3. **Run Pre-release Checks**
   ```bash
   # Run full test suite
   python -m pytest tests/ -v
   
   # Run linting
   flake8 src/ --count --select=E9,F63,F7,F82 --show-source
   
   # Test package build
   python -m build
   twine check dist/*
   ```

4. **Create and Push Git Tag**
   ```bash
   git tag -a v1.2.0 -m "Release version 1.2.0"
   git push origin v1.2.0
   ```

5. **Automated Workflows**
   - GitHub Actions automatically creates a GitHub Release from the tag
   - Release notes are extracted from CHANGELOG.md
   - Package is automatically published to PyPI

6. **Post-Release Tasks**
   - Verify release appears on GitHub: https://github.com/microsoft/agent-governance-toolkit/releases
   - Verify package on PyPI: https://pypi.org/project/agent-control-plane/
   - Test installation: `pip install agent-control-plane==X.Y.Z`
   - Announce in GitHub Discussions

For detailed PyPI publishing instructions, see [docs/PYPI_PUBLISHING.md](docs/PYPI_PUBLISHING.md).

Thank you for contributing to Agent Control Plane!

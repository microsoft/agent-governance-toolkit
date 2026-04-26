# Contributing to EMK

Thank you for your interest in contributing to EMK (Episodic Memory Kernel)! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, be constructive, and be patient with others.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- A GitHub account

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/emk.git
   cd emk
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/microsoft/agent-governance-toolkit.git
   ```

## Development Setup

### Create a Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Install Development Dependencies

```bash
# Install package in editable mode with dev dependencies
pip install -e ".[dev]"

# Or install all optional dependencies
pip install -e ".[all,dev]"
```

### Verify Installation

```bash
# Run tests
pytest tests/ -v

# Check code style
black --check .
ruff check .

# Run type checking
mypy emk/
```

## Making Changes

### Branch Naming

Create a descriptive branch name:

```bash
git checkout -b feature/add-redis-adapter
git checkout -b fix/episode-id-collision
git checkout -b docs/improve-readme
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: add Redis storage adapter
fix: resolve episode ID collision on rapid creation
docs: add ChromaDB usage examples
test: add integration tests for FileAdapter
refactor: simplify Indexer tag extraction
chore: update dependencies
```

### Keep Commits Atomic

Each commit should represent a single logical change. If you're fixing multiple issues, make multiple commits.

## Pull Request Process

1. **Update your fork** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature
   ```

3. **Open a Pull Request** on GitHub with:
   - Clear title describing the change
   - Description of what and why
   - Reference to any related issues
   - Screenshots/examples if applicable

4. **Address review feedback** promptly and push updates

5. **Squash commits** if requested before merge

### PR Checklist

- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] Code is formatted (`black .`)
- [ ] Linting passes (`ruff check .`)
- [ ] Type hints added for new code
- [ ] Docstrings added/updated
- [ ] Documentation updated if needed
- [ ] CHANGELOG updated for significant changes

## Coding Standards

### Style Guide

We follow [PEP 8](https://pep8.org/) with these tools:

- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **mypy** for type checking

### Type Hints

All public functions must have type hints:

```python
from typing import List, Optional, Dict, Any

def store(self, episode: Episode, embedding: Optional[np.ndarray] = None) -> str:
    """Store an episode and return its ID."""
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def generate_episode_tags(episode: Episode) -> List[str]:
    """
    Generate searchable tags from an episode.
    
    Args:
        episode: The episode to generate tags from.
        
    Returns:
        List of tags for indexing.
        
    Raises:
        ValueError: If episode content is empty.
        
    Example:
        >>> episode = Episode(goal="Test", action="Run", result="Pass", reflection="Good")
        >>> tags = generate_episode_tags(episode)
        >>> print(tags)
        ['test', 'run', 'pass', 'good']
    """
    ...
```

### Import Order

1. Standard library imports
2. Third-party imports
3. Local imports

```python
from datetime import datetime
from typing import List, Optional

import numpy as np
from pydantic import BaseModel

from emk.schema import Episode
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=emk --cov-report=html

# Run specific test file
pytest tests/test_schema.py -v

# Run specific test
pytest tests/test_schema.py::test_episode_immutability -v
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Name test functions `test_*`
- Use descriptive test names that explain what's being tested

```python
def test_episode_id_is_deterministic_for_same_content():
    """Episodes with identical content should have identical IDs."""
    episode1 = Episode(
        goal="Test",
        action="Run",
        result="Pass",
        reflection="Good",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    episode2 = Episode(
        goal="Test",
        action="Run", 
        result="Pass",
        reflection="Good",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    assert episode1.episode_id == episode2.episode_id
```

### Test Coverage

Aim for >80% code coverage. Critical paths (schema, storage) should have >95%.

## Documentation

### README Updates

Update `README.md` if you:
- Add new features
- Change public API
- Add new dependencies
- Change installation instructions

### Docstring Updates

All public classes, methods, and functions need docstrings.

### Example Updates

Add examples to `examples/` for significant new features.

## Design Principles

When contributing, keep these principles in mind:

1. **Immutability**: Episodes are append-only and cannot be modified
2. **Minimal Dependencies**: Core functionality should require minimal packages
3. **No Smart Logic**: EMK stores and retrieves; it doesn't summarize or interpret
4. **Type Safety**: Use type hints everywhere
5. **Backward Compatibility**: Don't break existing APIs without deprecation

## Questions?

- Open a [GitHub Issue](https://github.com/microsoft/agent-governance-toolkit/issues) for bugs or feature requests
- Start a [Discussion](https://github.com/microsoft/agent-governance-toolkit/discussions) for questions

## License

By contributing to EMK, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to EMK! 🎉

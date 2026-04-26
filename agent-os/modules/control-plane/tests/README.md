# Tests

This directory contains the test suite for Agent Control Plane.

## Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest -v tests/

# Run specific test file
python -m pytest tests/test_control_plane.py

# Run with coverage
python -m pytest --cov=agent_control_plane tests/
```

## Test Structure

- `test_control_plane.py` - Tests for core control plane functionality
- `test_advanced_features.py` - Tests for advanced features (Mute Agent, Shadow Mode, etc.)

## Writing Tests

Use unittest framework and follow these conventions:
- Place all tests in this directory
- Name test files with `test_` prefix
- Name test classes with `Test` prefix
- Name test methods with `test_` prefix
- Include docstrings explaining what each test does

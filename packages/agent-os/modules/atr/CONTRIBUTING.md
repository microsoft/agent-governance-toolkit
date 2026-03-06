# Contributing to ATR

Thank you for your interest in contributing to the Agent Tool Registry!

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/microsoft/agent-governance-toolkit.git
   cd atr
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # or
   source .venv/bin/activate  # Unix/macOS
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Code Style

We use the following tools to maintain code quality:

- **Ruff**: For linting and formatting
- **MyPy**: For type checking
- **pytest**: For testing

### Running Checks Locally

```bash
# Linting
ruff check .

# Formatting
ruff format .

# Type checking
mypy atr

# Tests
pytest
```

## Pull Request Guidelines

1. **Fork** the repository and create a branch from `main`
2. **Write tests** for any new functionality
3. **Update documentation** if needed
4. **Run all checks** before submitting
5. **Write clear commit messages** following conventional commits

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=atr --cov-report=html

# Run specific test file
pytest tests/test_registry.py
```

## Documentation

- Use Google-style docstrings
- Include type hints for all parameters and return values
- Add examples in docstrings where helpful

## Questions?

Open an issue on GitHub or reach out to the maintainers.

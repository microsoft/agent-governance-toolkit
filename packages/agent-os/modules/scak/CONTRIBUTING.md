# Contributing to Self-Correcting Agent Kernel

Thank you for your interest in contributing to the Self-Correcting Agent Kernel (SCAK)! This document provides guidelines for contributions.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Coding Standards](#coding-standards)
5. [Testing](#testing)
6. [Pull Request Process](#pull-request-process)
7. [Research Contributions](#research-contributions)
8. [Documentation](#documentation)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- ✅ Be respectful and considerate
- ✅ Focus on constructive feedback
- ✅ Welcome newcomers and help them learn
- ❌ No harassment, discrimination, or trolling

---

## Getting Started

### Types of Contributions

We welcome:

1. **Bug Fixes**: Fix existing issues in the codebase
2. **Feature Enhancements**: Improve existing features
3. **New Features**: Add new capabilities (discuss first in an issue)
4. **Documentation**: Improve README, wiki, or code comments
5. **Tests**: Add or improve test coverage
6. **Research**: Add benchmarks, datasets, or experiments
7. **Performance**: Optimize latency or resource usage

### Before You Start

1. **Check existing issues**: Look for related issues or PRs
2. **Open a discussion**: For large changes, create an issue first
3. **Read the architecture**: Understand the self-correction design (see `wiki/`)
4. **Review coding standards**: See below

---

## Development Setup

### Prerequisites

- Python 3.8+ (recommended: 3.10)
- Git
- Virtual environment tool (venv, conda, etc.)

### Installation

```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd self-correcting-agent-kernel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"  # Includes testing and development tools
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_triage.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Code Quality

```bash
# Run type checking (if mypy is installed)
mypy src/

# Run linting (if flake8 is installed)
flake8 src/ --max-line-length=120
```

---

## Coding Standards

We follow **Partner-level coding standards** (see `.github/copilot-instructions.md`).

### Key Principles

1. **Type Safety**: All functions must have type hints
   ```python
   def compute_score(value: float, threshold: float = 0.5) -> bool:
       return value >= threshold
   ```

2. **Async-First**: All I/O operations must be async
   ```python
   async def call_llm(prompt: str) -> str:
       return await llm_client.generate(prompt)
   ```

3. **No Silent Failures**: Every `try/except` must emit telemetry
   ```python
   try:
       result = risky_operation()
   except Exception as e:
       telemetry.emit_failure_detected(
           agent_id=agent_id,
           error_message=str(e)
       )
       raise
   ```

4. **Pydantic Models**: Use Pydantic for data exchange
   ```python
   from pydantic import BaseModel
   
   class PatchRequest(BaseModel):
       agent_id: str
       patch_content: str
       patch_type: str
   ```

5. **Structured Telemetry**: JSON logs, not print statements
   ```python
   telemetry.emit_patch_applied(
       agent_id=agent_id,
       patch_id=patch.patch_id
   )
   ```

### File Organization

- **src/kernel/**: Core correction engine
- **src/agents/**: Agent implementations
- **src/interfaces/**: External interfaces (telemetry, LLM clients, etc.)
- **tests/**: Test suite
- **experiments/**: Benchmarks and validation
- **examples/**: Demos and usage examples

### Naming Conventions

- **Functions**: `snake_case` (e.g., `handle_failure`, `compute_score`)
- **Classes**: `PascalCase` (e.g., `ShadowTeacher`, `MemoryController`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `GLOBAL_SEED`, `MAX_RETRIES`)
- **Modules**: `snake_case` (e.g., `triage.py`, `memory.py`)

---

## Testing

### Test Requirements

Every PR must include:

1. **Unit tests** for new functions
2. **Integration tests** for new features
3. **Docstrings** explaining test purpose
4. **Assertions** with clear failure messages

### Example Test

```python
import pytest
from src.kernel.triage import FailureTriage, FixStrategy


class TestFailureTriage:
    """Test the Failure Triage Engine."""
    
    @pytest.fixture
    def triage(self):
        """Create triage instance."""
        return FailureTriage()
    
    def test_critical_operations_go_sync(self, triage):
        """Test that critical operations route to SYNC_JIT."""
        strategy = triage.decide_strategy(
            user_prompt="Process refund for customer",
            context={"action": "execute_payment"}
        )
        
        assert strategy == FixStrategy.SYNC_JIT, \
            "Payment operations must be sync for safety"
```

### Running Tests Locally

```bash
# Before submitting PR, run:
pytest tests/ -v --cov=src
```

Expected: All tests pass, >80% coverage

---

## Pull Request Process

### 1. Fork and Branch

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/self-correcting-agent-kernel.git
cd self-correcting-agent-kernel

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow coding standards (see above)
- Write tests
- Update documentation
- Add yourself to `.github/CONTRIBUTORS.md` (if it exists)

### 3. Commit

**Commit Message Format:**
```
<type>: <description>

<optional body>

<optional footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code restructuring (no behavior change)
- `perf`: Performance improvement
- `chore`: Maintenance (dependencies, config, etc.)

**Example:**
```bash
git add .
git commit -m "feat: add multi-turn laziness detection

- Extend Completeness Auditor to handle multi-turn context
- Add new test suite for multi-turn scenarios
- Update GAIA benchmark with multi-turn queries

Closes #123"
```

### 4. Push and Open PR

```bash
git push origin feature/your-feature-name
```

Then open a pull request on GitHub with:

- **Title**: Clear, concise summary
- **Description**: What changes, why, and how to test
- **Linked Issues**: `Closes #123` or `Relates to #456`
- **Checklist**: 
  - [ ] Tests pass
  - [ ] Documentation updated
  - [ ] Coding standards followed

### 5. Code Review

- Respond to feedback promptly
- Make requested changes
- Push updates to the same branch (PR auto-updates)

### 6. Merge

Once approved by maintainers:
- PR will be squashed and merged
- Feature branch can be deleted

---

## Research Contributions

### Adding Benchmarks

To add a new benchmark:

1. **Create dataset**: Add to `datasets/<benchmark_name>/`
   ```json
   {
     "id": "query_001",
     "category": "laziness",
     "query": "Find recent errors",
     "ground_truth": {"data_exists": true, ...}
   }
   ```

2. **Create benchmark script**: Add to `experiments/<benchmark_name>/`
   ```python
   def run_benchmark(queries: List[Dict]) -> Dict:
       # Implementation
       pass
   ```

3. **Document**: Add README.md explaining:
   - Purpose of benchmark
   - How to run
   - Expected results
   - Citation (if based on prior work)

4. **Cite prior work**: Add references to the project documentation

### Adding Papers to Bibliography

To add a new paper citation:

1. **Add to documentation**: In relevant section, add:
   ```markdown
   ### [Section Name]
   
   1. **Authors (Year).**  
      *"Paper Title"*  
      Venue. DOI/arXiv
      - **Core Contribution**: What they did
      - **Our Implementation**: How we use it
      - **Connection**: Why it's relevant
   ```

2. **Add to paper/bibliography.bib** (for LaTeX):
   ```bibtex
   @inproceedings{author2023title,
     title={Paper Title},
     author={Author, A. and Author, B.},
     booktitle={Venue},
     year={2023},
     url={https://arxiv.org/abs/...}
   }
   ```

---

## Documentation

### Code Documentation

**Docstrings** (Google style):
```python
def handle_failure(
    agent_id: str,
    error_message: str,
    context: dict
) -> dict:
    """
    Handle agent failure with self-correction architecture.
    
    Args:
        agent_id: Unique agent identifier
        error_message: Error description
        context: Additional context (tool trace, user prompt, etc.)
    
    Returns:
        Dict with patch_applied, patch_id, strategy
    
    Raises:
        ValueError: If agent_id is invalid
    
    Example:
        >>> result = handle_failure("agent-001", "Timeout", {})
        >>> print(result["patch_applied"])
        True
    """
    # Implementation
    pass
```

### README Updates

If your change affects usage:

1. Update relevant section in `README.md`
2. Add example if new feature
3. Update table of contents if new section

### Wiki Updates

For architectural changes:

1. Update relevant wiki page (`wiki/*.md`)
2. Add diagrams if helpful (Mermaid or ASCII)
3. Link from main wiki README

---

## Questions?

- **Issues**: Open a GitHub issue for bugs or questions
- **Discussions**: Use GitHub Discussions for general questions
- **Email**: research@scak.ai (for sensitive or private matters)

---

## Recognition

Contributors will be:

- Listed in `.github/CONTRIBUTORS.md`
- Acknowledged in paper (if research contribution)
- Invited to co-author follow-up papers (for significant contributions)

---

Thank you for contributing to SCAK! 🚀

**Last Updated:** 2026-01-18  
**Version:** 1.0

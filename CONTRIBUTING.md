# Contributing Guidelines

Thank you for contributing to the Web Security Assessment Scanner.

## Code Standards
- **Python**: Minimum version 3.11+ (targeting 3.12).
- **Type Checking**: 100% strict type hints; `mypy src tests` must pass with zero errors.
- **Formatting & Linting**: `ruff format --check .` and `ruff check .` with max line length 100 characters.
- **Security Scans**: `bandit -c pyproject.toml -r src` must report 0 issues.
- **Test Coverage**: Pytest suite must achieve $\ge 90\%$ branch/statement coverage.
- **Safety**: All probes must be non-destructive and adhere to the scope verification engine.

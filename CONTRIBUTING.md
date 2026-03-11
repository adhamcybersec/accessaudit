# Contributing to AccessAudit

Thank you for your interest in contributing to AccessAudit! This document provides guidelines for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check if the issue already exists in [Issues](https://github.com/adhamcybersec/accessaudit/issues)
- Ensure you're using the latest version

When creating a bug report, include:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Relevant logs/error messages

### Suggesting Features

Feature requests are welcome! Please:
- Check if it's already been suggested
- Explain the use case
- Describe the proposed solution
- Consider implementation complexity

### Pull Requests

1. **Fork the repository**
   ```bash
   gh repo fork adhamcybersec/accessaudit --clone
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests and linters**
   ```bash
   # Run tests
   pytest
   
   # Format code
   black src/ tests/
   
   # Lint
   ruff check src/ tests/
   
   # Type check
   mypy src/
   ```

5. **Commit your changes**
   ```bash
   git commit -m "feat: Add your feature description"
   ```
   
   Use conventional commit messages:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `docs:` - Documentation changes
   - `test:` - Test additions/changes
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance tasks

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   gh pr create --fill
   ```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/accessaudit.git
cd accessaudit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=accessaudit --cov-report=html

# Run specific test file
pytest tests/unit/test_models.py -v
```

## Code Style

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings for public functions/classes

Example:
```python
async def analyze_permissions(
    accounts: list[Account],
    permissions: dict[str, list[Permission]]
) -> list[Finding]:
    """Analyze permissions for security issues.
    
    Args:
        accounts: List of accounts to analyze
        permissions: Dict mapping account_id -> permissions
        
    Returns:
        List of security findings
    """
    # Implementation
```

## Project Structure

```
src/accessaudit/
├── connectors/    # IAM provider integrations
├── analysis/      # Security analysis modules
├── core/          # Scanner, Analyzer, Reporter
├── cli/           # CLI tool
├── models/        # Data models
└── utils/         # Utilities

tests/
├── unit/          # Unit tests
├── integration/   # Integration tests
└── fixtures/      # Test data
```

## Adding a New Connector

To add support for a new IAM provider:

1. Create `src/accessaudit/connectors/provider.py`
2. Extend `BaseConnector`
3. Implement required methods
4. Add tests in `tests/unit/test_connectors.py`
5. Update documentation

## Documentation

- Update README.md for user-facing changes
- Add/update docstrings for code changes
- Create/update docs in `docs/` for major features
- Include examples where helpful

## Questions?

- Open a [Discussion](https://github.com/adhamcybersec/accessaudit/discussions)
- Reach out to [@adhamcybersec](https://github.com/adhamcybersec)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

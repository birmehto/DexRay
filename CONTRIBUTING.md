# Contributing to DexRay

Thank you for your interest in contributing to DexRay! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Open a new issue with a clear title and description
3. Include steps to reproduce, expected behavior, and actual behavior
4. Add relevant labels (bug, enhancement, etc.)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature, its use case, and potential implementation
3. Check if it aligns with OWASP Mobile Top 10 or MASVS standards

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes following the code style
4. Add or update tests as needed
5. Run the test suite: `pytest`
6. Run linting: `ruff check .`
7. Submit a pull request

## Development Setup

```bash
git clone https://github.com/birmehto/DexRay.git
cd DexRay
pip install -e ".[dev]"
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for all function signatures
- Keep functions focused and concise
- Write docstrings for public APIs

## Testing

```bash
pytest                          # Run all tests
pytest tests/test_scanner.py    # Run specific test file
pytest --cov=dexray             # Run with coverage
```

## Scanner Modules

When adding new scanner modules:

1. Place them in `scanner/modules/`
2. Follow the existing module pattern
3. Add corresponding tests in `tests/`
4. Update the analysis engine if needed

## Pull Request Guidelines

- Keep PRs focused on a single change
- Write clear commit messages
- Reference related issues
- Ensure all tests pass
- Update documentation if applicable

## Questions?

Open a discussion in the repository's Discussions tab.

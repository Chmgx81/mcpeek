# Contributing to MCPeek

Thanks for your interest in contributing to MCPeek! This document provides guidelines for contributing.

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 18+
- Git

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Running Tests

```bash
cd backend
python -m pytest tests/ -v
python -m ruff check app/
```

```bash
cd frontend
npx tsc --noEmit
```

## Code Style

### Python

- Follow PEP 8
- Use type hints
- Max line length: 100 characters
- Linter: `ruff`

### TypeScript/React

- Use TypeScript for all new files
- Follow existing component patterns
- Use Tailwind CSS for styling

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `python -m pytest tests/ -v`
5. Commit with a clear message describing your changes
6. Push to your fork and open a Pull Request

## Pull Request Guidelines

- Include a clear description of what the PR does
- Add tests for new functionality
- Ensure all tests pass
- Keep PRs focused on a single change
- Update documentation if your change affects user-facing behavior

## Adding Detection Patterns

If you want to add a new threat detection pattern:

1. Add the pattern to `backend/app/services/vulnerability_db.py` or `attack_defense.py`
2. Add test cases in the corresponding test file
3. Update documentation if it's a new threat category

## Reporting Bugs

Open a GitHub issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- MCPeek version
- OS/Python version

## Code of Conduct

Be respectful and constructive. We're all here to make AI agents safer.

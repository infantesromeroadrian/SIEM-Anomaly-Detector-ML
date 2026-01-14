# 🚀 Installation Guide

## Prerequisites

- Python 3.10, 3.11, or 3.12
- uv (recommended) or pip
- PostgreSQL 15+ (for production)
- Redis 7+ (for production)

## Quick Start with uv (Recommended)

```bash
# 1. Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Create virtual environment
uv venv .venv --python 3.12

# 3. Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows

# 4. Install dependencies from lockfile
uv pip sync requirements.lock

# 5. Install project in development mode
uv pip install -e ".[dev]"
```

## Alternative: pip

```bash
# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Install dependencies
pip install -e ".[dev]"
```

## Verify Installation

```bash
# Check tools are installed
ruff --version
mypy --version
pytest --version

# Run linter
ruff check backend/

# Run type checker
mypy backend/

# Run tests (when available)
pytest tests/
```

## Dependency Management

### Adding New Dependencies

```bash
# Add to pyproject.toml [project.dependencies] section
# Then regenerate lockfile:
uv pip compile pyproject.toml --extra dev --extra benchmarking -o requirements.lock

# Sync environment:
uv pip sync requirements.lock
```

### Updating Dependencies

```bash
# Update all dependencies:
uv pip compile pyproject.toml --extra dev --extra benchmarking -o requirements.lock --upgrade

# Update specific package:
uv pip compile pyproject.toml --extra dev --extra benchmarking -o requirements.lock --upgrade-package numpy
```

## Next Steps

1. Copy `.env.example` to `.env` and configure
2. Train ML models: `python scripts/train_ensemble.py`
3. Start API: `uvicorn backend.main:app --reload`
4. Visit docs: http://localhost:8000/docs

## Troubleshooting

### uv not found

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH (if needed)
export PATH="$HOME/.local/bin:$PATH"
```

### Permission errors

```bash
# On Linux, you might need to fix permissions
sudo chown -R $USER:$USER .venv
```

### ImportError after install

```bash
# Make sure you're in the virtual environment
which python  # Should point to .venv/bin/python

# Reinstall in editable mode
uv pip install -e ".[dev]"
```

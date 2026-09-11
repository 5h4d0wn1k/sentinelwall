# Contributing to SentinelWall

Thank you for your interest in contributing to SentinelWall.

## Development Setup

```bash
git clone https://github.com/5h4d0wn1k/sentinelwall.git
cd sentinelwall
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -q
```

## Code Style

- Python 3.10+ required
- Type hints on all public APIs
- Follow existing code conventions in the file you're editing
- Run `ruff check` and `mypy` before submitting

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Add tests for any new functionality
4. Ensure all tests pass
5. Submit a pull request with a clear description

## Adding Rules

Rules use the SentinelWall DSL (see `docs/rule-dsl.md` or the RuleParser
docstring). Add built-in rules to `sentinelwall/rules/builtin.py` and
corresponding tests to `tests/rules/test_engine.py`.

## Adding MITRE Techniques

Technique definitions live in `sentinelwall/mitre/techniques.py`. Each technique
needs detection patterns, protocol hints, and port hints for accurate mapping.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.

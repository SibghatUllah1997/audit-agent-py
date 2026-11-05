## Contributing to sibaudit

Thanks for your interest in improving sibaudit! This project aims to be a crisp, typed, and well‑tested reference for small-but-useful security checks.

- Open small, focused pull requests
- Keep changes readable and well-typed
- Add tests for every rule change (true/false positive fixtures)
- Keep coverage ≥90% (CI enforces this)

### Dev setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
pytest -q
```

### Rule boundaries

- Prefer simple, high-signal heuristics
- Be explicit about limitations and link references if helpful
- Minimize false positives; add a false-positive fixture for each new rule

### Releases

- Version is managed in `pyproject.toml` and `sibaudit/__init__.py`
- Follow semantic versioning for breaking changes in outputs or codes

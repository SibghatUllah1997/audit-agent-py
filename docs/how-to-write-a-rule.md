## How to write a rule

Rules live in `sibaudit/scanner.py` and follow a simple pattern:

- Input: `lines: list[str]`, `file_path: Path`, and optional `ignore_next_lines`
- Output: `Iterator[Finding]` with `file`, `line`, `code`, `severity`, `message`, `line_text`
- Comment-aware: use `_strip_block_comments` and skip `//` single-line comments
- Respect the `// sibaudit:ignore-next-line` directive (already handled in `scan_paths`)

### Template

```python
def _detect_example(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    severity = "LOW"
    in_block_comment = False
    for idx, raw in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        line, in_block_comment = _strip_block_comments(raw, in_block_comment)
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if SOME_REGEX.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A999",
                severity=severity,
                message="Short description of the risk.",
                line_text=line.rstrip(),
            )
```

### Tests

- Add at least one true-positive and one false-positive fixture under `tests/fixtures`
- Add or extend tests to assert expected codes
- Run `pytest -q --cov=sibaudit --cov-report=term-missing`

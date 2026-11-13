from __future__ import annotations

from pathlib import Path

import pytest

from sibaudit.config import (
    Config,
    ConfigError,
    RuleSetting,
    apply_config,
    find_and_load_config,
    find_config_path,
    load_config,
)
from sibaudit.scanner import Finding


def _finding(code: str = "A001", severity: str = "MEDIUM") -> Finding:
    return Finding(
        file_path=Path("demo.sol"),
        line_number=1,
        code=code,
        severity=severity,
        message="demo",
        line_text="//",
    )


def test_load_sibaudit_toml_bool_and_severity(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text(
        """
[rules]
A017 = false
A006 = "LOW"
A001 = { enabled = true, severity = "HIGH" }
""".lstrip()
    )
    config = load_config(path)
    assert config.source == path.resolve()
    assert config.rules["A017"] == RuleSetting(enabled=False)
    assert config.rules["A006"] == RuleSetting(severity="LOW")
    assert config.rules["A001"] == RuleSetting(enabled=True, severity="HIGH")


def test_load_pyproject_tool_table(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        """
[project]
name = "demo"

[tool.sibaudit.rules]
A010 = false
A008 = { severity = "MEDIUM" }
""".lstrip()
    )
    config = load_config(path)
    assert config.rules["A010"].enabled is False
    assert config.rules["A008"].severity == "MEDIUM"


def test_pyproject_without_sibaudit_table_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text("[project]\nname = 'demo'\n")
    config = load_config(path)
    assert config.rules == {}


def test_find_prefers_sibaudit_toml_over_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.sibaudit.rules]\nA001 = false\n")
    (tmp_path / "sibaudit.toml").write_text("[rules]\nA002 = false\n")
    found = find_config_path(tmp_path)
    assert found == tmp_path / "sibaudit.toml"
    config = find_and_load_config(tmp_path)
    assert "A002" in config.rules
    assert "A001" not in config.rules


def test_find_walks_parents_and_skips_bare_pyproject(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "contracts"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text("[project]\nname = 'inner'\n")
    (tmp_path / "sibaudit.toml").write_text("[rules]\nA003 = false\n")
    assert find_config_path(nested) == tmp_path / "sibaudit.toml"


def test_find_uses_pyproject_when_no_dedicated_file(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.sibaudit.rules]\nA004 = false\n")
    assert find_config_path(tmp_path / "src") == tmp_path / "pyproject.toml"


def test_find_returns_none_when_nothing_matches(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    assert find_config_path(tmp_path) is None
    assert find_and_load_config(tmp_path).rules == {}


def test_unknown_rule_code_raises(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text("[rules]\nA999 = false\n")
    with pytest.raises(ConfigError, match="unknown rule code"):
        load_config(path)


def test_invalid_severity_raises(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text('[rules]\nA001 = "CRITICAL"\n')
    with pytest.raises(ConfigError, match="unknown severity"):
        load_config(path)


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text("[scan]\ninclude = ['src']\n")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(path)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")


def test_invalid_toml_raises(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text("[rules\n")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_apply_config_disables_and_overrides_severity() -> None:
    findings = [
        _finding("A001", "MEDIUM"),
        _finding("A017", "LOW"),
        _finding("A006", "MEDIUM"),
    ]
    config = Config(
        rules={
            "A017": RuleSetting(enabled=False),
            "A001": RuleSetting(severity="HIGH"),
        }
    )
    out = apply_config(findings, config)
    assert [f.code for f in out] == ["A001", "A006"]
    assert out[0].severity == "HIGH"
    assert out[1] is findings[2]
    # Original objects are not mutated.
    assert findings[0].severity == "MEDIUM"


def test_apply_config_empty_is_identity() -> None:
    findings = [_finding()]
    out = apply_config(findings, Config(rules={}))
    assert out == findings
    assert out[0] is findings[0]


def test_severity_is_case_insensitive(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text('[rules]\nA001 = "high"\n')
    assert load_config(path).rules["A001"].severity == "HIGH"


def test_table_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "sibaudit.toml"
    path.write_text("[rules]\nA001 = { enabled = true, extra = 1 }\n")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(path)

"""Load rule enable/disable/severity settings from TOML config files.

Looks for ``sibaudit.toml``, then ``[tool.sibaudit]`` in ``pyproject.toml``,
walking from a start directory up to the filesystem root. The first file found
wins; the two sources are not merged.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .rules import get_rule
from .scanner import Finding

SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class ConfigError(ValueError):
    """Raised when a config file cannot be read or does not match the schema."""


@dataclass(frozen=True)
class RuleSetting:
    enabled: bool = True
    severity: str | None = None


@dataclass(frozen=True)
class Config:
    rules: dict[str, RuleSetting]
    source: Path | None = None


def normalize_severity(value: str) -> str:
    """Return ``HIGH``, ``MEDIUM``, or ``LOW``, or raise ``ConfigError``."""
    level = value.strip().upper()
    if level not in SEVERITY_RANK:
        raise ConfigError(f"unknown severity {value!r}; use LOW, MEDIUM, or HIGH")
    return level


def find_config_path(start: Path) -> Path | None:
    """Nearest ``sibaudit.toml`` or ``pyproject.toml`` with ``[tool.sibaudit]``."""
    directory = start.resolve()
    if directory.is_file():
        directory = directory.parent
    for current in [directory, *directory.parents]:
        dedicated = current / "sibaudit.toml"
        if dedicated.is_file():
            return dedicated
        pyproject = current / "pyproject.toml"
        if pyproject.is_file() and _pyproject_has_sibaudit(pyproject):
            return pyproject
    return None


def load_config(path: Path) -> Config:
    """Parse ``path`` as a sibaudit TOML config."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config file is not valid TOML: {path}") from exc
    table = _sibaudit_table(data, path)
    return Config(rules=_parse_rules(table.get("rules", {}), path), source=path.resolve())


def find_and_load_config(start: Path) -> Config:
    """Load the nearest config, or an empty ``Config`` if none is present."""
    path = find_config_path(start)
    if path is None:
        return Config(rules={})
    return load_config(path)


def apply_config(findings: Sequence[Finding], config: Config) -> list[Finding]:
    """Drop disabled rules and rewrite severities. Order is preserved."""
    if not config.rules:
        return list(findings)
    out: list[Finding] = []
    for finding in findings:
        setting = config.rules.get(finding.code)
        if setting is not None and not setting.enabled:
            continue
        if setting is not None and setting.severity and setting.severity != finding.severity:
            finding = replace(finding, severity=setting.severity)
        out.append(finding)
    return out


def _pyproject_has_sibaudit(path: Path) -> bool:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    tool = data.get("tool")
    return isinstance(tool, dict) and "sibaudit" in tool


def _sibaudit_table(data: Mapping[str, Any], path: Path) -> dict[str, Any]:
    if path.name == "pyproject.toml":
        tool = data.get("tool")
        if not isinstance(tool, dict) or "sibaudit" not in tool:
            return {}
        table = tool["sibaudit"]
        if not isinstance(table, dict):
            raise ConfigError(f'[tool.sibaudit] in {path} must be a table')
        return table
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a TOML table")
    unknown = sorted(key for key in data if key != "rules")
    if unknown:
        raise ConfigError(
            f"unknown key {unknown[0]!r} in {path}; only [rules] is supported"
        )
    return dict(data)


def _parse_rules(raw: object, path: Path) -> dict[str, RuleSetting]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f'"rules" in {path} must be a table')
    settings: dict[str, RuleSetting] = {}
    for key, value in raw.items():
        code = str(key).strip().upper()
        if get_rule(code) is None:
            raise ConfigError(f"unknown rule code {key!r} in {path}; see --list-rules")
        settings[code] = _parse_rule_value(code, value, path)
    return settings


def _parse_rule_value(code: str, value: object, path: Path) -> RuleSetting:
    if isinstance(value, bool):
        return RuleSetting(enabled=value)
    if isinstance(value, str):
        return RuleSetting(severity=normalize_severity(value))
    if isinstance(value, dict):
        unknown = sorted(key for key in value if key not in {"enabled", "severity"})
        if unknown:
            raise ConfigError(
                f"unknown key {unknown[0]!r} for {code} in {path}; "
                "use enabled and/or severity"
            )
        enabled = value.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{code}.enabled in {path} must be true or false")
        severity_raw = value.get("severity")
        severity: str | None
        if severity_raw is None:
            severity = None
        elif isinstance(severity_raw, str):
            severity = normalize_severity(severity_raw)
        else:
            raise ConfigError(f"{code}.severity in {path} must be a string")
        return RuleSetting(enabled=enabled, severity=severity)
    raise ConfigError(
        f"{code} in {path} must be true, false, a severity, or a table "
        "with enabled and/or severity"
    )

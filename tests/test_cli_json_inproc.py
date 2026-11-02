from __future__ import annotations

import json
from pathlib import Path

from sibaudit import cli


def test_cli_json_inproc(capsys, tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Z3 {
        function g(address t, bytes calldata d) external {
            t.call(d); // unchecked
        }
    }
    """.strip()
    dir_path = tmp_path / "contracts3"
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "Z3.sol").write_text(code)

    try:
        cli.main(["--format", "json", str(dir_path)])
    except SystemExit as e:  # pragma: no cover
        assert e.code == 1
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert lines
    rec = json.loads(lines[0])
    assert {"file_path", "line_number", "code", "severity", "message"} <= set(rec.keys())

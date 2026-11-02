from __future__ import annotations

import json
from pathlib import Path

from sibaudit import cli


def test_cli_text_inproc(capsys, tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Z {
        function f(address t, bytes calldata d) external {
            t.call(d); // unchecked
            address a = tx.origin; // risky
        }
    }
    """.strip()
    dir_path = tmp_path / "contracts"
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "Z.sol").write_text(code)

    # Capture SystemExit for non-zero exit
    try:
        cli.main(["--format", "text", str(dir_path)])
    except SystemExit as e:  # pragma: no cover - we assert below
        assert e.code == 1
    out = capsys.readouterr().out
    assert "A001" in out and "A002" in out


def test_cli_sarif_inproc(capsys, tmp_path: Path) -> None:
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract Z2 {
        function f(address t, bytes calldata d) external {
            (bool ok, ) = t.call(d);
            // No check to force A002
        }
    }
    """.strip()
    dir_path = tmp_path / "contracts2"
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "Z2.sol").write_text(code)

    try:
        cli.main(["--format", "sarif", str(dir_path)])
    except SystemExit as e:  # pragma: no cover
        # Non-zero because there are findings
        assert e.code == 1
    out = capsys.readouterr().out
    sarif = json.loads(out)
    assert sarif.get("version") == "2.1.0"
    runs = sarif["runs"]
    assert isinstance(runs, list) and runs
    results = runs[0]["results"]
    codes = {r["ruleId"] for r in results}
    assert "A002" in codes

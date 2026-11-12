from __future__ import annotations

import json
import shlex
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sibaudit.cli import main
from sibaudit.suggest import hint_for

RISKY = """
pragma solidity ^0.8.20;
contract C {
    function f() external view returns (address) {
        return tx.origin;
    }
}
""".strip()


def test_suggest_appends_hint_lines_in_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--suggest"])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    lines = out.splitlines()
    finding_line = next(ln for ln in lines if ": A001 " in ln)
    hint_line = lines[lines.index(finding_line) + 1]
    expected = hint_for("A001", "Potential risky use of tx.origin (often unsafe for auth).")
    assert hint_line == f"    hint: {expected}"
    assert f"hint: {expected}" in out
    # Indented hint lines must not look like finding lines.
    assert not hint_line.startswith(str(sol))


def test_suggest_json_adds_suggestion_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json", "--suggest"])
    rows = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert rows
    assert all(row.get("suggestion") for row in rows)
    assert all(row["suggestion_source"] == "catalog" for row in rows)
    assert all(row["code"] == "A001" for row in rows)
    assert "msg.sender" in rows[0]["suggestion"]


def test_json_without_suggest_omits_suggestion_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "json"])
    rows = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert rows
    assert all("suggestion" not in row for row in rows)
    assert all("suggestion_source" not in row for row in rows)


def test_suggest_github_includes_hint_in_annotation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--format", "github", "--suggest"])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    assert "A001 (MEDIUM)" in out
    assert " — " in out
    assert "msg.sender" in out
    assert "hint:" not in out


def test_suggest_summary_lists_hint_under_the_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit):
        main([str(sol), "--format", "summary", "--suggest"])
    out = capsys.readouterr().out
    assert "A001" in out
    assert "hint:" in out
    assert "msg.sender" in out
    assert "Token.sol:" not in out


def test_suggest_on_clean_file_prints_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Clean.sol"
    sol.write_text("pragma solidity ^0.8.20;\ncontract C {}\n")
    with pytest.raises(SystemExit) as clean:
        main([str(sol), "--suggest"])
    assert clean.value.code == 0
    assert capsys.readouterr().out == ""


def test_suggest_catalog_overrides_builtin_without_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    catalog = tmp_path / "hints.json"
    catalog.write_text(json.dumps({"A001": "Custom catalog hint."}))
    with pytest.raises(SystemExit) as shown:
        main([str(sol), "--suggest-catalog", str(catalog)])
    assert shown.value.code == 1
    out = capsys.readouterr().out
    assert "hint: Custom catalog hint." in out
    assert hint_for("A001") not in out


def test_missing_suggest_catalog_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    missing = tmp_path / "nope.json"
    with pytest.raises(SystemExit) as failed:
        main([str(sol), "--suggest-catalog", str(missing)])
    assert failed.value.code == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err
    assert captured.out == ""


def _py_cmd(source: str) -> str:
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(source)}"


def test_suggest_cmd_overrides_and_falls_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    builtin = hint_for("A001", "Potential risky use of tx.origin (often unsafe for auth).")

    with pytest.raises(SystemExit):
        main([str(sol), "--suggest-cmd", _py_cmd('print("from local cmd")')])
    assert "hint: from local cmd" in capsys.readouterr().out

    with pytest.raises(SystemExit):
        main([str(sol), "--suggest-cmd", _py_cmd("raise SystemExit(1)")])
    assert f"hint: {builtin}" in capsys.readouterr().out



def test_cli_rejects_remote_model_url(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as failed:
        main(
            [
                str(sol),
                "--suggest-backend",
                "local-llm",
                "--llm-model",
                "m",
                "--llm-url",
                "http://example.com",
            ]
        )
    assert failed.value.code == 2
    captured = capsys.readouterr()
    assert "loopback" in captured.err
    assert captured.out == ""


def test_cli_local_llm_requires_model_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as failed:
        main([str(sol), "--suggest-backend", "local-llm"])
    assert failed.value.code == 2
    captured = capsys.readouterr()
    assert "model name" in captured.err
    assert captured.out == ""


def test_cli_llm_flags_require_local_llm_backend(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    with pytest.raises(SystemExit) as failed:
        main([str(sol), "--suggest", "--llm-model", "m"])
    assert failed.value.code == 2
    captured = capsys.readouterr()
    assert "require --suggest-backend local-llm" in captured.err
    assert captured.out == ""


class _FakeModel(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        answer = {"response": f"fake fix from {payload['model']}"}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        return


def test_cli_local_llm_against_fake_loopback_server(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    server = HTTPServer(("127.0.0.1", 0), _FakeModel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        with pytest.raises(SystemExit) as shown:
            main(
                [
                    str(sol),
                    "--suggest-backend",
                    "local-llm",
                    "--llm-model",
                    "demo",
                    "--llm-url",
                    url,
                    "--format",
                    "json",
                ]
            )
        assert shown.value.code == 1
    finally:
        server.shutdown()
        server.server_close()
    captured = capsys.readouterr()
    rows = [json.loads(ln) for ln in captured.out.splitlines() if ln.strip()]
    assert rows
    assert all(row["suggestion"] == "fake fix from demo" for row in rows)
    assert all(row["suggestion_source"] == "local-llm" for row in rows)
    assert "note:" not in captured.err


def test_cli_local_llm_unreachable_falls_back_with_note(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sol = tmp_path / "Token.sol"
    sol.write_text(RISKY)
    server = HTTPServer(("127.0.0.1", 0), _FakeModel)
    port = server.server_port
    server.server_close()
    with pytest.raises(SystemExit) as shown:
        main(
            [
                str(sol),
                "--suggest-backend",
                "local-llm",
                "--llm-model",
                "demo",
                "--llm-url",
                f"http://127.0.0.1:{port}",
                "--format",
                "json",
            ]
        )
    assert shown.value.code == 1
    captured = capsys.readouterr()
    rows = [json.loads(ln) for ln in captured.out.splitlines() if ln.strip()]
    assert rows
    assert all(row["suggestion_source"] == "catalog" for row in rows)
    assert "used catalog hints" in captured.err

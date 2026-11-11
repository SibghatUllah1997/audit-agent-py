from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths


def _scan(tmp_path: Path, source: str) -> list:
    (tmp_path / "C.sol").write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A019"]


def _contract(body: str, *, pragma: str = "^0.8.20", name: str = "C") -> str:
    return f"pragma solidity {pragma};\ncontract {name} {{\n{body}\n}}\n"


def test_flags_payable_deposit_without_withdraw(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        _contract("function deposit() external payable {}\nfunction peek() external view {}"),
    )
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert 'Payable function "deposit"' in findings[0].message
    assert "no withdraw path" in findings[0].message
    assert "function deposit()" in findings[0].line_text


def test_flags_receive_without_withdraw(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _contract("receive() external payable {}"))
    assert len(findings) == 1
    assert "Payable receive()" in findings[0].message


def test_flags_payable_fallback_without_withdraw(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _contract("fallback() external payable {}"))
    assert len(findings) == 1
    assert "Payable fallback()" in findings[0].message


def test_flags_payable_constructor_without_withdraw(tmp_path: Path) -> None:
    findings = _scan(tmp_path, _contract("constructor() payable {}"))
    assert len(findings) == 1
    assert "Payable constructor" in findings[0].message


def test_flags_each_payable_entry_point(tmp_path: Path) -> None:
    body = (
        "constructor() payable {}\n"
        "receive() external payable {}\n"
        "function donate() external payable {}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    labels = {f.message.split(" can receive")[0] for f in findings}
    assert labels == {
        "Payable constructor",
        "Payable receive()",
        'Payable function "donate"',
    }


def test_allows_payable_when_transfer_withdraws(tmp_path: Path) -> None:
    body = (
        "receive() external payable {}\n"
        "function pull(address payable to) external {\n"
        "    to.transfer(address(this).balance);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_payable_when_send_withdraws(tmp_path: Path) -> None:
    body = (
        "function donate() external payable {}\n"
        "function pull(address payable to) external {\n"
        "    to.send(address(this).balance);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_payable_when_call_value_withdraws(tmp_path: Path) -> None:
    body = (
        "function donate() external payable {}\n"
        "function pull() external {\n"
        "    payable(msg.sender).call{value: address(this).balance}(\"\");\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_allows_payable_when_selfdestruct_withdraws(tmp_path: Path) -> None:
    body = (
        "function donate() external payable {}\n"
        "function boom(address payable to) external {\n"
        "    selfdestruct(to);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_erc20_transfer_is_not_a_withdraw_path(tmp_path: Path) -> None:
    body = (
        "function donate() external payable {}\n"
        "function dump(address token, address to) external {\n"
        "    token.transfer(to, 5);\n"
        "}\n"
    )
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert "donate" in findings[0].message


def test_commented_transfer_is_not_a_withdraw_path(tmp_path: Path) -> None:
    body = (
        "function donate() external payable {}\n"
        "function noop(address payable to) external {\n"
        "    // to.transfer(address(this).balance);\n"
        "    to;\n"
        "}\n"
    )
    assert _scan(tmp_path, _contract(body))


def test_ignores_internal_payable_helper(tmp_path: Path) -> None:
    body = "function stash() internal payable {}\nfunction peek() external view {}"
    assert not _scan(tmp_path, _contract(body))


def test_ignores_non_payable_contract(tmp_path: Path) -> None:
    body = (
        "function ping() external {}\n"
        "function pull(address payable to) external {\n"
        "    to.transfer(address(this).balance);\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))


def test_ignores_interface_payable_prototype(tmp_path: Path) -> None:
    source = (
        "pragma solidity ^0.8.20;\n"
        "interface IVault {\n"
        "    function deposit() external payable;\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_ignores_library(tmp_path: Path) -> None:
    source = (
        "pragma solidity ^0.8.20;\n"
        "library Pay {\n"
        "    function take() internal payable {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_same_file_parent_withdraw_covers_child(tmp_path: Path) -> None:
    source = (
        "pragma solidity ^0.8.20;\n"
        "contract Wallet {\n"
        "    function pull(address payable to) public {\n"
        "        to.transfer(address(this).balance);\n"
        "    }\n"
        "}\n"
        "contract Vault is Wallet {\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_locked_sibling_is_still_flagged(tmp_path: Path) -> None:
    source = (
        "pragma solidity ^0.8.20;\n"
        "contract Open {\n"
        "    receive() external payable {}\n"
        "    function pull(address payable to) external { to.transfer(1); }\n"
        "}\n"
        "contract Locked {\n"
        "    function donate() external payable {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "donate" in findings[0].message


def test_ignore_directive_skips_payable_function(tmp_path: Path) -> None:
    body = "// sibaudit:ignore-next-line\nfunction donate() external payable {}\n"
    assert not _scan(tmp_path, _contract(body))


def test_handles_multiline_payable_header(tmp_path: Path) -> None:
    body = "function donate(\n    uint256 note\n)\n    external\n    payable\n{\n    note;\n}\n"
    findings = _scan(tmp_path, _contract(body))
    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_address_payable_param_does_not_make_function_payable(tmp_path: Path) -> None:
    body = (
        "function setSink(address payable to) external {\n"
        "    to;\n"
        "}\n"
    )
    assert not _scan(tmp_path, _contract(body))

from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

INITIALIZABLE = """
abstract contract Initializable {
    uint64 private _initialized;
    modifier initializer() {
        require(_initialized == 0, "init");
        _initialized = 1;
        _;
    }
    function _disableInitializers() internal {
        _initialized = type(uint64).max;
    }
}
"""


def _scan(tmp_path: Path, source: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(source)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A025"]


def test_flags_public_initialize_without_lock(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    address public owner;\n"
        "    function initialize(address owner_) public {\n"
        "        owner = owner_;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "initialize" in findings[0].message
    assert "without an initializer lock" in findings[0].message
    assert "function initialize" in findings[0].line_text


def test_flags_external_initialize_without_lock(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function initialize() external {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "external" in findings[0].message


def test_flags_reinitialize_without_lock(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function reinitialize() public {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "reinitialize" in findings[0].message


def test_flags_initialize_v2_name(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function initializeV2() public {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "initializeV2" in findings[0].message


def test_allows_initializer_modifier(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    uint64 private _initialized;\n"
        "    modifier initializer() {\n"
        "        require(_initialized == 0);\n"
        "        _initialized = 1;\n"
        "        _;\n"
        "    }\n"
        "    function initialize() public initializer {}\n"
        "}\n"
    )
    # Looks upgradeable because of the lock, so missing disable still flags.
    messages = [f.message for f in _scan(tmp_path, source)]
    assert not any("without an initializer lock" in m for m in messages)
    assert any("_disableInitializers" in m for m in messages)


def test_allows_reinitializer_modifier(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    modifier reinitializer(uint64 n) {\n"
        "        _;\n"
        "    }\n"
        "    function initialize() public reinitializer(2) {}\n"
        "}\n"
    )
    messages = [f.message for f in _scan(tmp_path, source)]
    assert not any("without an initializer lock" in m for m in messages)


def test_allows_only_initializing_modifier(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    modifier onlyInitializing() {\n"
        "        _;\n"
        "    }\n"
        "    function initialize() public onlyInitializing {}\n"
        "}\n"
    )
    messages = [f.message for f in _scan(tmp_path, source)]
    assert not any("without an initializer lock" in m for m in messages)


def test_skips_internal_initialize(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function initialize() internal {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_skips_view_initialize(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function initialize() public view returns (bool) {\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_flags_missing_disable_when_inheriting_initializable(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "contract Vault is Initializable {\n"
        "    address public owner;\n"
        "    function initialize(address owner_) public initializer {\n"
        "        require(owner_ != address(0), \"zero\");\n"
        "        owner = owner_;\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "Vault" in findings[0].message
    assert "_disableInitializers" in findings[0].message
    assert "no constructor" in findings[0].message
    assert "contract Vault" in findings[0].line_text


def test_flags_constructor_that_skips_disable(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "contract Vault is Initializable {\n"
        "    constructor() {}\n"
        "    function initialize() public initializer {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "constructor does not call" in findings[0].message
    assert "constructor()" in findings[0].line_text


def test_allows_constructor_that_disables(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "contract Vault is Initializable {\n"
        "    address public owner;\n"
        "    constructor() {\n"
        "        _disableInitializers();\n"
        "    }\n"
        "    function initialize(address owner_) public initializer {\n"
        "        require(owner_ != address(0), \"zero\");\n"
        "        owner = owner_;\n"
        "    }\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_parent_constructor_covers_child(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "abstract contract Guarded is Initializable {\n"
        "    constructor() {\n"
        "        _disableInitializers();\n"
        "    }\n"
        "}\n"
        "contract Vault is Guarded {\n"
        "    function initialize() public initializer {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_flags_uups_style_upgrade_function(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    function upgradeTo(address next) external {}\n"
        "}\n"
    )
    findings = _scan(tmp_path, source)
    assert len(findings) == 1
    assert "_disableInitializers" in findings[0].message


def test_skips_plain_contract_without_initialize(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    uint256 public n;\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_skips_abstract_missing_disable(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "abstract contract Vault is Initializable {\n"
        "    function initialize() public initializer {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_initializer_lock_is_not_missing_access_control(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        f"{INITIALIZABLE}\n"
        "contract Vault is Initializable {\n"
        "    address public owner;\n"
        "    constructor() {\n"
        "        _disableInitializers();\n"
        "    }\n"
        "    function initialize(address owner_) public initializer {\n"
        "        require(owner_ != address(0), \"zero\");\n"
        "        owner = owner_;\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "C.sol").write_text(source)
    codes = {f.code for f in scan_paths([str(tmp_path)])}
    assert "A009" not in codes
    assert "A025" not in codes


def test_ignore_directive_skips_initialize(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    // sibaudit:ignore-next-line\n"
        "    function initialize() public {}\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)


def test_commented_initialize_is_ignored(tmp_path: Path) -> None:
    source = (
        "pragma solidity 0.8.20;\n"
        "contract Vault {\n"
        "    // function initialize() public {}\n"
        "    uint256 public n;\n"
        "}\n"
    )
    assert not _scan(tmp_path, source)

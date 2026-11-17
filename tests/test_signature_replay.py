from __future__ import annotations

from pathlib import Path

from sibaudit.scanner import scan_paths

HEADER = "pragma solidity 0.8.20;\n"


def _scan(tmp_path: Path, body: str, name: str = "C.sol") -> list:
    (tmp_path / name).write_text(HEADER + body)
    return [f for f in scan_paths([str(tmp_path)]) if f.code == "A026"]


def test_flags_digest_with_no_guards(tmp_path: Path) -> None:
    body = (
        "contract Voucher {\n"
        "    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "        bytes32 digest = keccak256(abi.encode(msg.sender, amount));\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert finding.line_number == 5
    assert "ecrecover" in finding.line_text
    assert '"redeem"' in finding.message
    assert "no nonce, deadline, chain id" in finding.message


def test_lists_only_the_missing_guards(tmp_path: Path) -> None:
    body = (
        "contract Voucher {\n"
        "    mapping(address => uint256) public nonces;\n"
        "    function redeem(uint256 amount, uint256 deadline, bytes calldata sig) external {\n"
        "        bytes32 digest = keccak256(\n"
        "            abi.encode(msg.sender, amount, nonces[msg.sender]++, deadline)\n"
        "        );\n"
        "        address signer = ECDSA.recover(digest, sig);\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert findings[0].message.endswith("no chain id.")


def test_allows_nonce_deadline_and_chain_id(tmp_path: Path) -> None:
    body = (
        "contract Voucher {\n"
        "    mapping(address => uint256) public nonces;\n"
        "    function redeem(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)\n"
        "        external\n"
        "    {\n"
        "        require(block.timestamp <= deadline);\n"
        "        bytes32 digest = keccak256(\n"
        "            abi.encode(block.chainid, msg.sender, amount, nonces[msg.sender]++,\n"
        "                deadline)\n"
        "        );\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_eip712_typed_data_counts_as_chain_binding(tmp_path: Path) -> None:
    body = (
        "contract Permit {\n"
        "    using ECDSA for bytes32;\n"
        "    mapping(address => uint256) public nonces;\n"
        "    function permit(address owner, uint256 deadline, bytes calldata sig) external {\n"
        "        bytes32 structHash = keccak256(abi.encode(owner, nonces[owner]++, deadline));\n"
        "        address signer = _hashTypedDataV4(structHash).recover(sig);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_used_digest_mapping_counts_as_nonce(tmp_path: Path) -> None:
    body = (
        "contract Claims {\n"
        "    mapping(bytes32 => bool) public usedDigests;\n"
        "    function claim(uint256 expiry, uint8 v, bytes32 r, bytes32 s) external {\n"
        "        bytes32 digest = keccak256(abi.encode(block.chainid, msg.sender, expiry));\n"
        "        require(!usedDigests[digest]);\n"
        "        usedDigests[digest] = true;\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_skips_digest_passed_in_already_hashed(tmp_path: Path) -> None:
    # The scanner cannot see inside an opaque digest, so it stays quiet.
    body = (
        "contract Gate {\n"
        "    function check(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external pure {\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_reads_guards_from_a_same_contract_caller(tmp_path: Path) -> None:
    body = (
        "contract Relay {\n"
        "    mapping(address => uint256) public nonces;\n"
        "    function execute(address from, uint256 deadline, bytes calldata sig) external {\n"
        "        bytes32 digest = keccak256(\n"
        "            abi.encode(block.chainid, from, nonces[from]++, deadline)\n"
        "        );\n"
        "        _verify(digest, sig);\n"
        "    }\n"
        "    function _verify(bytes32 digest, bytes calldata sig) internal pure {\n"
        "        address signer = ECDSA.recover(digest, sig);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_flags_helper_when_caller_builds_bare_digest(tmp_path: Path) -> None:
    body = (
        "contract Relay {\n"
        "    function execute(address from, bytes calldata sig) external {\n"
        "        _verify(keccak256(abi.encode(from)), sig);\n"
        "    }\n"
        "    function _verify(bytes32 digest, bytes calldata sig) internal pure {\n"
        "        address signer = ECDSA.recover(digest, sig);\n"
        "    }\n"
        "}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1
    assert '"_verify"' in findings[0].message


def test_signature_checker_is_covered(tmp_path: Path) -> None:
    body = (
        "contract Gate {\n"
        "    function run(address who, bytes calldata sig) external view {\n"
        "        bytes32 digest = keccak256(abi.encode(who));\n"
        "        require(SignatureChecker.isValidSignatureNow(who, digest, sig));\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1


def test_skips_erc1271_verifier_and_libraries(tmp_path: Path) -> None:
    body = (
        "library SigLib {\n"
        "    function check(bytes memory m, uint8 v, bytes32 r, bytes32 s)\n"
        "        internal\n"
        "        pure\n"
        "        returns (address)\n"
        "    {\n"
        "        return ecrecover(keccak256(m), v, r, s);\n"
        "    }\n"
        "}\n"
        "contract Account {\n"
        "    function isValidSignature(bytes32 h, bytes calldata sig)\n"
        "        external\n"
        "        view\n"
        "        returns (bytes4)\n"
        "    {\n"
        "        address signer = ECDSA.recover(keccak256(abi.encode(h)), sig);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_respects_ignore_next_line(tmp_path: Path) -> None:
    body = (
        "contract Voucher {\n"
        "    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "        bytes32 digest = keccak256(abi.encode(msg.sender, amount));\n"
        "        // sibaudit:ignore-next-line\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_comments_are_not_evidence(tmp_path: Path) -> None:
    body = (
        "contract Voucher {\n"
        "    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {\n"
        "        // TODO: add nonce, deadline and chainid\n"
        "        bytes32 digest = keccak256(abi.encode(msg.sender, amount));\n"
        "        address signer = ecrecover(digest, v, r, s);\n"
        "    }\n"
        "}\n"
    )
    assert len(_scan(tmp_path, body)) == 1

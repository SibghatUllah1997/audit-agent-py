from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# Basic risky patterns
TX_ORIGIN_PATTERN = re.compile(r"\btx\.origin\b")
LOW_LEVEL_CALL_PATTERN = re.compile(
    r"\.(?:call|delegatecall|staticcall|callcode)\s*\(", re.IGNORECASE
)
DELEGATECALL_PATTERN = re.compile(r"\.delegatecall\s*\(", re.IGNORECASE)
BOOL_ASSIGN_PATTERN = re.compile(
    # Matches: (bool success, ... ) = something.call(...)
    r"\(\s*bool\s+(?P<var>[A-Za-z_]\w*)\b[\s\S]*?\)\s*=.*?\.(?:call|delegatecall|staticcall|callcode)\s*\(",
    re.IGNORECASE,
)
SELFDESTRUCT_OR_SUICIDE_PATTERN = re.compile(r"\b(?:selfdestruct|suicide)\s*\(", re.IGNORECASE)
TIMESTAMP_PATTERN = re.compile(r"\b(?:block\.timestamp|now)\b")
ARITH_EXPR_PATTERN = re.compile(
    r"(?:[A-Za-z_]\w*|\d+)\s*[\+\-\*\/]\s*(?:[A-Za-z_]\w*|\d+|\()"
)
EXTERNAL_INTERACTION_PATTERN = re.compile(
    r"\.(?:call|delegatecall|callcode|transfer|send)\s*(?:\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)
FUNC_START_PATTERN = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
VISIBILITY_PATTERN = re.compile(r"\b(external|public|internal|private)\b")
VIEW_PURE_PATTERN = re.compile(r"\b(?:view|pure)\b")
TYPE_DECL_HEAD_PATTERN = re.compile(
    r"^\s*\(?\s*(?:"
    r"bool|address(?:\s+payable)?|string(?:\s+(?:memory|calldata|storage))?|"
    r"bytes\d*|bytes(?:\s+(?:memory|calldata|storage))?|"
    r"u?int\d*|mapping\b"
    r")\b",
    re.IGNORECASE,
)
STATE_WRITE_PATTERN = re.compile(
    r"[A-Za-z_]\w*(?:\s*\[[^\]]*\])*\s*(?:\+=|-=|\*=|/=|\|=|&=|\^=|=(?!=))"
)
INCREMENT_PATTERN = re.compile(
    r"(?:\+\+|--)\s*[A-Za-z_]\w*|[A-Za-z_]\w*(?:\s*\[[^\]]*\])*\s*(?:\+\+|--)"
)
DELETE_STATE_PATTERN = re.compile(r"\bdelete\s+[A-Za-z_]\w*")
ACCESS_MODIFIER_PATTERN = re.compile(
    r"\bonly[A-Z]\w*\b|\b(?:onlyRole|restricted|auth|requiresAuth)\b"
)
SENDER_GUARD_PATTERN = re.compile(
    r"require\s*\(\s*(?:msg\.sender\s*==|[A-Za-z_]\w*\s*==\s*msg\.sender)"
    r"|if\s*\(\s*msg\.sender\s*!="
    r"|\bhasRole\s*\(",
    re.IGNORECASE,
)
SENSITIVE_BODY_PATTERN = re.compile(
    r"\b(?:selfdestruct|suicide)\s*\("
    r"|(?<![A-Za-z_])owner\s*=(?!=)"
    r"|\.delegatecall\s*(?:\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)
SENSITIVE_FUNC_NAMES = frozenset(
    {
        "setowner",
        "transferownership",
        "renounceownership",
        "mint",
        "burn",
        "pause",
        "unpause",
        "kill",
        "destroy",
        "nuke",
        "upgradeto",
        "upgrade",
        "initialize",
        "init",
        "sweep",
        "withdrawall",
        "setadmin",
        "changeowner",
        "setprice",
        "setfee",
    }
)
HEADER_SKIP_TOKENS = frozenset(
    {
        "external",
        "public",
        "internal",
        "private",
        "view",
        "pure",
        "payable",
        "virtual",
        "override",
        "returns",
        "memory",
        "calldata",
        "storage",
        "constant",
        "immutable",
        "nonpayable",
    }
)

GASPRICE_PATTERN = re.compile(r"\btx\.gasprice\b")

ASSERT_CALL_PATTERN = re.compile(r"\bassert\s*\((?P<expr>.*)\)")
USER_INPUT_PATTERN = re.compile(
    r"\bmsg\.(?:sender|value|data)\b|\btx\.origin\b|\.balance\b|\bbalanceOf\s*\("
)

REQUIRE_VAR_PATTERN_FMT = r"require\s*\(\s*{var}\s*(?:[,)])"
ASSERT_VAR_PATTERN_FMT = r"assert\s*\(\s*{var}\s*\)"
IF_NOT_VAR_PATTERN_FMT = r"if\s*\(\s*!\s*{var}\s*\)"


@dataclass(frozen=True)
class Finding:
    file_path: Path
    line_number: int
    code: str
    severity: str
    message: str
    line_text: str


@dataclass(frozen=True)
class _FunctionInfo:
    name: str
    start_line: int
    end_line: int
    header: str
    visibility: str
    modifiers: tuple[str, ...]
    is_view_or_pure: bool


def _iter_solidity_files(paths: Iterable[Path]) -> Iterator[Path]:
    for p in paths:
        if p.is_file() and p.suffix.lower() == ".sol":
            yield p
        elif p.is_dir():
            for sub in p.rglob("*.sol"):
                if sub.is_file():
                    yield sub


def _without_line_comment(line: str) -> str:
    idx = line.find("//")
    if idx >= 0:
        return line[:idx]
    return line


def _iter_functions(lines: list[str]) -> Iterator[_FunctionInfo]:
    n = len(lines)
    i = 0
    while i < n:
        match = FUNC_START_PATTERN.search(_without_line_comment(lines[i]))
        if not match:
            i += 1
            continue
        name = match.group(1)
        header_chunks: list[str] = []
        paren = 0
        seen_open_paren = False
        params_closed = False
        body_open_i: int | None = None
        is_proto = False
        j = i
        while j < n:
            piece = _without_line_comment(lines[j])
            header_chunks.append(piece)
            for ch in piece:
                if ch == "(":
                    paren += 1
                    seen_open_paren = True
                elif ch == ")":
                    paren -= 1
                    if seen_open_paren and paren == 0:
                        params_closed = True
                elif params_closed and paren == 0 and ch == "{":
                    body_open_i = j
                    break
                elif params_closed and paren == 0 and ch == ";":
                    is_proto = True
                    break
            if body_open_i is not None or is_proto:
                break
            j += 1
        if is_proto or body_open_i is None:
            i = j + 1
            continue
        brace = 0
        started = False
        end_i = body_open_i
        k = body_open_i
        while k < n:
            piece = _without_line_comment(lines[k])
            for ch in piece:
                if ch == "{":
                    brace += 1
                    started = True
                elif ch == "}":
                    brace -= 1
                    if started and brace == 0:
                        end_i = k
                        break
            if started and brace == 0:
                break
            k += 1
        header = "\n".join(header_chunks)
        vis_match = VISIBILITY_PATTERN.search(header)
        after_params = header.split(")", 1)[-1].split("{", 1)[0]
        tokens = re.findall(r"[A-Za-z_]\w*", after_params)
        yield _FunctionInfo(
            name=name,
            start_line=i + 1,
            end_line=end_i + 1,
            header=header,
            visibility=vis_match.group(1) if vis_match else "",
            modifiers=tuple(t for t in tokens if t not in HEADER_SKIP_TOKENS),
            is_view_or_pure=bool(VIEW_PURE_PATTERN.search(header)),
        )
        i = end_i + 1


def _looks_like_state_write(line: str) -> bool:
    stripped = _without_line_comment(line).strip()
    if not stripped:
        return False
    if TYPE_DECL_HEAD_PATTERN.match(stripped):
        return False
    if DELETE_STATE_PATTERN.search(stripped):
        return True
    if INCREMENT_PATTERN.search(stripped):
        return True
    return bool(STATE_WRITE_PATTERN.search(stripped))


def _detect_tx_origin(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    severity = "MEDIUM"
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if TX_ORIGIN_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A001",
                severity=severity,
                message="Potential risky use of tx.origin (often unsafe for auth).",
                line_text=line.rstrip(),
            )

def _is_pre_0_8_solidity(lines: list[str]) -> bool:
    pragma_re = re.compile(r"^\s*pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
    for raw in lines:
        m = pragma_re.search(raw)
        if not m:
            continue
        spec = m.group(1)
        spec_no_ws = spec.replace(" ", "")
        if "<0.8" in spec_no_ws:
            return True
        mver = re.search(r"[\^~]?\s*0\.(\d+)", spec)
        if mver:
            try:
                minor = int(mver.group(1))
                if minor < 8 and "0.8" not in spec:
                    return True
            except ValueError:
                pass
        if spec_no_ws.startswith(">=") and spec_no_ws.startswith(">=0.") and "0.8" not in spec:
            try:
                minor = int(re.search(r">=0\.(\d+)", spec_no_ws).group(1))  # type: ignore[union-attr]
                if minor < 8:
                    return True
            except Exception:
                continue
    return False


def _detect_pre_08_unchecked_arithmetic(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    if not _is_pre_0_8_solidity(lines):
        return
    severity = "MEDIUM"
    in_block_comment = False
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if "/*" in line:
            in_block_comment = True
        if in_block_comment and "*/" in line:
            in_block_comment = False
            continue
        if in_block_comment:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("pragma "):
            continue
        if "++" in line or "--" in line:
            continue
        if ARITH_EXPR_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A007",
                severity=severity,
                message="Unchecked arithmetic in pre-0.8 Solidity (overflow/underflow risk).",
                line_text=line.rstrip(),
            )

def _detect_unchecked_low_level_call(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Simple heuristic:
    # 1) If a low-level call appears without assigning (bool var, ...) = ...call(...):
    #    flag it
    # 2) If assigned to (bool var, ...), ensure a nearby check exists:
    #    require(var), assert(var), or if(!var) { revert/... }
    window = 3  # lines to look ahead for checks
    severity = "MEDIUM"
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        call_match = LOW_LEVEL_CALL_PATTERN.search(line)
        if not call_match:
            continue

        # Case: tuple assignment capturing bool success?
        tuple_assign = BOOL_ASSIGN_PATTERN.search(line)
        if tuple_assign:
            var_name = tuple_assign.group("var")
            # Look ahead a few lines for an obvious check of var_name
            for look_ahead in range(0, min(window, len(lines) - idx)):
                future_line = lines[idx + look_ahead].strip()
                if re.search(REQUIRE_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
                if re.search(ASSERT_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
                if re.search(IF_NOT_VAR_PATTERN_FMT.format(var=re.escape(var_name)), future_line):
                    break
            else:
                # No check found in the window; flag as potentially unchecked
                yield Finding(
                    file_path=file_path,
                    line_number=idx,
                    code="A002",
                    severity=severity,
                    message="Low-level call success not obviously checked (heuristic).",
                    line_text=line.rstrip(),
                )
            continue

        # No tuple assignment found on this line — highly likely unchecked
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A002",
            severity=severity,
            message="Low-level call without capturing/validating success (heuristic).",
            line_text=line.rstrip(),
        )


def _detect_delegatecall_usage(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Flag any usage of delegatecall regardless of success checks.
    # delegatecall executes code in the caller's context and is often dangerous
    # unless used in a well-reviewed proxy pattern.
    severity = "HIGH"
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if DELEGATECALL_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A003",
                severity=severity,
                message="Use of delegatecall detected; review proxy pattern and calldata handling.",
                line_text=line.rstrip(),
            )


def _detect_selfdestruct_or_suicide(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    severity = "HIGH"
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if SELFDESTRUCT_OR_SUICIDE_PATTERN.search(line):
            keyword = "selfdestruct" if "selfdestruct" in line.lower() else "suicide"
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A004",
                severity=severity,
                message=f"Use of {keyword} detected; can brick contracts and break integrations.",
                line_text=line.rstrip(),
            )


def _detect_state_var_shadowing(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Heuristic: collect state variable names declared at contract scope, then
    # flag any function parameter that reuses the same identifier.
    severity = "LOW"
    state_vars: set[str] = set()
    in_contract = False
    brace_depth = 0

    # First pass: gather state variables
    for raw in lines:
        line = raw.strip()
        # Track braces to approximate contract scope
        brace_depth += raw.count("{")
        brace_depth -= raw.count("}")
        if line.startswith("contract "):
            in_contract = True
        if in_contract and ";" in raw:
            lower = line.lower()
            if any(
                k in lower
                for k in (
                    "function ",
                    "event ",
                    "struct ",
                    "enum ",
                    "modifier ",
                    "using ",
                    "error ",
                )
            ):
                continue
            # Extract the last identifier token before the semicolon as the variable name
            identifiers = re.findall(r"[A-Za-z_]\w*", raw)
            if identifiers:
                candidate = identifiers[-1]
                # Basic guard: avoid common qualifiers accidentally captured
                if candidate not in {
                    "public",
                    "private",
                    "internal",
                    "external",
                    "constant",
                    "immutable",
                    "memory",
                    "calldata",
                    "storage",
                    "payable",
                    "view",
                    "pure",
                    "virtual",
                    "override",
                }:
                    state_vars.add(candidate)
        if in_contract and brace_depth <= 0:
            in_contract = False

    # Second pass: check function parameter lists
    func_sig = re.compile(r"\bfunction\b[^{;]*\((?P<params>[^)]*)\)")
    for idx, raw in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        m = func_sig.search(raw)
        if not m:
            continue
        params = m.group("params")
        for part in params.split(","):
            part = part.strip()
            if not part:
                continue
            identifiers = re.findall(r"[A-Za-z_]\w*", part)
            if not identifiers:
                continue
            candidate = identifiers[-1]
            if candidate in state_vars:
                yield Finding(
                    file_path=file_path,
                    line_number=idx,
                    code="A005",
                    severity=severity,
                    message=f'Function parameter "{candidate}" shadows a state variable.',
                    line_text=raw.rstrip(),
                )

def _detect_block_timestamp_usage(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    severity = "MEDIUM"
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        # Skip one-line block comments
        if "/*" in line and "*/" in line:
            continue
        if TIMESTAMP_PATTERN.search(line):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A006",
                severity=severity,
                message="Use of block.timestamp/now detected; time can be manipulated slightly.",
                line_text=line.rstrip(),
            )


def _detect_missing_access_control(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Heuristic: public/external functions that look privileged (by name or body)
    # and have no obvious modifier or msg.sender check.
    severity = "HIGH"
    for func in _iter_functions(lines):
        if ignore_next_lines and func.start_line in ignore_next_lines:
            continue
        if func.is_view_or_pure:
            continue
        if func.visibility in {"internal", "private"}:
            continue
        body = "\n".join(
            _without_line_comment(lines[idx])
            for idx in range(func.start_line - 1, func.end_line)
        )
        name_hit = func.name.lower() in SENSITIVE_FUNC_NAMES
        body_hit = bool(SENSITIVE_BODY_PATTERN.search(body))
        if not name_hit and not body_hit:
            continue
        if ACCESS_MODIFIER_PATTERN.search(func.header):
            continue
        if SENDER_GUARD_PATTERN.search(body):
            continue
        yield Finding(
            file_path=file_path,
            line_number=func.start_line,
            code="A009",
            severity=severity,
            message="Sensitive function appears to lack access control (heuristic).",
            line_text=lines[func.start_line - 1].rstrip(),
        )


def _detect_reentrancy_prone_calls(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Heuristic: in a mutating function, an external call that is later
    # followed by a storage write is the classic checks-effects-interactions miss.
    severity = "HIGH"
    for func in _iter_functions(lines):
        if func.is_view_or_pure:
            continue
        call_lines: list[int] = []
        write_lines: list[int] = []
        for lineno in range(func.start_line, func.end_line + 1):
            raw = lines[lineno - 1]
            code = _without_line_comment(raw)
            if EXTERNAL_INTERACTION_PATTERN.search(code):
                call_lines.append(lineno)
            if _looks_like_state_write(raw):
                write_lines.append(lineno)
        for call_line in call_lines:
            if ignore_next_lines and call_line in ignore_next_lines:
                continue
            if any(write_line > call_line for write_line in write_lines):
                yield Finding(
                    file_path=file_path,
                    line_number=call_line,
                    code="A008",
                    severity=severity,
                    message="External call before state update looks reentrancy-prone (heuristic).",
                    line_text=lines[call_line - 1].rstrip(),
                )


def _detect_tx_gasprice_usage(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if GASPRICE_PATTERN.search(_without_line_comment(line)):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A010",
                severity="LOW",
                message="Logic relies on tx.gasprice, which the sender fully controls.",
                line_text=line.rstrip(),
            )


def _detect_assert_misuse(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # assert() is for invariants that should never fail. Checks on caller input,
    # sent value, or balances are business rules and belong in require().
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        match = ASSERT_CALL_PATTERN.search(_without_line_comment(line))
        if match and USER_INPUT_PATTERN.search(match.group("expr")):
            yield Finding(
                file_path=file_path,
                line_number=idx,
                code="A011",
                severity="LOW",
                message="assert() checks caller input or balances; use require() instead.",
                line_text=line.rstrip(),
            )


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    root_paths = [Path(p).resolve() for p in paths]
    findings: list[Finding] = []
    for file_path in _iter_solidity_files(root_paths):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            # Skip unreadable files
            continue
        lines = content.splitlines()
        # Build ignore set: for any line containing the directive, ignore the next line index.
        ignore_next_lines: set[int] = set()
        for idx, line in enumerate(lines, start=1):
            if "sibaudit:ignore-next-line" in line:
                ignore_next_lines.add(idx + 1)

        findings.extend(_detect_tx_origin(lines, file_path, ignore_next_lines))
        findings.extend(_detect_unchecked_low_level_call(lines, file_path, ignore_next_lines))
        findings.extend(_detect_delegatecall_usage(lines, file_path, ignore_next_lines))
        findings.extend(_detect_selfdestruct_or_suicide(lines, file_path, ignore_next_lines))
        findings.extend(_detect_state_var_shadowing(lines, file_path, ignore_next_lines))
        findings.extend(_detect_block_timestamp_usage(lines, file_path, ignore_next_lines))
        findings.extend(_detect_pre_08_unchecked_arithmetic(lines, file_path, ignore_next_lines))
        findings.extend(_detect_reentrancy_prone_calls(lines, file_path, ignore_next_lines))
        findings.extend(_detect_missing_access_control(lines, file_path, ignore_next_lines))
        findings.extend(_detect_tx_gasprice_usage(lines, file_path, ignore_next_lines))
        findings.extend(_detect_assert_misuse(lines, file_path, ignore_next_lines))
    return findings


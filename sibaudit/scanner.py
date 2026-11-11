from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from .globs import is_selected

# Basic risky patterns
TX_ORIGIN_PATTERN = re.compile(r"\btx\.origin\b")
TX_ORIGIN_COMPARE_PATTERN = re.compile(
    r"tx\.origin\s*(?:==|!=)|(?:==|!=)\s*tx\.origin"
)
TX_ORIGIN_VS_SENDER_PATTERN = re.compile(
    r"tx\.origin\s*(?:==|!=)\s*msg\.sender|msg\.sender\s*(?:==|!=)\s*tx\.origin"
)
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
CALLABLE_START_PATTERN = re.compile(
    r"(?<![\w.])(?:function\s+(?P<func>[A-Za-z_]\w*)|(?P<ctor>constructor)|"
    r"(?P<special>receive|fallback))\s*\("
)
TYPE_START_PATTERN = re.compile(
    r"\b(?P<abstract>abstract\s+)?(?P<kind>contract|library|interface)\s+(?P<name>[A-Za-z_]\w*)"
)
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

EVENT_DECL_PATTERN = re.compile(r"\bevent\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)")
VALUE_EVENT_NAME_PATTERN = re.compile(
    r"transfer|deposit|withdraw|mint|burn|payment|purchase|bid|sale|"
    r"payout|reward|fee|donate|stake|unstake|claim",
    re.IGNORECASE,
)
ADDRESS_EVENT_NAME_PATTERN = re.compile(
    r"transfer|approval|owner|admin|operator|deposit|withdraw|mint|burn|"
    r"claim|stake|send|receive",
    re.IGNORECASE,
)
UINT_PARAM_PATTERN = re.compile(r"\bu?int(?:\d+)?\b", re.IGNORECASE)
ADDRESS_PARAM_PATTERN = re.compile(r"\baddress\b", re.IGNORECASE)
BLOCKHASH_CALL_PATTERN = re.compile(r"\b(?:blockhash|block\.blockhash)\s*\(", re.IGNORECASE)
BLOCKHASH_CURRENT_PATTERN = re.compile(
    r"\b(?:blockhash|block\.blockhash)\s*\(\s*block\.number\s*\)",
    re.IGNORECASE,
)

ASSERT_CALL_PATTERN = re.compile(r"\bassert\s*\((?P<expr>.*)\)")
USER_INPUT_PATTERN = re.compile(
    r"\bmsg\.(?:sender|value|data)\b|\btx\.origin\b|\.balance\b|\bbalanceOf\s*\("
)

ADDRESS_DECL_NO_INIT_PATTERN = re.compile(
    r"^\s*address(?:\s+payable)?"
    r"(?:\s+(?:public|private|internal|immutable|override))*"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*;"
)
STRUCT_START_PATTERN = re.compile(r"\bstruct\s+[A-Za-z_]\w*\s*\{")
ASSIGN_TARGET_FMT = r"\b{name}\b(?:\s*\[[^\]]*\])*\s*(?::=|=(?!=))"
TUPLE_ASSIGN_FMT = r"\([^()]*\b{name}\b[^()]*\)\s*=(?!=)"

ADDRESS_PARAM_NAME_PATTERN = re.compile(
    r"\baddress(?:\s+payable)?(?!\s*\[)"
    r"(?:\s+(?:memory|calldata|storage))?"
    r"\s+(?P<name>[A-Za-z_]\w*)",
    re.IGNORECASE,
)
LOCAL_ADDRESS_DECL_PATTERN = re.compile(
    r"\baddress(?:\s+payable)?(?:\s+(?:memory|calldata|storage))?"
    r"\s+(?P<name>[A-Za-z_]\w*)",
    re.IGNORECASE,
)
ZERO_ADDRESS_CHECK_FMT = (
    r"(?:"
    r"{name}\s*(?:!=|==)\s*address\s*\(\s*0(?:x0+)?\s*\)"
    r"|address\s*\(\s*0(?:x0+)?\s*\)\s*(?:!=|==)\s*{name}"
    r")"
)
STORE_PARAM_FMT = (
    r"\b(?P<lhs>[A-Za-z_]\w*)\s*=(?!=)\s*"
    r"(?:(?:payable|address|[A-Z][A-Za-z0-9_]*)\s*\(\s*)?{name}\b"
)

MAGIC_LITERAL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<lit>\d(?:_?\d)*(?:\.\d(?:_?\d)*)?(?:[eE]\d+)?)"
    r"(?![A-Za-z_0-9])"
)
CONSTANT_OR_IMMUTABLE_PATTERN = re.compile(r"\b(?:constant|immutable)\b", re.IGNORECASE)
ENUM_START_PATTERN = re.compile(r"\benum\s+[A-Za-z_]\w*\s*\{")
PRAGMA_OR_IMPORT_PATTERN = re.compile(r"^\s*(?:pragma|import)\b", re.IGNORECASE)
TRIVIAL_NUMBER_VALUES = frozenset({0, 1})

CTOR_LOW_LEVEL_CALL_PATTERN = re.compile(
    r"\.(?P<method>call|delegatecall|staticcall|transfer|send)\s*(?:\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)
CTOR_CAST_CALL_PATTERN = re.compile(
    r"\b(?P<type>[A-Z]\w*)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\.\s*[A-Za-z_]\w*\s*"
    r"(?:\{[^}]*\})?\s*\("
)
CTOR_THIS_CALL_PATTERN = re.compile(r"\bthis\s*\.\s*[A-Za-z_]\w*\s*\(")
CONTRACT_TYPED_NAME_PATTERN = re.compile(
    r"\b(?P<type>[A-Z]\w*)(?:\s+(?:public|private|internal|immutable|memory|calldata|storage))*"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*(?=[,;)=])"
)
MEMBER_CALL_FMT = r"(?<![\w.]){name}\s*\.\s*[A-Za-z_]\w*\s*(?:\{{[^}}]*\}})?\s*\("
NON_CONTRACT_TYPES = frozenset({"Error", "Panic"})
CALL_WITH_VALUE_PATTERN = re.compile(
    r"\.\s*call\s*\{[^}]*\bvalue\s*:",
    re.IGNORECASE,
)
ETHER_SEND_PATTERN = re.compile(r"\.\s*send\s*\(")
ETHER_TRANSFER_OPEN_PATTERN = re.compile(r"\.\s*transfer\s*\(")
CONTRACT_DECL_PATTERN = re.compile(r"(?:abstract\s+)?contract\s+[A-Za-z_]\w*\b")
MODIFIER_START_PATTERN = re.compile(r"\bmodifier\s+(?P<name>[A-Za-z_]\w*)\b")
OWNER_MODIFIER_NAMES = frozenset(
    {
        "onlyowner",
        "onlyadmin",
        "onlygovernance",
        "onlyguardian",
        "onlyminter",
    }
)
MODIFIER_PLACEHOLDER_PATTERN = re.compile(r"(?<![A-Za-z0-9_])_;")
SENDER_EXPR = r"(?:msg\.sender|_msgSender\s*\(\s*\))"
SENDER_COMPARE_PATTERN = re.compile(rf"{SENDER_EXPR}\s*(?:==|!=)|(?:==|!=)\s*{SENDER_EXPR}")
SENDER_TAUTOLOGY_PATTERN = re.compile(rf"{SENDER_EXPR}\s*(?:==|!=)\s*{SENDER_EXPR}")
OWNER_HELPER_PATTERN = re.compile(
    r"\b(?:hasRole|_checkOwner|_checkRole|isOwner|_isOwner|onlyRole)\s*\("
)
TX_ORIGIN_COMPARE_IN_MOD_PATTERN = re.compile(
    r"tx\.origin\s*(?:==|!=)|(?:==|!=)\s*tx\.origin"
)
REQUIRE_TRUE_PATTERN = re.compile(r"\brequire\s*\(\s*true\s*[,)]")

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


@dataclass(frozen=True)
class _ContractInfo:
    name: str
    kind: str
    is_abstract: bool
    start_line: int
    end_line: int
    bases: tuple[str, ...]


@dataclass(frozen=True)
class _ModifierInfo:
    name: str
    start_line: int
    end_line: int
    header: str


def _iter_solidity_files(
    paths: Iterable[Path],
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> Iterator[Path]:
    for p in paths:
        if p.is_file() and p.suffix.lower() == ".sol":
            # A file given directly is matched by its name only.
            if is_selected(p.name, include, exclude):
                yield p
        elif p.is_dir():
            for sub in sorted(p.rglob("*.sol")):
                if sub.is_file() and is_selected(sub.relative_to(p).as_posix(), include, exclude):
                    yield sub


def _without_line_comment(line: str) -> str:
    idx = line.find("//")
    if idx >= 0:
        return line[:idx]
    return line


def _iter_functions(
    lines: list[str], *, include_constructors: bool = False
) -> Iterator[_FunctionInfo]:
    n = len(lines)
    i = 0
    while i < n:
        match = CALLABLE_START_PATTERN.search(_without_line_comment(lines[i]))
        if not match:
            i += 1
            continue
        name = match.group("func") or match.group("special") or "constructor"
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
        if name != "constructor" or include_constructors:
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


def _detect_tx_origin_auth_comparison(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Deeper than A001: equality checks are how tx.origin is used as auth,
    # including the phishing-prone "tx.origin == msg.sender" EOA-only guard.
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        code = _without_line_comment(line)
        if not TX_ORIGIN_COMPARE_PATTERN.search(code):
            continue
        if TX_ORIGIN_VS_SENDER_PATTERN.search(code):
            message = (
                "tx.origin == msg.sender does not stop phishing; "
                "a malicious contract can still relay the call."
            )
        else:
            message = "tx.origin used in an authorization comparison; prefer msg.sender."
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A014",
            severity="HIGH",
            message=message,
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
    # flag any function parameter that reuses the same identifier. Only lines at
    # the top level of a contract body count as declarations; statements inside
    # functions or modifiers (e.g. `balances[to] += amount;`) are not state.
    severity = "LOW"
    state_vars: set[str] = set()
    in_contract = False
    brace_depth = 0

    # First pass: gather state variables
    for raw in lines:
        code = _without_line_comment(raw)
        line = code.strip()
        depth_before = brace_depth
        brace_depth += code.count("{")
        brace_depth -= code.count("}")
        if CONTRACT_DECL_PATTERN.match(line):
            in_contract = True
            continue
        if in_contract and depth_before == 1 and ";" in code:
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
            # The declared name is the last identifier before `=` or `;`.
            declaration = re.split(r"=|;", code, maxsplit=1)[0]
            identifiers = re.findall(r"[A-Za-z_]\w*", declaration)
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
    # Match the first parenthesised list (inputs), not a later `returns (...)`.
    func_sig = re.compile(r"\bfunction\b[^({;]*\((?P<params>[^)]*)\)")
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


def _detect_blockhash_misuse(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # blockhash is only defined for the 256 most recent blocks, is miner-
    # influenceable, and blockhash(block.number) is always zero.
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if "/*" in line and "*/" in line:
            continue
        code = _without_line_comment(line)
        if not BLOCKHASH_CALL_PATTERN.search(code):
            continue
        if BLOCKHASH_CURRENT_PATTERN.search(code):
            message = "blockhash(block.number) is always zero and cannot seed randomness."
        else:
            message = (
                "blockhash is miner-influenceable and only defined for the last 256 blocks."
            )
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A013",
            severity="MEDIUM",
            message=message,
            line_text=line.rstrip(),
        )


def _detect_events_missing_critical_params(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Events that record value movement or privilege changes should carry the
    # amount and/or address so off-chain indexers can reconstruct what happened.
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        code = _without_line_comment(line)
        match = EVENT_DECL_PATTERN.search(code)
        if not match:
            continue
        name = match.group("name")
        params = match.group("params")
        missing: list[str] = []
        if VALUE_EVENT_NAME_PATTERN.search(name) and not UINT_PARAM_PATTERN.search(params):
            missing.append("amount")
        if ADDRESS_EVENT_NAME_PATTERN.search(name) and not ADDRESS_PARAM_PATTERN.search(params):
            missing.append("address")
        if not missing:
            continue
        detail = " and ".join(missing)
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A012",
            severity="LOW",
            message=f'Event "{name}" is missing a critical {detail} parameter.',
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


def _struct_body_lines(lines: list[str]) -> set[int]:
    # Struct members are field layouts, not variables, so they are never "assigned".
    inside: set[int] = set()
    depth = 0
    for idx, line in enumerate(lines, start=1):
        code = _without_line_comment(line)
        if depth == 0 and STRUCT_START_PATTERN.search(code):
            depth = code.count("{") - code.count("}")
            continue
        if depth > 0:
            inside.add(idx)
            depth += code.count("{") - code.count("}")
    return inside


def _is_assigned(name: str, lines: list[str], start: int, end: int, skip: int) -> bool:
    assign = re.compile(ASSIGN_TARGET_FMT.format(name=re.escape(name)))
    tuple_assign = re.compile(TUPLE_ASSIGN_FMT.format(name=re.escape(name)))
    for lineno in range(start, end + 1):
        if lineno == skip:
            continue
        code = _without_line_comment(lines[lineno - 1])
        if assign.search(code) or tuple_assign.search(code):
            return True
    return False


def _detect_uninitialized_address(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # An address declared without a value and never assigned stays address(0).
    # State variables are searched across the whole file (constructor, setters);
    # locals only inside their own function.
    struct_lines = _struct_body_lines(lines)
    functions = list(_iter_functions(lines))
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if idx in struct_lines:
            continue
        match = ADDRESS_DECL_NO_INIT_PATTERN.match(_without_line_comment(line))
        if not match:
            continue
        name = match.group("name")
        owner_func = next((f for f in functions if f.start_line <= idx <= f.end_line), None)
        if owner_func is None:
            start, end, kind = 1, len(lines), "State"
        else:
            start, end, kind = owner_func.start_line, owner_func.end_line, "Local"
        if _is_assigned(name, lines, start, end, skip=idx):
            continue
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A015",
            severity="MEDIUM",
            message=f'{kind} address "{name}" is never assigned and stays address(0).',
            line_text=line.rstrip(),
        )


def _callable_params(header: str) -> str:
    """Return the parameter list inside the first parenthesized group of `header`."""
    start = header.find("(")
    if start < 0:
        return ""
    depth = 0
    for index, char in enumerate(header[start:], start=start):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return header[start + 1 : index]
    return ""


def _address_param_names(params: str) -> tuple[str, ...]:
    """Address argument names from a Solidity parameter list."""
    return tuple(match.group("name") for match in ADDRESS_PARAM_NAME_PATTERN.finditer(params))


def _has_zero_address_check(body: str, name: str) -> bool:
    """True if `name` is compared to address(0) anywhere in `body`."""
    pattern = re.compile(ZERO_ADDRESS_CHECK_FMT.format(name=re.escape(name)), re.IGNORECASE)
    return bool(pattern.search(body))


def _function_source(lines: list[str], func: _FunctionInfo) -> str:
    """Join a function header and body with line comments stripped."""
    return "\n".join(
        _without_line_comment(lines[index])
        for index in range(func.start_line - 1, func.end_line)
    )


def _enum_body_lines(lines: list[str]) -> set[int]:
    """Line numbers that sit inside an enum body (member names, not magic values)."""
    inside: set[int] = set()
    depth = 0
    for idx, line in enumerate(lines, start=1):
        code = _without_line_comment(line)
        if depth == 0 and ENUM_START_PATTERN.search(code):
            depth = code.count("{") - code.count("}")
            continue
        if depth > 0:
            inside.add(idx)
            depth += code.count("{") - code.count("}")
    return inside


def _is_trivial_number(literal: str) -> bool:
    """True for 0/1 in decimal, scientific, or dotted form."""
    normalized = literal.replace("_", "")
    try:
        if "." in normalized or "e" in normalized.lower():
            return float(normalized) in (0.0, 1.0)
        return int(normalized) in TRIVIAL_NUMBER_VALUES
    except ValueError:
        return False


def _detect_magic_numbers(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Bare numeric literals in logic are harder to review than named constants.
    enum_lines = _enum_body_lines(lines)
    for idx, line in enumerate(lines, start=1):
        if ignore_next_lines and idx in ignore_next_lines:
            continue
        if idx in enum_lines:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if "/*" in line and "*/" in line:
            continue
        code = _without_line_comment(line)
        if not code.strip():
            continue
        if PRAGMA_OR_IMPORT_PATTERN.match(code):
            continue
        if CONSTANT_OR_IMMUTABLE_PATTERN.search(code):
            continue
        literals = [
            match.group("lit")
            for match in MAGIC_LITERAL_PATTERN.finditer(code)
            if not _is_trivial_number(match.group("lit"))
        ]
        if not literals:
            continue
        unique = list(dict.fromkeys(literals))
        if len(unique) == 1:
            detail = f"Magic number {unique[0]} is not a named constant."
        else:
            joined = ", ".join(unique)
            detail = f"Magic numbers {joined} are not named constants."
        yield Finding(
            file_path=file_path,
            line_number=idx,
            code="A017",
            severity="LOW",
            message=detail,
            line_text=line.rstrip(),
        )


def _detect_missing_zero_address_check(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Address parameters copied into storage without an address(0) guard can
    # permanently lock ownership, token, or treasury slots.
    for func in _iter_functions(lines, include_constructors=True):
        if func.is_view_or_pure:
            continue
        params = _address_param_names(_callable_params(func.header))
        if not params:
            continue
        body = _function_source(lines, func)
        local_names = {match.group("name") for match in LOCAL_ADDRESS_DECL_PATTERN.finditer(body)}
        for name in params:
            if _has_zero_address_check(body, name):
                continue
            store = re.compile(STORE_PARAM_FMT.format(name=re.escape(name)))
            for lineno in range(func.start_line, func.end_line + 1):
                if ignore_next_lines and lineno in ignore_next_lines:
                    continue
                code = _without_line_comment(lines[lineno - 1])
                match = store.search(code)
                if not match:
                    continue
                lhs = match.group("lhs")
                if lhs == name or lhs in local_names:
                    continue
                yield Finding(
                    file_path=file_path,
                    line_number=lineno,
                    code="A016",
                    severity="MEDIUM",
                    message=(
                        f'Address parameter "{name}" is stored without a zero-address check.'
                    ),
                    line_text=lines[lineno - 1].rstrip(),
                )


def _contract_typed_names(text: str) -> set[str]:
    """Names declared with a capitalized (contract or interface) type in `text`."""
    names: set[str] = set()
    for match in CONTRACT_TYPED_NAME_PATTERN.finditer(text):
        if match.group("type") in NON_CONTRACT_TYPES:
            continue
        names.add(match.group("name"))
    return names


def _state_level_lines(lines: list[str]) -> list[str]:
    """Lines outside any function or constructor body (state declarations)."""
    inside: set[int] = set()
    for func in _iter_functions(lines, include_constructors=True):
        inside.update(range(func.start_line, func.end_line + 1))
    return [
        _without_line_comment(line)
        for idx, line in enumerate(lines, start=1)
        if idx not in inside
    ]


def _external_call_kind(code: str, typed_names: set[str]) -> str | None:
    """Describe the external call on `code`, or None if it has none."""
    low_level = CTOR_LOW_LEVEL_CALL_PATTERN.search(code)
    if low_level:
        return f"call via .{low_level.group('method')}()"
    if CTOR_THIS_CALL_PATTERN.search(code):
        return "call through this (no code is deployed yet)"
    for match in CTOR_CAST_CALL_PATTERN.finditer(code):
        if match.group("type") not in NON_CONTRACT_TYPES:
            return f"call on {match.group('type')}(...)"  # cast-then-call, e.g. IERC20(t).x()
    for name in sorted(typed_names):
        if re.search(MEMBER_CALL_FMT.format(name=re.escape(name)), code):
            return f'call on contract "{name}"'
    return None


def _detect_constructor_external_calls(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Calling out while the contract is half-built hands control to code that
    # can re-enter or observe uninitialized state, and the address may be wrong.
    state_names = _contract_typed_names("\n".join(_state_level_lines(lines)))
    for func in _iter_functions(lines, include_constructors=True):
        if func.name != "constructor":
            continue
        source = _function_source(lines, func)
        typed_names = state_names | _contract_typed_names(source)
        body_start = func.start_line
        for lineno in range(func.start_line, func.end_line + 1):
            if "{" in _without_line_comment(lines[lineno - 1]):
                body_start = lineno
                break
        for lineno in range(body_start, func.end_line + 1):
            if ignore_next_lines and lineno in ignore_next_lines:
                continue
            code = _without_line_comment(lines[lineno - 1])
            if lineno == body_start:
                code = code.split("{", 1)[1]
            kind = _external_call_kind(code, typed_names)
            if kind is None:
                continue
            yield Finding(
                file_path=file_path,
                line_number=lineno,
                code="A018",
                severity="MEDIUM",
                message=f"External {kind} inside a constructor; the contract is not fully set up.",
                line_text=lines[lineno - 1].rstrip(),
            )


def _parse_bases(header: str) -> tuple[str, ...]:
    """Base contract names from a `contract X is A, B(1)` header."""
    match = re.search(r"\bis\b(?P<bases>[^{]*)\{", header, re.DOTALL)
    if not match:
        return ()
    names: list[str] = []
    depth = 0
    current: list[str] = []
    for char in match.group("bases"):
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            continue
        if char == "," and depth == 0:
            ident = re.findall(r"[A-Za-z_]\w*", "".join(current))
            if ident:
                names.append(ident[0])
            current = []
            continue
        if depth == 0:
            current.append(char)
    ident = re.findall(r"[A-Za-z_]\w*", "".join(current))
    if ident:
        names.append(ident[0])
    return tuple(names)


def _iter_contracts(lines: list[str]) -> Iterator[_ContractInfo]:
    n = len(lines)
    i = 0
    while i < n:
        match = TYPE_START_PATTERN.search(_without_line_comment(lines[i]))
        if not match:
            i += 1
            continue
        header_chunks: list[str] = []
        body_open_i: int | None = None
        is_proto = False
        j = i
        while j < n:
            piece = _without_line_comment(lines[j])
            header_chunks.append(piece)
            if "{" in piece:
                body_open_i = j
                break
            if ";" in piece:
                is_proto = True
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
        yield _ContractInfo(
            name=match.group("name"),
            kind=match.group("kind"),
            is_abstract=bool(match.group("abstract")),
            start_line=i + 1,
            end_line=end_i + 1,
            bases=_parse_bases(header),
        )
        i = end_i + 1


def _extract_paren_args(text: str, open_index: int) -> str | None:
    """Return the text inside the parenthesis group that starts at `open_index`."""
    if open_index >= len(text) or text[open_index] != "(":
        return None
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    return None


def _has_top_level_comma(args: str) -> bool:
    depth = 0
    for char in args:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            return True
    return False


def _sends_ether(code: str) -> bool:
    """True if `code` sends ether (not an ERC-20 transfer)."""
    if SELFDESTRUCT_OR_SUICIDE_PATTERN.search(code):
        return True
    if ETHER_SEND_PATTERN.search(code):
        return True
    if CALL_WITH_VALUE_PATTERN.search(code):
        return True
    for match in ETHER_TRANSFER_OPEN_PATTERN.finditer(code):
        args = _extract_paren_args(code, match.end() - 1)
        if args is None:
            continue
        if not _has_top_level_comma(args):
            return True
    return False


def _header_is_payable(header: str, name: str) -> bool:
    """True if this callable can receive ether."""
    if name == "receive":
        return True
    after_params = header.split(")", 1)[-1].split("{", 1)[0]
    return bool(re.search(r"\bpayable\b", after_params))


def _payable_entry_label(func: _FunctionInfo) -> str:
    if func.name == "constructor":
        return "Payable constructor"
    if func.name == "receive":
        return "Payable receive()"
    if func.name == "fallback":
        return "Payable fallback()"
    return f'Payable function "{func.name}"'


def _contract_family_names(
    contract: _ContractInfo, by_name: dict[str, _ContractInfo]
) -> set[str]:
    """This contract plus same-file ancestors, following `is` lists."""
    family = {contract.name}
    stack = list(contract.bases)
    while stack:
        base = stack.pop()
        if base in family:
            continue
        family.add(base)
        parent = by_name.get(base)
        if parent is not None:
            stack.extend(parent.bases)
    return family


def _detect_payable_without_withdraw(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # Ether that can enter a contract with no way out is stuck forever.
    # Same-file parents count as a withdraw path so inherited wallets are quiet.
    contracts = [c for c in _iter_contracts(lines) if c.kind == "contract"]
    if not contracts:
        return
    by_name = {c.name: c for c in contracts}
    functions = list(_iter_functions(lines, include_constructors=True))
    for contract in contracts:
        family = _contract_family_names(contract, by_name)
        family_source_parts: list[str] = []
        for member in contracts:
            if member.name not in family:
                continue
            family_source_parts.append(
                "\n".join(
                    _without_line_comment(lines[idx])
                    for idx in range(member.start_line - 1, member.end_line)
                )
            )
        if _sends_ether("\n".join(family_source_parts)):
            continue
        for func in functions:
            if not (contract.start_line <= func.start_line <= contract.end_line):
                continue
            if ignore_next_lines and func.start_line in ignore_next_lines:
                continue
            if func.is_view_or_pure:
                continue
            if func.name != "constructor" and func.visibility in {"internal", "private"}:
                continue
            if not _header_is_payable(func.header, func.name):
                continue
            label = _payable_entry_label(func)
            yield Finding(
                file_path=file_path,
                line_number=func.start_line,
                code="A019",
                severity="MEDIUM",
                message=f"{label} can receive ether, but the contract has no withdraw path.",
                line_text=lines[func.start_line - 1].rstrip(),
            )


def _iter_modifiers(lines: list[str]) -> Iterator[_ModifierInfo]:
    n = len(lines)
    i = 0
    while i < n:
        match = MODIFIER_START_PATTERN.search(_without_line_comment(lines[i]))
        if not match:
            i += 1
            continue
        header_chunks: list[str] = []
        body_open_i: int | None = None
        is_proto = False
        j = i
        while j < n:
            piece = _without_line_comment(lines[j])
            header_chunks.append(piece)
            if "{" in piece:
                body_open_i = j
                break
            if ";" in piece:
                is_proto = True
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
        yield _ModifierInfo(
            name=match.group("name"),
            start_line=i + 1,
            end_line=end_i + 1,
            header="\n".join(header_chunks),
        )
        i = end_i + 1


def _is_owner_modifier_name(name: str) -> bool:
    return name.lower() in OWNER_MODIFIER_NAMES


def _modifier_source(lines: list[str], modifier: _ModifierInfo) -> str:
    return "\n".join(
        _without_line_comment(lines[idx])
        for idx in range(modifier.start_line - 1, modifier.end_line)
    )


def _has_real_sender_compare(text: str) -> bool:
    for match in SENDER_COMPARE_PATTERN.finditer(text):
        window = text[max(0, match.start() - 48) : match.end() + 48]
        if SENDER_TAUTOLOGY_PATTERN.search(window):
            continue
        return True
    return False


def _has_auth_check(text: str) -> bool:
    if _has_real_sender_compare(text):
        return True
    return bool(OWNER_HELPER_PATTERN.search(text))


def _detect_incorrect_only_owner(
    lines: list[str], file_path: Path, ignore_next_lines: set[int] | None = None
) -> Iterator[Finding]:
    # onlyOwner that never checks the caller, checks after `_;`, or uses
    # tx.origin is access control that looks real and does nothing useful.
    for modifier in _iter_modifiers(lines):
        if ignore_next_lines and modifier.start_line in ignore_next_lines:
            continue
        if not _is_owner_modifier_name(modifier.name):
            continue
        source = _modifier_source(lines, modifier)
        placeholder = MODIFIER_PLACEHOLDER_PATTERN.search(source)
        before = source[: placeholder.start()] if placeholder else source
        after = source[placeholder.end() :] if placeholder else ""
        if TX_ORIGIN_COMPARE_IN_MOD_PATTERN.search(before) and not _has_real_sender_compare(
            before
        ):
            message = (
                f'Modifier "{modifier.name}" authenticates with tx.origin; use msg.sender.'
            )
        elif SENDER_TAUTOLOGY_PATTERN.search(before) and not _has_auth_check(before):
            message = f'Modifier "{modifier.name}" compares msg.sender to itself.'
        elif REQUIRE_TRUE_PATTERN.search(before) and not _has_auth_check(before):
            message = f'Modifier "{modifier.name}" requires true and never checks the caller.'
        elif _has_auth_check(before):
            continue
        elif _has_auth_check(after):
            message = (
                f'Modifier "{modifier.name}" checks authorization after the function body runs.'
            )
        else:
            message = f'Modifier "{modifier.name}" never checks the caller.'
        yield Finding(
            file_path=file_path,
            line_number=modifier.start_line,
            code="A020",
            severity="HIGH",
            message=message,
            line_text=lines[modifier.start_line - 1].rstrip(),
        )


def scan_paths(
    paths: Iterable[str],
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> list[Finding]:
    root_paths = [Path(p).resolve() for p in paths]
    findings: list[Finding] = []
    for file_path in _iter_solidity_files(root_paths, include, exclude):
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
        findings.extend(_detect_tx_origin_auth_comparison(lines, file_path, ignore_next_lines))
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
        findings.extend(_detect_events_missing_critical_params(lines, file_path, ignore_next_lines))
        findings.extend(_detect_blockhash_misuse(lines, file_path, ignore_next_lines))
        findings.extend(_detect_uninitialized_address(lines, file_path, ignore_next_lines))
        findings.extend(_detect_missing_zero_address_check(lines, file_path, ignore_next_lines))
        findings.extend(_detect_magic_numbers(lines, file_path, ignore_next_lines))
        findings.extend(_detect_constructor_external_calls(lines, file_path, ignore_next_lines))
        findings.extend(_detect_payable_without_withdraw(lines, file_path, ignore_next_lines))
        findings.extend(_detect_incorrect_only_owner(lines, file_path, ignore_next_lines))
    return findings


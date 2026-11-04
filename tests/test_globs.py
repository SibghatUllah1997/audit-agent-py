from __future__ import annotations

from sibaudit.globs import is_selected, matches_any


def test_name_glob_matches_in_any_folder() -> None:
    assert matches_any("contracts/test/MockToken.sol", ["Mock*.sol"])
    assert not matches_any("contracts/Token.sol", ["Mock*.sol"])


def test_folder_glob_matches_nested_files() -> None:
    assert matches_any("lib/openzeppelin/ERC20.sol", ["lib/*"])
    assert matches_any("vendor/lib/openzeppelin/ERC20.sol", ["lib/*"])


def test_double_star_prefix_also_matches_top_level() -> None:
    assert matches_any("test/A.sol", ["**/test/*.sol"])
    assert matches_any("src/test/A.sol", ["**/test/*.sol"])


def test_leading_dot_slash_and_backslashes_are_ignored() -> None:
    assert matches_any("src/A.sol", ["./src/*"])
    assert matches_any("src/A.sol", ["src\\*"])


def test_partial_folder_name_does_not_match() -> None:
    assert not matches_any("mylib/A.sol", ["lib/*"])


def test_no_globs_selects_everything() -> None:
    assert is_selected("a/B.sol")
    assert is_selected("a/B.sol", [], [])


def test_include_limits_and_exclude_wins() -> None:
    assert is_selected("src/A.sol", include=["src/*"])
    assert not is_selected("test/A.sol", include=["src/*"])
    assert not is_selected("src/Mock.sol", include=["src/*"], exclude=["Mock*.sol"])

#!/usr/bin/env python3
"""Reject undocumented authored C and C++ function declarations and definitions."""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (
    "foundation",
    "core",
    "providers",
    "transports",
    "c-api",
    "sdk/cpp17",
    "tests",
)
EXCLUDED_PARTS = {"build", ".build", "node_modules", ".gradle", ".cxx"}
CONTROL_WORDS = {
    "case",
    "catch",
    "default",
    "for",
    "if",
    "return",
    "static_assert",
    "switch",
    "while",
}


def looks_like_function(candidate: str) -> bool:
    """Recognize an authored function declaration using bounded linear scans."""
    text = candidate.strip()
    if not text or text.startswith("}"):
        return False
    if text.endswith(("= default;", "= delete;")):
        text = text.rsplit("=", 1)[0].rstrip()
    elif text.endswith((";", "{")):
        text = text[:-1].rstrip()
    else:
        return False

    opening = text.find("(")
    if opening <= 0:
        return False
    depth = 0
    closing = -1
    for index in range(opening, len(text)):
        character = text[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        return False

    prefix = text[:opening].rstrip()
    if not prefix or any(character in prefix for character in "{};"):
        return False
    leading_name = prefix.split(None, 1)[0].rstrip(":")
    if leading_name in CONTROL_WORDS:
        return False

    operator_at = prefix.rfind("operator")
    if operator_at >= 0:
        before = prefix[operator_at - 1] if operator_at else " "
        after_index = operator_at + len("operator")
        after = prefix[after_index] if after_index < len(prefix) else " "
        if (before.isspace() or before == ":") and (after.isspace() or not after.isalnum()):
            return True

    if "=" in prefix:
        return False
    name = prefix.rsplit(None, 1)[-1]
    if any(marker in name for marker in (".", "->", "=")):
        return False
    unqualified = name.rsplit("::", 1)[-1].removeprefix("~")
    return bool(unqualified) and (unqualified[0].isalpha() or unqualified[0] == "_") and all(
        character.isalnum() or character == "_" for character in unqualified
    )


def source_files() -> list[pathlib.Path]:
    """Return authored C/C++ files while excluding generated and local build trees."""
    files: list[pathlib.Path] = []
    for folder in SOURCE_ROOTS:
        base = ROOT / folder
        if not base.exists():
            continue
        files.extend(
            path
            for path in base.rglob("*")
            if path.suffix in {".h", ".hpp", ".c", ".cpp"}
            and not EXCLUDED_PARTS.intersection(path.parts)
            and ".generated." not in path.name
        )
    return sorted(files)


def documented(lines: list[str], index: int) -> bool:
    """Check whether a declaration has an adjacent Doxygen block or copy command."""
    cursor = index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    if cursor < 0:
        return False
    if lines[cursor].lstrip().startswith("///"):
        return True
    if "@copydoc" in lines[cursor]:
        return True
    if "*/" not in lines[cursor]:
        return False
    while cursor >= 0:
        if "/**" in lines[cursor] or "/*!" in lines[cursor]:
            return True
        if "/*" in lines[cursor]:
            return False
        cursor -= 1
    return False


def main() -> int:
    """Report likely undocumented functions; Doxygen remains the semantic authority."""
    failures: list[str] = []
    for path in source_files():
        lines = path.read_text(errors="replace").splitlines()
        logical = ""
        start = 0
        brace_depth = 0
        function_body_parent_depth: int | None = None
        for index, line in enumerate(lines):
            stripped = line.strip()
            depth_before = brace_depth
            # Authored sources follow the formatting rule that structural braces are not hidden
            # in string literals. This small scanner can therefore ignore statements inside an
            # already-documented function body without mistaking calls and direct initialization
            # for new declarations.
            code = line.split("//", 1)[0]
            brace_depth += code.count("{") - code.count("}")
            if function_body_parent_depth is not None:
                if brace_depth <= function_body_parent_depth:
                    function_body_parent_depth = None
                logical = ""
                continue
            if not logical:
                start = index
            logical = f"{logical} {stripped}".strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                logical = ""
                continue
            if ";" not in stripped and "{" not in stripped:
                continue
            candidate = logical
            logical = ""
            if path.suffix in {".c", ".cpp"} and not candidate.rstrip().endswith("{"):
                continue
            if looks_like_function(candidate):
                if not documented(lines, start):
                    failures.append(f"{path.relative_to(ROOT)}:{start + 1}: {candidate[:120]}")
                if candidate.rstrip().endswith("{") and brace_depth > depth_before:
                    function_body_parent_depth = depth_before
    if failures:
        print("Undocumented C/C++ functions:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Checked documentation in {len(source_files())} C/C++ files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

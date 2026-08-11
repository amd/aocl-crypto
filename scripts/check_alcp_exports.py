#!/usr/bin/env python3
"""Validate libalcp's dynamic export surface against explicit manifests."""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Optional


MINIMUM_PYTHON = (3, 9)
if sys.version_info < MINIMUM_PYTHON:
    print("Python 3.9 or newer required", file=sys.stderr)
    sys.exit(1)


def load_symbols(path: Path) -> list[str]:
    symbols = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not symbols:
        raise ValueError(f"empty symbol manifest: {path}")
    return symbols


def load_cpp_patterns(path: Path) -> list[tuple[bool, str]]:
    patterns: list[tuple[bool, str]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, separator, pattern = line.partition(" ")
        if not separator or kind not in {"required", "allow"} or not pattern:
            raise ValueError(
                f"{path}: expected 'required <pattern>' or 'allow <pattern>': {line}"
            )
        patterns.append((kind == "required", pattern))
    if not patterns:
        raise ValueError(f"empty C++ export manifest: {path}")
    return patterns


def dynamic_symbols(library: Path) -> list[str]:
    output = subprocess.check_output(
        ["nm", "-D", "--defined-only", str(library)], text=True
    )
    symbols = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            symbols.append(fields[-1])
    if not symbols:
        raise ValueError(f"no defined dynamic symbols found: {library}")
    return symbols


def demangle(symbols: list[str]) -> dict[str, str]:
    names = {symbol: symbol for symbol in symbols}
    candidates = [
        (symbol, symbol)
        for symbol in symbols
        if symbol.startswith("_Z")
    ]
    asan_prefix = "__odr_asan_gen_"
    candidates.extend(
        (symbol, symbol[len(asan_prefix) :])
        for symbol in symbols
        if symbol.startswith(f"{asan_prefix}_Z")
    )
    if not candidates:
        return names
    output = subprocess.check_output(
        ["c++filt", *(candidate for _, candidate in candidates)], text=True
    ).splitlines()
    names.update(
        {
            original: demangled
            for (original, _), demangled in zip(candidates, output)
        }
    )
    return names


ABI_PREFIXES = (
    "guard variable for ",
    "non-virtual thunk to ",
    "virtual thunk to ",
    "covariant return thunk to ",
    "typeinfo for ",
    "typeinfo name for ",
    "vtable for ",
    "VTT for ",
)


def symbol_views(symbol: str) -> list[str]:
    """Return only ABI-structured or return-type-stripped symbol owners."""
    views = [symbol]
    for prefix in ABI_PREFIXES:
        if symbol.startswith(prefix):
            views.append(symbol[len(prefix) :])

    # c++filt includes return types for some template instantiations. A return
    # type ends at the last whitespace outside template brackets before the
    # function argument list. This parses structure instead of slicing at an
    # embedded namespace in another owner's template or argument.
    for candidate in tuple(views):
        template_depth = 0
        boundary = -1
        for index, character in enumerate(candidate):
            if character == "<":
                template_depth += 1
            elif character == ">" and template_depth:
                template_depth -= 1
            elif character == "(" and template_depth == 0:
                break
            elif character.isspace() and template_depth == 0:
                boundary = index
        if boundary >= 0:
            owner = candidate[boundary + 1 :].lstrip()
            if owner.startswith(("alcp::", "std::")):
                views.append(owner)
    return views


def matches(pattern: str, symbol: str) -> bool:
    # Patterns are exact unless they end in '*'. This permits only anchored
    # fully-qualified prefixes, not free substring matches.
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return any(view.startswith(prefix) for view in symbol_views(symbol))
    return pattern in symbol_views(symbol)


def validate(
    library: Path,
    c_manifest: Path,
    cpp_manifest: Optional[Path],
    allow_unlisted: bool,
    cpp_exports_disabled: bool,
) -> list[str]:
    expected_c = set(load_symbols(c_manifest))
    cpp_patterns = load_cpp_patterns(cpp_manifest) if cpp_manifest else []
    exported = dynamic_symbols(library)
    exported_set = set(exported)
    demangled = demangle(exported)
    errors: list[str] = []

    for symbol in sorted(expected_c - exported_set):
        errors.append(f"missing C export: {symbol}")

    if not cpp_exports_disabled:
        for required, pattern in cpp_patterns:
            if required and not any(
                matches(pattern, name) for name in demangled.values()
            ):
                errors.append(f"missing required C++ export: {pattern}")

    if allow_unlisted:
        return errors

    for symbol in exported:
        if symbol in expected_c:
            continue
        name = demangled.get(symbol)
        if not cpp_exports_disabled and name is not None and any(
            matches(pattern, name) for _, pattern in cpp_patterns
        ):
            continue
        errors.append(f"unexpected export: {symbol}" + (f" ({name})" if name else ""))

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument(
        "--manifest",
        "--c-manifest",
        dest="c_manifest",
        required=True,
        type=Path,
        help="plain manifest of exact required export names",
    )
    parser.add_argument(
        "--cpp-manifest",
        type=Path,
        help="optional manifest of required/allowed demangled C++ patterns",
    )
    parser.add_argument(
        "--allow-unlisted",
        action="store_true",
        help="check required exports without enforcing hidden visibility",
    )
    parser.add_argument(
        "--cpp-exports-disabled",
        action="store_true",
        help="require every C++ symbol to remain hidden",
    )
    args = parser.parse_args()

    try:
        errors = validate(
            args.library,
            args.c_manifest,
            args.cpp_manifest,
            args.allow_unlisted,
            args.cpp_exports_disabled,
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    for error in errors:
        print(error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())

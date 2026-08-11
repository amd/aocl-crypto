#!/usr/bin/env python3
"""Validate libalcp's dynamic export surface against explicit manifests."""

import argparse
import subprocess
import sys
from pathlib import Path


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
        if len(fields) >= 3:
            symbols.append(fields[2])
    if not symbols:
        raise ValueError(f"no defined dynamic symbols found: {library}")
    return symbols


def demangle(symbols: list[str]) -> dict[str, str]:
    mangled = [symbol for symbol in symbols if symbol.startswith("_Z")]
    if not mangled:
        return {}
    output = subprocess.check_output(["c++filt", *mangled], text=True).splitlines()
    return dict(zip(mangled, output))


def symbol_views(symbol: str) -> list[str]:
    views = [symbol]
    for namespace in ("alcp::", "std::"):
        position = symbol.find(namespace)
        while position >= 0:
            views.append(symbol[position:])
            position = symbol.find(namespace, position + len(namespace))
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
    cpp_manifest: Path,
    allow_unlisted: bool,
    cpp_exports_disabled: bool,
) -> list[str]:
    expected_c = set(load_symbols(c_manifest))
    cpp_patterns = load_cpp_patterns(cpp_manifest)
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
    parser.add_argument("--c-manifest", required=True, type=Path)
    parser.add_argument("--cpp-manifest", required=True, type=Path)
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

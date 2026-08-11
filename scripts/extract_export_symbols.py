#!/usr/bin/env python3
"""Extract ALCP or IPP compatibility exports from source declarations."""

import argparse
import re
import sys
from pathlib import Path


def alcp_symbols(header_dir: Path) -> set[str]:
    symbols: set[str] = set()
    for path in sorted(header_dir.glob("*.h")):
        text = path.read_text()
        symbols.update(
            match.group(1)
            for match in re.finditer(
                r"ALCP_API_EXPORT[^\n]*\n\s*(alcp_[a-zA-Z0-9_]+)",
                text,
            )
        )
    return symbols


def active_ipp_lines(path: Path):
    disabled_depth = 0
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if disabled_depth and re.match(r"#\s*(?:if|ifdef|ifndef)\b", stripped):
            disabled_depth += 1
            continue
        if re.match(r"#\s*if\s+0\b", stripped):
            disabled_depth += 1
            continue
        if disabled_depth and re.match(r"#\s*endif\b", stripped):
            disabled_depth -= 1
            continue
        if not disabled_depth:
            yield line


def ipp_symbols(source_dir: Path) -> set[str]:
    symbols: set[str] = set()
    for path in sorted(source_dir.rglob("*.cc")):
        for line in active_ipp_lines(path):
            match = re.search(
                r"IPP_COMPAT_EXPORT\s+([A-Za-z_][A-Za-z0-9_]*)",
                line,
            )
            if match:
                symbols.add(match.group(1))
    return symbols


def main() -> int:
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer required", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("alcp", "ipp"), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    if not args.source.is_dir():
        parser.error(f"source directory does not exist: {args.source}")

    symbols = (
        alcp_symbols(args.source)
        if args.kind == "alcp"
        else ipp_symbols(args.source)
    )
    if not symbols:
        print(f"no {args.kind} export symbols found in {args.source}", file=sys.stderr)
        return 1
    output = "\n".join(sorted(symbols)) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())

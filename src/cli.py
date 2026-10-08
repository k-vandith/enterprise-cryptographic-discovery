#!/usr/bin/env python3
"""ECDAT command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scanner import CryptoScanner


def main() -> None:
    parser = argparse.ArgumentParser(description="Enterprise Cryptographic Discovery & Analysis Tool")
    parser.add_argument("path", type=Path, help="File or directory to scan")
    parser.add_argument("--json", type=Path, help="Write JSON report")
    parser.add_argument("--html", type=Path, help="Write HTML report")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    scanner = CryptoScanner()
    target = args.path
    if target.is_file():
        findings = scanner.scan_file(target)
    elif target.is_dir():
        findings = scanner.scan_directory(target)
    else:
        print(f"Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        for f in findings:
            print(f"[{f.severity.value.upper()}] {f.rule_id} @ {f.file}:{f.line}")
            print(f"  {f.evidence}")
            print(f"  → {f.remediation}\n")
        print(f"Total findings: {len(findings)}")

    if args.json:
        args.json.write_text(scanner.to_json(findings), encoding="utf-8")
        print(f"JSON → {args.json}")
    if args.html:
        args.html.write_text(scanner.to_html(findings), encoding="utf-8")
        print(f"HTML → {args.html}")


if __name__ == "__main__":
    main()

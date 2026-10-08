#!/usr/bin/env python3
"""ECDAT command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scanner import CryptoScanner
from src.inventory import build_inventory, post_quantum_readiness
from src.cbom import cbom_to_json
from src.tls_scan import scan_tls_endpoint, scan_tls_offline_demo, results_to_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Enterprise Cryptographic Discovery & Analysis Tool")
    sub = parser.add_subparsers(dest="cmd")

    scan_p = sub.add_parser("scan", help="Scan file or directory")
    scan_p.add_argument("path", type=Path)
    scan_p.add_argument("--json", type=Path)
    scan_p.add_argument("--html", type=Path)
    scan_p.add_argument("--cbom", type=Path)
    scan_p.add_argument("-q", "--quiet", action="store_true")

    tls_p = sub.add_parser("tls", help="Probe TLS endpoint")
    tls_p.add_argument("host")
    tls_p.add_argument("--port", type=int, default=443)
    tls_p.add_argument("--offline-demo", action="store_true")
    tls_p.add_argument("--json", type=Path)

    parser.add_argument("path", type=Path, nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--json", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--html", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("-q", "--quiet", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    if args.cmd == "tls":
        res = scan_tls_offline_demo(args.host, args.port) if args.offline_demo else scan_tls_endpoint(args.host, args.port)
        print(res)
        if args.json:
            args.json.write_text(results_to_json([res]), encoding="utf-8")
        return

    target = args.path
    if target is None:
        parser.print_help()
        sys.exit(2)

    scanner = CryptoScanner()
    if target.is_file():
        findings = scanner.scan_file(target)
    elif target.is_dir():
        findings = scanner.scan_directory(target)
    else:
        print(f"Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    if not getattr(args, "quiet", False):
        for f in findings:
            print(f"[{f.severity.value.upper()}] {f.rule_id} @ {f.file}:{f.line}")
            print(f"  {f.evidence}\n  → {f.remediation}\n")
        inv = build_inventory(findings)
        pq = post_quantum_readiness(findings)
        print(f"Total findings: {len(findings)}")
        print(f"Inventory assets: {len(inv)} | PQ readiness: {pq['score']} ({pq['band']})")

    if getattr(args, "json", None):
        args.json.write_text(scanner.to_json(findings), encoding="utf-8")
        print(f"JSON → {args.json}")
    if getattr(args, "html", None):
        args.html.write_text(scanner.to_html(findings), encoding="utf-8")
        print(f"HTML → {args.html}")
    if getattr(args, "cbom", None):
        args.cbom.write_text(cbom_to_json(findings), encoding="utf-8")
        print(f"CBOM → {args.cbom}")


if __name__ == "__main__":
    main()

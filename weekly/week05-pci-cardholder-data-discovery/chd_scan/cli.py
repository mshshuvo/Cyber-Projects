"""Command-line interface.

    python -m chd_scan scan   PATH [--suppressions FILE] [--as-of YYYY-MM-DD] [--out DIR] [--fail-on high]
    python -m chd_scan redact [FILE]          # mask PANs / remove SAD from a log stream (stdin -> stdout)

Exit codes: 0 = ran; 1 = usage or input error; 2 = --fail-on gate tripped.

Authorised use only: scan file systems you own or are explicitly authorised to assess. The
tool reads local paths only; it never connects to a network.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from .extract import DEFAULT_EXCLUDES, Limits
from .detectors import redact_line
from .report import console_report, findings_csv, json_report, markdown_report
from .scanner import SEV_RANK, load_suppressions, scan

NOTICE = ("Authorised use only: scan only systems and data you own or are authorised to assess. "
          "Reports contain masked values only, but still describe where card data lives; protect them.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="chd_scan", description="PCI DSS cardholder data discovery: find stored PANs and "
                                "prohibited sensitive authentication data, masked, with a Requirement 3 remediation plan.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a folder or file for stored account data")
    s.add_argument("path", type=Path)
    s.add_argument("--suppressions", type=Path, help="JSON register of documented, time-bound exceptions")
    s.add_argument("--as-of", type=date.fromisoformat, default=date.today(), help="Date used for suppression expiry")
    s.add_argument("--out", type=Path, help="Write report.md, report.json, findings.csv and console.txt here")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Skip paths matching GLOB (repeatable)")
    s.add_argument("--max-mb", type=int, default=50, help="Skip (and report) files larger than this (default 50)")
    s.add_argument("--no-binary", action="store_true", help="Do not extract strings from binary files")
    s.add_argument("--ignore-test-pans", action="store_true", help="Drop published test PANs (QA environments only)")
    s.add_argument("--limit", type=int, default=12, help="Rows per console section (default 12)")
    s.add_argument("--fail-on", choices=["critical", "high", "medium"], help="Exit 2 if any finding is at or above this")
    s.add_argument("--quiet", action="store_true", help="Suppress the authorised-use notice")

    r = sub.add_parser("redact", help="Mask PANs and strip SAD from text (a log-pipeline filter)")
    r.add_argument("file", nargs="?", type=Path, help="Input file (default stdin)")
    return p


def _write_private(path: Path, text: str) -> None:
    """Reports say where card data lives; create them readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "redact":
        stream = args.file.open(encoding="utf-8", errors="replace") if args.file else sys.stdin
        try:
            for line in stream:
                sys.stdout.write(redact_line(line.rstrip("\n")) + "\n")
        finally:
            if args.file:
                stream.close()
        return 0

    if not args.path.exists():
        print(f"error: {args.path} not found", file=sys.stderr)
        return 1
    try:
        sups = load_suppressions(args.suppressions)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read suppressions: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(NOTICE, file=sys.stderr)

    limits = Limits(max_file_bytes=args.max_mb * 1024 * 1024, scan_binary=not args.no_binary)
    excludes = DEFAULT_EXCLUDES + tuple(args.exclude)
    if args.out:
        out_abs = args.out.resolve()
        root_abs = args.path.resolve()
        if root_abs in out_abs.parents or out_abs == root_abs:
            excludes += (out_abs.relative_to(root_abs).as_posix() + "/*",)
    result = scan(args.path, args.as_of, sups, limits, args.ignore_test_pans, excludes=excludes)
    text = console_report(result, args.limit)
    print(text)

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        _write_private(args.out / "report.md", markdown_report(result))
        _write_private(args.out / "report.json", json_report(result) + "\n")
        _write_private(args.out / "findings.csv", findings_csv(result))
        _write_private(args.out / "console.txt", text + "\n")
        print(f"\nReports written to {args.out}/ (report.md, report.json, findings.csv, console.txt; mode 0600)")

    if args.fail_on:
        threshold = SEV_RANK[args.fail_on.capitalize()]
        if any(SEV_RANK[f.severity] <= threshold for f in result.findings):
            print(f"\nGATE: findings at or above {args.fail_on.capitalize()} present", file=sys.stderr)
            return 2
    return 0

"""Command-line interface.

    python -m crosswalk assess   --data sample_data --as-of 2026-11-01 --out sample_output
    python -m crosswalk evidence EV-012 --data sample_data
    python -m crosswalk lookup   iso A.8.15 --data sample_data
    python -m crosswalk groups

--data DIR reads controls.csv, mappings.csv, evidence.csv and (if present) scope.json
from DIR; --controls/--mappings/--evidence/--scope override individual files.

Exit codes: 0 = ran; 1 = usage or input error; 2 = a quality gate failed
(--fail-under coverage, or --strict with High data-quality findings).
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .catalog import FRAMEWORKS, framework_key, normalize_id
from .engine import Assessment, assess
from .model import load_dataset
from .report import (console_report, evidence_view, json_report, lookup_view, markdown_report,
                     matrix_csv)


def _add_data_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--data", type=Path, help="Folder with controls.csv, mappings.csv, evidence.csv, scope.json")
    p.add_argument("--controls", type=Path, help="Common control list (CSV)")
    p.add_argument("--mappings", type=Path, help="Control-to-framework crosswalk (CSV)")
    p.add_argument("--evidence", type=Path, help="Evidence register (CSV)")
    p.add_argument("--scope", type=Path, help="Scope and exclusions (JSON); default: everything in scope")
    p.add_argument("--as-of", type=date.fromisoformat, default=date.today(),
                   help="Assessment date, YYYY-MM-DD (default today)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crosswalk",
        description="Test a control once and see what it proves across ISO/IEC 27001:2022, SOC 2, "
                    "NIST CSF 2.0 and CIS Controls v8.1.")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assess", help="Assess coverage, gaps, evidence reuse and data quality")
    _add_data_args(a)
    a.add_argument("--out", type=Path, help="Write report.md, report.json and matrix.csv here")
    a.add_argument("--limit", type=int, default=8, help="Rows per console section (default 8)")
    a.add_argument("--fail-under", type=float, default=None, metavar="PCT",
                   help="Exit 2 if any in-scope framework's coverage is below PCT")
    a.add_argument("--strict", action="store_true", help="Exit 2 if there are High data-quality findings")

    e = sub.add_parser("evidence", help="Show every requirement one evidence item supports")
    e.add_argument("evidence_id")
    _add_data_args(e)

    lk = sub.add_parser("lookup", help="Show a requirement's status, controls, evidence and equivalents")
    lk.add_argument("framework", help="iso | soc2 | csf | cis")
    lk.add_argument("requirement", help="e.g. A.8.15, CC6.1, PR.AA-05, 5.1")
    _add_data_args(lk)

    sub.add_parser("groups", help="List the scope groups each framework catalog offers")
    return p


def _resolve(args: argparse.Namespace) -> tuple[Path, Path, Path, Path | None] | str:
    base: Path | None = args.data
    def pick(explicit: Path | None, name: str) -> Path | None:
        if explicit:
            return explicit
        return base / name if base else None
    files = (pick(args.controls, "controls.csv"), pick(args.mappings, "mappings.csv"),
             pick(args.evidence, "evidence.csv"))
    for f, label in zip(files, ("controls", "mappings", "evidence")):
        if f is None:
            return f"no {label} file: pass --data DIR or --{label} FILE"
        if not f.exists():
            return f"{label} file {f} not found"
    scope = args.scope or (base / "scope.json" if base and (base / "scope.json").exists() else None)
    if scope is not None and not scope.exists():
        return f"scope file {scope} not found"
    return files[0], files[1], files[2], scope


def _load(args: argparse.Namespace) -> Assessment | None:
    resolved = _resolve(args)
    if isinstance(resolved, str):
        print(f"error: {resolved}", file=sys.stderr)
        return None
    return assess(load_dataset(*resolved), args.as_of)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "groups":
        for fw in FRAMEWORKS.values():
            print(f"{fw.key:<9} {fw.name:<20} all, {', '.join(fw.groups)}")
        return 0

    a = _load(args)
    if a is None:
        return 1

    if args.command == "evidence":
        view = evidence_view(a, args.evidence_id)
        if view is None:
            print(f"error: evidence {args.evidence_id} not in the register", file=sys.stderr)
            return 1
        print(view)
        return 0

    if args.command == "lookup":
        fw = framework_key(args.framework)
        if fw is None:
            print(f"error: unknown framework '{args.framework}'", file=sys.stderr)
            return 1
        rid = normalize_id(fw, args.requirement)
        if rid not in FRAMEWORKS[fw].requirements:
            print(f"error: {rid} is not a {FRAMEWORKS[fw].name} requirement", file=sys.stderr)
            return 1
        print(lookup_view(a, fw, rid))
        return 0

    print(console_report(a, args.limit))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(markdown_report(a), encoding="utf-8")
        (args.out / "report.json").write_text(json_report(a) + "\n", encoding="utf-8")
        (args.out / "matrix.csv").write_text(matrix_csv(a), encoding="utf-8")
        print(f"\nReports written to {args.out}/ (report.md, report.json, matrix.csv)")

    rc = 0
    if args.fail_under is not None:
        low = [fw for fw in a.results if a.coverage(fw) < args.fail_under]
        if low:
            print(f"\nGATE: coverage below {args.fail_under:.0f}% for {', '.join(low)}", file=sys.stderr)
            rc = 2
    if args.strict and any(f.severity == "High" for f in a.findings):
        print("\nGATE: High data-quality findings present (--strict)", file=sys.stderr)
        rc = 2
    return rc

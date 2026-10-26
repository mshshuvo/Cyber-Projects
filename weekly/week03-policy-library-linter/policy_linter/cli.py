"""Command-line interface.

    python -m policy_linter PATH [--glossary glossary.md] [--owners owners.csv]
                                 [--as-of YYYY-MM-DD] [--out DIR] [--fail-on high]

Exit codes: 0 = ran (and nothing at or above --fail-on), 1 = usage/input error,
2 = findings at or above the --fail-on severity (for CI pipelines and pre-commit hooks).
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .checks import (DEFAULT_IGNORE_TERMS, DEFAULT_SECTIONS, SEVERITY_ORDER, LintConfig,
                     load_owners, run_all)
from .model import DEFAULT_ID_PATTERN, load_library, parse_glossary
from .report import console_report, github_annotations, json_report, markdown_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="policy_linter",
        description="Lint a folder of Markdown policies for stale reviews, missing owners, "
                    "broken cross-references, undefined terms and version drift.")
    p.add_argument("path", type=Path, help="Folder containing the policy library (*.md, recursive)")
    p.add_argument("--glossary", type=Path,
                   help="Glossary Markdown file (default: <path>/glossary.md if it exists)")
    p.add_argument("--owners", type=Path, help="Owner register CSV (role, holder, status)")
    p.add_argument("--as-of", type=date.fromisoformat, default=date.today(),
                   help="Assessment date, YYYY-MM-DD (default today)")
    p.add_argument("--due-soon-days", type=int, default=45,
                   help="Flag reviews due within this many days (default 45)")
    p.add_argument("--default-cycle", type=int, default=12,
                   help="Review cycle in months when a document sets none (default 12)")
    p.add_argument("--sections", default=",".join(DEFAULT_SECTIONS),
                   help="Comma-separated required section headings")
    p.add_argument("--ignore-terms", default="",
                   help="Comma-separated extra acronyms to accept without a definition")
    p.add_argument("--id-pattern", default=DEFAULT_ID_PATTERN,
                   help="Regular expression for document ids (default %(default)s)")
    p.add_argument("--org", default="", help="Organisation name for the report heading")
    p.add_argument("--out", type=Path, help="Write report.md and report.json to this folder")
    p.add_argument("--format", choices=("text", "github"), default="text",
                   help="Console format: text summary, or GitHub Actions annotations")
    p.add_argument("--limit", type=int, default=None, help="Show at most N findings on the console")
    p.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none",
                   help="Exit 2 if any finding is at or above this severity (default none)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root: Path = args.path
    if not root.is_dir():
        print(f"error: {root} is not a folder", file=sys.stderr)
        return 1
    glossary_path = args.glossary or (root / "glossary.md" if (root / "glossary.md").exists() else None)
    if glossary_path is not None and not glossary_path.exists():
        print(f"error: glossary {glossary_path} not found", file=sys.stderr)
        return 1
    if args.owners is not None and not args.owners.exists():
        print(f"error: owner register {args.owners} not found", file=sys.stderr)
        return 1

    lib = load_library(root, args.id_pattern)
    if not lib:
        print(f"error: no Markdown policies found under {root}", file=sys.stderr)
        return 1
    cfg = LintConfig(
        as_of=args.as_of, due_soon_days=args.due_soon_days, default_cycle_months=args.default_cycle,
        required_sections=tuple(s.strip() for s in args.sections.split(",") if s.strip()),
        ignore_terms=DEFAULT_IGNORE_TERMS | {t.strip() for t in args.ignore_terms.split(",") if t.strip()},
        glossary=parse_glossary(glossary_path), owners=load_owners(args.owners))
    findings, suppressed = run_all(lib, cfg)

    if args.format == "github":
        print(github_annotations(findings, root_prefix=root.as_posix().rstrip("/") + "/"))
    else:
        print(console_report(lib, findings, cfg, suppressed, args.limit))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(markdown_report(lib, findings, cfg, args.org, suppressed),
                                            encoding="utf-8")
        (args.out / "report.json").write_text(json_report(lib, findings, cfg, suppressed) + "\n",
                                              encoding="utf-8")
        if args.format == "text":
            print(f"\nReports written to {args.out}/report.md and {args.out}/report.json")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on.capitalize()]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings):
            return 2
    return 0

"""Command-line entry point: python -m soa_auditor --soa SOA.csv [options]"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .checks import HIGH, AuditConfig, run_all
from .models import load_evidence, load_risks, load_soa
from .report import console_summary, json_report, markdown_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soa_auditor",
        description="Audit an ISO/IEC 27001:2022 Statement of Applicability against "
                    "Annex A, the risk register and the evidence log.")
    p.add_argument("--soa", required=True, type=Path, help="SoA CSV file")
    p.add_argument("--risks", type=Path, help="Risk register CSV file (optional)")
    p.add_argument("--evidence", type=Path, help="Evidence log CSV file (optional)")
    p.add_argument("--as-of", type=date.fromisoformat, default=date.today(),
                   help="Audit date, YYYY-MM-DD (default: today)")
    p.add_argument("--org", default="Organization", help="Organization name for the report")
    p.add_argument("--review-days", type=int, default=365,
                   help="Maximum age of an SoA row review in days (default: 365)")
    p.add_argument("--out", type=Path, help="Folder to write report.md and report.json")
    p.add_argument("--fail-on-high", action="store_true",
                   help="Exit with code 2 if any High finding exists (useful in CI)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    soa = load_soa(args.soa)
    risks = load_risks(args.risks) if args.risks else None
    evidence = load_evidence(args.evidence) if args.evidence else None
    cfg = AuditConfig(as_of=args.as_of, review_max_age_days=args.review_days)

    findings = run_all(soa, risks, evidence, cfg)
    print(console_summary(soa, findings, cfg.as_of))

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(
            markdown_report(soa, findings, cfg.as_of, args.org), encoding="utf-8")
        (args.out / "report.json").write_text(
            json_report(soa, findings, cfg.as_of, args.org), encoding="utf-8")
        print(f"\nReports written to {args.out}/report.md and {args.out}/report.json")

    if args.fail_on_high and any(f.severity == HIGH for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

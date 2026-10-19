"""Command-line interface.

    python -m audit_sampling size     --confidence 0.95 --tolerable 0.05 [--expected 0.01] [--population N]
    python -m audit_sampling size     --frequency weekly --risk higher
    python -m audit_sampling draw     --population pop.csv --id-column change_id ... --out folder
    python -m audit_sampling evaluate --manifest manifest.json --tracker tracker.csv [--population pop.csv]
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .population import load_population
from .report import (console_evaluation, draw_summary, json_evaluation,
                     markdown_evaluation, size_summary)
from .sampler import Manifest, draw_sample, new_seed, reperform
from .stats import (FREQUENCY_GUIDE, RISK_LEVELS, SampleSize, attribute_sample_size,
                    frequency_sample_size)
from .tracker import NOT_EFFECTIVE, evaluate, load_tracker, write_tracker


def _rate(text: str) -> float:
    """Accept 0.05, 5 or 5% for five percent."""
    t = text.strip().rstrip("%")
    v = float(t)
    return v / 100 if (text.strip().endswith("%") or v >= 1) else v


def _add_size_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("sample size (statistical OR frequency-based)")
    g.add_argument("--confidence", type=_rate, help="Confidence level, e.g. 0.95 or 95%%")
    g.add_argument("--tolerable", type=_rate, help="Tolerable deviation rate, e.g. 0.05 or 5%%")
    g.add_argument("--expected", type=_rate, default=0.0,
                   help="Expected deviation rate (default 0)")
    g.add_argument("--frequency", choices=sorted(FREQUENCY_GUIDE),
                   help="Control frequency for a judgmental sample size")
    g.add_argument("--risk", choices=RISK_LEVELS, default="moderate",
                   help="Risk of control failure for frequency-based sizes (default moderate)")
    g.add_argument("--sample-size", type=int, help="Override with a fixed sample size")


def _resolve_size(args: argparse.Namespace, population: int | None) -> SampleSize:
    if args.sample_size:
        n = min(args.sample_size, population) if population else args.sample_size
        return SampleSize(n=n, allowed_deviations=0, method="fixed", population=population,
                          test_all=bool(population and n >= population),
                          basis="sample size set by the auditor")
    if args.frequency:
        return frequency_sample_size(args.frequency, args.risk, population)
    if args.confidence is None or args.tolerable is None:
        raise SystemExit("error: give --confidence and --tolerable, or --frequency, or --sample-size")
    return attribute_sample_size(args.confidence, args.tolerable, args.expected, population)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit_sampling",
        description="Audit sampling for tests of controls: size the sample, draw it "
                    "reproducibly, track evidence and evaluate the result.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("size", help="Calculate a sample size")
    _add_size_args(s)
    s.add_argument("--population", type=int, help="Population size (enables finite-population math)")

    d = sub.add_parser("draw", help="Validate a population and draw a reproducible sample")
    d.add_argument("--population", required=True, type=Path, help="Population CSV")
    d.add_argument("--id-column", required=True, help="Column holding the unique item ID")
    d.add_argument("--date-column", help="Date column used for the period check")
    d.add_argument("--period-start", type=date.fromisoformat, help="Audit period start (YYYY-MM-DD)")
    d.add_argument("--period-end", type=date.fromisoformat, help="Audit period end (YYYY-MM-DD)")
    d.add_argument("--expected-count", type=int,
                   help="Record count reported by the source system, for reconciliation")
    d.add_argument("--stratify-by", help="Column to stratify by (proportional allocation)")
    d.add_argument("--seed", help="Selection seed (default: a new random seed, recorded)")
    d.add_argument("--control-id", required=True, help="Control reference, e.g. ITGC-CM-02")
    d.add_argument("--control", default="", help="Control description")
    d.add_argument("--drawn-on", type=date.fromisoformat, help="Draw date (default today)")
    d.add_argument("--force", action="store_true",
                   help="Draw even if the population has High issues (not recommended)")
    d.add_argument("--out", required=True, type=Path, help="Folder for manifest.json and tracker.csv")
    _add_size_args(d)

    e = sub.add_parser("evaluate", help="Evaluate the evidence tracker and conclude")
    e.add_argument("--manifest", required=True, type=Path)
    e.add_argument("--tracker", required=True, type=Path)
    e.add_argument("--population", type=Path,
                   help="Population CSV, to re-perform the selection from the seed")
    e.add_argument("--date-column", help="Same date column used at draw time")
    e.add_argument("--period-start", type=date.fromisoformat)
    e.add_argument("--period-end", type=date.fromisoformat)
    e.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    e.add_argument("--overdue-days", type=int, default=10,
                   help="Days after which an evidence request is overdue (default 10)")
    e.add_argument("--org", default="Organization")
    e.add_argument("--out", type=Path, help="Folder for report.md and report.json")
    e.add_argument("--fail-on-ineffective", action="store_true",
                   help="Exit with code 2 when the conclusion is NOT EFFECTIVE")
    return p


def cmd_size(args: argparse.Namespace) -> int:
    print(size_summary(_resolve_size(args, args.population)))
    return 0


def cmd_draw(args: argparse.Namespace) -> int:
    pop = load_population(args.population, args.id_column, args.date_column,
                          args.period_start, args.period_end, args.expected_count)
    if pop.blocking and not args.force:
        print("Population has High issues; fix them or re-run with --force:", file=sys.stderr)
        for i in pop.blocking:
            print(f"  [{i.severity}] {i.ref}: {i.check} - {i.message}", file=sys.stderr)
        return 3
    size = _resolve_size(args, len(pop.frame))
    manifest = draw_sample(pop, size, args.seed or new_seed(), args.control_id,
                           args.control, args.stratify_by, args.drawn_on)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "manifest.json").write_text(manifest.to_json(), encoding="utf-8")
    write_tracker(args.out / "tracker.csv", manifest, pop)
    print(draw_summary(manifest))
    print(f"\nWrote {args.out}/manifest.json and {args.out}/tracker.csv")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    manifest = Manifest.load(args.manifest)
    rows = load_tracker(args.tracker)
    ev = evaluate(rows, manifest, args.as_of, args.overdue_days)
    reperf = None
    if args.population:
        pop = load_population(args.population, manifest.id_column, args.date_column,
                              args.period_start, args.period_end)
        reperf = reperform(manifest, pop)
    print(console_evaluation(manifest, ev, args.as_of, reperf))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(
            markdown_evaluation(manifest, ev, args.as_of, args.org, reperf), encoding="utf-8")
        (args.out / "report.json").write_text(
            json_evaluation(manifest, ev, args.as_of, args.org, reperf), encoding="utf-8")
        print(f"\nReports written to {args.out}/report.md and {args.out}/report.json")
    if args.fail_on_ineffective and ev.conclusion == NOT_EFFECTIVE:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"size": cmd_size, "draw": cmd_draw, "evaluate": cmd_evaluate}[args.command](args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

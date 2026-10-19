"""Rendering: console summaries, a Markdown working paper and JSON."""
from __future__ import annotations

import json
from collections import Counter
from datetime import date

from .population import HIGH, LOW, MEDIUM, Issue
from .sampler import Manifest
from .stats import SampleSize
from .tracker import Evaluation, remaining_capacity, round_up_pct


def _bar(part: int, whole: int, width: int = 24) -> str:
    filled = round(width * part / whole) if whole else 0
    return "█" * filled + "░" * (width - filled)


def _sev_line(issues: list[Issue]) -> str:
    c = Counter(i.severity for i in issues)
    return f"{len(issues)}  (High {c[HIGH]}, Medium {c[MEDIUM]}, Low {c[LOW]})"


def size_summary(size: SampleSize) -> str:
    lines = ["Sample size", "=" * 56]
    if size.method == "frequency":
        lines.append(f"Method:              judgmental (control frequency and risk)")
    else:
        model = "hypergeometric (finite population)" if size.population else "binomial (large population)"
        lines += [f"Method:              statistical attribute sampling, {model}",
                  f"Confidence:          {size.confidence:.0%}",
                  f"Tolerable rate:      {size.tolerable_rate:.1%}",
                  f"Expected rate:       {size.expected_rate:.1%}"]
    if size.population:
        lines.append(f"Population:          {size.population}")
    lines += [f"Sample size:         {size.n}" + ("  (test the whole population)" if size.test_all else ""),
              f"Allowed deviations:  {size.allowed_deviations}",
              f"Basis:               {size.basis}"]
    return "\n".join(lines)


def draw_summary(m: Manifest) -> str:
    s = m.sample_size
    lines = [f"Sample drawn for {m.control_id}: {m.control_description}", "=" * 56,
             f"Population file:  {m.population_file}  ({m.population_rows} rows, "
             f"{m.frame_size} in frame)",
             f"SHA-256:          {m.population_sha256[:16]}...",
             f"Seed:             {m.seed}",
             f"Sample size:      {s['n']} (allowed deviations {s['allowed_deviations']}, "
             f"method {s['method']})"]
    if m.allocation:
        alloc = ", ".join(f"{k} {v}" for k, v in sorted(m.allocation.items()))
        lines.append(f"Stratified by {m.stratify_by}: {alloc}")
    if m.population_issues:
        lines.append(f"Population issues: {len(m.population_issues)}")
        for i in m.population_issues[:8]:
            lines.append(f"  [{i['severity']:<6}] {i['ref']:<12} {i['check']:<16} {i['message']}")
    lines.append("First 10 selections: " + ", ".join(m.selected_ids[:10]))
    return "\n".join(lines)


def console_evaluation(m: Manifest, ev: Evaluation, as_of: date,
                       reperformance: list[str] | None = None) -> str:
    s = m.sample_size
    lines = [f"Control test evaluation: {m.control_id}  (as of {as_of})", "=" * 60,
             m.control_description,
             f"Design: n={ev.planned}, allowed deviations {ev.allowed_deviations}, "
             f"method {s['method']}"
             + (f", {s['confidence']:.0%} confidence / {s['tolerable_rate']:.1%} tolerable"
                if s.get("confidence") else ""),
             "",
             f"Progress  {_bar(ev.tested, ev.planned)} {ev.tested}/{ev.planned} tested "
             f"({ev.progress:.0%})",
             "Status    " + ", ".join(f"{k} {v}" for k, v in sorted(ev.status_counts.items())),
             f"Results   pass {ev.passed}, exception {ev.exceptions}"
             + (f"  (by stratum: " + ", ".join(f"{k} {v}" for k, v in
                                               sorted(ev.exceptions_by_stratum.items())) + ")"
                if ev.exceptions_by_stratum else "")]
    if ev.upper_limit is not None:
        lines.append(f"Upper deviation limit on items tested so far: {round_up_pct(ev.upper_limit)}")
    cap = remaining_capacity(ev)
    if cap is not None and ev.conclusion != "EFFECTIVE":
        lines.append(f"Exceptions still tolerable before failure: {cap}")
    if reperformance is not None:
        lines.append("Re-performance: " + ("PASS - seed and population reproduce the sample"
                                           if not reperformance else "FAIL - " + "; ".join(reperformance)))
    lines += ["", f"CONCLUSION: {ev.conclusion}", f"  {ev.rationale}", "",
              f"Tracker issues: {_sev_line(ev.issues)}"]
    for i in ev.issues[:12]:
        lines.append(f"  [{i.severity:<6}] {i.ref:<12} {i.check:<24} {i.message}")
    if len(ev.issues) > 12:
        lines.append(f"  ... and {len(ev.issues) - 12} more in the full report.")
    return "\n".join(lines)


def markdown_evaluation(m: Manifest, ev: Evaluation, as_of: date, org: str,
                        reperformance: list[str] | None = None) -> str:
    s = m.sample_size
    out = [f"# Control test working paper: {m.control_id}", "",
           f"**Organization:** {org}  ", f"**Control:** {m.control_description}  ",
           f"**Evaluated as of:** {as_of}  ", f"**Conclusion:** **{ev.conclusion}**", "",
           f"> {ev.rationale}", "",
           "## Sample design", "",
           "| Item | Value |", "|---|---|",
           f"| Method | {s['method']} |"]
    if s.get("confidence"):
        out += [f"| Confidence | {s['confidence']:.0%} |",
                f"| Tolerable deviation rate | {s['tolerable_rate']:.1%} |",
                f"| Expected deviation rate | {s['expected_rate']:.1%} |"]
    out += [f"| Sample size | {s['n']} |",
            f"| Allowed deviations | {s['allowed_deviations']} |",
            f"| Basis | {s['basis']} |",
            f"| Population file | `{m.population_file}` ({m.population_rows} rows, {m.frame_size} in frame) |",
            f"| Population SHA-256 | `{m.population_sha256}` |",
            f"| Selection seed | `{m.seed}` (drawn {m.drawn_on}) |"]
    if m.allocation:
        out.append(f"| Stratification ({m.stratify_by}) | "
                   + ", ".join(f"{k}: {v}" for k, v in sorted(m.allocation.items())) + " |")
    if reperformance is not None:
        out.append("| Re-performance | " + ("Pass" if not reperformance
                                            else "Fail: " + "; ".join(reperformance)) + " |")
    out += ["", "## Results", "",
            f"- Tested: {ev.tested} of {ev.planned} ({ev.progress:.0%})",
            f"- Pass: {ev.passed}",
            f"- Exceptions: {ev.exceptions}"
            + (" (" + ", ".join(f"{k}: {v}" for k, v in sorted(ev.exceptions_by_stratum.items())) + ")"
               if ev.exceptions_by_stratum else ""),
            "- Status: " + ", ".join(f"{k} {v}" for k, v in sorted(ev.status_counts.items()))]
    if ev.upper_limit is not None:
        out.append(f"- Upper deviation limit (items tested so far): {round_up_pct(ev.upper_limit)}")
    if m.population_issues:
        out += ["", "## Population (IPE) issues found at draw time", "",
                "| Severity | Ref | Check | Detail |", "|---|---|---|---|"]
        out += [f"| {i['severity']} | {i['ref']} | {i['check']} | {i['message']} |"
                for i in m.population_issues]
    out += ["", f"## Tracker issues ({len(ev.issues)})", ""]
    if ev.issues:
        out += ["| Severity | Ref | Check | Detail |", "|---|---|---|---|"]
        out += [f"| {i.severity} | {i.ref} | {i.check} | {i.message} |" for i in ev.issues]
    else:
        out.append("None.")
    out += ["", "## Selected items", "", "| # | Item | Stratum |", "|---|---|---|"]
    out += [f"| {n} | {sel['item_id']} | {sel['stratum'] or '-'} |"
            for n, sel in enumerate(m.selected, start=1)]
    out += ["", "---", "*Generated by audit_sampling. Re-perform the selection by ranking each "
            "item ID by SHA-256(\"<seed>:<item_id>\") and taking the lowest values.*", ""]
    return "\n".join(out)


def json_evaluation(m: Manifest, ev: Evaluation, as_of: date, org: str,
                    reperformance: list[str] | None = None) -> str:
    return json.dumps({
        "tool": "audit_sampling", "organization": org, "as_of": as_of.isoformat(),
        "control_id": m.control_id, "control_description": m.control_description,
        "sample_design": m.sample_size, "seed": m.seed,
        "population_sha256": m.population_sha256,
        "reperformance": None if reperformance is None else {"passed": not reperformance,
                                                             "problems": reperformance},
        "evaluation": ev.to_dict(),
    }, indent=2)

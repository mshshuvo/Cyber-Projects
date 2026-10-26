"""Render lint results: console summary, Markdown report and JSON."""
from __future__ import annotations

import json
from collections import Counter

from .checks import (ANNEX_A_2022, HIGH, INFO, LOW, MEDIUM, Finding, LintConfig,
                     health_score, next_review_date)
from .model import APPROVED, Policy

SEVS = (HIGH, MEDIUM, LOW, INFO)


def library_stats(lib: list[Policy], findings: list[Finding], cfg: LintConfig) -> dict:
    """Headline numbers for the library."""
    status = Counter(p.status or "unknown" for p in lib)
    approved = [p for p in lib if p.status == APPROVED]
    overdue = {f.file for f in findings if f.code == "REVIEW_OVERDUE"}
    mapped = {c for p in approved for c in p.get_list("iso27001") if c in ANNEX_A_2022}
    sev = Counter(f.severity for f in findings)
    return {
        "documents": len(lib),
        "by_status": dict(sorted(status.items())),
        "approved_overdue": len(overdue),
        "approved_current_pct": round(100 * (len(approved) - len(overdue)) / len(approved)) if approved else 0,
        "annex_a_controls_mapped": len(mapped),
        "annex_a_controls_total": len(ANNEX_A_2022),
        "findings": {s: sev.get(s, 0) for s in SEVS},
        "health_score": health_score(findings, len(lib)),
        "as_of": cfg.as_of.isoformat(),
    }


def review_calendar(lib: list[Policy], cfg: LintConfig) -> list[dict]:
    """Approved documents ordered by next review date (earliest first)."""
    rows = []
    for p in lib:
        if p.status != APPROVED:
            continue
        due = next_review_date(p, cfg)
        rows.append({"id": p.id, "title": p.title, "owner": p.get("owner") or "(none)",
                     "version": p.version, "next_review": due.isoformat() if due else "unknown",
                     "days": (due - cfg.as_of).days if due else None})
    return sorted(rows, key=lambda r: (r["days"] is None, r["days"] if r["days"] is not None else 0))


def console_report(lib: list[Policy], findings: list[Finding], cfg: LintConfig,
                   suppressed: int = 0, limit: int | None = None) -> str:
    s = library_stats(lib, findings, cfg)
    f = s["findings"]
    status = ", ".join(f"{k} {v}" for k, v in s["by_status"].items())
    lines = [
        f"Policy library lint  (as of {cfg.as_of})",
        "=" * 64,
        f"Documents: {s['documents']}  ({status})",
        f"Health score: {s['health_score']}/100   Findings: {sum(f.values())}  "
        f"(High {f[HIGH]}, Medium {f[MEDIUM]}, Low {f[LOW]})"
        + (f"   Suppressed: {suppressed}" if suppressed else ""),
        f"Approved documents within review cycle: {s['approved_current_pct']}%   "
        f"Annex A controls mapped: {s['annex_a_controls_mapped']}/{s['annex_a_controls_total']}",
        "",
    ]
    shown = findings if limit is None else findings[:limit]
    width = max((len(x.code) for x in shown), default=10)
    loc_w = max((len(f"{x.file}:{x.line}") for x in shown), default=10)
    for x in shown:
        loc = f"{x.file}:{x.line}"
        lines.append(f"  [{x.severity:<6}] {loc:<{loc_w}}  {x.code:<{width}}  {x.message}")
    if limit is not None and len(findings) > limit:
        lines.append(f"  ... {len(findings) - limit} more (see the Markdown or JSON report)")
    if not findings:
        lines.append("  No findings. The library is clean.")
    return "\n".join(lines)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def markdown_report(lib: list[Policy], findings: list[Finding], cfg: LintConfig,
                    org: str = "", suppressed: int = 0) -> str:
    s = library_stats(lib, findings, cfg)
    f = s["findings"]
    out = [f"# Policy library lint report{' — ' + org if org else ''}", "",
           f"Assessment date: **{cfg.as_of}**  ·  Documents: **{s['documents']}**  ·  "
           f"Health score: **{s['health_score']}/100**", "",
           "## Summary", "",
           "| Measure | Value |", "|---|---|"]
    out += [f"| Documents by status | {', '.join(f'{k}: {v}' for k, v in s['by_status'].items())} |",
            f"| Approved documents within review cycle | {s['approved_current_pct']}% |",
            f"| Approved documents overdue for review | {s['approved_overdue']} |",
            f"| ISO/IEC 27001:2022 Annex A controls mapped by an approved document | "
            f"{s['annex_a_controls_mapped']} of {s['annex_a_controls_total']} |",
            f"| Findings | High {f[HIGH]}, Medium {f[MEDIUM]}, Low {f[LOW]} |",
            f"| Suppressed by inline directive | {suppressed} |", ""]

    codes = Counter((x.severity, x.code) for x in findings)
    out += ["## Findings by rule", "", "| Severity | Rule | Count |", "|---|---|---|"]
    out += [f"| {sev} | `{code}` | {n} |" for (sev, code), n in
            sorted(codes.items(), key=lambda kv: (SEVS.index(kv[0][0]), -kv[1], kv[0][1]))]

    out += ["", "## Review calendar", "",
            "| Id | Title | Owner | Version | Next review | Days |", "|---|---|---|---|---|---|"]
    for r in review_calendar(lib, cfg):
        days = "?" if r["days"] is None else (f"**{r['days']}** (overdue)" if r["days"] < 0 else str(r["days"]))
        out.append(f"| {r['id']} | {_md_escape(r['title'])} | {_md_escape(r['owner'])} | {r['version']} | "
                   f"{r['next_review']} | {days} |")

    out += ["", "## Findings", "", "| Severity | Location | Rule | Detail |", "|---|---|---|---|"]
    out += [f"| {x.severity} | `{x.file}:{x.line}` | `{x.code}` | {_md_escape(x.message)} |" for x in findings]
    out += ["", "---", "*Generated by policy_linter. Severity reflects audit impact: High = a "
            "nonconformity an auditor would likely raise; Medium = weakens the control; Low = hygiene.*", ""]
    return "\n".join(out)


def json_report(lib: list[Policy], findings: list[Finding], cfg: LintConfig, suppressed: int = 0) -> str:
    doc = {"summary": library_stats(lib, findings, cfg) | {"suppressed": suppressed},
           "review_calendar": review_calendar(lib, cfg),
           "documents": [{"file": p.rel, "id": p.id, "title": p.title, "status": p.status,
                          "version": p.version, "owner": p.get("owner")} for p in lib],
           "findings": [x.as_dict() for x in findings]}
    return json.dumps(doc, indent=2)


def github_annotations(findings: list[Finding], root_prefix: str = "") -> str:
    """GitHub Actions workflow commands, so findings show inline on pull requests."""
    level = {HIGH: "error", MEDIUM: "warning", LOW: "notice", INFO: "notice"}
    return "\n".join(f"::{level[x.severity]} file={root_prefix}{x.file},line={x.line},"
                     f"title={x.code}::{x.message}" for x in findings)


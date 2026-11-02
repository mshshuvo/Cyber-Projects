"""Renderers: console summary, Markdown report, JSON and a flat CSV matrix."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter

from .catalog import FRAMEWORKS, describe
from .engine import (DEFICIENT, EFFECTIVE, EXCEPTION, EXCEPTIONS, EXCLUDED, FAILED, GAP_STATUSES,
                     NOT_TESTED, PARTIAL, REQ_NO_EVIDENCE, REQ_STALE, SATISFIED, STALE, UNMAPPED,
                     UNTESTED, Assessment, EvidenceImpact, equivalents)

SHORT = {"ISO27001": "ISO", "SOC2": "SOC 2", "CSF2": "CSF", "CIS8": "CIS"}
COLUMNS = [("Satisfied", SATISFIED), ("w/ exc.", EXCEPTIONS), ("Partial", PARTIAL), ("Deficient", DEFICIENT),
           ("Stale", REQ_STALE), ("Untested", NOT_TESTED), ("No evid.", REQ_NO_EVIDENCE),
           ("Unmapped", UNMAPPED), ("Excluded", EXCLUDED)]


def _evidence_counts(a: Assessment) -> Counter:
    return Counter(a.evidence_states.values())


def _at_risk(a: Assessment, impact: EvidenceImpact) -> dict[str, list[str]]:
    """Requirements this evidence item is pulling down on the assessment date.

    Failed evidence: every requirement it supports that is now Deficient.
    Exception evidence: fully mapped requirements that are only satisfied with exceptions.
    Stale or untested evidence: fully mapped requirements that are not satisfied at all.
    Partial-only requirements are left out unless the evidence failed, because they
    were never satisfiable by this evidence alone.
    """
    if impact.state == FAILED:
        affected, full_only = (DEFICIENT,), False
    elif impact.state == EXCEPTION:
        affected, full_only = (EXCEPTIONS,), True
    else:
        affected, full_only = (PARTIAL, REQ_STALE, NOT_TESTED, REQ_NO_EVIDENCE), True
    controls = set(impact.evidence.controls)
    out: dict[str, list[str]] = {}
    for fw, ids in impact.requirements.items():
        hit = []
        for rid in ids:
            res = a.result(fw, rid)
            if res is None or res.status not in affected:
                continue
            if full_only and not any(m.control_id in controls and m.strength == "full" for m in res.mappings):
                continue
            hit.append(rid)
        if hit:
            out[fw] = hit
    return out


def problem_evidence(a: Assessment) -> list[EvidenceImpact]:
    """Failed, stale and untested evidence, biggest blast radius first."""
    order = {FAILED: 0, STALE: 1, UNTESTED: 2, EXCEPTION: 3}
    items = [i for i in a.impacts if i.state in order]
    return sorted(items, key=lambda i: (order[i.state], -i.total, i.evidence.evidence_id))


def top_reuse(a: Assessment, n: int = 10) -> list[EvidenceImpact]:
    return sorted(a.impacts, key=lambda i: (-i.total, i.evidence.evidence_id))[:n]


def _refs(reqs: dict[str, list[str]], limit: int | None = None, sep: str = " | ") -> str:
    parts = []
    for fw, ids in reqs.items():
        shown = ids if limit is None or len(ids) <= limit else ids[:limit] + [f"+{len(ids) - limit}"]
        parts.append(f"{SHORT[fw]} {', '.join(shown)}")
    return sep.join(parts)


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------
def console_report(a: Assessment, limit: int = 8) -> str:
    d = a.data
    ev = _evidence_counts(a)
    lines = [f"Control crosswalk assessment  (as of {a.as_of})"]
    if d.scope.org:
        lines[0] = f"Control crosswalk assessment: {d.scope.org}  (as of {a.as_of})"
    lines += ["=" * 78,
              f"Inputs: {len(d.controls)} common controls, {len(d.mappings)} valid mappings, "
              f"{len(d.evidence)} evidence items",
              f"Evidence: {ev[EFFECTIVE]} effective, {ev[EXCEPTION]} with exceptions, {ev[FAILED]} failed, "
              f"{ev[STALE]} stale, {ev[UNTESTED]} untested",
              f"Test once, satisfy many: each passing evidence item supports {a.test_once_ratio:.1f} "
              "in-scope requirements on average", ""]
    head = f"{'Framework':<20}{'Scope':>6}" + "".join(f"{c:>10}" for c, _ in COLUMNS[:-1]) + f"{'Coverage':>10}"
    lines.append(head)
    lines.append("-" * len(head))
    for fw in a.results:
        c = a.summary(fw)
        scope = sum(c.values()) - c[EXCLUDED]
        lines.append(f"{FRAMEWORKS[fw].name:<20}{scope:>6}" + "".join(f"{c[s]:>10}" for _, s in COLUMNS[:-1])
                     + f"{a.coverage(fw):>9.0f}%")

    probs = problem_evidence(a)
    if probs:
        lines += ["", "Evidence problems and their blast radius (requirements each one is pulling down)"]
        for imp in probs[:limit]:
            risk = _at_risk(a, imp)
            n = sum(len(v) for v in risk.values())
            lines.append(f"  [{imp.state:<9}] {imp.evidence.evidence_id} {imp.evidence.title[:46]:<46} "
                         f"{n:>2} req / {len(risk)} fw")
            if risk:
                lines.append(f"{'':16}{_refs(risk, 6)}")
    lines += ["", "Most reused evidence"]
    for imp in top_reuse(a, 5):
        lines.append(f"  {imp.evidence.evidence_id} {imp.evidence.title[:52]:<52} {imp.total:>3} requirements "
                     f"({', '.join(f'{SHORT[k]} {len(v)}' for k, v in imp.requirements.items())})")
    if a.findings:
        sev = Counter(f.severity for f in a.findings)
        lines += ["", f"Data-quality findings: {len(a.findings)}  (High {sev['High']}, Medium {sev['Medium']}, "
                      f"Low {sev['Low']})"]
        for f in a.findings[:limit]:
            lines.append(f"  [{f.severity:<6}] {f.code:<24} {f.where:<20} {f.message}")
        if len(a.findings) > limit:
            lines.append(f"  ... {len(a.findings) - limit} more in report.md")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def markdown_report(a: Assessment) -> str:
    d = a.data
    ev = _evidence_counts(a)
    title = "Control Crosswalk Assessment" + (f": {d.scope.org}" if d.scope.org else "")
    out = [f"# {title}", "",
           f"**Assessment date:** {a.as_of}  ",
           f"**Inputs:** {len(d.controls)} common controls, {len(d.mappings)} valid mappings, "
           f"{len(d.evidence)} evidence items  ",
           f"**Evidence states:** {ev[EFFECTIVE]} effective, {ev[EXCEPTION]} with exceptions, {ev[FAILED]} failed, "
           f"{ev[STALE]} stale, {ev[UNTESTED]} untested  ",
           f"**Test once, satisfy many:** each passing evidence item supports **{a.test_once_ratio:.1f}** "
           "in-scope requirements on average", "",
           "## Coverage by framework", "",
           "| Framework | In scope | " + " | ".join(c for c, _ in COLUMNS) + " | Coverage |",
           "|---|---:|" + "---:|" * len(COLUMNS) + "---:|"]
    for fw in a.results:
        c = a.summary(fw)
        scope = sum(c.values()) - c[EXCLUDED]
        out.append(f"| {FRAMEWORKS[fw].name} | {scope} | " + " | ".join(str(c[s]) for _, s in COLUMNS)
                   + f" | {a.coverage(fw):.0f}% |")
    out += ["", "*Coverage* = requirements satisfied (with or without exceptions) by a fully mapped, effective "
            "control, divided by in-scope requirements. Partial mappings never count as coverage.", ""]

    probs = problem_evidence(a)
    if probs:
        out += ["## Evidence problems: blast radius", "",
                "One weak piece of evidence breaks requirements in several frameworks at once. "
                "Fix these first.", "",
                "| Evidence | State | Controls | Requirements affected | Notes |", "|---|---|---|---|---|"]
        for imp in probs:
            e = imp.evidence
            risk = _at_risk(a, imp)
            out.append(f"| {e.evidence_id} {_md_escape(e.title)} | {imp.state} | {', '.join(e.controls)} | "
                       f"{_refs(risk, sep='; ') or 'none (other evidence covers them)'} | {_md_escape(e.notes)} |")
        out.append("")

    out += ["## Evidence reuse", "", "| Evidence | State | " + " | ".join(SHORT[f] for f in a.results)
            + " | Total |", "|---|---|" + "---:|" * (len(a.results) + 1)]
    for imp in sorted(a.impacts, key=lambda i: (-i.total, i.evidence.evidence_id)):
        out.append(f"| {imp.evidence.evidence_id} {_md_escape(imp.evidence.title)} | {imp.state} | "
                   + " | ".join(str(len(imp.requirements.get(f, []))) for f in a.results)
                   + f" | {imp.total} |")
    out.append("")

    out += ["## Gaps by framework", ""]
    for fw, results in a.results.items():
        gaps = [r for r in results if r.status in GAP_STATUSES]
        out += [f"### {FRAMEWORKS[fw].name} ({len(gaps)} gaps)", ""]
        if not gaps:
            out += ["No gaps.", ""]
            continue
        out += ["| Requirement | Status | Mapped controls | Why |", "|---|---|---|---|"]
        for r in sorted(gaps, key=lambda r: (GAP_STATUSES.index(r.status), list(FRAMEWORKS[fw].requirements).index(r.req_id))):
            ctl = ", ".join(f"{m.control_id}{'' if m.strength == 'full' else ' (partial)'}" for m in r.mappings)
            out.append(f"| {_md_escape(describe(fw, r.req_id))} | {r.status} | {ctl or '-'} | {_md_escape(r.reason)} |")
        out.append("")
        excluded = [r for r in results if r.status == EXCLUDED]
        if excluded:
            out += ["Excluded: " + "; ".join(f"{r.req_id} ({r.reason or 'no justification'})" for r in excluded), ""]

    out += ["## Data-quality findings", ""]
    if not a.findings:
        out.append("None.")
    else:
        out += ["| Severity | Rule | Where | Finding |", "|---|---|---|---|"]
        out += [f"| {f.severity} | `{f.code}` | {f.where} | {_md_escape(f.message)} |" for f in a.findings]
    out += ["", "---", "*Generated by the control crosswalk engine. The mappings are the organisation's own "
            "judgement; this report checks their consistency and the evidence behind them, not their "
            "authority. Framework titles are short labels, not the standards' text.*", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# JSON and CSV
# ---------------------------------------------------------------------------
def json_report(a: Assessment) -> str:
    data = {
        "as_of": a.as_of.isoformat(),
        "org": a.data.scope.org,
        "test_once_ratio": round(a.test_once_ratio, 2),
        "frameworks": {fw: {"name": FRAMEWORKS[fw].name, "coverage_pct": round(a.coverage(fw), 1),
                            "summary": a.summary(fw)} for fw in a.results},
        "controls": {cid: {"state": a.control_states.get(cid), "evidence": a.control_evidence.get(cid, [])}
                     for cid in a.data.controls},
        "evidence": [{"id": i.evidence.evidence_id, "title": i.evidence.title, "state": i.state,
                      "controls": i.evidence.controls, "supports": i.requirements, "supports_total": i.total,
                      "affected": _at_risk(a, i)} for i in a.impacts],
        "requirements": {fw: [{"id": r.req_id, "title": r.title, "status": r.status, "reason": r.reason,
                               "controls": [{"id": m.control_id, "strength": m.strength} for m in r.mappings],
                               "evidence": r.evidence} for r in res] for fw, res in a.results.items()},
        "findings": [f.__dict__ for f in a.findings],
    }
    return json.dumps(data, indent=2)


def matrix_csv(a: Assessment) -> str:
    """One row per in-scope requirement: the cross-framework matrix auditors ask for."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["framework", "requirement_id", "title", "status", "full_controls", "partial_controls",
                "evidence", "equivalents_in_other_frameworks", "reason"])
    for fw, results in a.results.items():
        for r in results:
            eq = equivalents(a.data, fw, r.req_id)
            w.writerow([fw, r.req_id, r.title, r.status,
                        ";".join(m.control_id for m in r.mappings if m.strength == "full"),
                        ";".join(m.control_id for m in r.mappings if m.strength == "partial"),
                        ";".join(r.evidence),
                        " | ".join(f"{k} {','.join(sorted(v, key=list(FRAMEWORKS[k].requirements).index))}"
                                   for k, v in sorted(eq.items()) if k != fw),
                        r.reason])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Single-item views for the CLI
# ---------------------------------------------------------------------------
def evidence_view(a: Assessment, evidence_id: str) -> str | None:
    imp = next((i for i in a.impacts if i.evidence.evidence_id == evidence_id.upper()), None)
    if imp is None:
        return None
    e = imp.evidence
    lines = [f"{e.evidence_id}  {e.title}",
             f"  State: {imp.state}   Result: {e.result}   Collected: {e.collected_on}   Valid until: {e.valid_until}",
             f"  Controls: {', '.join(e.controls) or '-'}   Owner: {e.owner or '-'}"]
    if e.notes:
        lines.append(f"  Notes: {e.notes}")
    lines.append(f"  Supports {imp.total} in-scope requirements:")
    for fw, ids in imp.requirements.items():
        lines.append(f"    {FRAMEWORKS[fw].name}")
        for rid in ids:
            res = a.result(fw, rid)
            lines.append(f"      {describe(fw, rid)[:64]:<64} {res.status if res else ''}")
    return "\n".join(lines)


def lookup_view(a: Assessment, framework: str, req_id: str) -> str:
    fw = FRAMEWORKS[framework]
    res = a.result(framework, req_id)
    lines = [f"{fw.name}  {describe(framework, req_id)}",
             f"  Status: {res.status if res else 'Out of scope'}" + (f"  ({res.reason})" if res and res.reason else "")]
    maps = [m for m in a.data.mappings if m.framework == framework and m.req_id == req_id]
    if not maps:
        lines.append("  No common control is mapped to this requirement.")
    for m in maps:
        evs = a.control_evidence.get(m.control_id, [])
        ctl = a.data.controls.get(m.control_id)
        lines.append(f"  {m.control_id} ({m.strength}) {ctl.title if ctl else '[undefined control]'}: "
                     f"{a.control_states.get(m.control_id, '-')}")
        for e in evs:
            lines.append(f"      {e} {a.evidence_states.get(e, '')}")
        if m.rationale:
            lines.append(f"      rationale: {m.rationale}")
    eq = equivalents(a.data, framework, req_id)
    if eq:
        lines.append("  The same controls also cover:")
        for k in FRAMEWORKS:
            if k in eq and k != framework:
                ids = sorted(eq[k], key=list(FRAMEWORKS[k].requirements).index)
                lines.append(f"    {FRAMEWORKS[k].name:<20} {', '.join(ids)}")
    return "\n".join(lines)

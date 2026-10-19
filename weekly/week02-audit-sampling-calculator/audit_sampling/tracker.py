"""Evidence tracker: one row per sampled item, and its evaluation.

The tracker is a plain CSV so it can live in a shared drive or be edited in
Excel during fieldwork. ``evaluate`` reconciles it to the manifest, flags
evidence-quality issues, and reaches a conclusion on the control.
"""
from __future__ import annotations

import csv
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from .population import HIGH, LOW, MEDIUM, SEVERITY_ORDER, Issue, Population
from .sampler import Manifest
from .stats import supports_reliance, upper_deviation_limit

STATUSES = ("not started", "requested", "received", "tested")
RESULTS = ("pass", "exception")
CORE_COLUMNS = ["sample_no", "item_id", "stratum", "status", "result", "evidence_ref",
                "requested_on", "received_on", "tester", "notes"]

EFFECTIVE = "EFFECTIVE"
NOT_EFFECTIVE = "NOT EFFECTIVE"
INCOMPLETE = "INCOMPLETE"


@dataclass
class TrackerRow:
    line: int
    sample_no: str
    item_id: str
    stratum: str
    status: str
    result: str
    evidence_ref: str
    requested_on: date | None
    received_on: date | None
    tester: str
    notes: str


def _d(value: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def write_tracker(path: Path, manifest: Manifest, pop: Population | None = None) -> None:
    """Create a blank tracker for the drawn sample. Population columns are
    appended after the core columns so testers can see each item's details."""
    extra: list[str] = []
    by_id: dict[str, dict[str, str]] = {}
    if pop is not None:
        extra = [f for f in pop.fieldnames if f != pop.id_column and f not in CORE_COLUMNS]
        by_id = {r[pop.id_column]: r for r in pop.frame}
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CORE_COLUMNS + extra)
        for i, s in enumerate(manifest.selected, start=1):
            details = by_id.get(s["item_id"], {})
            w.writerow([i, s["item_id"], s["stratum"], "not started", "", "", "", "", "", ""]
                       + [details.get(c, "") for c in extra])


def load_tracker(path: Path) -> list[TrackerRow]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = {"item_id", "status", "result"} - {c.lower() for c in (reader.fieldnames or [])}
        if missing:
            raise ValueError(f"tracker is missing column(s): {', '.join(sorted(missing))}")
        rows = []
        for line, raw in enumerate(reader, start=2):
            r = {k.strip().lower(): (v or "").strip() for k, v in raw.items() if k}
            rows.append(TrackerRow(
                line=line, sample_no=r.get("sample_no", ""), item_id=r.get("item_id", ""),
                stratum=r.get("stratum", ""), status=r.get("status", "").lower(),
                result=r.get("result", "").lower(), evidence_ref=r.get("evidence_ref", ""),
                requested_on=_d(r.get("requested_on", "")),
                received_on=_d(r.get("received_on", "")),
                tester=r.get("tester", ""), notes=r.get("notes", "")))
    return rows


@dataclass
class Evaluation:
    """Outcome of evaluating the tracker against the manifest."""
    planned: int
    status_counts: dict[str, int]
    tested: int
    passed: int
    exceptions: int
    allowed_deviations: int
    conclusion: str
    rationale: str
    upper_limit: float | None            # achieved upper deviation limit (statistical only)
    exceptions_by_stratum: dict[str, int] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)

    @property
    def progress(self) -> float:
        return self.tested / self.planned if self.planned else 0.0

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "issues"}
        d["progress"] = round(self.progress, 4)
        d["issues"] = [i.to_dict() for i in self.issues]
        return d


def check_tracker(rows: list[TrackerRow], manifest: Manifest, as_of: date,
                  overdue_days: int = 10) -> list[Issue]:
    """Reconcile tracker to manifest and check evidence quality."""
    issues: list[Issue] = []
    selected = set(manifest.selected_ids)
    counts = Counter(r.item_id for r in rows)

    for item_id, c in counts.items():
        if c > 1:
            issues.append(Issue("DUPLICATE_TRACKER_ROW", MEDIUM, item_id,
                                f"Item appears {c} times in the tracker; results may be double-counted."))
    for r in rows:
        if r.item_id not in selected:
            issues.append(Issue("NOT_IN_SAMPLE", HIGH, r.item_id or f"line {r.line}",
                                "Item is in the tracker but was not selected by the sample; "
                                "substituted or added items break randomness."))
    for item_id in manifest.selected_ids:
        if item_id not in counts:
            issues.append(Issue("SAMPLE_ITEM_MISSING", HIGH, item_id,
                                "Selected item is missing from the tracker (dropped or replaced)."))

    for r in rows:
        ref = r.item_id or f"line {r.line}"
        if r.status not in STATUSES:
            issues.append(Issue("BAD_STATUS", LOW, ref,
                                f"Status '{r.status}' is not one of: {', '.join(STATUSES)}."))
        if r.result and r.result not in RESULTS:
            issues.append(Issue("BAD_RESULT", MEDIUM, ref,
                                f"Result '{r.result}' is not 'pass' or 'exception'."))
        if r.status == "tested" and not r.result:
            issues.append(Issue("TESTED_NO_RESULT", MEDIUM, ref,
                                "Marked tested but no result is recorded."))
        if r.result in RESULTS and r.status != "tested":
            issues.append(Issue("RESULT_BEFORE_TESTED", LOW, ref,
                                f"Result '{r.result}' recorded while status is '{r.status}'."))
        if r.result in RESULTS and not r.evidence_ref:
            issues.append(Issue("NO_EVIDENCE_REF", MEDIUM, ref,
                                "Result recorded with no evidence reference; the conclusion "
                                "cannot be re-performed by a reviewer."))
        if r.result in RESULTS and not r.tester:
            issues.append(Issue("NO_TESTER", LOW, ref, "Result recorded with no tester named."))
        if r.result == "exception" and not r.notes:
            issues.append(Issue("EXCEPTION_NOT_DESCRIBED", MEDIUM, ref,
                                "Exception has no description of what failed."))
        if r.status == "requested" and r.requested_on and not r.received_on:
            age = (as_of - r.requested_on).days
            if age > overdue_days:
                issues.append(Issue("EVIDENCE_OVERDUE", LOW, ref,
                                    f"Evidence requested {age} days ago ({r.requested_on}) "
                                    "and not yet received."))
        if r.received_on and r.requested_on and r.received_on < r.requested_on:
            issues.append(Issue("DATE_ORDER", LOW, ref, "Received date is before requested date."))
    issues.sort(key=lambda i: (SEVERITY_ORDER[i.severity], i.check, i.ref))
    return issues


def evaluate(rows: list[TrackerRow], manifest: Manifest, as_of: date,
             overdue_days: int = 10) -> Evaluation:
    """Count results and reach a conclusion on control operating effectiveness."""
    issues = check_tracker(rows, manifest, as_of, overdue_days)
    selected = set(manifest.selected_ids)
    # Only rows that belong to the sample count, each item once.
    seen: set[str] = set()
    valid: list[TrackerRow] = []
    for r in rows:
        if r.item_id in selected and r.item_id not in seen:
            seen.add(r.item_id)
            valid.append(r)

    size = manifest.sample_size
    planned = len(manifest.selected)
    tested_rows = [r for r in valid if r.status == "tested" and r.result in RESULTS]
    exceptions = [r for r in tested_rows if r.result == "exception"]
    passed = len(tested_rows) - len(exceptions)
    k = len(exceptions)
    allowed = int(size.get("allowed_deviations", 0))
    statistical = str(size.get("method", "")).startswith("attribute")
    conf = size.get("confidence")
    tol = size.get("tolerable_rate")
    pop_n = size.get("population")
    complete = len(tested_rows) == planned and planned > 0

    upper = None
    if statistical and tested_rows:
        upper = upper_deviation_limit(k, len(tested_rows), conf, pop_n)

    if k > allowed:
        conclusion = NOT_EFFECTIVE
        rationale = (f"{k} exception(s) found, more than the {allowed} the sample design allows. "
                     "Further testing cannot change this outcome; stop, report the deficiency "
                     "and assess compensating controls.")
    elif not complete:
        conclusion = INCOMPLETE
        rationale = (f"{len(tested_rows)} of {planned} items tested. No conclusion until "
                     "every selected item is tested (do not substitute items).")
    elif statistical:
        ok = supports_reliance(k, planned, conf, tol, pop_n)
        conclusion = EFFECTIVE if ok else NOT_EFFECTIVE
        rationale = (f"{k} exception(s) in {planned}; upper deviation limit {round_up_pct(upper)} "
                     f"{'is within' if ok else 'exceeds'} the tolerable rate of {tol:.1%} "
                     f"at {conf:.0%} confidence.")
    else:
        conclusion = EFFECTIVE
        rationale = (f"No exceptions in {planned} items (judgmental sample: the conclusion "
                     "rests on auditor judgment, not a statistical limit).")

    return Evaluation(
        planned=planned,
        status_counts=dict(Counter(r.status or "(blank)" for r in valid)),
        tested=len(tested_rows), passed=passed, exceptions=k, allowed_deviations=allowed,
        conclusion=conclusion, rationale=rationale, upper_limit=upper,
        exceptions_by_stratum=dict(Counter(r.stratum or "(none)" for r in exceptions)),
        issues=issues,
    )


def remaining_capacity(evaluation: Evaluation) -> int | None:
    """How many more exceptions can be found before the conclusion becomes
    NOT EFFECTIVE (None once it already has)."""
    left = evaluation.allowed_deviations - evaluation.exceptions
    return left if left >= 0 else None


def round_up_pct(x: float) -> str:
    """Format a rate rounded *up* to one decimal - never overstate assurance."""
    return f"{math.ceil(x * 1000) / 10:.1f}%"

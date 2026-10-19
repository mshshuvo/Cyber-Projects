"""Population loading and completeness / accuracy checks.

Before any item is sampled, an auditor has to trust the population itself
(the "information produced by the entity", IPE). A perfect sample drawn from
an incomplete list proves nothing. This module loads the population CSV,
fingerprints it with SHA-256 and flags the problems that most often
invalidate a sample: blank or duplicate IDs, items outside the audit period,
unreadable dates and a record count that does not reconcile to the source
system.
"""
from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

HIGH, MEDIUM, LOW = "High", "Medium", "Low"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass(frozen=True)
class Issue:
    """A problem found in the population or the evidence tracker."""
    check: str
    severity: str
    ref: str
    message: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Population:
    """The sampling frame: the items eligible for selection."""
    path: str
    sha256: str
    id_column: str
    fieldnames: list[str]
    rows: list[dict[str, str]]                 # every row read from the file
    frame: list[dict[str, str]]                # rows eligible for sampling
    issues: list[Issue] = field(default_factory=list)

    @property
    def ids(self) -> list[str]:
        return [r[self.id_column] for r in self.frame]

    @property
    def blocking(self) -> list[Issue]:
        """High-severity issues that make sampling unsafe."""
        return [i for i in self.issues if i.severity == HIGH]


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_date(value: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value[:19], fmt).date()
        except ValueError:
            continue
    return None


def _find_column(fieldnames: list[str], wanted: str) -> str:
    """Case-insensitive column lookup; returns the actual header name."""
    for name in fieldnames:
        if name.strip().lower() == wanted.strip().lower():
            return name
    raise ValueError(f"column '{wanted}' not found; available: {', '.join(fieldnames)}")


def load_population(path: Path, id_column: str, date_column: str | None = None,
                    period_start: date | None = None, period_end: date | None = None,
                    expected_count: int | None = None) -> Population:
    """Read a population CSV and build the sampling frame.

    - Blank IDs and duplicate IDs are High issues (the frame is ambiguous).
    - Rows dated outside the period are Medium issues and are excluded.
    - Rows with an unreadable date (when a date column is given) are Medium
      issues and are excluded.
    - A record count that differs from ``expected_count`` is High: the
      population does not reconcile to the source system.
    """
    path = Path(path)
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        fieldnames = [f for f in (reader.fieldnames or [])]
        rows = [{k: (v or "").strip() for k, v in r.items() if k is not None} for r in reader]
    if not fieldnames:
        raise ValueError(f"{path} has no header row")
    id_col = _find_column(fieldnames, id_column)
    date_col = _find_column(fieldnames, date_column) if date_column else None

    issues: list[Issue] = []
    frame: list[dict[str, str]] = []
    seen: dict[str, int] = {}
    for line_no, row in enumerate(rows, start=2):           # header is line 1
        item_id = row.get(id_col, "")
        if not item_id:
            issues.append(Issue("BLANK_ID", HIGH, f"line {line_no}",
                                "Row has no item ID, so it cannot be selected or traced."))
            continue
        if item_id in seen:
            issues.append(Issue("DUPLICATE_ID", HIGH, item_id,
                                f"ID appears on lines {seen[item_id]} and {line_no}; "
                                "duplicates distort selection probability."))
            continue
        seen[item_id] = line_no
        if date_col:
            d = _parse_date(row.get(date_col, ""))
            if d is None:
                issues.append(Issue("UNREADABLE_DATE", MEDIUM, item_id,
                                    f"Date '{row.get(date_col, '')}' is blank or unreadable; "
                                    "item excluded from the frame."))
                continue
            if (period_start and d < period_start) or (period_end and d > period_end):
                issues.append(Issue("OUT_OF_PERIOD", MEDIUM, item_id,
                                    f"Dated {d}, outside the audit period "
                                    f"{period_start or '...'} to {period_end or '...'}; excluded."))
                continue
        frame.append(row)

    if expected_count is not None and expected_count != len(frame):
        issues.append(Issue("COUNT_MISMATCH", HIGH, "population",
                            f"Frame has {len(frame)} items but the source system reports "
                            f"{expected_count}; reconcile before sampling."))

    return Population(path=str(path), sha256=file_sha256(path), id_column=id_col,
                      fieldnames=fieldnames, rows=rows, frame=frame, issues=issues)

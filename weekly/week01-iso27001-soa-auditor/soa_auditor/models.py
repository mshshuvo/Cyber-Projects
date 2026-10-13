"""Data models and CSV loaders for the SoA, risk register and evidence log."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

IMPLEMENTED = "implemented"
PARTIAL = "partially implemented"
PLANNED = "planned"
NOT_IMPLEMENTED = "not implemented"
VALID_STATUSES = {IMPLEMENTED, PARTIAL, PLANNED, NOT_IMPLEMENTED}


def _split(value: str | None) -> list[str]:
    """Split a semicolon-separated cell into a clean list."""
    return [v.strip() for v in (value or "").split(";") if v.strip()]


def _parse_date(value: str | None) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _is_yes(value: str | None) -> bool:
    return (value or "").strip().lower() in {"yes", "y", "true", "1", "applicable"}


@dataclass
class SoAEntry:
    """One row of the Statement of Applicability."""
    row: int
    control_id: str
    control_name: str
    applicable: bool
    justification: str
    status: str
    evidence_refs: list[str] = field(default_factory=list)
    owner: str = ""
    last_reviewed: date | None = None


@dataclass
class Risk:
    """One row of the risk register."""
    risk_id: str
    description: str
    likelihood: int
    impact: int
    treatment: str
    controls: list[str] = field(default_factory=list)
    owner: str = ""

    @property
    def score(self) -> int:
        return self.likelihood * self.impact


@dataclass
class Evidence:
    """One item in the evidence log."""
    evidence_id: str
    control_id: str
    description: str
    collected: date | None
    valid_until: date | None


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        # Normalise header names so minor spelling differences don't break loading.
        return [
            {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            for row in reader
        ]


def load_soa(path: Path) -> list[SoAEntry]:
    entries: list[SoAEntry] = []
    for i, r in enumerate(_read_csv(path), start=2):  # row 1 is the header
        entries.append(SoAEntry(
            row=i,
            control_id=r.get("control_id", "").removeprefix("A.").strip(),
            control_name=r.get("control_name", ""),
            applicable=_is_yes(r.get("applicable")),
            justification=r.get("justification", ""),
            status=r.get("implementation_status", "").lower(),
            evidence_refs=_split(r.get("evidence_refs")),
            owner=r.get("owner", ""),
            last_reviewed=_parse_date(r.get("last_reviewed")),
        ))
    return entries


def load_risks(path: Path) -> list[Risk]:
    risks: list[Risk] = []
    for r in _read_csv(path):
        risks.append(Risk(
            risk_id=r.get("risk_id", ""),
            description=r.get("description", ""),
            likelihood=int(r.get("likelihood") or 0),
            impact=int(r.get("impact") or 0),
            treatment=r.get("treatment", "").lower(),
            controls=[c.removeprefix("A.") for c in _split(r.get("controls"))],
            owner=r.get("owner", ""),
        ))
    return risks


def load_evidence(path: Path) -> dict[str, Evidence]:
    items: dict[str, Evidence] = {}
    for r in _read_csv(path):
        ev = Evidence(
            evidence_id=r.get("evidence_id", ""),
            control_id=r.get("control_id", "").removeprefix("A."),
            description=r.get("description", ""),
            collected=_parse_date(r.get("collected")),
            valid_until=_parse_date(r.get("valid_until")),
        )
        items[ev.evidence_id] = ev
    return items

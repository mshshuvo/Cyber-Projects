"""Input model: common controls, framework mappings, evidence register and scope.

All inputs are plain CSV/JSON so they can live in Git next to the policies they
support. Loading never raises on bad rows: every problem becomes a ``Finding``
with a file and line, and the row is skipped or kept as far as it is usable.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .catalog import FRAMEWORKS, framework_key, hint_for_unknown, normalize_id

STRENGTHS = ("full", "partial")
RESULTS = ("pass", "pass_with_exceptions", "fail", "not_tested")
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


@dataclass(frozen=True)
class Finding:
    """A data-quality or consistency problem in the crosswalk inputs."""

    severity: str  # High | Medium | Low
    code: str
    where: str  # file:line, or a requirement / control id
    message: str


@dataclass
class Control:
    """A common (internal) control: the thing you actually operate and test once."""

    control_id: str
    title: str
    domain: str = ""
    owner: str = ""
    frequency: str = ""


@dataclass(frozen=True)
class Mapping:
    """One link from a common control to a framework requirement."""

    control_id: str
    framework: str
    req_id: str
    strength: str  # full: the control alone meets the requirement; partial: contributes
    rationale: str = ""
    line: int = 0


@dataclass
class Evidence:
    """One evidence artefact (report, export, ticket sample, test result)."""

    evidence_id: str
    title: str
    controls: list[str]
    result: str
    collected_on: date | None
    valid_until: date | None
    ev_type: str = ""
    owner: str = ""
    tested_by: str = ""
    notes: str = ""
    line: int = 0

    def is_current(self, as_of: date) -> bool:
        """Evidence counts only while it is inside its validity window."""
        if self.collected_on is None or self.collected_on > as_of:
            return False
        return self.valid_until is None or self.valid_until >= as_of


@dataclass
class Scope:
    """Requirements in scope per framework, plus justified exclusions."""

    in_scope: dict[str, list[str]] = field(default_factory=dict)
    exclusions: dict[str, dict[str, str]] = field(default_factory=dict)  # fw -> {req: justification}
    org: str = ""


@dataclass
class Dataset:
    """Everything the engine needs, plus the problems found while loading it."""

    controls: dict[str, Control]
    mappings: list[Mapping]
    evidence: list[Evidence]
    scope: Scope
    findings: list[Finding] = field(default_factory=list)


def _sentence(text: str) -> str:
    """Close a hint with a full stop unless it already ends a sentence."""
    return text if text.endswith(("?", ".", "!")) else text + "."


def _read_csv(path: Path) -> list[tuple[int, dict[str, str]]]:
    """Read a CSV into (line number, row) pairs with stripped keys and values."""
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        rows = []
        for row in reader:
            clean = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if any(clean.values()):
                rows.append((reader.line_num, clean))
        return rows


def _parse_date(value: str, where: str, label: str, findings: list[Finding]) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        findings.append(Finding("Medium", "BAD_DATE", where, f"{label} '{value}' is not a YYYY-MM-DD date."))
        return None


def load_controls(path: Path, findings: list[Finding]) -> dict[str, Control]:
    controls: dict[str, Control] = {}
    for line, row in _read_csv(path):
        where = f"{path.name}:{line}"
        cid = row.get("control_id", "").upper()
        if not cid:
            findings.append(Finding("High", "MISSING_FIELD", where, "Control row has no control_id."))
            continue
        if cid in controls:
            findings.append(Finding("High", "DUPLICATE_CONTROL", where, f"Control {cid} is defined twice."))
            continue
        if not row.get("owner"):
            findings.append(Finding("Medium", "CONTROL_NO_OWNER", where,
                                    f"Control {cid} has no owner; nobody is accountable for its evidence."))
        controls[cid] = Control(cid, row.get("title", ""), row.get("domain", ""), row.get("owner", ""),
                                row.get("frequency", ""))
    return controls


def load_mappings(path: Path, findings: list[Finding]) -> list[Mapping]:
    """Load the crosswalk. Unknown ids are reported with a hint and dropped."""
    mappings: list[Mapping] = []
    seen: dict[tuple[str, str, str], int] = {}
    for line, row in _read_csv(path):
        where = f"{path.name}:{line}"
        cid = row.get("control_id", "").upper()
        fw = framework_key(row.get("framework", ""))
        if fw is None:
            findings.append(Finding("High", "UNKNOWN_FRAMEWORK", where,
                                    f"Framework '{row.get('framework', '')}' is not one of "
                                    f"{', '.join(FRAMEWORKS)}."))
            continue
        raw = row.get("requirement_id", "")
        rid = normalize_id(fw, raw)
        if rid not in FRAMEWORKS[fw].requirements:
            findings.append(Finding("High", "UNKNOWN_REQUIREMENT", where,
                                    f"{fw} '{raw}' is not in the catalog: {_sentence(hint_for_unknown(fw, rid))}"))
            continue
        strength = row.get("strength", "full").lower() or "full"
        if strength not in STRENGTHS:
            findings.append(Finding("Medium", "BAD_STRENGTH", where,
                                    f"Strength '{strength}' should be full or partial; treated as partial."))
            strength = "partial"
        key = (cid, fw, rid)
        if key in seen:
            findings.append(Finding("Low", "DUPLICATE_MAPPING", where,
                                    f"{cid} -> {fw} {rid} already mapped on line {seen[key]}."))
            continue
        seen[key] = line
        mappings.append(Mapping(cid, fw, rid, strength, row.get("rationale", ""), line))
    return mappings


def load_evidence(path: Path, findings: list[Finding]) -> list[Evidence]:
    items: list[Evidence] = []
    ids: set[str] = set()
    for line, row in _read_csv(path):
        where = f"{path.name}:{line}"
        eid = row.get("evidence_id", "").upper()
        if not eid:
            findings.append(Finding("High", "MISSING_FIELD", where, "Evidence row has no evidence_id."))
            continue
        if eid in ids:
            findings.append(Finding("High", "DUPLICATE_EVIDENCE", where, f"Evidence id {eid} is used twice."))
            continue
        ids.add(eid)
        result = row.get("result", "").lower().replace(" ", "_") or "not_tested"
        if result not in RESULTS:
            findings.append(Finding("Medium", "BAD_RESULT", where,
                                    f"Result '{result}' is not one of {', '.join(RESULTS)}; treated as not_tested."))
            result = "not_tested"
        controls = [c.strip().upper() for c in row.get("controls", "").replace(",", ";").split(";") if c.strip()]
        if not controls:
            findings.append(Finding("Medium", "EVIDENCE_UNLINKED", where,
                                    f"{eid} is not linked to any control, so it supports nothing."))
        items.append(Evidence(
            eid, row.get("title", ""), controls, result,
            _parse_date(row.get("collected_on", ""), where, "collected_on", findings),
            _parse_date(row.get("valid_until", ""), where, "valid_until", findings),
            row.get("type", ""), row.get("owner", ""), row.get("tested_by", ""), row.get("notes", ""), line))
    return items


def load_scope(path: Path | None, findings: list[Finding]) -> Scope:
    """Load scope.json. Without a file every framework is in scope in full.

    Format::

        {"org": "...",
         "frameworks": {
            "ISO27001": {"include": ["clauses", "annex_a"],
                         "exclude": {"A.7.5": "justification", ...}},
            "CIS8": {"include": ["ig1"]}}}

    ``include`` takes catalog group names (see ``--list-groups``), explicit ids, or "all".
    A framework that is not listed is out of scope.
    """
    if path is None:
        return Scope({k: list(f.requirements) for k, f in FRAMEWORKS.items()})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(Finding("High", "BAD_SCOPE", path.name, f"Cannot read scope file: {exc}"))
        return Scope({k: list(f.requirements) for k, f in FRAMEWORKS.items()})
    scope = Scope(org=data.get("org", ""))
    for name, spec in (data.get("frameworks") or {}).items():
        fw = framework_key(name)
        if fw is None:
            findings.append(Finding("High", "UNKNOWN_FRAMEWORK", path.name, f"Scope names unknown framework '{name}'."))
            continue
        catalog = FRAMEWORKS[fw]
        include = spec.get("include", "all")
        include = [include] if isinstance(include, str) else include
        wanted: set[str] = set()
        for item in include:
            members = catalog.group_members(str(item))
            if members:
                wanted.update(members)
                continue
            rid = normalize_id(fw, str(item))
            if rid in catalog.requirements:
                wanted.add(rid)
            else:
                findings.append(Finding("Medium", "BAD_SCOPE_ITEM", f"{path.name}:{fw}",
                                        f"'{item}' is neither a {fw} group nor a requirement id."))
        exclusions: dict[str, str] = {}
        for raw, why in (spec.get("exclude") or {}).items():
            rid = normalize_id(fw, raw)
            if rid not in catalog.requirements:
                findings.append(Finding("Medium", "BAD_SCOPE_ITEM", f"{path.name}:{fw}",
                                        f"Excluded '{raw}' is not a {fw} requirement: {_sentence(hint_for_unknown(fw, rid))}"))
                continue
            if not str(why).strip():
                findings.append(Finding("High", "EXCLUSION_NOT_JUSTIFIED", f"{fw} {rid}",
                                        f"{rid} is excluded without a justification."))
            exclusions[rid] = str(why).strip()
        scope.in_scope[fw] = [r for r in catalog.requirements if r in wanted]
        scope.exclusions[fw] = exclusions
    return scope


def load_dataset(controls: Path, mappings: Path, evidence: Path, scope: Path | None = None) -> Dataset:
    """Load and cross-reference all inputs; referential problems are added as findings."""
    findings: list[Finding] = []
    ctl = load_controls(controls, findings)
    maps = load_mappings(mappings, findings)
    ev = load_evidence(evidence, findings)
    sc = load_scope(scope, findings)

    mapped_controls = {m.control_id for m in maps}
    for m in maps:
        if m.control_id not in ctl:
            findings.append(Finding("High", "UNKNOWN_CONTROL", f"{mappings.name}:{m.line}",
                                    f"Mapping refers to control {m.control_id}, which is not defined."))
    for cid in ctl:
        if cid not in mapped_controls:
            findings.append(Finding("Medium", "CONTROL_UNMAPPED", cid,
                                    f"Control {cid} maps to no framework requirement; its testing earns no credit."))
    evidenced = {c for e in ev for c in e.controls}
    for e in ev:
        for c in e.controls:
            if c not in ctl:
                findings.append(Finding("High", "UNKNOWN_CONTROL", f"{evidence.name}:{e.line}",
                                        f"{e.evidence_id} supports control {c}, which is not defined."))
        if e.collected_on and e.valid_until and e.valid_until < e.collected_on:
            findings.append(Finding("Medium", "BAD_DATE", f"{evidence.name}:{e.line}",
                                    f"{e.evidence_id} expires before it was collected."))
    for cid in ctl:
        if cid not in evidenced:
            findings.append(Finding("Medium", "CONTROL_NO_EVIDENCE", cid,
                                    f"Control {cid} has no evidence in the register."))
    return Dataset(ctl, maps, ev, sc, findings)

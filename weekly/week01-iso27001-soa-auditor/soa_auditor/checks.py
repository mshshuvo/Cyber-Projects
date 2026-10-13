"""Audit checks that compare the SoA, risk register and evidence log.

Each check returns Finding objects tied to a clause of ISO/IEC 27001:2022,
so every result can go straight into an audit working paper.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict
from datetime import date, timedelta

from .catalog import ANNEX_A, HARD_TO_EXCLUDE
from .models import (
    IMPLEMENTED, NOT_IMPLEMENTED, PARTIAL, PLANNED, VALID_STATUSES,
    Evidence, Risk, SoAEntry,
)

HIGH, MEDIUM, LOW = "High", "Medium", "Low"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}
SEVERITY_WEIGHT = {HIGH: 5.0, MEDIUM: 2.0, LOW: 0.5}


@dataclass(frozen=True)
class Finding:
    check: str        # short machine-readable check code
    severity: str     # High / Medium / Low
    ref: str          # control ID, risk ID or row reference
    clause: str       # ISO/IEC 27001:2022 clause the finding relates to
    message: str      # human-readable description

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AuditConfig:
    as_of: date
    review_max_age_days: int = 365   # SoA rows should be reviewed at least yearly
    high_risk_score: int = 15        # on a 5x5 likelihood x impact scale


def _index(soa: list[SoAEntry]) -> dict[str, SoAEntry]:
    """Map control ID to its first SoA entry (duplicates are reported separately)."""
    idx: dict[str, SoAEntry] = {}
    for e in soa:
        idx.setdefault(e.control_id, e)
    return idx


def check_structure(soa: list[SoAEntry]) -> list[Finding]:
    """Completeness against Annex A, duplicates, legacy numbering, bad values."""
    out: list[Finding] = []
    ids = [e.control_id for e in soa]
    present = set(ids)

    for cid, name in ANNEX_A.items():
        if cid not in present:
            out.append(Finding("MISSING_CONTROL", HIGH, cid, "6.1.3 c-d",
                               f"Annex A control {cid} '{name}' is not addressed in the SoA."))

    for cid, n in Counter(ids).items():
        if n > 1:
            out.append(Finding("DUPLICATE_CONTROL", LOW, cid, "7.5",
                               f"Control {cid} appears {n} times; keep one authoritative row."))

    for e in soa:
        if e.control_id not in ANNEX_A:
            hint = (" Looks like ISO 27001:2013 numbering; map it to the 2022 controls."
                    if e.control_id.count(".") >= 2 else "")
            out.append(Finding("UNKNOWN_CONTROL", MEDIUM, f"row {e.row}", "6.1.3 c",
                               f"'{e.control_id}' is not an ISO/IEC 27001:2022 Annex A control.{hint}"))
        if e.applicable and e.status not in VALID_STATUSES:
            out.append(Finding("INVALID_STATUS", LOW, e.control_id, "6.1.3 d",
                               f"Status '{e.status or 'blank'}' is not one of: "
                               f"{', '.join(sorted(VALID_STATUSES))}."))
    return out


def check_justifications(soa: list[SoAEntry]) -> list[Finding]:
    """Clause 6.1.3 d requires justification for both inclusions and exclusions."""
    out: list[Finding] = []
    for e in soa:
        if e.control_id not in ANNEX_A:
            continue
        if not e.applicable:
            if not e.justification:
                out.append(Finding("EXCLUSION_NO_JUSTIFICATION", HIGH, e.control_id, "6.1.3 d",
                                   "Control is excluded with no justification."))
            elif len(e.justification.split()) < 5:
                out.append(Finding("WEAK_EXCLUSION_JUSTIFICATION", MEDIUM, e.control_id, "6.1.3 d",
                                   f"Exclusion justification is too thin: '{e.justification}'."))
            if e.control_id in HARD_TO_EXCLUDE:
                out.append(Finding("UNUSUAL_EXCLUSION", MEDIUM, e.control_id, "6.1.3 b-d",
                                   f"'{ANNEX_A[e.control_id]}' is rarely excludable; expect auditor challenge."))
        elif not e.justification:
            out.append(Finding("INCLUSION_NO_JUSTIFICATION", LOW, e.control_id, "6.1.3 d",
                               "Applicable control has no justification for inclusion "
                               "(e.g. linked risk, legal or contractual requirement)."))
    return out


def check_evidence(soa: list[SoAEntry], evidence: dict[str, Evidence] | None,
                   cfg: AuditConfig) -> list[Finding]:
    """Implemented controls need current, traceable evidence."""
    out: list[Finding] = []
    for e in soa:
        if not e.applicable or e.control_id not in ANNEX_A:
            continue
        if e.status in (IMPLEMENTED, PARTIAL) and not e.evidence_refs:
            sev = MEDIUM if e.status == IMPLEMENTED else LOW
            out.append(Finding("NO_EVIDENCE", sev, e.control_id, "7.5 / 9.2",
                               f"Marked '{e.status}' but no evidence is referenced."))
        if evidence is None:
            continue
        for ref in e.evidence_refs:
            ev = evidence.get(ref)
            if ev is None:
                out.append(Finding("EVIDENCE_NOT_FOUND", MEDIUM, e.control_id, "7.5",
                                   f"Evidence '{ref}' is referenced but not in the evidence log."))
            elif ev.control_id and ev.control_id != e.control_id:
                out.append(Finding("EVIDENCE_MISMATCH", LOW, e.control_id, "7.5",
                                   f"Evidence '{ref}' is logged against {ev.control_id}, not {e.control_id}."))
            elif ev.valid_until and ev.valid_until < cfg.as_of:
                out.append(Finding("EVIDENCE_EXPIRED", MEDIUM, e.control_id, "7.5 / 9.2",
                                   f"Evidence '{ref}' expired on {ev.valid_until}."))
    return out


def check_hygiene(soa: list[SoAEntry], cfg: AuditConfig) -> list[Finding]:
    """Ownership and review currency of SoA rows."""
    out: list[Finding] = []
    cutoff = cfg.as_of - timedelta(days=cfg.review_max_age_days)
    for e in soa:
        if e.control_id not in ANNEX_A or not e.applicable:
            continue
        if not e.owner:
            out.append(Finding("NO_OWNER", LOW, e.control_id, "5.3",
                               "Applicable control has no accountable owner."))
        if e.last_reviewed is None:
            out.append(Finding("NEVER_REVIEWED", LOW, e.control_id, "9.3 / 10.1",
                               "No review date recorded."))
        elif e.last_reviewed < cutoff:
            out.append(Finding("STALE_REVIEW", LOW, e.control_id, "9.3 / 10.1",
                               f"Last reviewed {e.last_reviewed}, more than "
                               f"{cfg.review_max_age_days} days before {cfg.as_of}."))
    return out


def check_risk_alignment(soa: list[SoAEntry], risks: list[Risk] | None,
                         cfg: AuditConfig) -> list[Finding]:
    """The SoA must agree with the risk treatment plan (clauses 6.1.3 and 8.3)."""
    if risks is None:
        return []
    out: list[Finding] = []
    idx = _index(soa)
    referenced: set[str] = set()

    for r in risks:
        referenced.update(r.controls)
        if r.treatment in ("mitigate", "modify", "reduce") and not r.controls:
            out.append(Finding("RISK_NO_CONTROLS", HIGH, r.risk_id, "6.1.3 b",
                               f"Risk '{r.description}' is being mitigated but no controls are mapped."))
        for cid in r.controls:
            entry = idx.get(cid)
            if entry is None:
                out.append(Finding("RISK_CONTROL_NOT_IN_SOA", HIGH, r.risk_id, "6.1.3 c-d",
                                   f"Treatment relies on control {cid}, which is missing from the SoA."))
            elif not entry.applicable:
                out.append(Finding("RISK_RELIES_ON_EXCLUDED", HIGH, r.risk_id, "6.1.3 d",
                                   f"Treatment relies on control {cid}, but the SoA marks it not applicable."))
        if r.score >= cfg.high_risk_score and r.controls:
            effective = [c for c in r.controls
                         if c in idx and idx[c].applicable and idx[c].status == IMPLEMENTED]
            if not effective:
                out.append(Finding("HIGH_RISK_UNTREATED", HIGH, r.risk_id, "8.3",
                                   f"High risk (score {r.score}) has no mapped control fully implemented yet."))
        if r.treatment == "accept" and r.score >= cfg.high_risk_score:
            out.append(Finding("HIGH_RISK_ACCEPTED", MEDIUM, r.risk_id, "6.1.3 f",
                               f"High risk (score {r.score}) is accepted; confirm documented "
                               f"risk-owner approval{f' ({r.owner})' if r.owner else ''}."))

    for e in soa:
        if (e.applicable and e.control_id in ANNEX_A and e.status in (PLANNED, NOT_IMPLEMENTED)
                and e.control_id not in referenced and not e.justification):
            out.append(Finding("ORPHAN_GAP", MEDIUM, e.control_id, "6.1.3 d-e",
                               f"Applicable control is '{e.status}' with no linked risk or justification, "
                               "so there is no basis to prioritise it."))
    return out


def run_all(soa: list[SoAEntry], risks: list[Risk] | None,
            evidence: dict[str, Evidence] | None, cfg: AuditConfig) -> list[Finding]:
    findings = (
        check_structure(soa)
        + check_justifications(soa)
        + check_evidence(soa, evidence, cfg)
        + check_hygiene(soa, cfg)
        + check_risk_alignment(soa, risks, cfg)
    )
    # A control linked to a risk treatment is justified by that link, and an
    # orphan gap already reports the missing rationale, so drop the duplicate.
    linked = {c for r in (risks or []) for c in r.controls}
    orphans = {f.ref for f in findings if f.check == "ORPHAN_GAP"}
    findings = [f for f in findings
                if not (f.check == "INCLUSION_NO_JUSTIFICATION" and (f.ref in linked or f.ref in orphans))]
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.check, f.ref))


def readiness_score(findings: list[Finding]) -> int:
    """A simple 0–100 certification-readiness indicator (100 = no findings)."""
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, round(100 - penalty))

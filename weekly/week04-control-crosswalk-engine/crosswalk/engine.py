"""Crosswalk engine: evidence -> common controls -> framework requirements.

The chain of reasoning is deliberately simple so an auditor can re-perform it:

1. Each evidence item has a result and a validity window. On the assessment
   date it is EFFECTIVE (passed, current), EXCEPTION (passed with exceptions),
   FAILED, STALE (outside its window) or UNTESTED.
2. A common control takes the status of its current evidence, worst result
   first: one failed test is not cancelled out by another that passed.
3. A framework requirement is SATISFIED only when a control mapped to it with
   strength "full" is effective. Partial mappings alone give PARTIAL, never
   SATISFIED, because two partial controls do not prove the whole requirement.
   Any failed mapped control makes the requirement DEFICIENT.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

from .catalog import FRAMEWORKS
from .model import Dataset, Evidence, Finding, Mapping

# Evidence / control states, best first (used to pick the best control for a requirement)
EFFECTIVE, EXCEPTION, STALE, UNTESTED, NO_EVIDENCE, FAILED = (
    "Effective", "Exception", "Stale", "Untested", "No evidence", "Failed")
_CONTROL_RANK = {EFFECTIVE: 0, EXCEPTION: 1, STALE: 2, UNTESTED: 3, NO_EVIDENCE: 4, FAILED: 5}

# Requirement statuses, in report order (worst first after the excluded/unmapped bookends)
DEFICIENT, SATISFIED, EXCEPTIONS, PARTIAL = "Deficient", "Satisfied", "Satisfied with exceptions", "Partial"
REQ_STALE, NOT_TESTED, REQ_NO_EVIDENCE, UNMAPPED, EXCLUDED = (
    "Evidence stale", "Not tested", "No evidence", "Unmapped", "Excluded")
REQ_STATUSES = (SATISFIED, EXCEPTIONS, PARTIAL, DEFICIENT, REQ_STALE, NOT_TESTED, REQ_NO_EVIDENCE,
                UNMAPPED, EXCLUDED)
GAP_STATUSES = (DEFICIENT, REQ_STALE, NOT_TESTED, REQ_NO_EVIDENCE, UNMAPPED, PARTIAL)


def evidence_state(ev: Evidence, as_of: date) -> str:
    """State of one evidence item on the assessment date."""
    if ev.collected_on is None or ev.collected_on > as_of:
        return UNTESTED
    if not ev.is_current(as_of):
        return STALE
    return {"pass": EFFECTIVE, "pass_with_exceptions": EXCEPTION, "fail": FAILED}.get(ev.result, UNTESTED)


def control_state(states: list[str]) -> str:
    """Combine the states of a control's evidence. Current failures and exceptions win."""
    if not states:
        return NO_EVIDENCE
    for s in (FAILED, EXCEPTION, EFFECTIVE, STALE, UNTESTED):
        if s in states:
            return s
    return NO_EVIDENCE


@dataclass
class RequirementResult:
    framework: str
    req_id: str
    title: str
    status: str
    mappings: list[Mapping] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # ids of evidence behind the mapped controls
    reason: str = ""


@dataclass
class EvidenceImpact:
    """What one evidence item proves (or breaks) across every framework in scope."""

    evidence: Evidence
    state: str
    requirements: dict[str, list[str]]  # framework -> requirement ids supported (in scope)

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.requirements.values())


@dataclass
class Assessment:
    as_of: date
    data: Dataset
    evidence_states: dict[str, str]
    control_states: dict[str, str]
    control_evidence: dict[str, list[str]]
    results: dict[str, list[RequirementResult]]  # framework -> results in catalog order
    impacts: list[EvidenceImpact]
    findings: list[Finding]

    def summary(self, framework: str) -> dict[str, int]:
        counts = {s: 0 for s in REQ_STATUSES}
        for r in self.results.get(framework, []):
            counts[r.status] += 1
        return counts

    def coverage(self, framework: str) -> float:
        """Share of in-scope (non-excluded) requirements that are satisfied, with or without exceptions."""
        c = self.summary(framework)
        denom = sum(c.values()) - c[EXCLUDED]
        return 0.0 if denom == 0 else 100.0 * (c[SATISFIED] + c[EXCEPTIONS]) / denom

    def result(self, framework: str, req_id: str) -> RequirementResult | None:
        return next((r for r in self.results.get(framework, []) if r.req_id == req_id), None)

    @property
    def test_once_ratio(self) -> float:
        """Requirement credits earned per evidence item tested (the 'test once, satisfy many' factor)."""
        used = [i for i in self.impacts if i.state in (EFFECTIVE, EXCEPTION) and i.total]
        return 0.0 if not used else sum(i.total for i in used) / len(used)


def _requirement_status(maps: list[Mapping], cstate: dict[str, str]) -> tuple[str, str]:
    if not maps:
        return UNMAPPED, "No common control is mapped to this requirement."
    failed = [m.control_id for m in maps if cstate.get(m.control_id) == FAILED]
    if failed:
        return DEFICIENT, f"Mapped control failed testing: {', '.join(failed)}."
    full = [m for m in maps if m.strength == "full"]
    best_full = min((cstate.get(m.control_id, NO_EVIDENCE) for m in full),
                    key=_CONTROL_RANK.__getitem__, default=None)
    if best_full == EFFECTIVE:
        return SATISFIED, ""
    if best_full == EXCEPTION:
        return EXCEPTIONS, "Best full-strength control passed with exceptions."
    partial_ok = [m.control_id for m in maps if m.strength == "partial"
                  and cstate.get(m.control_id) in (EFFECTIVE, EXCEPTION)]
    if partial_ok:
        why = "Only partial-strength controls are effective"
        if full:
            why += f"; full-strength control(s) {', '.join(m.control_id for m in full)} are " \
                   f"{best_full.lower()}"
        return PARTIAL, why + "."
    states = {cstate.get(m.control_id, NO_EVIDENCE) for m in maps}
    if STALE in states:
        return REQ_STALE, "Evidence for every mapped control is outside its validity window."
    if UNTESTED in states:
        return NOT_TESTED, "Evidence exists but has not been tested yet."
    return REQ_NO_EVIDENCE, "Mapped controls have no evidence in the register."


def assess(data: Dataset, as_of: date) -> Assessment:
    """Run the full crosswalk assessment on a loaded dataset."""
    findings = list(data.findings)
    ev_state: dict[str, str] = {}
    by_control: dict[str, list[str]] = defaultdict(list)
    for ev in data.evidence:
        ev_state[ev.evidence_id] = evidence_state(ev, as_of)
        if ev.collected_on and ev.collected_on > as_of:
            findings.append(Finding("Medium", "FUTURE_DATE", ev.evidence_id,
                                    f"{ev.evidence_id} is dated {ev.collected_on}, after the assessment date."))
        for c in ev.controls:
            by_control[c].append(ev.evidence_id)

    cstate = {cid: control_state([ev_state[e] for e in by_control.get(cid, [])]) for cid in data.controls}
    # Controls referenced by evidence or mappings but not defined still get a state, so nothing is lost.
    for cid in set(by_control) | {m.control_id for m in data.mappings}:
        cstate.setdefault(cid, control_state([ev_state[e] for e in by_control.get(cid, [])]))

    maps_by_req: dict[tuple[str, str], list[Mapping]] = defaultdict(list)
    for m in data.mappings:
        maps_by_req[(m.framework, m.req_id)].append(m)

    results: dict[str, list[RequirementResult]] = {}
    for fw, req_ids in data.scope.in_scope.items():
        excluded = data.scope.exclusions.get(fw, {})
        out: list[RequirementResult] = []
        for rid in req_ids:
            maps = maps_by_req.get((fw, rid), [])
            evidence = sorted({e for m in maps for e in by_control.get(m.control_id, [])})
            title = FRAMEWORKS[fw].requirements[rid].title
            if rid in excluded:
                out.append(RequirementResult(fw, rid, title, EXCLUDED, maps, evidence, excluded[rid]))
                if any(cstate.get(m.control_id) == EFFECTIVE for m in maps if m.strength == "full"):
                    findings.append(Finding(
                        "Medium", "EXCLUDED_BUT_OPERATING", f"{fw} {rid}",
                        f"{rid} is excluded from scope, yet a fully mapped control operates effectively. "
                        "Check the justification (ISO 27001 6.1.3 d)."))
                continue
            status, reason = _requirement_status(maps, cstate)
            out.append(RequirementResult(fw, rid, title, status, maps, evidence, reason))
        results[fw] = out

    in_scope = {fw: {r.req_id for r in res if r.status != EXCLUDED} for fw, res in results.items()}
    impacts: list[EvidenceImpact] = []
    for ev in data.evidence:
        reqs: dict[str, list[str]] = {}
        for fw in results:
            ids = sorted({m.req_id for m in data.mappings
                          if m.framework == fw and m.control_id in ev.controls and m.req_id in in_scope[fw]},
                         key=list(FRAMEWORKS[fw].requirements).index)
            if ids:
                reqs[fw] = ids
        impacts.append(EvidenceImpact(ev, ev_state[ev.evidence_id], reqs))

    findings.sort(key=lambda f: (0 if f.severity == "High" else 1 if f.severity == "Medium" else 2, f.code, f.where))
    return Assessment(as_of, data, ev_state, cstate, dict(by_control), results, impacts, findings)


def equivalents(data: Dataset, framework: str, req_id: str) -> dict[str, set[str]]:
    """Requirements in other frameworks that share a common control with this one.

    This is the 'translation' view: what an ISO auditor's A.8.15 means in SOC 2,
    CSF and CIS terms, through the controls the organisation actually runs.
    """
    controls = {m.control_id for m in data.mappings if m.framework == framework and m.req_id == req_id}
    out: dict[str, set[str]] = defaultdict(set)
    for m in data.mappings:
        if m.control_id in controls and not (m.framework == framework and m.req_id == req_id):
            out[m.framework].add(m.req_id)
    return dict(out)

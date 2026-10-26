"""Lint rules for a policy library.

Each check takes the parsed library plus a :class:`LintConfig` and returns
:class:`Finding` objects. Checks are grouped by the question an auditor asks:

* Is every document governed?          (metadata, ownership, approval)
* Is it current?                        (review cycle, stale drafts, future dates)
* Is it internally consistent?          (version drift, unapproved changes)
* Does it hang together as a library?   (broken references, links, anchors, retired targets)
* Does it speak one language?           (undefined acronyms, conflicting definitions)
* Is it finished?                       (required sections, placeholder text)
"""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .model import (APPROVED, DRAFT, RETIRED, STATUSES, Glossary, Policy, add_months,
                    parse_date, slugify, version_key)

HIGH, MEDIUM, LOW, INFO = "High", "Medium", "Low", "Info"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

REQUIRED_META = ("id", "title", "version", "status", "owner", "approver",
                 "approved_on", "last_reviewed")
DEFAULT_SECTIONS = ("Purpose", "Scope", "Roles and Responsibilities",
                    "Compliance", "Exceptions", "Review")
#: Upper-case words that are normative keywords (RFC 2119) or otherwise not acronyms.
DEFAULT_IGNORE_TERMS = frozenset({"MUST", "SHALL", "SHOULD", "MAY", "NOT", "REQUIRED",
                                  "RECOMMENDED", "OPTIONAL", "NOTE", "TODO", "TBD", "ID"})
PLACEHOLDER = re.compile(r"\b(TODO|TBD|TBC|FIXME|XXX|lorem ipsum)\b|\[(insert|add|enter)[^\]]*\]"
                         r"|<\s*(insert|company|name)[^>]*>", re.I)

# ISO/IEC 27001:2022 Annex A: 5.1-5.37, 6.1-6.8, 7.1-7.14, 8.1-8.34 (93 controls).
ANNEX_A_2022 = frozenset(f"A.{t}.{n}" for t, last in ((5, 37), (6, 8), (7, 14), (8, 34))
                         for n in range(1, last + 1))


@dataclass
class Finding:
    """One lint result, located to a file and line."""
    code: str
    severity: str
    file: str
    line: int
    message: str
    policy_id: str = ""

    def as_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "file": self.file,
                "line": self.line, "policy_id": self.policy_id, "message": self.message}


@dataclass
class Owner:
    role: str
    holder: str
    status: str   # active | vacant | departed


@dataclass
class LintConfig:
    as_of: date
    due_soon_days: int = 45
    default_cycle_months: int = 12
    stale_draft_days: int = 180
    required_sections: tuple[str, ...] = DEFAULT_SECTIONS
    ignore_terms: frozenset[str] = DEFAULT_IGNORE_TERMS
    glossary: Glossary = field(default_factory=Glossary)
    owners: dict[str, Owner] | None = None     # role (lower case) -> Owner


def load_owners(path: Path | None) -> dict[str, Owner] | None:
    """Read an owner register CSV with columns role, holder, status."""
    if path is None:
        return None
    with path.open(newline="", encoding="utf-8") as fh:
        rows = csv.DictReader(fh)
        return {r["role"].strip().lower(): Owner(r["role"].strip(), (r.get("holder") or "").strip(),
                                                 (r.get("status") or "active").strip().lower())
                for r in rows if (r.get("role") or "").strip()}


def _f(pol: Policy, code: str, sev: str, line: int, msg: str) -> Finding:
    return Finding(code, sev, pol.rel, line, msg, pol.id)


def _active(pol: Policy) -> bool:
    return pol.status != RETIRED


# --------------------------------------------------------------------------- governance
def check_metadata(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Required fields, valid status and dates, unique ids, valid control mappings."""
    out: list[Finding] = []
    by_id: dict[str, list[Policy]] = defaultdict(list)
    for p in lib:
        if not p.has_front_matter:
            out.append(_f(p, "NO_FRONT_MATTER", HIGH, 1,
                          "No front matter; the document has no id, owner, version or approval record."))
            continue
        for ln, msg in p.meta_errors:
            out.append(_f(p, "BAD_FRONT_MATTER", MEDIUM, ln, msg))
        for key in REQUIRED_META:
            if key in ("owner", "approver"):
                continue                           # handled by check_ownership
            if key in ("approved_on", "last_reviewed") and p.status != APPROVED:
                continue                           # drafts and retired documents need not carry these
            if not p.get(key):
                sev = HIGH if key in ("id", "status") else MEDIUM
                out.append(_f(p, "MISSING_FIELD", sev, 1, f"Required field '{key}' is missing or empty."))
        if p.status and p.status not in STATUSES:
            out.append(_f(p, "BAD_STATUS", MEDIUM, p.line_of("status"),
                          f"Status '{p.get('status')}' is not one of {', '.join(STATUSES)}."))
        for key in ("approved_on", "last_reviewed", "next_review"):
            if p.get(key) and parse_date(p.get(key)) is None:
                out.append(_f(p, "BAD_DATE", MEDIUM, p.line_of(key),
                              f"'{key}' value '{p.get(key)}' is not a YYYY-MM-DD date."))
            d = parse_date(p.get(key))
            if d and key != "next_review" and d > cfg.as_of:
                out.append(_f(p, "FUTURE_DATE", MEDIUM, p.line_of(key),
                              f"'{key}' is {d}, after the assessment date {cfg.as_of}."))
        cycle = p.get("review_cycle_months")
        if cycle and not (cycle.isdigit() and 1 <= int(cycle) <= 36):
            out.append(_f(p, "BAD_REVIEW_CYCLE", MEDIUM, p.line_of("review_cycle_months"),
                          f"review_cycle_months '{cycle}' should be a whole number from 1 to 36."))
        for ctl in p.get_list("iso27001"):
            if ctl not in ANNEX_A_2022:
                out.append(_f(p, "INVALID_CONTROL_REF", MEDIUM, p.line_of("iso27001"),
                              f"'{ctl}' is not an ISO/IEC 27001:2022 Annex A control "
                              f"(2013 numbering, or a typo?)."))
        if p.id:
            by_id[p.id].append(p)
    for pid, pols in by_id.items():
        if len(pols) > 1:
            names = ", ".join(x.rel for x in pols)
            for p in pols:
                out.append(_f(p, "DUPLICATE_ID", HIGH, p.line_of("id"),
                              f"Id {pid} is used by {len(pols)} documents ({names}); references are ambiguous."))
    return out


def check_ownership(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Owner and approver present, independent of each other, and still in post."""
    out: list[Finding] = []
    for p in filter(_active, lib):
        if not p.has_front_matter:
            continue
        owner, approver = p.get("owner"), p.get("approver")
        if not owner:
            out.append(_f(p, "MISSING_OWNER", HIGH, 1,
                          "No owner; nobody is accountable for keeping this document current (ISO 27001 5.3, A.5.1)."))
        if not approver and p.status == APPROVED:
            out.append(_f(p, "MISSING_APPROVER", HIGH, 1,
                          "Marked approved but no approver is recorded (ISO 27001 7.5.2)."))
        if owner and approver and owner.strip().lower() == approver.strip().lower():
            out.append(_f(p, "SELF_APPROVED", MEDIUM, p.line_of("approver"),
                          f"Owner and approver are both '{owner}'; approval is not independent."))
        if cfg.owners is not None and owner:
            reg = cfg.owners.get(owner.strip().lower())
            if reg is None:
                out.append(_f(p, "OWNER_NOT_IN_REGISTER", MEDIUM, p.line_of("owner"),
                              f"Owner '{owner}' is not a role in the owner register."))
            elif reg.status != "active":
                out.append(_f(p, "OWNER_VACANT", HIGH, p.line_of("owner"),
                              f"Owner role '{reg.role}' is {reg.status}; the document is effectively unowned."))
    return out


# --------------------------------------------------------------------------- currency
def next_review_date(p: Policy, cfg: LintConfig) -> date | None:
    """Explicit next_review if given, else last_reviewed + cycle (default 12 months)."""
    explicit = parse_date(p.get("next_review"))
    if explicit:
        return explicit
    last = parse_date(p.get("last_reviewed")) or parse_date(p.get("approved_on"))
    if last is None:
        return None
    cycle = p.get("review_cycle_months")
    months = int(cycle) if cycle.isdigit() and 1 <= int(cycle) <= 36 else cfg.default_cycle_months
    return add_months(last, months)


def check_review(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Overdue and soon-due reviews; drafts that have stalled."""
    out: list[Finding] = []
    for p in lib:
        if p.status == APPROVED:
            due = next_review_date(p, cfg)
            if due is None:
                continue
            days = (due - cfg.as_of).days
            line = p.line_of("next_review") if p.get("next_review") else p.line_of("last_reviewed")
            if days < 0:
                out.append(_f(p, "REVIEW_OVERDUE", HIGH, line,
                              f"Review was due {due} ({-days} days overdue)."))
            elif days <= cfg.due_soon_days:
                out.append(_f(p, "REVIEW_DUE_SOON", LOW, line, f"Review due {due} (in {days} days)."))
            last = parse_date(p.get("last_reviewed"))
            nxt = parse_date(p.get("next_review"))
            if last and nxt and nxt <= last:
                out.append(_f(p, "BAD_DATE", MEDIUM, p.line_of("next_review"),
                              f"next_review {nxt} is not after last_reviewed {last}."))
        elif p.status == DRAFT:
            last_change = max((r.date for r in p.revisions if r.date), default=None)
            if last_change and (cfg.as_of - last_change).days > cfg.stale_draft_days:
                out.append(_f(p, "STALE_DRAFT", LOW, 1,
                              f"Draft not updated since {last_change} ({(cfg.as_of - last_change).days} "
                              f"days); approve it or withdraw it."))
    return out


# --------------------------------------------------------------------------- versions
def check_versions(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Front-matter version vs revision history; changes made after approval."""
    out: list[Finding] = []
    for p in filter(_active, lib):
        if not p.has_front_matter:
            continue
        v = p.version
        if v and version_key(v) is None:
            out.append(_f(p, "BAD_VERSION", MEDIUM, p.line_of("version"),
                          f"Version '{v}' is not a dotted number like 1.0 or 2.3."))
        if not p.revisions:
            out.append(_f(p, "NO_REVISION_HISTORY", MEDIUM, 1,
                          "No revision history table; changes to the document cannot be traced (ISO 27001 7.5.3)."))
            continue
        # The latest entry is the highest version, not the last row: rows are sometimes appended
        # out of order, which HISTORY_ORDER reports separately.
        numbered = [r for r in p.revisions if version_key(r.version)]
        latest = max(numbered, key=lambda r: version_key(r.version)) if numbered else p.revisions[-1]
        if v and version_key(v) and version_key(latest.version) and version_key(v) != version_key(latest.version):
            out.append(_f(p, "VERSION_DRIFT", HIGH, p.line_of("version"),
                          f"Front matter says v{v.lstrip('vV')} but the revision history ends at "
                          f"v{latest.version.lstrip('vV')} (line {latest.line})."))
        keys = [version_key(r.version) for r in p.revisions]
        dates = [r.date for r in p.revisions]
        if any(a is None or b is None or b <= a for a, b in zip(keys, keys[1:])):
            out.append(_f(p, "HISTORY_ORDER", LOW, p.revisions[0].line,
                          "Revision history versions are not in strictly increasing order."))
        elif any(r.date is None for r in p.revisions):
            bad = next(r for r in p.revisions if r.date is None)
            out.append(_f(p, "BAD_DATE", LOW, bad.line, f"Revision date '{bad.date_text}' is not YYYY-MM-DD."))
        elif any(b < a for a, b in zip(dates, dates[1:])):
            out.append(_f(p, "HISTORY_ORDER", LOW, p.revisions[0].line,
                          "Revision history dates go backwards."))
        approved = parse_date(p.get("approved_on"))
        if p.status == APPROVED and approved and latest.date and latest.date > approved:
            out.append(_f(p, "UNAPPROVED_CHANGE", HIGH, latest.line,
                          f"v{latest.version} is dated {latest.date}, after the last approval on "
                          f"{approved}; the text in force has not been approved."))
        if p.status == APPROVED and version_key(v) and version_key(v)[0] == 0:
            out.append(_f(p, "DRAFT_VERSION_APPROVED", LOW, p.line_of("version"),
                          f"Status is approved but version {v} is a 0.x draft number."))
    return out


# --------------------------------------------------------------------------- references
def check_references(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Ids that don't exist, links to missing files or anchors, retired targets, stale pins."""
    out: list[Finding] = []
    by_id = {p.id: p for p in lib if p.id}
    by_path = {p.path.resolve(): p for p in lib}
    for p in filter(_active, lib):
        seen: set[tuple[str, int]] = set()
        for ref in p.references:
            if (ref.target, ref.line) in seen:
                continue
            seen.add((ref.target, ref.line))
            target: Policy | None = None
            if ref.kind == "id":
                target = by_id.get(ref.target)
                if target is None:
                    out.append(_f(p, "BROKEN_REFERENCE", HIGH, ref.line,
                                  f"References {ref.target}, which is not in the library."))
                    continue
                if ref.pinned_version and target.version and \
                        version_key(ref.pinned_version) != version_key(target.version):
                    out.append(_f(p, "STALE_PINNED_REFERENCE", MEDIUM, ref.line,
                                  f"Cites {ref.target} v{ref.pinned_version} but the current version is "
                                  f"v{target.version.lstrip('vV')}."))
            else:
                url = ref.target
                if re.match(r"^[a-z][a-z0-9+.\-]*:", url, re.I):
                    continue                       # http:, mailto:, etc. are out of scope (offline tool)
                file_part, _, anchor = url.partition("#")
                if file_part:
                    dest = (p.path.parent / file_part).resolve()
                    if not dest.exists():
                        out.append(_f(p, "BROKEN_LINK", HIGH, ref.line,
                                      f"Link '{ref.text}' points to '{file_part}', which does not exist."))
                        continue
                    target = by_path.get(dest)
                else:
                    target = p
                if anchor and target is not None and slugify(anchor) not in target.anchors:
                    out.append(_f(p, "BROKEN_ANCHOR", MEDIUM, ref.line,
                                  f"Link '{ref.text}' points to section '#{anchor}', which does not exist "
                                  f"in {target.rel}."))
            if target is not None and target is not p and p.status == APPROVED:
                if target.status == RETIRED:
                    out.append(_f(p, "REFERENCE_TO_RETIRED", MEDIUM, ref.line,
                                  f"Relies on {target.id or target.rel} ({target.title}), which is retired."))
                elif target.status == DRAFT:
                    out.append(_f(p, "REFERENCE_TO_DRAFT", LOW, ref.line,
                                  f"Relies on {target.id or target.rel} ({target.title}), which is still a draft."))
    return out


# --------------------------------------------------------------------------- terminology
def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", re.sub(r"\s+", " ", text.lower())).strip()


def check_terms(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Acronyms never expanded; local definitions that contradict the glossary."""
    out: list[Finding] = []
    gloss = cfg.glossary
    known = {t.lower(): d for t, d in gloss.terms.items()}
    for p in filter(_active, lib):
        defined = p.acronyms_defined | gloss.acronyms | set(cfg.ignore_terms)
        for acr, line in sorted(p.acronyms_used.items(), key=lambda kv: kv[1]):
            if acr not in defined:
                out.append(_f(p, "UNDEFINED_TERM", LOW, line,
                              f"Acronym '{acr}' is used but not expanded here or defined in the glossary."))
        for term, local in p.definitions.items():
            g = known.get(term.lower())
            if g is not None and _norm(g) != _norm(local):
                out.append(_f(p, "CONFLICTING_DEFINITION", MEDIUM,
                              next((i + 1 for i, ln in enumerate(p.lines) if f"**{term}**" in ln), 1),
                              f"Defines '{term}' differently from the glossary. Here: \"{local[:70]}\" "
                              f"Glossary: \"{g[:70]}\""))
    if gloss.path is not None:
        rel = gloss.path.name
        for term, line in gloss.duplicates:
            out.append(Finding("DUPLICATE_TERM", MEDIUM, rel, line, f"Glossary defines '{term}' more than once."))
    return out


# --------------------------------------------------------------------------- completeness
def check_structure(lib: list[Policy], cfg: LintConfig) -> list[Finding]:
    """Required sections present; no placeholder or unfinished text."""
    out: list[Finding] = []
    for p in filter(_active, lib):
        titles = [t.lower() for _, t, _ in p.headings]
        for section in cfg.required_sections:
            if not any(section.lower() in t for t in titles):
                out.append(_f(p, "MISSING_SECTION", MEDIUM if p.status == APPROVED else LOW, 1,
                              f"No '{section}' section."))
        in_fence = False
        for i, ln in enumerate(p.lines, start=1):
            if ln.strip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if in_fence or "policylint-disable" in ln:
                continue
            for m in PLACEHOLDER.finditer(ln):
                out.append(_f(p, "PLACEHOLDER_TEXT", MEDIUM if p.status == APPROVED else LOW, i,
                              f"Unfinished text '{m.group(0)}'."))
    return out


ALL_CHECKS = (check_metadata, check_ownership, check_review, check_versions,
              check_references, check_terms, check_structure)


def run_all(lib: list[Policy], cfg: LintConfig) -> tuple[list[Finding], int]:
    """Run every check. Returns (findings, number suppressed by inline directives)."""
    by_file = {p.rel: p for p in lib}
    findings, suppressed = [], 0
    for check in ALL_CHECKS:
        for f in check(lib, cfg):
            pol = by_file.get(f.file)
            if pol is not None and (f.code in pol.suppressed or "ALL" in pol.suppressed):
                suppressed += 1
                continue
            findings.append(f)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line, f.code))
    return findings, suppressed


def health_score(findings: list[Finding], documents: int) -> int:
    """0-100 library health: deduct 8/3/1 points per High/Medium/Low per document."""
    if documents == 0:
        return 0
    weight = {HIGH: 8, MEDIUM: 3, LOW: 1, INFO: 0}
    penalty = sum(weight[f.severity] for f in findings) / documents
    return max(0, round(100 - penalty * 4))

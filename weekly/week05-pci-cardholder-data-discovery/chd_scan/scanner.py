"""Scan orchestration: detectors over documents, severity, PCI DSS mapping, suppressions.

Severity model (worst first):

    Critical  Sensitive authentication data (track, CVV, PIN) stored after authorisation.
              PCI DSS 3.3.1 prohibits this outright; encryption does not make it acceptable.
    High      Clear-text PAN with card context (a card-like label, column or co-located SAD).
    Medium    Clear-text PAN with no context, or a masked PAN showing more than BIN + last 4.

Published test PANs (4111 1111 1111 1111 and friends) are *not* downgraded: they are
flagged (``test_pan``) and counted, because test data in production is itself a finding
and because real numbers are routinely pasted next to them. Exclude QA fixtures with a
time-bound suppression, or ``--ignore-test-pans`` in a test environment.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date
from fnmatch import fnmatch
from pathlib import Path

from .cards import PanFingerprinter
from .detectors import (CVV, CVV_COLUMNS, MASK_EXPOSED, PAN, PAN_COLUMNS, PIN, PIN_COLUMNS, SAD_KINDS, TRACK, Hit,
                        norm_header, scan_line)
from .extract import DEFAULT_EXCLUDES, Document, Extractor, Gap, Limits

SEVERITIES = ("Critical", "High", "Medium")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

REQUIREMENTS = {
    "3.2.1": "Account data storage kept to a minimum; retention and disposal defined and applied",
    "3.3.1": "SAD is not stored after authorisation, even if encrypted",
    "3.3.1.1": "Full track data is not stored after authorisation",
    "3.3.1.2": "Card verification code is not stored after authorisation",
    "3.3.1.3": "PIN and PIN block are not stored after authorisation",
    "3.4.1": "PAN is masked when displayed (BIN and last four at most)",
    "3.5.1": "PAN is rendered unreadable anywhere it is stored",
    "10.3.x": "Log files are account data locations too: protect them (10.3) and purge clear-text values (3.5.1)",
    "12.5.2": "PCI DSS scope (all locations of account data) documented and confirmed",
    "A3.2.5": "Data discovery methodology confirms no clear-text PAN outside the defined CDE (DESV)",
}

KIND_REQS = {
    TRACK: ["3.3.1", "3.3.1.1"],
    CVV: ["3.3.1", "3.3.1.2"],
    PIN: ["3.3.1", "3.3.1.3"],
    PAN: ["3.5.1", "3.2.1", "12.5.2"],
    MASK_EXPOSED: ["3.4.1"],
}

KIND_LABEL = {TRACK: "Track data", CVV: "Card verification code", PIN: "PIN / PIN block",
              PAN: "Clear-text PAN", MASK_EXPOSED: "Over-exposed masked PAN"}


# ---------- where the data is says a lot about how it got there and how to fix it ----------

@dataclass(frozen=True)
class LocationClass:
    key: str
    label: str
    patterns: tuple[str, ...]
    action: str


LOCATION_CLASSES = (
    LocationClass("log", "Application / system log", (r"\.log(\.\d+)?(\.gz)?$", r"(^|/)logs?/"),
                  "Stop the leak at source: disable request/response body logging on payment paths and add a "
                  "PAN/SAD redaction filter to the logger (see `chd_scan redact`). Purge affected logs, including "
                  "copies in the SIEM and log archive (10.3.x, 3.5.1)."),
    LocationClass("db_export", "Database export / backup", (r"\.(sql|bak|dump|db|sqlite3?)$", r"(^|/)(backup|db_?exports?|dumps?)/"),
                  "Find the source table. Tokenise or encrypt the column at source (3.5.1), purge exports beyond "
                  "retention (3.2.1), and bring backup media into scope or out of reach."),
    LocationClass("archive", "Archive / legacy copy", (r"\.(zip|gz|tar|7z)(!|$)", r"(^|/)(archive|legacy|old)/"),
                  "Confirm whether a retention requirement applies (3.2.1). If not, securely delete. If so, move it "
                  "into the CDE and encrypt it (3.5.1)."),
    LocationClass("support", "Customer support / ticket / email", (r"(^|/)(support|tickets?|helpdesk|mail|email|crm)/", r"\.(eml|msg|mbox)$"),
                  "Customers paste card numbers into free text. Redact in the ticketing system, enable its "
                  "PAN-masking or DLP feature, and train agents never to request card data by email or chat."),
    LocationClass("pos", "POS / terminal output", (r"(^|/)(pos|terminals?|kiosk)/",),
                  "Track data or PIN on disk points at a terminal, middleware or debug setting. Engage the POS "
                  "vendor, confirm P2PE/SRED configuration, and treat as a potential compromise indicator."),
    LocationClass("office", "Office document / spreadsheet", (r"\.(docx|xlsx|pptx|odt|ods|csv|tsv|xls|doc)$",),
                  "Find the business process that needs a spreadsheet of card numbers and replace it with a "
                  "token or the last four digits. Delete the file and any copies in email and sync folders."),
    LocationClass("other", "Other file share content", (r".",),
                  "Identify the owner and process that wrote this file, then delete, truncate or tokenise (3.5.1)."),
)


def classify_location(path: str) -> LocationClass:
    p = path.lower()
    for lc in LOCATION_CLASSES:
        if any(re.search(rx, p) for rx in lc.patterns):
            return lc
    return LOCATION_CLASSES[-1]  # pragma: no cover


# ---------- suppressions (documented exceptions) ----------

@dataclass
class Suppression:
    path: str
    reason: str
    approved_by: str
    expires: date | None
    ticket: str = ""
    kinds: tuple[str, ...] = ()
    used: int = 0
    problems: list[str] = field(default_factory=list)

    def active(self, as_of: date) -> bool:
        return not self.problems and self.expires is not None and as_of <= self.expires

    def matches(self, path: str, kind: str) -> bool:
        top = path.split("!", 1)[0]
        return (fnmatch(path, self.path) or fnmatch(top, self.path)) and (not self.kinds or kind in self.kinds)


def load_suppressions(path: Path | None) -> list[Suppression]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: list[Suppression] = []
    for i, item in enumerate(raw.get("suppressions", []), start=1):
        problems = []
        exp = None
        try:
            exp = date.fromisoformat(item["expires"]) if item.get("expires") else None
        except ValueError:
            problems.append(f"expiry '{item.get('expires')}' is not YYYY-MM-DD")
        if exp is None and not problems:
            problems.append("no expiry date; exceptions must be time-bound")
        for key in ("path", "reason", "approved_by"):
            if not str(item.get(key, "")).strip():
                problems.append(f"missing '{key}'")
        kinds = tuple(k.upper() for k in item.get("kinds", []))
        out.append(Suppression(str(item.get("path", "")), str(item.get("reason", "")), str(item.get("approved_by", "")),
                               exp, str(item.get("ticket", "")), kinds, problems=problems))
    return out


# ---------- results ----------

@dataclass
class Finding:
    id: str
    severity: str
    kind: str
    path: str
    location: str           # "line 12" or "string 40" for binary
    masked: str
    brand: str | None
    confidence: str
    detail: str
    requirements: list[str]
    location_class: str
    test_pan: bool = False
    suppressed_by: str = ""  # suppression path pattern, when suppressed


@dataclass
class FileSummary:
    path: str
    location_class: str
    container: str
    worst: str
    counts: dict[str, int]
    unique_pans: int
    action: str


@dataclass
class Note:
    code: str
    severity: str
    subject: str
    message: str


@dataclass
class ScanResult:
    root: str
    as_of: date
    findings: list[Finding]
    suppressed: list[Finding]
    files: list[FileSummary]
    gaps: list[Gap]
    notes: list[Note]
    files_seen: int
    documents: int
    lines_scanned: int
    compliant_masked: int
    unique_pans: int
    unique_test_pans: int

    def by_severity(self) -> Counter:
        return Counter(f.severity for f in self.findings)

    def requirement_counts(self) -> dict[str, int]:
        c: Counter = Counter()
        for f in self.findings:
            c.update(f.requirements)
        return {k: c[k] for k in REQUIREMENTS if c.get(k)}

    def to_dict(self) -> dict:
        return {
            "root": self.root, "as_of": self.as_of.isoformat(),
            "summary": {"files_seen": self.files_seen, "documents_scanned": self.documents,
                        "lines_scanned": self.lines_scanned, "findings": len(self.findings),
                        "by_severity": {s: self.by_severity().get(s, 0) for s in SEVERITIES},
                        "unique_pans": self.unique_pans, "unique_test_pans": self.unique_test_pans,
                        "compliant_masked_pans": self.compliant_masked, "suppressed": len(self.suppressed),
                        "coverage_gaps": len(self.gaps)},
            "requirements": {k: {"title": REQUIREMENTS.get(k, ""), "findings": v} for k, v in self.requirement_counts().items()},
            "files": [asdict(f) for f in self.files],
            "findings": [asdict(f) for f in self.findings],
            "suppressed": [asdict(f) for f in self.suppressed],
            "coverage_gaps": [asdict(g) for g in self.gaps],
            "notes": [asdict(n) for n in self.notes],
        }


def _severity(hit: Hit, sad_on_line: bool) -> str:
    if hit.kind in SAD_KINDS:
        return "Critical"
    if hit.kind == MASK_EXPOSED:
        return "Medium"
    return "High" if (hit.confidence == "high" or sad_on_line) else "Medium"


def _csv_column_hits(doc: Document) -> dict[int, list[Hit]]:
    """Header-aware pass for delimited files: a CVV column has no 'cvv=' label on each row."""
    if doc.ext not in (".csv", ".tsv", ".txt") or len(doc.lines) < 2:
        return {}
    sample = "\n".join(doc.lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return {}
    rows = list(csv.reader(io.StringIO("\n".join(doc.lines)), dialect))
    if not rows:
        return {}
    header = [norm_header(h) for h in rows[0]]
    cvv_cols = [i for i, h in enumerate(header) if h in CVV_COLUMNS]
    pin_cols = [i for i, h in enumerate(header) if h in PIN_COLUMNS]
    if not (cvv_cols or pin_cols):
        return {}
    out: dict[int, list[Hit]] = defaultdict(list)
    for lineno, row in enumerate(rows[1:], start=2):
        for cols, kind, rx in ((cvv_cols, CVV, r"\d{3,4}"), (pin_cols, PIN, r"\d{4,12}|[0-9A-Fa-f]{16}")):
            for c in cols:
                if c < len(row) and re.fullmatch(rx, row[c].strip()):
                    out[lineno].append(Hit(kind, 0, 0, "*" * len(row[c].strip()), None, "high",
                                           f"column '{rows[0][c].strip()}' ({len(row[c].strip())} chars)"))
    return out


def _csv_pan_context(doc: Document) -> bool:
    if doc.ext not in (".csv", ".tsv") or not doc.lines:
        return False
    return any(norm_header(h) in PAN_COLUMNS for h in re.split(r"[,;\t|]", doc.lines[0]))


def scan(root: Path, as_of: date | None = None, suppressions: list[Suppression] | None = None,
         limits: Limits | None = None, ignore_test_pans: bool = False,
         fingerprinter: PanFingerprinter | None = None, excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> ScanResult:
    """Scan ``root`` (a folder or one file) and return masked, mapped, de-duplicated findings."""
    as_of = as_of or date.today()
    suppressions = suppressions or []
    fp = fingerprinter or PanFingerprinter()
    extracted = Extractor(limits, excludes).walk(root)

    findings: list[Finding] = []
    suppressed: list[Finding] = []
    file_pans: dict[str, set[str]] = defaultdict(set)
    all_pans: set[str] = set()
    test_pans: set[str] = set()
    compliant = 0
    lines_scanned = 0
    notes: list[Note] = []
    containers: dict[str, str] = {}

    for doc in extracted.documents:
        containers[doc.path] = doc.container
        col_hits = _csv_column_hits(doc)
        pan_ctx = _csv_pan_context(doc)
        seen: set[tuple] = set()
        for lineno, line in enumerate(doc.lines, start=1):
            lines_scanned += 1
            hits, ok_masked = scan_line(line, context_hint=pan_ctx)
            compliant += ok_masked
            hits += col_hits.get(lineno, [])
            if not hits:
                continue
            sad_here = any(h.kind in SAD_KINDS for h in hits)
            for h in hits:
                if ignore_test_pans and h.test_pan and h.kind == PAN:
                    continue
                if h._pan:
                    print_fp = fp.fingerprint(h._pan)
                    key = (lineno, h.kind, print_fp)
                    if key in seen:
                        continue
                    seen.add(key)
                    all_pans.add(print_fp)
                    file_pans[doc.path].add(print_fp)
                    if h.test_pan:
                        test_pans.add(print_fp)
                loc = {"binary-strings": "string", "sqlite": "record"}.get(doc.container, "line") + f" {lineno}"
                lc = classify_location(doc.path)
                sev = _severity(h, sad_here)
                detail = h.detail
                if h.kind == PAN and sad_here:
                    detail = (detail + "; " if detail else "") + "stored with SAD in the same record"
                f = Finding("", sev, h.kind, doc.path, loc, h.masked, h.brand, h.confidence, detail,
                            list(KIND_REQS[h.kind]) + (["10.3.x"] if lc.key == "log" and h.kind in (PAN, TRACK, CVV) else []),
                            lc.key, h.test_pan)
                sup = next((s for s in suppressions if s.matches(doc.path, h.kind)), None)
                if sup and sup.active(as_of) and h.kind not in SAD_KINDS:
                    sup.used += 1
                    f.suppressed_by = sup.path
                    suppressed.append(f)
                    continue
                if sup and sup.active(as_of) and h.kind in SAD_KINDS:
                    sup.used += 1
                    f.detail += "; suppression ignored: SAD storage cannot be excepted"
                elif sup and not sup.active(as_of):
                    sup.used += 1
                    why = "; ".join(sup.problems) or f"expired {sup.expires}"
                    f.detail = (f.detail + "; " if f.detail else "") + f"suppression '{sup.path}' not applied ({why})"
                findings.append(f)

    # Stable order and ids: worst first, then path and line.
    def line_no(f: Finding) -> int:
        return int(f.location.split()[-1])
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.path, line_no(f), f.kind))
    for i, f in enumerate(findings, start=1):
        f.id = f"CHD-{i:03d}"
    suppressed.sort(key=lambda f: (f.path, line_no(f)))

    # Per-file roll-up.
    per_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        per_file[f.path].append(f)
    files: list[FileSummary] = []
    for path, fs in per_file.items():
        lc = classify_location(path)
        worst = min((f.severity for f in fs), key=SEV_RANK.__getitem__)
        files.append(FileSummary(path, lc.label, containers.get(path, ""), worst, dict(Counter(f.kind for f in fs)),
                                 len(file_pans.get(path, set())), lc.action))
    files.sort(key=lambda s: (SEV_RANK[s.worst], -sum(s.counts.values()), s.path))

    # Governance notes about the exceptions register itself.
    for s in suppressions:
        if s.problems:
            notes.append(Note("SUPPRESSION_INVALID", "High", s.path, "Not applied: " + "; ".join(s.problems) + "."))
        elif s.expires and as_of > s.expires:
            notes.append(Note("SUPPRESSION_EXPIRED", "High", s.path,
                              f"Expired {s.expires} ({(as_of - s.expires).days} days ago); {s.used} finding(s) re-surfaced. "
                              f"Renew with fresh approval or remediate."))
        elif s.used == 0:
            notes.append(Note("SUPPRESSION_UNUSED", "Low", s.path,
                              "Matched nothing in this scan; remove it so the register reflects reality."))
        elif s.expires and (s.expires - as_of).days <= 30:
            notes.append(Note("SUPPRESSION_EXPIRING", "Medium", s.path, f"Expires {s.expires}; plan renewal or remediation."))
    for g in extracted.gaps:
        notes.append(Note("COVERAGE_GAP", "High" if "encrypted" in g.reason else "Medium", g.path, g.reason))

    return ScanResult(str(root), as_of, findings, suppressed, files, extracted.gaps, notes, extracted.files_seen,
                      len(extracted.documents), lines_scanned, compliant, len(all_pans), len(test_pans))

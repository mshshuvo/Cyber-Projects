"""Console, Markdown, JSON and CSV reports. Every value shown is already masked."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter

from .detectors import SAD_KINDS
from .scanner import KIND_LABEL, REQUIREMENTS, SEVERITIES, ScanResult

ORDER = ("TRACK_DATA", "CVV", "PIN", "PAN", "MASK_OVEREXPOSED")
SHORT = {"TRACK_DATA": "Track", "CVV": "CVV", "PIN": "PIN", "PAN": "PAN", "MASK_OVEREXPOSED": "Mask+"}


def _counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[k]} {SHORT[k]}" for k in ORDER if counts.get(k))


def _trim(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def headline(r: ScanResult) -> list[str]:
    sev = r.by_severity()
    sad = sum(1 for f in r.findings if f.kind in SAD_KINDS)
    pan_files = sum(1 for f in r.files if f.counts.get("PAN") or f.counts.get("TRACK_DATA"))
    return [
        f"Files: {r.files_seen} on disk, {r.documents} documents scanned (archive members and Office parts "
        f"included), {r.lines_scanned:,} lines",
        f"Findings: {len(r.findings)}  (" + ", ".join(f"{s} {sev.get(s, 0)}" for s in SEVERITIES) + ")"
        f"  |  suppressed {len(r.suppressed)}  |  coverage gaps {len(r.gaps)}",
        f"Unique PANs exposed: {r.unique_pans} across {pan_files} locations"
        + ((" (all are published test numbers)" if r.unique_test_pans == r.unique_pans else
            f" ({r.unique_test_pans} are published test numbers)") if r.unique_test_pans else ""),
        f"Prohibited SAD hits (3.3.1): {sad}   Correctly masked PANs seen: {r.compliant_masked}",
    ]


def console_report(r: ScanResult, limit: int = 12) -> str:
    out = [f"Cardholder data discovery: {r.root}  (as of {r.as_of})", "=" * 92]
    out += headline(r)
    out += ["", "Locations, worst first"]
    out.append(f"  {'Sev':<9}{'Path':<48}{'Hits':<24}Uniq PAN")
    for f in r.files[:limit]:
        out.append(f"  {f.worst:<9}{_trim(f.path, 46):<48}{_counts(f.counts):<24}{f.unique_pans}")
    if len(r.files) > limit:
        out.append(f"  ... {len(r.files) - limit} more in report.md")
    out += ["", "Top findings (values masked; CVV/PIN never shown)"]
    for f in r.findings[:limit]:
        out.append(f"  [{f.severity:<8}] {f.id} {SHORT[f.kind]:<5} {_trim(f.path + ':' + f.location.split()[-1], 44):<45} "
                   f"{f.masked:<20} {_trim(f.detail, 60)}")
    if len(r.findings) > limit:
        out.append(f"  ... {len(r.findings) - limit} more in report.md / findings.csv")
    out += ["", "PCI DSS v4.0.1 requirements implicated"]
    for req, n in r.requirement_counts().items():
        out.append(f"  {req:<8} {n:>3}  {REQUIREMENTS[req]}")
    if r.notes:
        out += ["", "Exceptions register and coverage"]
        for n in r.notes:
            out.append(f"  [{n.severity:<6}] {n.code:<20} {_trim(n.subject, 44):<45} {_trim(n.message, 70)}")
    return "\n".join(out)


def markdown_report(r: ScanResult) -> str:
    md = [f"# Cardholder data discovery report", "",
          f"**Scope:** `{r.root}`  ", f"**As of:** {r.as_of}  ",
          "**Standard:** PCI DSS v4.0.1, Requirement 3 (protect stored account data) and 12.5.2 (scope)", ""]
    md += ["## Summary", ""] + [f"- {line}" for line in headline(r)] + [""]
    sad = [f for f in r.findings if f.kind in SAD_KINDS]
    if sad:
        md += ["> **Sensitive authentication data is stored.** PCI DSS 3.3.1 prohibits storing track data, card "
               "verification codes and PINs after authorisation, even encrypted. Treat each Critical location as an "
               "incident: contain, find the writing process, securely delete, and assess whether it indicates a "
               "compromise.", ""]

    md += ["## Remediation plan by location", "",
           "| # | Severity | Location | Type | Hits | Unique PANs | Action |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(r.files, start=1):
        md.append(f"| {i} | {f.worst} | `{f.path}` | {f.location_class} | {_counts(f.counts)} | {f.unique_pans} | {f.action} |")
    md.append("")

    md += ["## PCI DSS requirements implicated", "", "| Requirement | Findings | What it requires |", "|---|---|---|"]
    for req, n in r.requirement_counts().items():
        md.append(f"| {req} | {n} | {REQUIREMENTS[req]} |")
    md.append("")

    md += ["## Findings", "", "Values are masked to BIN and last four (PCI DSS 3.4.1). CVV and PIN values are never "
           "recorded, only their length.", "",
           "| Id | Severity | Type | Location | Masked value | Brand | Confidence | Detail |",
           "|---|---|---|---|---|---|---|---|"]
    for f in r.findings:
        md.append(f"| {f.id} | {f.severity} | {KIND_LABEL[f.kind]} | `{f.path}` {f.location} | `{f.masked}` | "
                  f"{f.brand or ''} | {f.confidence} | {f.detail} |")
    md.append("")

    if r.suppressed:
        md += ["## Suppressed by documented exception", "", "| Location | Type | Masked value | Exception |", "|---|---|---|---|"]
        for f in r.suppressed:
            md.append(f"| `{f.path}` {f.location} | {KIND_LABEL[f.kind]} | `{f.masked}` | `{f.suppressed_by}` |")
        md.append("")

    if r.notes:
        md += ["## Exceptions register and scan coverage", "",
               "A location the scanner could not read is not a clean location. 12.5.2 requires *all* locations "
               "of account data to be known.", "", "| Severity | Code | Subject | Detail |", "|---|---|---|---|"]
        for n in r.notes:
            md.append(f"| {n.severity} | {n.code} | `{n.subject}` | {n.message} |")
        md.append("")

    kinds = Counter(f.kind for f in r.findings)
    md += ["## Method", "",
           "- **PAN:** 13-19 digits (spaces or hyphens allowed as one consistent separator), Luhn-valid, in a "
           "published brand IIN range and length, not glued to other letters or digits, not a repeated or "
           "sequential number. Confidence is *high* with a card-like label nearby, a card-number column header "
           "or SAD on the same line.",
           "- **Track data:** Track 1 (`%B...^NAME^YYMM...`) and Track 2 (`;PAN=YYMM...`) structures with a valid PAN.",
           "- **CVV / PIN:** values next to an explicit label (`cvv2=`, `\"cvc\":`, `<cvv>`) or in a column with "
           "such a header. Ambiguous labels (`cid`, `csc`, `pin`) only count on a line that also holds card data.",
           "- **Masking:** masked PANs showing more than the first 6 (8 for 16+ digit PANs) and last 4 digits.",
           "- Unique PANs are counted with a keyed hash under a per-run random key that is never stored.",
           f"- Finding mix this run: " + ", ".join(f"{KIND_LABEL[k]} {kinds[k]}" for k in ORDER if kinds.get(k)) + ".",
           ""]
    return "\n".join(md)


def json_report(r: ScanResult) -> str:
    return json.dumps(r.to_dict(), indent=2, default=str)


def findings_csv(r: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "severity", "kind", "path", "location", "masked_value", "brand", "confidence", "test_pan",
                "location_class", "requirements", "detail"])
    for f in r.findings:
        w.writerow([f.id, f.severity, f.kind, f.path, f.location, f.masked, f.brand or "", f.confidence,
                    "yes" if f.test_pan else "no", f.location_class, " ".join(f.requirements), f.detail])
    return buf.getvalue()

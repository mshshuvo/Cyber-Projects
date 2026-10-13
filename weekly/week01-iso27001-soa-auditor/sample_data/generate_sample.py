"""Generate the synthetic sample SoA, risk register and evidence log.

The organization 'Maple Ridge Credit Union' is fictional. Defects are planted
on purpose so the auditor has something to find. Re-run to regenerate:
    python sample_data/generate_sample.py
"""
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from soa_auditor.catalog import ANNEX_A  # noqa: E402

HERE = Path(__file__).parent
rng = random.Random(27001)
OWNERS = ["CISO", "IT Ops Manager", "HR Director", "Facilities Lead",
          "Head of Engineering", "Compliance Officer", "Privacy Officer"]

MISSING = {"5.32", "7.12", "8.17"}                       # not in SoA at all
EXCLUDED = {
    "7.4": "",                                            # no justification
    "8.11": "No production data is used outside production systems.",  # but a risk relies on it
    "8.8": "Handled by vendor",                           # weak + hard to exclude
    "8.30": "All software development is performed in-house; no development is outsourced.",
    "7.6": "No secure areas exist; all servers are hosted in a third-party cloud region.",
}
STATUS_OVERRIDE = {
    "5.7": ("implemented", ""),            # implemented, no evidence
    "8.16": ("implemented", ""),
    "8.13": ("implemented", "EV-813"),     # expired evidence
    "5.23": ("implemented", "EV-999"),     # evidence missing from log
    "5.30": ("planned", ""),               # orphan gap
    "8.12": ("planned", ""),
    "8.5": ("partially implemented", "EV-805"),
    "8.24": ("planned", ""),
    "5.29": ("not implemented", ""),
}
STALE = {"6.1", "7.1", "7.2", "5.11"}

soa_rows, evidence_rows = [], []
for cid, name in ANNEX_A.items():
    if cid in MISSING:
        continue
    owner = "" if cid == "8.23" else rng.choice(OWNERS)
    reviewed = "2025-03-14" if cid in STALE else f"2026-0{rng.randint(3, 9)}-{rng.randint(10, 28)}"
    if cid in EXCLUDED:
        soa_rows.append([cid, name, "No", EXCLUDED[cid], "", "", owner, reviewed])
        continue
    status, ev = STATUS_OVERRIDE.get(cid, ("implemented", f"EV-{cid.replace('.', '')}"))
    just = "" if cid in {"5.30", "8.12"} else "Required to treat identified risks and regulatory obligations."
    soa_rows.append([cid, name, "Yes", just, status, ev, owner, reviewed])
    if ev and ev != "EV-999":
        valid = "2026-06-30" if cid == "8.13" else "2027-06-30"
        evidence_rows.append([ev, cid, f"Evidence for {name.lower()}", "2026-07-01", valid])

# A duplicate row and a legacy ISO 27001:2013 identifier
soa_rows.append(["5.15", ANNEX_A["5.15"], "Yes", "Duplicate row from old template.",
                 "implemented", "EV-515", "CISO", "2026-05-02"])
soa_rows.append(["A.12.6.1", "Management of technical vulnerabilities (2013)", "Yes",
                 "Carried over from the 2013 SoA.", "implemented", "", "IT Ops Manager", "2024-11-01"])

with (HERE / "soa.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["control_id", "control_name", "applicable", "justification",
                "implementation_status", "evidence_refs", "owner", "last_reviewed"])
    w.writerows(soa_rows)

with (HERE / "evidence.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["evidence_id", "control_id", "description", "collected", "valid_until"])
    w.writerows(evidence_rows)

risks = [
    ["R-001", "Ransomware encrypts member account systems", 4, 5, "Mitigate", "8.7;8.13;5.29", "CISO"],
    ["R-002", "Unpatched internet-facing servers exploited", 4, 4, "Mitigate", "8.8;8.9", "IT Ops Manager"],
    ["R-003", "Credential stuffing against online banking", 4, 4, "Mitigate", "8.5;8.16", "Head of Engineering"],
    ["R-004", "Member PII leaked via email", 3, 5, "Mitigate", "8.12;8.24", "Privacy Officer"],
    ["R-005", "Network cabling tapped in branch offices", 2, 3, "Mitigate", "7.12", "Facilities Lead"],
    ["R-006", "Card processor outage disrupts payments", 3, 4, "Transfer", "5.19;5.20", "Compliance Officer"],
    ["R-007", "Real member data copied into test environments", 3, 4, "Mitigate", "8.11;8.33", "Head of Engineering"],
    ["R-008", "Insider fraud by privileged staff", 2, 5, "Mitigate", "", "Compliance Officer"],
    ["R-009", "Legacy core banking platform cannot be encrypted", 4, 4, "Accept", "", "CISO"],
    ["R-010", "Phishing leads to account takeover of staff", 4, 3, "Mitigate", "6.3;8.5;8.23", "CISO"],
]
with (HERE / "risk_register.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["risk_id", "description", "likelihood", "impact", "treatment", "controls", "owner"])
    w.writerows(risks)

print(f"Wrote {len(soa_rows)} SoA rows, {len(evidence_rows)} evidence items, {len(risks)} risks.")

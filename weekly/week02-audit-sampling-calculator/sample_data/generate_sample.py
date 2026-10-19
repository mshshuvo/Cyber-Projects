"""Generate the synthetic sample population, manifest and evidence tracker.

Scenario: testing the IT general control ITGC-CM-02 ("production changes are
approved by the Change Advisory Board before deployment") at the fictional
Maple Ridge Credit Union for Jan 1 - Sep 30, 2026. All tickets, systems and
people are invented. Problems are planted on purpose:

- 2 tickets dated outside the audit period (must be excluded from the frame)
- 2 exceptions (changes deployed before CAB approval)
- 1 result recorded without an evidence reference
- 1 selected item quietly swapped for a different ticket
- 1 evidence request overdue

Re-run to regenerate:  python sample_data/generate_sample.py
"""
import csv
import random
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_sampling.population import load_population  # noqa: E402
from audit_sampling.sampler import draw_sample  # noqa: E402
from audit_sampling.stats import attribute_sample_size  # noqa: E402

HERE = Path(__file__).parent
SEED = "MRCU-ITGC-CM02-FY26"
rng = random.Random(2026)

SYSTEMS = ["Core banking", "Online banking", "Card management", "Loan origination",
           "AML monitoring", "Active Directory", "Firewall", "Data warehouse"]
TIERS = [("High", 0.18), ("Medium", 0.42), ("Low", 0.40)]
TESTERS = ["Auditor A", "Auditor B"]


def tier() -> str:
    x, acc = rng.random(), 0.0
    for name, p in TIERS:
        acc += p
        if x < acc:
            return name
    return "Low"


def build_population() -> Path:
    path = HERE / "change_tickets.csv"
    start, days = date(2026, 1, 1), (date(2026, 9, 30) - date(2026, 1, 1)).days
    rows = []
    for i in range(1, 411):
        deployed = start + timedelta(days=rng.randint(0, days))
        rows.append([f"CHG-26-{i:04d}", deployed.isoformat(), rng.choice(SYSTEMS), tier(),
                     rng.choice(["Standard", "Standard", "Standard", "Normal", "Emergency"]),
                     f"CAB-{rng.randint(1000, 9999)}"])
    # Two out-of-period tickets that slipped into the extract.
    rows.append(["CHG-25-0987", "2025-12-29", "Core banking", "High", "Normal", "CAB-0871"])
    rows.append(["CHG-26-0411", "2026-10-02", "Firewall", "Medium", "Standard", "CAB-5310"])
    rows.sort(key=lambda r: r[1])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["change_id", "deployed_on", "system", "risk_tier", "change_type", "cab_ref"])
        w.writerows(rows)
    return path


def main() -> None:
    pop_path = build_population()
    pop = load_population(pop_path, "change_id", "deployed_on",
                          date(2026, 1, 1), date(2026, 9, 30), expected_count=410)
    size = attribute_sample_size(0.95, 0.10, 0.01, population=len(pop.frame))
    manifest = draw_sample(pop, size, SEED, "ITGC-CM-02",
                           "Production changes are approved by the CAB before deployment",
                           stratify_by="risk_tier", drawn_on=date(2026, 10, 5))
    (HERE / "manifest.json").write_text(manifest.to_json(), encoding="utf-8")

    details = {r["change_id"]: r for r in pop.frame}
    selected = manifest.selected
    out = []
    for n, sel in enumerate(selected, start=1):
        d = details[sel["item_id"]]
        row = {"sample_no": n, "item_id": sel["item_id"], "stratum": sel["stratum"],
               "status": "tested", "result": "pass", "evidence_ref": f"WP-CM02-{n:03d}",
               "requested_on": "2026-10-06", "received_on": "2026-10-08",
               "tester": TESTERS[n % 2], "notes": "", "deployed_on": d["deployed_on"],
               "system": d["system"], "change_type": d["change_type"], "cab_ref": d["cab_ref"]}
        out.append(row)

    # Planted fieldwork states and defects (indexes are into the sample order).
    out[4].update(result="exception", notes="CAB approval dated 2 days after deployment")
    out[17].update(result="exception", notes="No CAB approval found; deployed by on-call engineer")
    out[9].update(evidence_ref="")                                   # no evidence reference
    for i in (36, 37, 38):
        out[i].update(status="requested", result="", evidence_ref="", received_on="", tester="")
    out[36]["requested_on"] = "2026-10-01"                           # overdue request
    out[39].update(status="received", result="", evidence_ref="", tester="")
    for i in (40, 41, 42):
        out[i].update(status="not started", result="", evidence_ref="", requested_on="",
                      received_on="", tester="")
    # A tester swapped a hard-to-evidence item for an easier one.
    unselected = sorted(set(details) - set(manifest.selected_ids))
    swap = unselected[7]
    out[22].update(item_id=swap, system=details[swap]["system"],
                   change_type=details[swap]["change_type"], cab_ref=details[swap]["cab_ref"],
                   deployed_on=details[swap]["deployed_on"], notes="Replacement item")

    with open(HERE / "evidence_tracker.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)
    print(f"Population {len(pop.rows)} rows ({len(pop.frame)} in frame), "
          f"sample n={size.n}, allowed deviations={size.allowed_deviations}")


if __name__ == "__main__":
    main()

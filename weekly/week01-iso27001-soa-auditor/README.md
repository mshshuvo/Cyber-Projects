# Week 01: ISO 27001 Statement of Applicability Auditor

A command-line tool that audits an **ISO/IEC 27001:2022 Statement of Applicability (SoA)** the way a certification auditor would. It checks the SoA against the 93 Annex A controls, the **risk register** and the **evidence log**, and then reports every inconsistency with the clause it relates to.

## Why this matters

The SoA is the document certification auditors read first, and it is where many ISMS programs quietly fall apart:

- A control is marked "not applicable", yet the risk treatment plan depends on it.
- A control shows "Implemented", but the evidence behind it expired months ago.
- A high risk is "mitigated" only by controls that are still at the planned stage.
- Controls get lost when moving from ISO 27001:2013 to 2022 numbering.

In audits these show up as nonconformities against clause **6.1.3**. They are tedious to find by hand across three spreadsheets, but easy to find with code.

The sample run below makes the point. Implementation coverage looks great (90–100% per theme), but the readiness score is **34/100**. **High coverage does not mean a coherent SoA.**

## What it checks

| Check | Severity | ISO/IEC 27001:2022 clause |
|---|---|---|
| Annex A control missing from the SoA | High | 6.1.3 c–d |
| Exclusion with no justification | High | 6.1.3 d |
| Risk treatment relies on an excluded control | High | 6.1.3 d |
| Risk treatment relies on a control not in the SoA | High | 6.1.3 c–d |
| Mitigated risk with no controls mapped | High | 6.1.3 b |
| High risk (score ≥ 15) with no implemented control | High | 8.3 |
| Weak exclusion justification (fewer than 5 words) | Medium | 6.1.3 d |
| Exclusion of a control that is rarely excludable (e.g. 8.8, 8.13, 5.24) | Medium | 6.1.3 b–d |
| "Implemented" with no evidence, or evidence missing or expired | Medium | 7.5 / 9.2 |
| High risk accepted (risk-owner sign-off needed) | Medium | 6.1.3 f |
| Planned or not-implemented control with no linked risk or rationale | Medium | 6.1.3 d–e |
| Non-2022 control ID (with a hint for 2013 numbering) | Medium | 6.1.3 c |
| Duplicates, missing owners, stale or missing reviews, evidence logged against the wrong control | Low | 7.5 / 5.3 / 9.3 |

The tool also produces **coverage by theme** (Organizational, People, Physical, Technological) and a **0–100 readiness score**, where each High finding costs 5 points, each Medium 2 and each Low 0.5.

## How it works

```
soa.csv ─────────┐
risk_register.csv ├─► loaders (models.py) ─► checks.py ─► findings ─► report.py ─► console / report.md / report.json
evidence.csv ────┘                              ▲
                          catalog.py (93 Annex A controls)
```

- `catalog.py`: control IDs and titles for ISO/IEC 27001:2022 Annex A (titles only, no ISO text).
- `models.py`: tolerant CSV loaders (headers are case-insensitive, and an `A.` prefix is accepted).
- `checks.py`: independent check functions. Each one returns `Finding(check, severity, ref, clause, message)`.
- `report.py`: console summary, a Markdown working paper, and JSON for dashboards (Week 52's KRI dashboard will consume this).
- Standard library only. No dependencies.

## Run it

Requires Python 3.10 or later.

```bash
cd weekly/week01-iso27001-soa-auditor
python -m soa_auditor \
  --soa sample_data/soa.csv \
  --risks sample_data/risk_register.csv \
  --evidence sample_data/evidence.csv \
  --as-of 2026-10-12 \
  --org "Maple Ridge Credit Union (fictional)" \
  --out sample_output
```

Options:
- `--risks` and `--evidence` are optional. Without them, only SoA-internal checks run.
- `--review-days 365` sets the maximum age of an SoA row review.
- `--fail-on-high` makes the tool exit with code 2 if any High finding exists, so the SoA can be checked in CI whenever it changes.

Run the tests:

```bash
python -m unittest -v
```

### Input format

`soa.csv`
```
control_id,control_name,applicable,justification,implementation_status,evidence_refs,owner,last_reviewed
8.13,Information backup,Yes,Treats R-001 ransomware risk,implemented,EV-813,IT Ops Manager,2026-05-10
```
- `implementation_status` is one of: implemented, partially implemented, planned, not implemented.
- `evidence_refs` and the risk register's `controls` column are separated by semicolons.

`risk_register.csv`: `risk_id,description,likelihood,impact,treatment,controls,owner` (likelihood and impact on a 1–5 scale)

`evidence.csv`: `evidence_id,control_id,description,collected,valid_until`

## Sample output

From the synthetic sample (a fictional credit union, with defects planted on purpose by `sample_data/generate_sample.py`):

```
ISO/IEC 27001:2022 SoA audit  (as of 2026-10-12)
========================================================
Readiness score: 34/100   Findings: 24  (High 9, Medium 9, Low 6)

Implementation coverage of applicable controls:
  Organizational ███████████████████░  94%  (34/36 implemented, 0 partial, 0 excluded)
  People         ████████████████████ 100%  (8/8 implemented, 0 partial, 0 excluded)
  Physical       ████████████████████ 100%  (11/11 implemented, 0 partial, 2 excluded)
  Technological  ██████████████████░░  90%  (27/30 implemented, 1 partial, 3 excluded)

Top findings:
  [High  ] 7.4      EXCLUSION_NO_JUSTIFICATION   Control is excluded with no justification.
  [High  ] R-004    HIGH_RISK_UNTREATED          High risk (score 15) has no mapped control fully implemented yet.
  [High  ] 5.32     MISSING_CONTROL              Annex A control 5.32 'Intellectual property rights' is not addressed in the SoA.
  [High  ] 7.12     MISSING_CONTROL              Annex A control 7.12 'Cabling security' is not addressed in the SoA.
  [High  ] 8.17     MISSING_CONTROL              Annex A control 8.17 'Clock synchronization' is not addressed in the SoA.
  [High  ] R-005    RISK_CONTROL_NOT_IN_SOA      Treatment relies on control 7.12, which is missing from the SoA.
  [High  ] R-008    RISK_NO_CONTROLS             Risk 'Insider fraud by privileged staff' is being mitigated but no controls are mapped.
  [High  ] R-002    RISK_RELIES_ON_EXCLUDED      Treatment relies on control 8.8, but the SoA marks it not applicable.
  [High  ] R-007    RISK_RELIES_ON_EXCLUDED      Treatment relies on control 8.11, but the SoA marks it not applicable.
  [Medium] 8.13     EVIDENCE_EXPIRED             Evidence 'EV-813' expired on 2026-06-30.
  ... and 14 more in the full report.
```

The full working paper is in [`sample_output/report.md`](sample_output/report.md) and the machine-readable version in [`sample_output/report.json`](sample_output/report.json).

## Limitations

- The tool checks **consistency and completeness**, not whether a control is actually effective. That still takes sampling and testing (see Week 02: audit sampling).
- Justification quality is judged by a simple length heuristic. An auditor still needs to read the reasoning.
- The "rarely excludable" list reflects practitioner judgement, not a requirement of the standard.
- Risk scoring assumes a 5×5 matrix. Adjust `AuditConfig.high_risk_score` to fit your methodology.

## Ideas to extend

- Read the SoA directly from Excel, or from a GRC tool's API export.
- Add an ISO 27001:2013 → 2022 mapping table to auto-suggest migrations for legacy IDs.
- Cross-map findings to SOC 2 and NIST CSF 2.0 (see Week 04: control crosswalk engine).
- Track the readiness score over time and alert when it drops.

---
*All data is synthetic. Maple Ridge Credit Union is fictional. ISO/IEC 27001 control titles are listed for reference only; the standard itself is available from ISO.*

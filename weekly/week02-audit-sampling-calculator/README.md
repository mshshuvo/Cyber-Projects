# Week 02: Audit Sampling Calculator & Evidence Tracker

A command-line toolkit for the part of control testing that is easy to get wrong without noticing: **how many items to test, which ones, and what the results actually let you conclude**. It sizes the sample with exact attribute-sampling math, validates the population, draws a sample anyone can re-perform, tracks evidence during fieldwork, and reaches a defensible conclusion.

## Why this matters

Most control-testing failures I've seen in audit files aren't about the testing. They're about the sample:

- **"We tested 25."** Why 25? A sample size picked from habit, with no confidence level or tolerable rate behind it, can't support a statistical conclusion.
- **The population was never checked.** The list of changes came from a report filter that dropped emergency changes, or included items from outside the period. A good sample of a bad population proves nothing (ISA 500 / PCAOB AS 1105 call this information produced by the entity, or IPE).
- **The selection can't be re-performed.** "Random" was done by hand, or with a spreadsheet `RAND()` that recalculated and never got saved.
- **Items were quietly swapped.** A hard-to-evidence ticket was replaced with an easier one. Randomness is gone, and no one can tell.
- **Testing kept going after the answer was known.** Once the exceptions are above what the design allows, testing more items can't rescue the control.

This tool deals with all five.

## Framework and regulatory mapping

| Area | Reference | How the tool supports it |
|---|---|---|
| ISO/IEC 27001:2022 | Clause 9.2 (internal audit), 9.1 (monitoring and measurement), 7.5 (documented information) | Documented, repeatable sampling method with a re-performable record |
| ISO 19011:2018 | 6.4.7 and Annex A.6 (audit sampling, judgmental and statistical) | Both statistical and judgmental sizing, with the basis recorded |
| ISA 530 / PCAOB AS 2315 | Audit sampling: tolerable rate, expected rate, sampling risk, evaluating deviations | Attribute sampling design and upper deviation limit evaluation |
| ISA 500 / PCAOB AS 1105 | Reliability of information produced by the entity | Population fingerprint, period checks, duplicate and blank IDs, count reconciliation |
| SOX 404 / ITGC testing | Change management, user access, operations controls | Sample scenario is a CAB-approval ITGC test |
| NIST CSF 2.0 | GV.OV (oversight), ID.IM-02 (improvements from assessments and tests) | Evidence-based conclusions on control operation |
| OSFI E-21 / B-13, FINTRAC compliance program effectiveness reviews | Independent testing of operational, technology and AML controls | Defensible sample sizes for the two-year FINTRAC effectiveness review and internal audit |
| PCI DSS v4.0.1 | Assessor sampling (ROC Template, "sampling" sections) | Documents the sample rationale and selection, as assessors are required to |

## What it does

| Command | What it does |
|---|---|
| `size` | Calculates a sample size: **statistical** (confidence, tolerable rate, expected rate, optional finite population) or **judgmental** (control frequency and risk). |
| `draw` | Loads the population, checks it, fingerprints it with SHA-256, draws a reproducible (optionally stratified) sample, and writes `manifest.json` and a blank `tracker.csv`. |
| `evaluate` | Reconciles the tracker to the manifest, re-performs the selection from the seed, flags evidence issues, and concludes **EFFECTIVE / NOT EFFECTIVE / INCOMPLETE**. |

### Checks

| Check | Severity | Why it matters |
|---|---|---|
| `BLANK_ID`, `DUPLICATE_ID` in population | High (blocks the draw) | Duplicates change selection probability; blanks can't be traced |
| `COUNT_MISMATCH` (vs `--expected-count`) | High (blocks the draw) | The population doesn't reconcile to the source system |
| `OUT_OF_PERIOD`, `UNREADABLE_DATE` | Medium (item excluded) | Items outside the audit period don't belong in the frame |
| `NOT_IN_SAMPLE`, `SAMPLE_ITEM_MISSING` | High | Items added, dropped or substituted after the draw |
| Re-performance fails | High | The population file changed after the draw, or the selection was edited |
| `NO_EVIDENCE_REF`, `TESTED_NO_RESULT`, `EXCEPTION_NOT_DESCRIBED`, `BAD_RESULT`, `DUPLICATE_TRACKER_ROW` | Medium | A reviewer couldn't re-perform the conclusion |
| `EVIDENCE_OVERDUE`, `NO_TESTER`, `RESULT_BEFORE_TESTED`, `DATE_ORDER`, `BAD_STATUS` | Low | Fieldwork hygiene |

## How it works

```
population.csv ─► population.py ──► sampler.py ──► manifest.json + tracker.csv
                  (IPE checks,      (hash-ranked       │
                   SHA-256)          selection,         │ fieldwork: testers fill in
                                     stratification)    ▼ status / result / evidence
stats.py ──────── sample size ──────────┘          tracker.csv ─► tracker.py ─► report.py
(binomial, hypergeometric,                                         (reconcile,    (console,
 upper deviation limit)                                             evaluate)      .md, .json)
```

**Sample size.** The design rule is the one behind the AICPA attribute-sampling tables: choose the smallest *n* such that, if the true deviation rate equalled the tolerable rate, the probability of seeing no more than *k* = ⌈*n* × expected rate⌉ deviations is at most 1 − confidence. Without a population size this uses the binomial distribution, and it reproduces the published table values exactly (59, 93, 124, 45, 29, 22 – these are in the unit tests). With a population size it uses the exact **hypergeometric** distribution, which is correct for sampling without replacement and gives smaller samples for small populations (56 instead of 59 for a population of 410).

**Selection.** Each item is ranked by `SHA-256("<seed>:<item_id>")` and the *n* lowest are chosen. That is a simple random sample, but:
- it gives the same result on any machine, in any language, forever;
- a reviewer can re-perform it with any SHA-256 tool, without this code;
- re-sorting the population file doesn't change the sample; only adding or removing items does.

Stratification uses proportional allocation (largest remainder), with at least one item per stratum.

**Evaluation.** The tool computes the achieved upper deviation limit (Clopper-Pearson for binomial; the exact discrete bound for hypergeometric). A statistical sample is EFFECTIVE only when every selected item is tested and the tolerable rate can be rejected at the design confidence. As soon as exceptions exceed the allowed number, the conclusion is NOT EFFECTIVE, even mid-fieldwork, because more testing can only add exceptions. Judgmental samples tolerate zero exceptions and make no statistical claim.

Standard library only. No dependencies. Python 3.10 or later.

## Run it

```bash
cd weekly/week02-audit-sampling-calculator

# 1. Size a sample
python -m audit_sampling size --confidence 95% --tolerable 5%
python -m audit_sampling size --confidence 95% --tolerable 10% --expected 1% --population 410
python -m audit_sampling size --frequency weekly --risk higher

# 2. Validate the population and draw the sample
python -m audit_sampling draw \
  --population sample_data/change_tickets.csv --id-column change_id \
  --date-column deployed_on --period-start 2026-01-01 --period-end 2026-09-30 \
  --expected-count 410 --stratify-by risk_tier \
  --confidence 95% --tolerable 10% --expected 1% \
  --seed MRCU-ITGC-CM02-FY26 --drawn-on 2026-10-05 \
  --control-id ITGC-CM-02 --control "Production changes are approved by the CAB before deployment" \
  --out sample_output/draw

# 3. During fieldwork, testers fill in tracker.csv. Then evaluate:
python -m audit_sampling evaluate \
  --manifest sample_data/manifest.json --tracker sample_data/evidence_tracker.csv \
  --population sample_data/change_tickets.csv --date-column deployed_on \
  --period-start 2026-01-01 --period-end 2026-09-30 \
  --as-of 2026-10-16 --org "Maple Ridge Credit Union (fictional)" --out sample_output
```

Rates can be written as `0.05`, `5` or `5%`. Other options:
- `--sample-size N` sets a fixed size (recorded as "set by the auditor").
- `--seed` is optional. Without it a random seed is generated **and recorded**.
- `--force` draws despite High population issues (not recommended).
- `--fail-on-ineffective` exits with code 2 on NOT EFFECTIVE, for continuous control monitoring pipelines.
- `--overdue-days 10` sets when an evidence request counts as overdue.

Run the tests (23 tests):

```bash
python -m unittest -v
```

Regenerate the sample data: `python sample_data/generate_sample.py`

### Tracker format

`tracker.csv` (created by `draw`; population columns are appended for the tester's convenience):

```
sample_no,item_id,stratum,status,result,evidence_ref,requested_on,received_on,tester,notes,...
5,CHG-26-0371,High,tested,exception,WP-CM02-005,2026-10-06,2026-10-08,Auditor B,CAB approval dated 2 days after deployment,...
```
- `status`: not started, requested, received, tested
- `result`: pass, exception (blank until tested)

## Sample output

The synthetic scenario tests a change-management ITGC at a fictional credit union: 412 change tickets, 2 of them out of period, a sample of 44 stratified by risk tier, and fieldwork about 80% done. Defects were planted on purpose by `sample_data/generate_sample.py`.

Sizing:

```
Sample size
========================================================
Method:              statistical attribute sampling, hypergeometric (finite population)
Confidence:          95%
Tolerable rate:      10.0%
Expected rate:       1.0%
Population:          410
Sample size:         44
Allowed deviations:  1
Basis:               95% confidence that the deviation rate is below 10.0% if no more than 1 deviation(s) are found
```

Drawing:

```
Sample drawn for ITGC-CM-02: Production changes are approved by the CAB before deployment
========================================================
Population file:  change_tickets.csv  (412 rows, 410 in frame)
SHA-256:          1bb3104cb1ccf6da...
Seed:             MRCU-ITGC-CM02-FY26
Sample size:      44 (allowed deviations 1, method attribute-hypergeometric)
Stratified by risk_tier: High 8, Low 17, Medium 19
Population issues: 2
  [Medium] CHG-25-0987  OUT_OF_PERIOD    Dated 2025-12-29, outside the audit period 2026-01-01 to 2026-09-30; excluded.
  [Medium] CHG-26-0411  OUT_OF_PERIOD    Dated 2026-10-02, outside the audit period 2026-01-01 to 2026-09-30; excluded.
First 10 selections: CHG-26-0298, CHG-26-0178, CHG-26-0367, CHG-26-0203, CHG-26-0371, CHG-26-0302, CHG-26-0260, CHG-26-0030, CHG-26-0226, CHG-26-0274
```

Evaluating:

```
Control test evaluation: ITGC-CM-02  (as of 2026-10-16)
============================================================
Production changes are approved by the CAB before deployment
Design: n=44, allowed deviations 1, method attribute-hypergeometric, 95% confidence / 10.0% tolerable

Progress  ████████████████████░░░░ 36/44 tested (82%)
Status    not started 3, received 1, requested 3, tested 36
Results   pass 34, exception 2  (by stratum: High 1, Low 1)
Upper deviation limit on items tested so far: 16.1%
Re-performance: PASS - seed and population reproduce the sample

CONCLUSION: NOT EFFECTIVE
  2 exception(s) found, more than the 1 the sample design allows. Further testing cannot change this outcome; stop, report the deficiency and assess compensating controls.

Tracker issues: 4  (High 2, Medium 1, Low 1)
  [High  ] CHG-26-0008  NOT_IN_SAMPLE            Item is in the tracker but was not selected by the sample; substituted or added items break randomness.
  [High  ] CHG-26-0081  SAMPLE_ITEM_MISSING      Selected item is missing from the tracker (dropped or replaced).
  [Medium] CHG-26-0274  NO_EVIDENCE_REF          Result recorded with no evidence reference; the conclusion cannot be re-performed by a reviewer.
  [Low   ] CHG-26-0087  EVIDENCE_OVERDUE         Evidence requested 15 days ago (2026-10-01) and not yet received.
```

The two High issues are one event: a tester replaced selected ticket CHG-26-0081 with CHG-26-0008. The full working paper is in [`sample_output/report.md`](sample_output/report.md), the JSON in [`sample_output/report.json`](sample_output/report.json), and the draw output in [`sample_output/draw/`](sample_output/draw/).

## Limitations

- **Attribute sampling only.** It answers "does the control operate?" (tests of controls). It doesn't do monetary-unit or variables sampling for substantive testing of balances.
- **Stratified samples are evaluated as one sample.** With proportional allocation this is a reasonable approximation, but per-stratum conclusions need separate designs.
- **The frequency guide is a practitioner convention**, not a requirement of any standard. Firms and regulators vary; record your own basis.
- **The tool can't judge evidence quality.** It checks that a reference exists, not that the evidence is sufficient and appropriate.
- **Population checks catch structural problems** (duplicates, period, count). Completeness against the source system still needs a reconciliation you perform, which `--expected-count` records.
- A seed chosen *after* looking at the results defeats the purpose. Draw once, record the seed, and don't redraw.

## Ideas to extend

- Monetary-unit sampling for substantive tests of financial balances.
- Sequential (stop-or-go) sampling, to end testing early with zero exceptions.
- Read trackers from Excel or a GRC tool's export, and write results back.
- Feed `report.json` into the Week 10 audit finding builder to draft the finding automatically, and into the Week 52 KRI dashboard as a control-effectiveness KRI.
- Accept the Week 01 SoA auditor's "implemented" controls as the list of controls that need testing.

---
*All data is synthetic. Maple Ridge Credit Union is fictional. Standards are cited by clause for reference only.*

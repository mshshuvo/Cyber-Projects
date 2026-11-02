# Week 04: Control Crosswalk Engine

Test a control once and see what it proves in **ISO/IEC 27001:2022, SOC 2, NIST CSF 2.0 and CIS Controls v8.1** together.

The engine reads three plain CSV files: your common controls, a crosswalk that maps each control to framework requirements, and an evidence register. For every requirement in scope, it works out whether current, passing evidence backs it up. It then shows what each piece of evidence proves across all four frameworks and what breaks when one piece fails. It also checks the crosswalk for the errors that creep into crosswalk spreadsheets: 2013 ISO numbering, CSF 1.1 ids, safeguards that don't exist, and duplicate rows.

## Why this matters

Most organisations past a certain size answer to more than one framework. A Canadian payments company might hold ISO 27001 certification for enterprise customers, produce a SOC 2 Type II report for US customers, report to its board against NIST CSF 2.0 and use CIS Controls as its technical baseline. Without a crosswalk, that means four audits that ask for the same quarterly access review in four different formats.

A common control set fixes this: run the access review once and map it to ISO A.5.18, SOC 2 CC6.3, CSF PR.AA-05 and CIS 5.1/5.3. But the crosswalk is usually a spreadsheet nobody tests, and it fails quietly:

- **One failed test breaks several frameworks at once.** When the Q3 access review fails, that isn't one finding. It's a deficiency against seven requirements in four frameworks. Teams that track evidence per framework don't see that until the auditors do.
- **Partial mappings get counted as full coverage.** "Our pen test covers A.8.8" is only partly true. Annual testing supports vulnerability management but doesn't replace it. Adding up partial mappings overstates coverage, and the gap shows up in the audit.
- **Evidence expires, and the mapping doesn't notice.** A restore test from last September is still "mapped" to A1.3 and RC.RP-03. It just no longer proves anything.
- **Old ids hang around.** Crosswalks built in 2021 still say `A.12.4.1` (ISO 2013) and `PR.AC-7` (CSF 1.1). Those requirements no longer exist, so those rows silently earn no credit.
- **Exclusions drift away from reality.** A control is excluded in the SoA "because we have no data centre" while a badge-and-CCTV control is mapped to it and operating.

The point of the tool is to make the crosswalk re-performable. Every status traces back to a mapping row and an evidence row that an auditor can check.

## Framework and regulatory mapping

| Area | Reference | How the tool supports it |
|---|---|---|
| ISO/IEC 27001:2022 | 6.1.3 (risk treatment, "compare the controls determined with those in Annex A"; SoA with justified exclusions), 9.1 (monitoring and measurement), 9.2 (internal audit), Annex A (93 controls) | Requirement status per clause and Annex A control; `EXCLUSION_NOT_JUSTIFIED`, `EXCLUDED_BUT_OPERATING`; legacy-numbering detection |
| SOC 2 | AICPA Trust Services Criteria 2017 (revised points of focus 2022): CC1–CC9, A1, C1 | Criteria-level status, so the same evidence pack serves the Type II walkthrough |
| NIST CSF 2.0 | All 106 subcategories; GV.OV-01..03 (oversight of the risk strategy), ID.IM-01..04 (improvement from evaluations) | Organisational Profile-style coverage by subcategory; flags CSF 1.1 ids that no longer exist |
| CIS Controls v8.1 | 153 safeguards; Implementation Group 1 as a scope group | IG1 coverage, safeguard range validation |
| NIST OLIR / CSF Informative References | NIST's approach to documenting relationships between frameworks | Mapping strength (`full` / `partial`) and rationale are kept per row, in the spirit of OLIR's relationship types |
| OSFI Guideline B-13 | 1.3 technology and cyber risk management framework; 2.3 cyber security controls tested and monitored | One evidence-backed view of control effectiveness across the frameworks a Canadian FRFI reports against |
| PCI DSS v4.0.1 | 12.4 (executive responsibility for compliance), 12.5.2 (scope confirmed annually) | Not catalogued here (see *Ideas to extend*). The model is the same; PCI is a fifth framework column |

## How it works

```
controls.csv ─┐
mappings.csv ─┼─► model.py ───────────────► engine.py ────────────────────► report.py
evidence.csv ─┤   load and validate:        evidence state on the date      console summary
scope.json  ──┘   ids normalised and        → control state                 report.md (coverage,
                  checked against the       → requirement status            blast radius, reuse,
catalog.py ────►  four catalogs, with       per framework, plus reuse,      gaps, findings)
(ISO 123, SOC 2   hints for legacy ids,     blast radius and                report.json
38, CSF 106,      orphans, duplicates,      equivalents across              matrix.csv
CIS 153)          bad dates                 frameworks
```

**Three steps an auditor can re-perform:**

1. **Evidence state on the assessment date.** `pass` inside its validity window → *Effective*; `pass_with_exceptions` → *Exception*; `fail` → *Failed*; outside the window → *Stale*; `not_tested`, undated or future-dated → *Untested*.
2. **Control state.** Taken from the control's *current* evidence, worst result first: a failed test isn't cancelled out by another test that passed. Stale evidence only counts if nothing current exists.
3. **Requirement status.**

   | Status | Rule |
   |---|---|
   | Deficient | Any mapped control (full or partial) failed testing |
   | Satisfied | A control mapped with strength `full` is effective |
   | Satisfied with exceptions | The best full-strength control passed with exceptions |
   | Partial | Only partial-strength controls are effective. Two partials never add up to full |
   | Evidence stale / Not tested / No evidence | Mapped controls exist, but nothing current proves them |
   | Unmapped | No common control maps to the requirement: a crosswalk gap |
   | Excluded | Excluded in `scope.json` (with or without a justification) |

   **Coverage** = (Satisfied + Satisfied with exceptions) ÷ in-scope requirements, not counting exclusions.

**What you get from that:**

- **Blast radius** for every failed, stale, untested or exception evidence item: the requirements it is pulling down, by framework.
- **Evidence reuse**: how many in-scope requirements each item supports, and the *test once, satisfy many* ratio (requirement credits per passing evidence item).
- **Equivalents**: for any requirement, what the same controls cover in the other three frameworks (`lookup`, and a column in `matrix.csv`).
- **Data-quality findings** with file and line: `UNKNOWN_REQUIREMENT` (with a hint for ISO 2013, CSF 1.1, CIS out-of-range ids and clause/Annex A mix-ups), `UNKNOWN_FRAMEWORK`, `UNKNOWN_CONTROL`, `DUPLICATE_MAPPING`, `DUPLICATE_CONTROL`, `DUPLICATE_EVIDENCE`, `BAD_STRENGTH` (downgraded to partial, never upgraded), `BAD_RESULT`, `BAD_DATE`, `FUTURE_DATE`, `CONTROL_NO_OWNER`, `CONTROL_UNMAPPED`, `CONTROL_NO_EVIDENCE`, `EVIDENCE_UNLINKED`, `EXCLUSION_NOT_JUSTIFIED`, `EXCLUDED_BUT_OPERATING`, `BAD_SCOPE_ITEM`.

### Input formats

`controls.csv`: `control_id, title, domain, owner, frequency`

`mappings.csv`: one row per link. The framework can be `ISO`, `SOC2`, `CSF` or `CIS` (aliases accepted). Ids are normalised (`pr.aa-1` → `PR.AA-01`, `CIS 5.1` → `5.1`), but ISO clause and Annex A ids are never guessed: `8.9` is reported, not rewritten to `A.8.9`.

```csv
control_id,framework,requirement_id,strength,rationale
CTL-IAM-02,ISO,A.5.18,full,
CTL-IAM-02,CIS,5.1,partial,Review validates accounts but the inventory itself is CTL-IAM-06
```

`evidence.csv`: `evidence_id, title, controls (semicolon-separated), type, owner, collected_on, valid_until, result, tested_by, notes`. One artefact can support several controls (`CTL-CFG-01; CTL-CFG-04`).

`scope.json`: which parts of each framework are in scope, and justified exclusions. A framework that isn't listed is out of scope. Without a scope file, everything is in scope.

```json
{"org": "Harbourline Payments Inc. (fictional)",
 "frameworks": {
   "ISO27001": {"include": ["clauses", "annex_a"], "exclude": {"A.8.30": "No outsourced development"}},
   "SOC2": {"include": ["cc", "a1", "c1"]},
   "CSF2": {"include": "all"},
   "CIS8": {"include": ["ig1"]}}}
```

`python -m crosswalk groups` lists every scope group (`clause6`, `a.8`, `cc6`, `gv.sc`, `pr`, `control5`, `ig1`, ...). Explicit ids work too.

Standard library only, no dependencies. Python 3.10 or later.

## Run it

```bash
cd weekly/week04-control-crosswalk-engine

# Full assessment: console summary plus report.md, report.json and matrix.csv
python -m crosswalk assess --data sample_data --as-of 2026-11-01 --out sample_output

# What does one evidence item prove, and what is it breaking?
python -m crosswalk evidence EV-012 --data sample_data --as-of 2026-11-01

# Translate a requirement: status, controls, evidence, and equivalents elsewhere
python -m crosswalk lookup iso A.8.15 --data sample_data --as-of 2026-11-01
python -m crosswalk lookup csf pr.aa-5 --data sample_data --as-of 2026-11-01

# Regenerate the synthetic dataset
python sample_data/generate_sample.py
```

Quality gates for CI: `--fail-under 80` exits 2 if any in-scope framework's coverage is below 80%. `--strict` exits 2 on High data-quality findings, so a broken crosswalk row fails the pull request that introduced it.

Run the tests (25 tests):

```bash
python -m unittest -v
```

## Sample output

The synthetic dataset belongs to a fictional Toronto payments company, Harbourline Payments Inc. It has 41 common controls, 281 mapping rows and 40 evidence items, assessed on 2026-11-01. Defects are planted on purpose.

```
Control crosswalk assessment: Harbourline Payments Inc. (fictional)  (as of 2026-11-01)
==============================================================================
Inputs: 41 common controls, 276 valid mappings, 40 evidence items
Evidence: 32 effective, 2 with exceptions, 1 failed, 3 stale, 2 untested
Test once, satisfy many: each passing evidence item supports 7.0 in-scope requirements on average

Framework            Scope Satisfied   w/ exc.   Partial Deficient     Stale  Untested  No evid.  Unmapped  Coverage
--------------------------------------------------------------------------------------------------------------------
ISO/IEC 27001:2022     120        49         3        20         2         3         5         0        38       43%
SOC 2 (TSC 2017)        38        18         0        10         2         1         1         0         6       47%
NIST CSF 2.0           106        31         2        12         1         3         3         0        54       31%
CIS Controls v8.1       56        37         9         5         2         1         1         0         1       82%

Evidence problems and their blast radius (requirements each one is pulling down)
  [Failed   ] EV-012 Q3 2026 user access review                      7 req / 4 fw
                ISO A.5.15, A.5.18 | SOC 2 CC6.2, CC6.3 | CSF PR.AA-05 | CIS 5.1, 5.3
  [Stale    ] EV-029 DR exercise 2025 (region failover)              5 req / 3 fw
                ISO A.5.29, A.5.30 | SOC 2 CC9.1, A1.3 | CSF RC.RP-01
  [Stale    ] EV-010 Production data store ACL export                2 req / 2 fw
                ISO A.8.3 | CIS 3.3
  [Stale    ] EV-028 Production database restore test                1 req / 1 fw
                CSF RC.RP-03
  [Untested ] EV-032 Vendor security assessments, 12 critical suppl  6 req / 4 fw
                ISO A.5.19, A.5.20 | SOC 2 CC9.2 | CSF GV.SC-06, GV.SC-07 | CIS 15.1
  ...

Most reused evidence
  EV-033 Awareness training completion and phishing simulatio  14 requirements (ISO 3, SOC 2 2, CSF 1, CIS 8)
  EV-003 2026 internal audit report and management review min  13 requirements (ISO 7, SOC 2 3, CSF 3)
  EV-031 Ransomware tabletop exercise report, June 2026        11 requirements (ISO 3, SOC 2 2, CSF 3, CIS 3)
  ...

Data-quality findings: 12  (High 6, Medium 5, Low 1)
  [High  ] EXCLUSION_NOT_JUSTIFIED  ISO27001 A.5.32      A.5.32 is excluded without a justification.
  [High  ] UNKNOWN_CONTROL          evidence.csv:41      EV-038 supports control CTL-DLP-01, which is not defined.
  [High  ] UNKNOWN_REQUIREMENT      mappings.csv:104     CSF2 'PR.AC-7' is not in the catalog: PR.AC is a CSF 1.1 category that CSF 2.0 removed; remap to the 2.0 subcategory.
  [High  ] UNKNOWN_REQUIREMENT      mappings.csv:113     CIS8 '5.7' is not in the catalog: CIS Control 5 has safeguards 5.1-5.6 in v8.1.
  [High  ] UNKNOWN_REQUIREMENT      mappings.csv:124     ISO27001 '8.9' is not in the catalog: clause 8.9 does not exist; did you mean Annex A control A.8.9?
  [High  ] UNKNOWN_REQUIREMENT      mappings.csv:166     ISO27001 'A.12.4.1' is not in the catalog: looks like ISO/IEC 27001:2013 numbering; map it to the 2022 control.
  ...
```

Looking up one requirement shows the reasoning and the translation into the other frameworks:

```
$ python -m crosswalk lookup soc2 CC6.3 --data sample_data --as-of 2026-11-01
SOC 2 (TSC 2017)  CC6.3 Access modified and removed; least privilege and segregation
  Status: Deficient  (Mapped control failed testing: CTL-IAM-02.)
  CTL-IAM-01 (partial) Joiner/mover/leaver provisioning through HR-driven workflow: Effective
      EV-011 Effective
  CTL-IAM-02 (full) Quarterly user access review: Failed
      EV-012 Failed
  CTL-IAM-04 (partial) Privileged access through dedicated admin accounts: Effective
      EV-014 Effective
  The same controls also cover:
    ISO/IEC 27001:2022   A.5.15, A.5.16, A.5.18, A.6.5, A.8.2, A.8.18
    NIST CSF 2.0         PR.AA-01, PR.AA-05
    CIS Controls v8.1    5.1, 5.3, 5.4, 6.1, 6.2
```

Full results: [`sample_output/report.md`](sample_output/report.md) (coverage, blast radius, reuse table, gaps per framework, findings), [`sample_output/matrix.csv`](sample_output/matrix.csv) (one row per requirement with controls, evidence and equivalents), [`sample_output/report.json`](sample_output/report.json) and [`sample_output/console.txt`](sample_output/console.txt).

What the sample shows:

- **One failed access review, four frameworks.** EV-012 found four leavers still active in the finance ERP and two reviewers approving their own access. That single failure makes ISO A.5.15/A.5.18, SOC 2 CC6.2/CC6.3, CSF PR.AA-05 and CIS 5.1/5.3 deficient. The joiner/mover/leaver test passed, but the tool doesn't let it hide the failure.
- **The DR exercise lapsed one day before the assessment.** The 2025 exercise was valid to 31 October. The 2026 exercise is booked for 20 November, so for three weeks business continuity is unproven in ISO, SOC 2 and CSF at once.
- **CIS IG1 looks great (82%), and that's the point.** A technical baseline maps cleanly to technical controls. ISO (43%) and CSF (31%) are lower because a control set built around SOC 2 and CIS leaves out the ISMS clauses (5.1 leadership, 9.1 measurement, 10.1 improvement) and much of CSF *Govern*. That's the gap a single-framework view hides.
- **Five crosswalk rows earn nothing.** Four point at requirements that don't exist (ISO 2013 `A.12.4.1`, CSF 1.1 `PR.AC-7`, CIS `5.7`, clause `8.9` instead of `A.8.9`) and one is a duplicate. Each looks fine in the spreadsheet. Wherever no other row covers the intended requirement, it becomes a gap that nobody planned for.
- **A.7.4 is excluded, but its control is running.** Either the exclusion is wrong or the control is wasted effort. Either way, an ISO auditor will ask about it.

## Limitations

- **The crosswalk is your judgement.** The tool checks that the crosswalk is consistent, current and backed by evidence. It doesn't say whether CTL-IAM-02 really meets CC6.3. The sample mappings are a practitioner's starting point, not an authoritative crosswalk. For published mappings, see NIST OLIR, the CIS mappings and the AICPA's SOC 2 to ISO 27001 and CSF mappings.
- **Requirement titles are labels, not text.** ISO Annex A titles are the published control names. SOC 2 titles are paraphrased. CSF subcategories are labelled by their category name and CIS safeguards by their control name. No standard's text is reproduced, so read the standard before you map.
- **Evidence results are inputs.** The tool trusts `result` and the dates. It doesn't inspect the artefact or re-perform the test. Pair it with the Week 02 sampling tracker for how the result was reached.
- **Conservative by design.** A failed partial-strength control makes a requirement deficient even if another control fully covers it. An auditor would raise it, and you can always explain it down.
- **Four frameworks.** PCI DSS, OSFI B-13, SOC 2 Processing Integrity and Privacy, and ISO 27701 aren't catalogued yet.

## Ideas to extend

- Add PCI DSS v4.0.1 and OSFI B-13 as catalogs (the model is unchanged: a dictionary of ids and a few scope groups).
- Import a published crosswalk (NIST OLIR, or the CIS mapping spreadsheets) and diff it against your own mappings, flagging rows where yours is stronger than the reference.
- Read the Week 01 SoA so that ISO exclusions come from the SoA itself, and feed Week 02 sample results straight into `evidence.csv`.
- Forecast mode: `--as-of` a month ahead to see which evidence expires before the next audit fieldwork.
- An HTML heatmap (framework × domain) for the Week 14 board report and the Week 52 KRI dashboard.
- Weighted coverage, so that a deficient CC6.3 counts for more than an unmapped CC1.1 when you report to a risk committee.

---
*All data is synthetic. Harbourline Payments Inc., its controls and its evidence are fictional. Framework identifiers are cited for reference only. ISO/IEC 27001 is © ISO/IEC, the SOC 2 Trust Services Criteria are © AICPA, CIS Controls are © Center for Internet Security, and NIST CSF 2.0 is a U.S. Government work.*

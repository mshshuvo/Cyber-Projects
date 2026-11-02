One failed access review. Seven deficient requirements. Four frameworks.

For week 4 of my 53-project series, I built a control crosswalk engine. You test a control once, and it shows what that evidence proves across ISO 27001, SOC 2, NIST CSF 2.0 and CIS Controls v8.1, and what breaks when it fails.

Most multi-framework programmes already have a crosswalk spreadsheet. The trouble is that nobody tests the spreadsheet. Running the tool on a synthetic payments company turned up the usual problems:

- One quarterly access review failed (leavers still active, reviewers approving their own access). That single result made ISO A.5.18, SOC 2 CC6.3, CSF PR.AA-05 and CIS 5.1 deficient at the same time.
- Mapping rows still used ISO 2013 and CSF 1.1 ids. They looked fine but earned no credit.
- "Partial" mappings were being added up as if they were full coverage.
- The DR exercise had lapsed the day before the assessment, which left continuity unproven in three frameworks.

The rule I built in is conservative on purpose: two partial controls never add up to a satisfied requirement, and one failed test isn't cancelled out by another that passed. Auditors work the same way.

CIS coverage was 82%, while ISO and CSF were much lower. Technical baselines don't cover governance, and a crosswalk makes that easy to see.

Code, sample data and report: https://github.com/mshshuvo/Cyber-Projects/tree/main/weekly/week04-control-crosswalk-engine

#GRC #ISO27001 #SOC2 #NISTCSF #CyberRisk

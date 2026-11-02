"""Generate the synthetic sample dataset for Harbourline Payments Inc. (fictional).

Run from this folder: python generate_sample.py
Writes controls.csv, mappings.csv, evidence.csv and scope.json.

The mappings are a practitioner's judgement of how each common control lines
up with each framework, written for this demo. They are a reasonable starting
point, not an authoritative crosswalk. A few defects are planted on purpose
(legacy ISO 2013 and CSF 1.1 ids, a non-existent CIS safeguard, a clause/Annex A
mix-up, a duplicate row, an unowned legacy control) so the validator has
something to find.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

# control id: (title, domain, owner, frequency)
CONTROLS: dict[str, tuple[str, str, str, str]] = {
    "CTL-GOV-01": ("Information security policy set approved and reviewed annually", "Governance", "CISO", "Annual"),
    "CTL-GOV-02": ("Security roles, responsibilities and reporting lines defined", "Governance", "CISO", "Annual"),
    "CTL-GOV-03": ("Internal audit programme and management review", "Governance", "Head of Risk", "Annual"),
    "CTL-GOV-04": ("ISMS scope, context, interested parties and objectives", "Governance", "CISO", "Annual"),
    "CTL-GOV-05": ("Legal, regulatory and contractual obligations register", "Governance", "General Counsel", "Semi-annual"),
    "CTL-RSK-01": ("Annual information security risk assessment", "Risk", "Head of Risk", "Annual"),
    "CTL-RSK-02": ("Risk treatment plan and formal risk acceptance", "Risk", "Head of Risk", "Quarterly"),
    "CTL-AST-01": ("Hardware asset inventory reconciled to MDM and cloud accounts", "Assets", "IT Operations Manager", "Monthly"),
    "CTL-AST-02": ("Software inventory and authorised software list", "Assets", "IT Operations Manager", "Quarterly"),
    "CTL-DAT-01": ("Data classification and handling standard", "Data", "Privacy Officer", "Annual"),
    "CTL-DAT-02": ("Data retention schedule and secure disposal", "Data", "Privacy Officer", "Quarterly"),
    "CTL-DAT-03": ("Access to production data stores restricted by ACLs", "Data", "Head of Engineering", "Quarterly"),
    "CTL-IAM-01": ("Joiner/mover/leaver provisioning through HR-driven workflow", "Identity", "IT Operations Manager", "Per event"),
    "CTL-IAM-02": ("Quarterly user access review", "Identity", "IT Operations Manager", "Quarterly"),
    "CTL-IAM-03": ("MFA enforced for workforce, remote and administrative access", "Identity", "Security Engineering Lead", "Continuous"),
    "CTL-IAM-04": ("Privileged access through dedicated admin accounts", "Identity", "Security Engineering Lead", "Quarterly"),
    "CTL-IAM-05": ("Password and authentication standard enforced by the IdP", "Identity", "Security Engineering Lead", "Annual"),
    "CTL-IAM-06": ("Account inventory with automatic disablement of dormant accounts", "Identity", "IT Operations Manager", "Monthly"),
    "CTL-CFG-01": ("Hardened configuration baselines (CIS Benchmark based)", "Configuration", "Security Engineering Lead", "Quarterly"),
    "CTL-CFG-02": ("Endpoint detection and response on all endpoints and servers", "Endpoint", "IT Operations Manager", "Continuous"),
    "CTL-CFG-03": ("Endpoint session lock and host firewall enforced by MDM", "Endpoint", "IT Operations Manager", "Continuous"),
    "CTL-CFG-04": ("Default accounts disabled and unnecessary services removed", "Configuration", "Security Engineering Lead", "Quarterly"),
    "CTL-VUL-01": ("Vulnerability scanning and risk-based patching within SLA", "Vulnerability", "Security Engineering Lead", "Monthly"),
    "CTL-VUL-02": ("Annual independent penetration test with retest", "Vulnerability", "CISO", "Annual"),
    "CTL-LOG-01": ("Centralised logging with 13-month retention", "Logging", "Security Operations Lead", "Continuous"),
    "CTL-LOG-02": ("24x7 security monitoring and alert triage", "Logging", "Security Operations Lead", "Continuous"),
    "CTL-LOG-03": ("Clock synchronisation to approved time sources", "Logging", "IT Operations Manager", "Continuous"),
    "CTL-NET-01": ("Network segmentation and semi-annual firewall rule review", "Network", "Head of Engineering", "Semi-annual"),
    "CTL-NET-02": ("DNS filtering and email security gateway", "Network", "IT Operations Manager", "Continuous"),
    "CTL-CRY-01": ("Encryption of data at rest and in transit", "Cryptography", "Security Engineering Lead", "Annual"),
    "CTL-BCK-01": ("Automated, immutable backups of production data", "Resilience", "Head of Engineering", "Daily"),
    "CTL-BCK-02": ("Restore testing of backups", "Resilience", "Head of Engineering", "Semi-annual"),
    "CTL-BCP-01": ("Business continuity and DR plan exercised annually", "Resilience", "Head of Risk", "Annual"),
    "CTL-IR-01": ("Incident response plan, roles and annual tabletop exercise", "Incident", "Security Operations Lead", "Annual"),
    "CTL-TPR-01": ("Third-party security risk assessment and contract clauses", "Third party", "Vendor Risk Manager", "Annual"),
    "CTL-HR-01": ("Security awareness training and phishing simulation", "People", "CISO", "Annual"),
    "CTL-HR-02": ("Pre-employment background screening", "People", "People Operations Lead", "Per hire"),
    "CTL-CHG-01": ("Change management with peer review and approval", "Change", "Head of Engineering", "Per change"),
    "CTL-SDL-01": ("Secure SDLC: code review, SAST and dependency scanning", "Development", "Head of Engineering", "Per release"),
    "CTL-PHY-01": ("Office physical access control and visitor log", "Physical", "Office Manager", "Monthly"),
    "CTL-LEG-01": ("Offsite backup tape rotation (legacy)", "Resilience", "", "Weekly"),
}

# control id: mapping strings "FW:requirement" (full) or "FW:requirement:p" (partial)
MAPPINGS: dict[str, list[str]] = {
    "CTL-GOV-01": ["ISO:5.2", "ISO:A.5.1", "ISO:7.5.2:p", "ISO:7.5.3:p", "SOC2:CC5.3", "SOC2:CC2.2:p",
                   "CSF:GV.PO-01", "CSF:GV.PO-02"],
    "CTL-GOV-02": ["ISO:5.3", "ISO:A.5.2", "ISO:A.5.4:p", "SOC2:CC1.3", "CSF:GV.RR-02", "CSF:GV.RR-01:p"],
    "CTL-GOV-03": ["ISO:9.2.1", "ISO:9.2.2", "ISO:9.3.1", "ISO:9.3.2", "ISO:9.3.3", "ISO:A.5.35:p", "ISO:10.2:p",
                   "SOC2:CC4.1", "SOC2:CC4.2", "SOC2:CC1.2:p", "CSF:GV.OV-01", "CSF:GV.OV-02:p", "CSF:ID.IM-01:p"],
    "CTL-GOV-04": ["ISO:4.1", "ISO:4.2", "ISO:4.3", "ISO:4.4", "ISO:6.1.1:p", "ISO:6.2", "CSF:GV.OC-01",
                   "CSF:GV.OC-02:p", "SOC2:CC3.1:p"],
    "CTL-GOV-05": ["ISO:A.5.31", "ISO:A.5.34:p", "ISO:4.2:p", "CSF:GV.OC-03"],
    "CTL-RSK-01": ["ISO:6.1.2", "ISO:8.2", "SOC2:CC3.2", "SOC2:CC3.1:p", "SOC2:CC3.3:p", "CSF:ID.RA-05",
                   "CSF:ID.RA-03:p", "CSF:ID.RA-04:p"],
    "CTL-RSK-02": ["ISO:6.1.3", "ISO:8.3", "SOC2:CC9.1:p", "CSF:ID.RA-06", "CSF:GV.RM-02:p"],
    "CTL-AST-01": ["ISO:A.5.9", "ISO:A.5.11:p", "SOC2:CC6.1:p", "CSF:ID.AM-01", "CIS:1.1", "CIS:1.2"],
    "CTL-AST-02": ["ISO:A.8.19", "ISO:A.5.9:p", "CSF:ID.AM-02", "CSF:PR.PS-02:p", "CIS:2.1", "CIS:2.2", "CIS:2.3"],
    "CTL-DAT-01": ["ISO:A.5.12", "ISO:A.5.13", "SOC2:C1.1", "CSF:ID.AM-07", "CIS:3.1", "CIS:3.2:p"],
    "CTL-DAT-02": ["ISO:A.8.10", "ISO:A.7.14", "ISO:A.5.33:p", "SOC2:C1.2", "SOC2:CC6.5", "CIS:3.4", "CIS:3.5"],
    "CTL-DAT-03": ["ISO:A.8.3", "ISO:A.5.15:p", "SOC2:CC6.1:p", "CSF:PR.AA-05:p", "CIS:3.3"],
    "CTL-IAM-01": ["ISO:A.5.16", "ISO:A.5.18", "ISO:A.6.5:p", "SOC2:CC6.2", "SOC2:CC6.3:p", "CSF:PR.AA-01",
                   "CIS:6.1", "CIS:6.2"],
    "CTL-IAM-02": ["ISO:A.5.18", "ISO:A.5.15:p", "SOC2:CC6.3", "SOC2:CC6.2:p", "CSF:PR.AA-05", "CIS:5.1:p",
                   "CIS:5.3:p"],
    "CTL-IAM-03": ["ISO:A.8.5", "SOC2:CC6.1:p", "CSF:PR.AA-03", "CSF:PR.AC-7", "CIS:6.3", "CIS:6.4", "CIS:6.5"],
    "CTL-IAM-04": ["ISO:A.8.2", "ISO:A.8.18:p", "SOC2:CC6.3:p", "CSF:PR.AA-05:p", "CIS:5.4", "CIS:5.7"],
    "CTL-IAM-05": ["ISO:A.5.17", "SOC2:CC6.1:p", "CSF:PR.AA-03:p", "CIS:5.2"],
    "CTL-IAM-06": ["ISO:A.5.16:p", "SOC2:CC6.2:p", "CSF:PR.AA-01:p", "CIS:5.1", "CIS:5.3"],
    "CTL-CFG-01": ["ISO:A.8.9", "ISO:8.9", "SOC2:CC7.1:p", "SOC2:CC5.2:p", "CSF:PR.PS-01", "CIS:4.1", "CIS:4.2"],
    "CTL-CFG-02": ["ISO:A.8.7", "SOC2:CC6.8", "CSF:DE.CM-09", "CSF:PR.PS-05:p", "CIS:10.1", "CIS:10.2", "CIS:10.3"],
    "CTL-CFG-03": ["ISO:A.8.1", "ISO:A.7.7:p", "CSF:PR.PS-01:p", "CIS:4.3", "CIS:4.5"],
    "CTL-CFG-04": ["ISO:A.8.9:p", "CSF:PR.PS-01:p", "CIS:4.6", "CIS:4.7"],
    "CTL-VUL-01": ["ISO:A.8.8", "SOC2:CC7.1", "CSF:ID.RA-01", "CSF:PR.PS-02", "CSF:ID.RA-08:p",
                   "CIS:7.1", "CIS:7.2", "CIS:7.3", "CIS:7.4", "CIS:7.1"],
    "CTL-VUL-02": ["ISO:A.8.8:p", "ISO:A.8.29:p", "ISO:A.5.35:p", "SOC2:CC4.1:p", "SOC2:CC7.1:p",
                   "CSF:ID.RA-01:p", "CSF:ID.IM-02", "CIS:18.1", "CIS:18.2"],
    "CTL-LOG-01": ["ISO:A.8.15", "ISO:A.12.4.1", "SOC2:CC7.2:p", "CSF:PR.PS-04", "CIS:8.1", "CIS:8.2",
                   "CIS:8.3", "CIS:8.10"],
    "CTL-LOG-02": ["ISO:A.8.16", "ISO:A.5.25", "ISO:A.6.8:p", "SOC2:CC7.2", "SOC2:CC7.3", "CSF:DE.CM-01",
                   "CSF:DE.CM-03:p", "CSF:DE.AE-02", "CSF:DE.AE-03:p", "CSF:DE.AE-06", "CIS:8.11", "CIS:13.1"],
    "CTL-LOG-03": ["ISO:A.8.17", "CIS:8.4"],
    "CTL-NET-01": ["ISO:A.8.20", "ISO:A.8.22", "ISO:A.8.21:p", "SOC2:CC6.6", "CSF:PR.IR-01", "CIS:4.4",
                   "CIS:12.2:p"],
    "CTL-NET-02": ["ISO:A.8.23", "SOC2:CC6.8:p", "CIS:9.2", "CIS:9.1:p"],
    "CTL-CRY-01": ["ISO:A.8.24", "ISO:A.5.14:p", "SOC2:CC6.7", "SOC2:CC6.1:p", "CSF:PR.DS-01", "CSF:PR.DS-02",
                   "CIS:3.6", "CIS:3.10", "CIS:3.11"],
    "CTL-BCK-01": ["ISO:A.8.13", "SOC2:A1.2", "CSF:PR.DS-11", "CIS:11.2", "CIS:11.3", "CIS:11.4", "CIS:11.1:p"],
    "CTL-BCK-02": ["ISO:A.8.13:p", "SOC2:A1.3:p", "CSF:RC.RP-03", "CIS:11.5", "CIS:11.1:p"],
    "CTL-BCP-01": ["ISO:A.5.29", "ISO:A.5.30", "SOC2:A1.3", "SOC2:CC9.1", "SOC2:CC7.5:p", "CSF:RC.RP-01",
                   "CSF:ID.IM-04:p", "CSF:PR.IR-03:p"],
    "CTL-IR-01": ["ISO:A.5.24", "ISO:A.5.26", "ISO:A.5.27:p", "SOC2:CC7.4", "SOC2:CC7.5:p", "CSF:RS.MA-01",
                  "CSF:ID.IM-04", "CSF:RS.CO-02:p", "CIS:17.1", "CIS:17.2", "CIS:17.3"],
    "CTL-TPR-01": ["ISO:A.5.19", "ISO:A.5.20", "ISO:A.5.21:p", "ISO:A.5.22:p", "ISO:A.5.23:p", "SOC2:CC9.2",
                   "CSF:GV.SC-06", "CSF:GV.SC-07", "CSF:GV.SC-05:p", "CIS:15.1"],
    "CTL-HR-01": ["ISO:A.6.3", "ISO:7.3", "ISO:7.2:p", "SOC2:CC2.2:p", "SOC2:CC1.4:p", "CSF:PR.AT-01",
                  "CIS:14.1", "CIS:14.2", "CIS:14.3", "CIS:14.4", "CIS:14.5", "CIS:14.6", "CIS:14.7:p",
                  "CIS:14.8:p"],
    "CTL-HR-02": ["ISO:A.6.1", "SOC2:CC1.4:p", "CSF:GV.RR-04"],
    "CTL-CHG-01": ["ISO:A.8.32", "ISO:6.3:p", "SOC2:CC8.1", "SOC2:CC3.4:p", "CSF:ID.RA-07"],
    "CTL-SDL-01": ["ISO:A.8.25", "ISO:A.8.28", "ISO:A.8.29:p", "ISO:A.8.4:p", "SOC2:CC8.1:p", "CSF:PR.PS-06",
                   "CIS:16.1", "CIS:16.12:p"],
    "CTL-PHY-01": ["ISO:A.7.1", "ISO:A.7.2", "ISO:A.7.4", "SOC2:CC6.4", "CSF:PR.AA-06"],
}

RATIONALE = {
    ("CTL-IAM-02", "CIS", "5.1"): "Review validates accounts but the inventory itself is CTL-IAM-06",
    ("CTL-BCK-02", "SOC2", "A1.3"): "Restore tests are one part of recovery plan testing",
    ("CTL-VUL-02", "ISO", "A.8.8"): "Annual test supplements, but does not replace, continuous VM",
    ("CTL-CFG-03", "ISO", "A.7.7"): "Covers clear screen only, not clear desk",
    ("CTL-HR-01", "CIS", "14.7"): "Curriculum covers missing-update recognition only briefly",
}

# id, title, controls, type, owner, collected_on, valid_until, result, tested_by, notes
EVIDENCE = [
    ("EV-001", "Information Security Policy v4.0 and board approval minutes", "CTL-GOV-01", "Document", "CISO", "2026-03-12", "2027-03-31", "pass", "Internal Audit", ""),
    ("EV-002", "Security organisation chart and RACI", "CTL-GOV-02", "Document", "CISO", "2026-02-01", "2027-02-28", "pass", "Internal Audit", ""),
    ("EV-003", "2026 internal audit report and management review minutes", "CTL-GOV-03", "Report", "Head of Risk", "2026-06-20", "2027-06-30", "pass", "External Auditor", ""),
    ("EV-039", "ISMS manual: scope, context and 2026 objectives", "CTL-GOV-04", "Document", "CISO", "2026-01-20", "2027-01-31", "pass", "External Auditor", ""),
    ("EV-040", "Obligations register (PIPEDA, PCI DSS, contracts), H2 2026", "CTL-GOV-05", "Register", "General Counsel", "2026-07-15", "2027-01-31", "pass", "Internal Audit", ""),
    ("EV-004", "2026 information security risk assessment report", "CTL-RSK-01", "Report", "Head of Risk", "2026-04-15", "2027-04-30", "pass", "Internal Audit", ""),
    ("EV-005", "Risk treatment plan tracker, Q3 2026", "CTL-RSK-02", "Register", "Head of Risk", "2026-10-05", "2027-01-15", "pass", "Internal Audit", ""),
    ("EV-006", "MDM-to-CMDB reconciliation, September 2026", "CTL-AST-01", "Reconciliation", "IT Operations Manager", "2026-09-30", "2026-11-15", "pass", "Internal Audit", ""),
    ("EV-007", "Authorised software list and EDR software inventory export", "CTL-AST-02", "System export", "IT Operations Manager", "2026-08-14", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-008", "Data classification standard and sensitivity label report", "CTL-DAT-01", "Document", "Privacy Officer", "2026-05-02", "2027-05-31", "pass", "Internal Audit", ""),
    ("EV-009", "Retention job logs and disposal certificates, Q3 2026", "CTL-DAT-02", "Log sample", "Privacy Officer", "2026-10-03", "2027-01-10", "pass", "Internal Audit", ""),
    ("EV-010", "Production data store ACL export", "CTL-DAT-03", "System export", "Head of Engineering", "2026-07-20", "2026-10-31", "pass", "Internal Audit", "Quarterly re-export not yet received"),
    ("EV-011", "JML sample test: 25 joiners, 25 leavers (Q3)", "CTL-IAM-01", "Sample test", "IT Operations Manager", "2026-10-08", "2027-01-15", "pass", "Internal Audit", ""),
    ("EV-012", "Q3 2026 user access review", "CTL-IAM-02", "Sample test", "IT Operations Manager", "2026-10-14", "2027-01-15", "fail", "Internal Audit", "4 leavers still active in the finance ERP; 2 reviewers approved their own access"),
    ("EV-013", "IdP conditional access policy export (MFA)", "CTL-IAM-03", "System export", "Security Engineering Lead", "2026-10-20", "2027-01-31", "pass_with_exceptions", "Internal Audit", "2 legacy service accounts excluded from MFA under risk acceptance RA-2026-07"),
    ("EV-014", "Privileged account list vs admin group membership", "CTL-IAM-04", "Reconciliation", "Security Engineering Lead", "2026-09-12", "2026-12-31", "pass", "Internal Audit", ""),
    ("EV-015", "IdP password policy export", "CTL-IAM-05", "System export", "Security Engineering Lead", "2026-03-02", "2027-03-31", "pass", "Internal Audit", ""),
    ("EV-016", "Dormant account report (45 days), October 2026", "CTL-IAM-06", "System export", "IT Operations Manager", "2026-10-02", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-017", "CIS Benchmark compliance scan, production servers", "CTL-CFG-01; CTL-CFG-04", "Scan report", "Security Engineering Lead", "2026-09-28", "2026-12-31", "pass", "Internal Audit", ""),
    ("EV-018", "EDR console coverage report", "CTL-CFG-02", "System export", "IT Operations Manager", "2026-10-25", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-019", "MDM compliance policy export", "CTL-CFG-03", "System export", "IT Operations Manager", "2026-10-25", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-020", "Vulnerability scan and patch SLA report, October 2026", "CTL-VUL-01", "Report", "Security Engineering Lead", "2026-10-28", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-021", "2026 external penetration test report and retest letter", "CTL-VUL-02", "Report", "CISO", "2026-05-18", "2027-05-31", "pass", "Internal Audit", ""),
    ("EV-022", "SIEM log source coverage, retention and NTP settings", "CTL-LOG-01; CTL-LOG-03", "System export", "Security Operations Lead", "2026-10-10", "2027-01-10", "pass", "Internal Audit", ""),
    ("EV-023", "SOC alert triage sample (40 alerts), Q3 2026", "CTL-LOG-02", "Sample test", "Security Operations Lead", "2026-10-09", "2027-01-10", "pass", "Internal Audit", ""),
    ("EV-024", "Firewall rule review, H1 2026", "CTL-NET-01", "Review record", "Head of Engineering", "2026-07-06", "2027-01-06", "pass", "Internal Audit", ""),
    ("EV-025", "DNS filtering and email gateway policy export", "CTL-NET-02", "System export", "IT Operations Manager", "2026-09-01", "2026-12-01", "pass", "Internal Audit", ""),
    ("EV-026", "KMS key policy and TLS configuration export", "CTL-CRY-01", "System export", "Security Engineering Lead", "2026-08-30", "2027-02-28", "pass", "Internal Audit", ""),
    ("EV-027", "Backup job success report, October 2026", "CTL-BCK-01", "Report", "Head of Engineering", "2026-10-31", "2026-11-30", "pass", "Internal Audit", ""),
    ("EV-028", "Production database restore test", "CTL-BCK-02", "Test record", "Head of Engineering", "2025-09-22", "2026-03-31", "pass", "Internal Audit", "H1 2026 restore test was not performed"),
    ("EV-029", "DR exercise 2025 (region failover)", "CTL-BCP-01", "Test record", "Head of Risk", "2025-10-15", "2026-10-31", "pass", "Internal Audit", ""),
    ("EV-030", "DR exercise 2026 (planned)", "CTL-BCP-01", "Test record", "Head of Risk", "2026-11-20", "2027-11-30", "not_tested", "", "Scheduled for 20 November"),
    ("EV-031", "Ransomware tabletop exercise report, June 2026", "CTL-IR-01", "Test record", "Security Operations Lead", "2026-06-11", "2027-06-30", "pass", "Internal Audit", ""),
    ("EV-032", "Vendor security assessments, 12 critical suppliers", "CTL-TPR-01", "Assessment", "Vendor Risk Manager", "2026-10-22", "2027-10-31", "not_tested", "", "Collected; testing scheduled for November"),
    ("EV-033", "Awareness training completion and phishing simulation results", "CTL-HR-01", "Report", "CISO", "2026-09-30", "2027-03-31", "pass_with_exceptions", "Internal Audit", "Completion 94% against a 98% target"),
    ("EV-034", "Background check sample (15 hires)", "CTL-HR-02", "Sample test", "People Operations Lead", "2026-08-19", "2027-08-31", "pass", "Internal Audit", ""),
    ("EV-035", "Change ticket sample (40 changes), Q3 2026", "CTL-CHG-01; CTL-SDL-01", "Sample test", "Head of Engineering", "2026-10-12", "2027-01-15", "pass", "Internal Audit", ""),
    ("EV-036", "SAST and dependency scanning pipeline results", "CTL-SDL-01", "System export", "Head of Engineering", "2026-10-12", "2027-01-15", "pass", "Internal Audit", ""),
    ("EV-037", "Badge access review and visitor log, Q3 2026", "CTL-PHY-01", "Review record", "Office Manager", "2026-10-06", "2026-12-31", "pass", "Internal Audit", ""),
    ("EV-038", "DLP incident report, Q3 2026", "CTL-DLP-01", "Report", "Privacy Officer", "2026-10-01", "2026-12-31", "pass", "Internal Audit", "Control not yet in the common control set"),
]

SCOPE = {
    "org": "Harbourline Payments Inc. (fictional)",
    "frameworks": {
        "ISO27001": {
            "include": ["clauses", "annex_a"],
            "exclude": {
                "A.8.30": "No outsourced development; all software is built by employees.",
                "A.7.4": "No data centre; production is hosted in a cloud region.",
                "A.5.32": "",
            },
        },
        "SOC2": {"include": ["cc", "a1", "c1"]},
        "CSF2": {"include": "all"},
        "CIS8": {"include": ["ig1"]},
    },
}


def main() -> None:
    with (HERE / "controls.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["control_id", "title", "domain", "owner", "frequency"])
        for cid, row in CONTROLS.items():
            w.writerow([cid, *row])
    with (HERE / "mappings.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["control_id", "framework", "requirement_id", "strength", "rationale"])
        for cid, refs in MAPPINGS.items():
            for ref in refs:
                parts = ref.split(":")
                fw, rid = parts[0], parts[1]
                strength = "partial" if len(parts) > 2 else "full"
                w.writerow([cid, fw, rid, strength, RATIONALE.get((cid, fw, rid), "")])
    with (HERE / "evidence.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["evidence_id", "title", "controls", "type", "owner", "collected_on", "valid_until",
                    "result", "tested_by", "notes"])
        w.writerows(EVIDENCE)
    (HERE / "scope.json").write_text(json.dumps(SCOPE, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(CONTROLS)} controls, {sum(map(len, MAPPINGS.values()))} mappings, "
          f"{len(EVIDENCE)} evidence items and scope.json")


if __name__ == "__main__":
    main()

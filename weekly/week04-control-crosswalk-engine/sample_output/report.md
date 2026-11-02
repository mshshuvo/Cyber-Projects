# Control Crosswalk Assessment: Harbourline Payments Inc. (fictional)

**Assessment date:** 2026-11-01  
**Inputs:** 41 common controls, 276 valid mappings, 40 evidence items  
**Evidence states:** 32 effective, 2 with exceptions, 1 failed, 3 stale, 2 untested  
**Test once, satisfy many:** each passing evidence item supports **7.0** in-scope requirements on average

## Coverage by framework

| Framework | In scope | Satisfied | w/ exc. | Partial | Deficient | Stale | Untested | No evid. | Unmapped | Excluded | Coverage |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ISO/IEC 27001:2022 | 120 | 49 | 3 | 20 | 2 | 3 | 5 | 0 | 38 | 3 | 43% |
| SOC 2 (TSC 2017) | 38 | 18 | 0 | 10 | 2 | 1 | 1 | 0 | 6 | 0 | 47% |
| NIST CSF 2.0 | 106 | 31 | 2 | 12 | 1 | 3 | 3 | 0 | 54 | 0 | 31% |
| CIS Controls v8.1 | 56 | 37 | 9 | 5 | 2 | 1 | 1 | 0 | 1 | 0 | 82% |

*Coverage* = requirements satisfied (with or without exceptions) by a fully mapped, effective control, divided by in-scope requirements. Partial mappings never count as coverage.

## Evidence problems: blast radius

One weak piece of evidence breaks requirements in several frameworks at once. Fix these first.

| Evidence | State | Controls | Requirements affected | Notes |
|---|---|---|---|---|
| EV-012 Q3 2026 user access review | Failed | CTL-IAM-02 | ISO A.5.15, A.5.18; SOC 2 CC6.2, CC6.3; CSF PR.AA-05; CIS 5.1, 5.3 | 4 leavers still active in the finance ERP; 2 reviewers approved their own access |
| EV-029 DR exercise 2025 (region failover) | Stale | CTL-BCP-01 | ISO A.5.29, A.5.30; SOC 2 CC9.1, A1.3; CSF RC.RP-01 |  |
| EV-010 Production data store ACL export | Stale | CTL-DAT-03 | ISO A.8.3; CIS 3.3 | Quarterly re-export not yet received |
| EV-028 Production database restore test | Stale | CTL-BCK-02 | CSF RC.RP-03 | H1 2026 restore test was not performed |
| EV-032 Vendor security assessments, 12 critical suppliers | Untested | CTL-TPR-01 | ISO A.5.19, A.5.20; SOC 2 CC9.2; CSF GV.SC-06, GV.SC-07; CIS 15.1 | Collected; testing scheduled for November |
| EV-030 DR exercise 2026 (planned) | Untested | CTL-BCP-01 | ISO A.5.29, A.5.30; SOC 2 CC9.1, A1.3; CSF RC.RP-01 | Scheduled for 20 November |
| EV-033 Awareness training completion and phishing simulation results | Exception | CTL-HR-01 | ISO 7.3, A.6.3; CSF PR.AT-01; CIS 14.1, 14.2, 14.3, 14.4, 14.5, 14.6 | Completion 94% against a 98% target |
| EV-013 IdP conditional access policy export (MFA) | Exception | CTL-IAM-03 | ISO A.8.5; CSF PR.AA-03; CIS 6.3, 6.4, 6.5 | 2 legacy service accounts excluded from MFA under risk acceptance RA-2026-07 |

## Evidence reuse

| Evidence | State | ISO | SOC 2 | CSF | CIS | Total |
|---|---|---:|---:|---:|---:|---:|
| EV-033 Awareness training completion and phishing simulation results | Exception | 3 | 2 | 1 | 8 | 14 |
| EV-003 2026 internal audit report and management review minutes | Effective | 7 | 3 | 3 | 0 | 13 |
| EV-031 Ransomware tabletop exercise report, June 2026 | Effective | 3 | 2 | 3 | 3 | 11 |
| EV-023 SOC alert triage sample (40 alerts), Q3 2026 | Effective | 3 | 2 | 5 | 0 | 10 |
| EV-032 Vendor security assessments, 12 critical suppliers | Untested | 5 | 1 | 3 | 1 | 10 |
| EV-035 Change ticket sample (40 changes), Q3 2026 | Effective | 6 | 2 | 2 | 0 | 10 |
| EV-020 Vulnerability scan and patch SLA report, October 2026 | Effective | 1 | 1 | 3 | 4 | 9 |
| EV-039 ISMS manual: scope, context and 2026 objectives | Effective | 6 | 1 | 2 | 0 | 9 |
| EV-001 Information Security Policy v4.0 and board approval minutes | Effective | 4 | 2 | 2 | 0 | 8 |
| EV-004 2026 information security risk assessment report | Effective | 2 | 3 | 3 | 0 | 8 |
| EV-011 JML sample test: 25 joiners, 25 leavers (Q3) | Effective | 3 | 2 | 1 | 2 | 8 |
| EV-017 CIS Benchmark compliance scan, production servers | Effective | 1 | 2 | 1 | 4 | 8 |
| EV-029 DR exercise 2025 (region failover) | Stale | 2 | 3 | 3 | 0 | 8 |
| EV-030 DR exercise 2026 (planned) | Untested | 2 | 3 | 3 | 0 | 8 |
| EV-007 Authorised software list and EDR software inventory export | Effective | 2 | 0 | 2 | 3 | 7 |
| EV-009 Retention job logs and disposal certificates, Q3 2026 | Effective | 3 | 2 | 0 | 2 | 7 |
| EV-012 Q3 2026 user access review | Failed | 2 | 2 | 1 | 2 | 7 |
| EV-018 EDR console coverage report | Effective | 1 | 1 | 2 | 3 | 7 |
| EV-021 2026 external penetration test report and retest letter | Effective | 3 | 2 | 2 | 0 | 7 |
| EV-022 SIEM log source coverage, retention and NTP settings | Effective | 2 | 1 | 1 | 3 | 7 |
| EV-026 KMS key policy and TLS configuration export | Effective | 2 | 2 | 2 | 1 | 7 |
| EV-027 Backup job success report, October 2026 | Effective | 1 | 1 | 1 | 4 | 7 |
| EV-002 Security organisation chart and RACI | Effective | 3 | 1 | 2 | 0 | 6 |
| EV-006 MDM-to-CMDB reconciliation, September 2026 | Effective | 2 | 1 | 1 | 2 | 6 |
| EV-008 Data classification standard and sensitivity label report | Effective | 2 | 1 | 1 | 2 | 6 |
| EV-013 IdP conditional access policy export (MFA) | Exception | 1 | 1 | 1 | 3 | 6 |
| EV-024 Firewall rule review, H1 2026 | Effective | 3 | 1 | 1 | 1 | 6 |
| EV-036 SAST and dependency scanning pipeline results | Effective | 4 | 1 | 1 | 0 | 6 |
| EV-005 Risk treatment plan tracker, Q3 2026 | Effective | 2 | 1 | 2 | 0 | 5 |
| EV-010 Production data store ACL export | Stale | 2 | 1 | 1 | 1 | 5 |
| EV-014 Privileged account list vs admin group membership | Effective | 2 | 1 | 1 | 1 | 5 |
| EV-016 Dormant account report (45 days), October 2026 | Effective | 1 | 1 | 1 | 2 | 5 |
| EV-019 MDM compliance policy export | Effective | 2 | 0 | 1 | 2 | 5 |
| EV-015 IdP password policy export | Effective | 1 | 1 | 1 | 1 | 4 |
| EV-025 DNS filtering and email gateway policy export | Effective | 1 | 1 | 0 | 2 | 4 |
| EV-028 Production database restore test | Stale | 1 | 1 | 1 | 1 | 4 |
| EV-037 Badge access review and visitor log, Q3 2026 | Effective | 2 | 1 | 1 | 0 | 4 |
| EV-040 Obligations register (PIPEDA, PCI DSS, contracts), H2 2026 | Effective | 3 | 0 | 1 | 0 | 4 |
| EV-034 Background check sample (15 hires) | Effective | 1 | 1 | 1 | 0 | 3 |
| EV-038 DLP incident report, Q3 2026 | Effective | 0 | 0 | 0 | 0 | 0 |

## Gaps by framework

### ISO/IEC 27001:2022 (68 gaps)

| Requirement | Status | Mapped controls | Why |
|---|---|---|---|
| A.5.15 Access control | Deficient | CTL-DAT-03 (partial), CTL-IAM-02 (partial) | Mapped control failed testing: CTL-IAM-02. |
| A.5.18 Access rights | Deficient | CTL-IAM-01, CTL-IAM-02 | Mapped control failed testing: CTL-IAM-02. |
| A.5.29 Information security during disruption | Evidence stale | CTL-BCP-01 | Evidence for every mapped control is outside its validity window. |
| A.5.30 ICT readiness for business continuity | Evidence stale | CTL-BCP-01 | Evidence for every mapped control is outside its validity window. |
| A.8.3 Information access restriction | Evidence stale | CTL-DAT-03 | Evidence for every mapped control is outside its validity window. |
| A.5.19 Information security in supplier relationships | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| A.5.20 Addressing information security within supplier agreements | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| A.5.21 Managing information security in the ICT supply chain | Not tested | CTL-TPR-01 (partial) | Evidence exists but has not been tested yet. |
| A.5.22 Monitoring, review and change management of supplier services | Not tested | CTL-TPR-01 (partial) | Evidence exists but has not been tested yet. |
| A.5.23 Information security for use of cloud services | Not tested | CTL-TPR-01 (partial) | Evidence exists but has not been tested yet. |
| 5.1 Leadership and commitment | Unmapped | - | No common control is mapped to this requirement. |
| 7.1 Resources | Unmapped | - | No common control is mapped to this requirement. |
| 7.4 Communication | Unmapped | - | No common control is mapped to this requirement. |
| 7.5.1 Documented information: general | Unmapped | - | No common control is mapped to this requirement. |
| 8.1 Operational planning and control | Unmapped | - | No common control is mapped to this requirement. |
| 9.1 Monitoring, measurement, analysis and evaluation | Unmapped | - | No common control is mapped to this requirement. |
| 10.1 Continual improvement | Unmapped | - | No common control is mapped to this requirement. |
| A.5.3 Segregation of duties | Unmapped | - | No common control is mapped to this requirement. |
| A.5.5 Contact with authorities | Unmapped | - | No common control is mapped to this requirement. |
| A.5.6 Contact with special interest groups | Unmapped | - | No common control is mapped to this requirement. |
| A.5.7 Threat intelligence | Unmapped | - | No common control is mapped to this requirement. |
| A.5.8 Information security in project management | Unmapped | - | No common control is mapped to this requirement. |
| A.5.10 Acceptable use of information and other associated assets | Unmapped | - | No common control is mapped to this requirement. |
| A.5.28 Collection of evidence | Unmapped | - | No common control is mapped to this requirement. |
| A.5.36 Compliance with policies, rules and standards for information security | Unmapped | - | No common control is mapped to this requirement. |
| A.5.37 Documented operating procedures | Unmapped | - | No common control is mapped to this requirement. |
| A.6.2 Terms and conditions of employment | Unmapped | - | No common control is mapped to this requirement. |
| A.6.4 Disciplinary process | Unmapped | - | No common control is mapped to this requirement. |
| A.6.6 Confidentiality or non-disclosure agreements | Unmapped | - | No common control is mapped to this requirement. |
| A.6.7 Remote working | Unmapped | - | No common control is mapped to this requirement. |
| A.7.3 Securing offices, rooms and facilities | Unmapped | - | No common control is mapped to this requirement. |
| A.7.5 Protecting against physical and environmental threats | Unmapped | - | No common control is mapped to this requirement. |
| A.7.6 Working in secure areas | Unmapped | - | No common control is mapped to this requirement. |
| A.7.8 Equipment siting and protection | Unmapped | - | No common control is mapped to this requirement. |
| A.7.9 Security of assets off-premises | Unmapped | - | No common control is mapped to this requirement. |
| A.7.10 Storage media | Unmapped | - | No common control is mapped to this requirement. |
| A.7.11 Supporting utilities | Unmapped | - | No common control is mapped to this requirement. |
| A.7.12 Cabling security | Unmapped | - | No common control is mapped to this requirement. |
| A.7.13 Equipment maintenance | Unmapped | - | No common control is mapped to this requirement. |
| A.8.6 Capacity management | Unmapped | - | No common control is mapped to this requirement. |
| A.8.11 Data masking | Unmapped | - | No common control is mapped to this requirement. |
| A.8.12 Data leakage prevention | Unmapped | - | No common control is mapped to this requirement. |
| A.8.14 Redundancy of information processing facilities | Unmapped | - | No common control is mapped to this requirement. |
| A.8.26 Application security requirements | Unmapped | - | No common control is mapped to this requirement. |
| A.8.27 Secure system architecture and engineering principles | Unmapped | - | No common control is mapped to this requirement. |
| A.8.31 Separation of development, test and production environments | Unmapped | - | No common control is mapped to this requirement. |
| A.8.33 Test information | Unmapped | - | No common control is mapped to this requirement. |
| A.8.34 Protection of information systems during audit testing | Unmapped | - | No common control is mapped to this requirement. |
| 6.1.1 Actions to address risks and opportunities: general | Partial | CTL-GOV-04 (partial) | Only partial-strength controls are effective. |
| 6.3 Planning of changes | Partial | CTL-CHG-01 (partial) | Only partial-strength controls are effective. |
| 7.2 Competence | Partial | CTL-HR-01 (partial) | Only partial-strength controls are effective. |
| 7.5.2 Creating and updating documented information | Partial | CTL-GOV-01 (partial) | Only partial-strength controls are effective. |
| 7.5.3 Control of documented information | Partial | CTL-GOV-01 (partial) | Only partial-strength controls are effective. |
| 10.2 Nonconformity and corrective action | Partial | CTL-GOV-03 (partial) | Only partial-strength controls are effective. |
| A.5.4 Management responsibilities | Partial | CTL-GOV-02 (partial) | Only partial-strength controls are effective. |
| A.5.11 Return of assets | Partial | CTL-AST-01 (partial) | Only partial-strength controls are effective. |
| A.5.14 Information transfer | Partial | CTL-CRY-01 (partial) | Only partial-strength controls are effective. |
| A.5.27 Learning from information security incidents | Partial | CTL-IR-01 (partial) | Only partial-strength controls are effective. |
| A.5.33 Protection of records | Partial | CTL-DAT-02 (partial) | Only partial-strength controls are effective. |
| A.5.34 Privacy and protection of PII | Partial | CTL-GOV-05 (partial) | Only partial-strength controls are effective. |
| A.5.35 Independent review of information security | Partial | CTL-GOV-03 (partial), CTL-VUL-02 (partial) | Only partial-strength controls are effective. |
| A.6.5 Responsibilities after termination or change of employment | Partial | CTL-IAM-01 (partial) | Only partial-strength controls are effective. |
| A.6.8 Information security event reporting | Partial | CTL-LOG-02 (partial) | Only partial-strength controls are effective. |
| A.7.7 Clear desk and clear screen | Partial | CTL-CFG-03 (partial) | Only partial-strength controls are effective. |
| A.8.4 Access to source code | Partial | CTL-SDL-01 (partial) | Only partial-strength controls are effective. |
| A.8.18 Use of privileged utility programs | Partial | CTL-IAM-04 (partial) | Only partial-strength controls are effective. |
| A.8.21 Security of network services | Partial | CTL-NET-01 (partial) | Only partial-strength controls are effective. |
| A.8.29 Security testing in development and acceptance | Partial | CTL-VUL-02 (partial), CTL-SDL-01 (partial) | Only partial-strength controls are effective. |

Excluded: A.5.32 (no justification); A.7.4 (No data centre; production is hosted in a cloud region.); A.8.30 (No outsourced development; all software is built by employees.)

### SOC 2 (TSC 2017) (20 gaps)

| Requirement | Status | Mapped controls | Why |
|---|---|---|---|
| CC6.2 Users registered and authorised before access is granted | Deficient | CTL-IAM-01, CTL-IAM-02 (partial), CTL-IAM-06 (partial) | Mapped control failed testing: CTL-IAM-02. |
| CC6.3 Access modified and removed; least privilege and segregation | Deficient | CTL-IAM-01 (partial), CTL-IAM-02, CTL-IAM-04 (partial) | Mapped control failed testing: CTL-IAM-02. |
| A1.3 Recovery plan procedures tested | Evidence stale | CTL-BCK-02 (partial), CTL-BCP-01 | Evidence for every mapped control is outside its validity window. |
| CC9.2 Vendor and business partner risk managed | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| CC1.1 Commitment to integrity and ethical values | Unmapped | - | No common control is mapped to this requirement. |
| CC1.5 Individuals held accountable for internal control | Unmapped | - | No common control is mapped to this requirement. |
| CC2.1 Relevant, quality information supports internal control | Unmapped | - | No common control is mapped to this requirement. |
| CC2.3 Communication with external parties | Unmapped | - | No common control is mapped to this requirement. |
| CC5.1 Control activities selected and developed | Unmapped | - | No common control is mapped to this requirement. |
| A1.1 Capacity managed to meet objectives | Unmapped | - | No common control is mapped to this requirement. |
| CC1.2 Board independence and oversight of internal control | Partial | CTL-GOV-03 (partial) | Only partial-strength controls are effective. |
| CC1.4 Commitment to attract, develop and retain competent people | Partial | CTL-HR-01 (partial), CTL-HR-02 (partial) | Only partial-strength controls are effective. |
| CC2.2 Internal communication of objectives and responsibilities | Partial | CTL-GOV-01 (partial), CTL-HR-01 (partial) | Only partial-strength controls are effective. |
| CC3.1 Objectives specified clearly enough to identify risks | Partial | CTL-GOV-04 (partial), CTL-RSK-01 (partial) | Only partial-strength controls are effective. |
| CC3.3 Potential for fraud considered | Partial | CTL-RSK-01 (partial) | Only partial-strength controls are effective. |
| CC3.4 Significant changes identified and assessed | Partial | CTL-CHG-01 (partial) | Only partial-strength controls are effective. |
| CC5.2 General controls over technology | Partial | CTL-CFG-01 (partial) | Only partial-strength controls are effective. |
| CC6.1 Logical access security over protected information assets | Partial | CTL-AST-01 (partial), CTL-DAT-03 (partial), CTL-IAM-03 (partial), CTL-IAM-05 (partial), CTL-CRY-01 (partial) | Only partial-strength controls are effective. |
| CC7.5 Recovery from identified incidents | Partial | CTL-BCP-01 (partial), CTL-IR-01 (partial) | Only partial-strength controls are effective. |
| CC9.1 Risk mitigation for business disruption | Partial | CTL-RSK-02 (partial), CTL-BCP-01 | Only partial-strength controls are effective; full-strength control(s) CTL-BCP-01 are stale. |

### NIST CSF 2.0 (73 gaps)

| Requirement | Status | Mapped controls | Why |
|---|---|---|---|
| PR.AA-05 Identity Management, Authentication, and Access Control | Deficient | CTL-DAT-03 (partial), CTL-IAM-02, CTL-IAM-04 (partial) | Mapped control failed testing: CTL-IAM-02. |
| PR.IR-03 Technology Infrastructure Resilience | Evidence stale | CTL-BCP-01 (partial) | Evidence for every mapped control is outside its validity window. |
| RC.RP-01 Incident Recovery Plan Execution | Evidence stale | CTL-BCP-01 | Evidence for every mapped control is outside its validity window. |
| RC.RP-03 Incident Recovery Plan Execution | Evidence stale | CTL-BCK-02 | Evidence for every mapped control is outside its validity window. |
| GV.SC-05 Cybersecurity Supply Chain Risk Management | Not tested | CTL-TPR-01 (partial) | Evidence exists but has not been tested yet. |
| GV.SC-06 Cybersecurity Supply Chain Risk Management | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| GV.SC-07 Cybersecurity Supply Chain Risk Management | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| GV.OC-04 Organizational Context | Unmapped | - | No common control is mapped to this requirement. |
| GV.OC-05 Organizational Context | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-01 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-03 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-04 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-05 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-06 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RM-07 Risk Management Strategy | Unmapped | - | No common control is mapped to this requirement. |
| GV.RR-03 Roles, Responsibilities, and Authorities | Unmapped | - | No common control is mapped to this requirement. |
| GV.OV-03 Oversight | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-01 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-02 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-03 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-04 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-08 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-09 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| GV.SC-10 Cybersecurity Supply Chain Risk Management | Unmapped | - | No common control is mapped to this requirement. |
| ID.AM-03 Asset Management | Unmapped | - | No common control is mapped to this requirement. |
| ID.AM-04 Asset Management | Unmapped | - | No common control is mapped to this requirement. |
| ID.AM-05 Asset Management | Unmapped | - | No common control is mapped to this requirement. |
| ID.AM-08 Asset Management | Unmapped | - | No common control is mapped to this requirement. |
| ID.RA-02 Risk Assessment | Unmapped | - | No common control is mapped to this requirement. |
| ID.RA-09 Risk Assessment | Unmapped | - | No common control is mapped to this requirement. |
| ID.RA-10 Risk Assessment | Unmapped | - | No common control is mapped to this requirement. |
| ID.IM-03 Improvement | Unmapped | - | No common control is mapped to this requirement. |
| PR.AA-02 Identity Management, Authentication, and Access Control | Unmapped | - | No common control is mapped to this requirement. |
| PR.AA-04 Identity Management, Authentication, and Access Control | Unmapped | - | No common control is mapped to this requirement. |
| PR.AT-02 Awareness and Training | Unmapped | - | No common control is mapped to this requirement. |
| PR.DS-10 Data Security | Unmapped | - | No common control is mapped to this requirement. |
| PR.PS-03 Platform Security | Unmapped | - | No common control is mapped to this requirement. |
| PR.IR-02 Technology Infrastructure Resilience | Unmapped | - | No common control is mapped to this requirement. |
| PR.IR-04 Technology Infrastructure Resilience | Unmapped | - | No common control is mapped to this requirement. |
| DE.CM-02 Continuous Monitoring | Unmapped | - | No common control is mapped to this requirement. |
| DE.CM-06 Continuous Monitoring | Unmapped | - | No common control is mapped to this requirement. |
| DE.AE-04 Adverse Event Analysis | Unmapped | - | No common control is mapped to this requirement. |
| DE.AE-07 Adverse Event Analysis | Unmapped | - | No common control is mapped to this requirement. |
| DE.AE-08 Adverse Event Analysis | Unmapped | - | No common control is mapped to this requirement. |
| RS.MA-02 Incident Management | Unmapped | - | No common control is mapped to this requirement. |
| RS.MA-03 Incident Management | Unmapped | - | No common control is mapped to this requirement. |
| RS.MA-04 Incident Management | Unmapped | - | No common control is mapped to this requirement. |
| RS.MA-05 Incident Management | Unmapped | - | No common control is mapped to this requirement. |
| RS.AN-03 Incident Analysis | Unmapped | - | No common control is mapped to this requirement. |
| RS.AN-06 Incident Analysis | Unmapped | - | No common control is mapped to this requirement. |
| RS.AN-07 Incident Analysis | Unmapped | - | No common control is mapped to this requirement. |
| RS.AN-08 Incident Analysis | Unmapped | - | No common control is mapped to this requirement. |
| RS.CO-03 Incident Response Reporting and Communication | Unmapped | - | No common control is mapped to this requirement. |
| RS.MI-01 Incident Mitigation | Unmapped | - | No common control is mapped to this requirement. |
| RS.MI-02 Incident Mitigation | Unmapped | - | No common control is mapped to this requirement. |
| RC.RP-02 Incident Recovery Plan Execution | Unmapped | - | No common control is mapped to this requirement. |
| RC.RP-04 Incident Recovery Plan Execution | Unmapped | - | No common control is mapped to this requirement. |
| RC.RP-05 Incident Recovery Plan Execution | Unmapped | - | No common control is mapped to this requirement. |
| RC.RP-06 Incident Recovery Plan Execution | Unmapped | - | No common control is mapped to this requirement. |
| RC.CO-03 Incident Recovery Communication | Unmapped | - | No common control is mapped to this requirement. |
| RC.CO-04 Incident Recovery Communication | Unmapped | - | No common control is mapped to this requirement. |
| GV.OC-02 Organizational Context | Partial | CTL-GOV-04 (partial) | Only partial-strength controls are effective. |
| GV.RM-02 Risk Management Strategy | Partial | CTL-RSK-02 (partial) | Only partial-strength controls are effective. |
| GV.RR-01 Roles, Responsibilities, and Authorities | Partial | CTL-GOV-02 (partial) | Only partial-strength controls are effective. |
| GV.OV-02 Oversight | Partial | CTL-GOV-03 (partial) | Only partial-strength controls are effective. |
| ID.RA-03 Risk Assessment | Partial | CTL-RSK-01 (partial) | Only partial-strength controls are effective. |
| ID.RA-04 Risk Assessment | Partial | CTL-RSK-01 (partial) | Only partial-strength controls are effective. |
| ID.RA-08 Risk Assessment | Partial | CTL-VUL-01 (partial) | Only partial-strength controls are effective. |
| ID.IM-01 Improvement | Partial | CTL-GOV-03 (partial) | Only partial-strength controls are effective. |
| PR.PS-05 Platform Security | Partial | CTL-CFG-02 (partial) | Only partial-strength controls are effective. |
| DE.CM-03 Continuous Monitoring | Partial | CTL-LOG-02 (partial) | Only partial-strength controls are effective. |
| DE.AE-03 Adverse Event Analysis | Partial | CTL-LOG-02 (partial) | Only partial-strength controls are effective. |
| RS.CO-02 Incident Response Reporting and Communication | Partial | CTL-IR-01 (partial) | Only partial-strength controls are effective. |

### CIS Controls v8.1 (10 gaps)

| Requirement | Status | Mapped controls | Why |
|---|---|---|---|
| CIS 5.1 (Account Management) | Deficient | CTL-IAM-02 (partial), CTL-IAM-06 | Mapped control failed testing: CTL-IAM-02. |
| CIS 5.3 (Account Management) | Deficient | CTL-IAM-02 (partial), CTL-IAM-06 | Mapped control failed testing: CTL-IAM-02. |
| CIS 3.3 (Data Protection) | Evidence stale | CTL-DAT-03 | Evidence for every mapped control is outside its validity window. |
| CIS 15.1 (Service Provider Management) | Not tested | CTL-TPR-01 | Evidence exists but has not been tested yet. |
| CIS 12.1 (Network Infrastructure Management) | Unmapped | - | No common control is mapped to this requirement. |
| CIS 3.2 (Data Protection) | Partial | CTL-DAT-01 (partial) | Only partial-strength controls are effective. |
| CIS 9.1 (Email and Web Browser Protections) | Partial | CTL-NET-02 (partial) | Only partial-strength controls are effective. |
| CIS 11.1 (Data Recovery) | Partial | CTL-BCK-01 (partial), CTL-BCK-02 (partial) | Only partial-strength controls are effective. |
| CIS 14.7 (Security Awareness and Skills Training) | Partial | CTL-HR-01 (partial) | Only partial-strength controls are effective. |
| CIS 14.8 (Security Awareness and Skills Training) | Partial | CTL-HR-01 (partial) | Only partial-strength controls are effective. |

## Data-quality findings

| Severity | Rule | Where | Finding |
|---|---|---|---|
| High | `EXCLUSION_NOT_JUSTIFIED` | ISO27001 A.5.32 | A.5.32 is excluded without a justification. |
| High | `UNKNOWN_CONTROL` | evidence.csv:41 | EV-038 supports control CTL-DLP-01, which is not defined. |
| High | `UNKNOWN_REQUIREMENT` | mappings.csv:104 | CSF2 'PR.AC-7' is not in the catalog: PR.AC is a CSF 1.1 category that CSF 2.0 removed; remap to the 2.0 subcategory. |
| High | `UNKNOWN_REQUIREMENT` | mappings.csv:113 | CIS8 '5.7' is not in the catalog: CIS Control 5 has safeguards 5.1-5.6 in v8.1. |
| High | `UNKNOWN_REQUIREMENT` | mappings.csv:124 | ISO27001 '8.9' is not in the catalog: clause 8.9 does not exist; did you mean Annex A control A.8.9? |
| High | `UNKNOWN_REQUIREMENT` | mappings.csv:166 | ISO27001 'A.12.4.1' is not in the catalog: looks like ISO/IEC 27001:2013 numbering; map it to the 2022 control. |
| Medium | `CONTROL_NO_EVIDENCE` | CTL-LEG-01 | Control CTL-LEG-01 has no evidence in the register. |
| Medium | `CONTROL_NO_OWNER` | controls.csv:42 | Control CTL-LEG-01 has no owner; nobody is accountable for its evidence. |
| Medium | `CONTROL_UNMAPPED` | CTL-LEG-01 | Control CTL-LEG-01 maps to no framework requirement; its testing earns no credit. |
| Medium | `EXCLUDED_BUT_OPERATING` | ISO27001 A.7.4 | A.7.4 is excluded from scope, yet a fully mapped control operates effectively. Check the justification (ISO 27001 6.1.3 d). |
| Medium | `FUTURE_DATE` | EV-030 | EV-030 is dated 2026-11-20, after the assessment date. |
| Low | `DUPLICATE_MAPPING` | mappings.csv:155 | CTL-VUL-01 -> CIS8 7.1 already mapped on line 151. |

---
*Generated by the control crosswalk engine. The mappings are the organisation's own judgement; this report checks their consistency and the evidence behind them, not their authority. Framework titles are short labels, not the standards' text.*

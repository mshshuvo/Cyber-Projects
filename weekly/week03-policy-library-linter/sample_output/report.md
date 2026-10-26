# Policy library lint report — Maple Ridge Credit Union (fictional)

Assessment date: **2026-10-25**  ·  Documents: **10**  ·  Health score: **53/100**

## Summary

| Measure | Value |
|---|---|
| Documents by status | approved: 8, draft: 1, retired: 1 |
| Approved documents within review cycle | 88% |
| Approved documents overdue for review | 1 |
| ISO/IEC 27001:2022 Annex A controls mapped by an approved document | 29 of 93 |
| Findings | High 9, Medium 12, Low 10 |
| Suppressed by inline directive | 2 |

## Findings by rule

| Severity | Rule | Count |
|---|---|---|
| High | `DUPLICATE_ID` | 2 |
| High | `BROKEN_LINK` | 1 |
| High | `BROKEN_REFERENCE` | 1 |
| High | `MISSING_OWNER` | 1 |
| High | `OWNER_VACANT` | 1 |
| High | `REVIEW_OVERDUE` | 1 |
| High | `UNAPPROVED_CHANGE` | 1 |
| High | `VERSION_DRIFT` | 1 |
| Medium | `REFERENCE_TO_RETIRED` | 2 |
| Medium | `BROKEN_ANCHOR` | 1 |
| Medium | `CONFLICTING_DEFINITION` | 1 |
| Medium | `DUPLICATE_TERM` | 1 |
| Medium | `INVALID_CONTROL_REF` | 1 |
| Medium | `MISSING_SECTION` | 1 |
| Medium | `NO_REVISION_HISTORY` | 1 |
| Medium | `OWNER_NOT_IN_REGISTER` | 1 |
| Medium | `PLACEHOLDER_TEXT` | 1 |
| Medium | `SELF_APPROVED` | 1 |
| Medium | `STALE_PINNED_REFERENCE` | 1 |
| Low | `UNDEFINED_TERM` | 5 |
| Low | `HISTORY_ORDER` | 1 |
| Low | `PLACEHOLDER_TEXT` | 1 |
| Low | `REFERENCE_TO_DRAFT` | 1 |
| Low | `REVIEW_DUE_SOON` | 1 |
| Low | `STALE_DRAFT` | 1 |

## Review calendar

| Id | Title | Owner | Version | Next review | Days |
|---|---|---|---|---|---|
| STD-CR-001 | Cryptography Standard | Security Architect | 1.4 | 2026-06-30 | **-117** (overdue) |
| POL-BC-001 | Business Continuity Policy | Head of Business Continuity | 1.3 | 2026-11-20 | 26 |
| POL-AU-001 | Acceptable Use Policy | Head of HR | 1.1 | 2027-01-08 | 75 |
| POL-IS-001 | Information Security Policy | CISO | 3.0 | 2027-02-10 | 108 |
| POL-AC-001 | Access Control Policy | Head of IT Operations | 2.1 | 2027-03-14 | 140 |
| STD-CR-001 | Logging and Monitoring Standard | CISO | 1.1 | 2027-04-01 | 158 |
| POL-IR-001 | Incident Response Policy | Incident Response Manager | 2.0 | 2027-04-22 | 179 |
| POL-TP-001 | Third-Party Risk Management Policy | Vendor Manager | 1.0 | 2027-05-12 | 199 |

## Findings

| Severity | Location | Rule | Detail |
|---|---|---|---|
| High | `access-control-policy.md:4` | `VERSION_DRIFT` | Front matter says v2.1 but the revision history ends at v2.2 (line 66). |
| High | `access-control-policy.md:66` | `UNAPPROVED_CHANGE` | v2.2 is dated 2026-07-03, after the last approval on 2026-03-14; the text in force has not been approved. |
| High | `business-continuity-policy.md:28` | `BROKEN_LINK` | Link 'BIA procedure' points to 'procedures/bia-procedure.md', which does not exist. |
| High | `cryptography-standard.md:2` | `DUPLICATE_ID` | Id STD-CR-001 is used by 2 documents (cryptography-standard.md, logging-monitoring-standard.md); references are ambiguous. |
| High | `cryptography-standard.md:6` | `OWNER_VACANT` | Owner role 'Security Architect' is vacant; the document is effectively unowned. |
| High | `cryptography-standard.md:9` | `REVIEW_OVERDUE` | Review was due 2026-06-30 (117 days overdue). |
| High | `data-classification-policy.md:1` | `MISSING_OWNER` | No owner; nobody is accountable for keeping this document current (ISO 27001 5.3, A.5.1). |
| High | `incident-response-policy.md:39` | `BROKEN_REFERENCE` | References POL-VM-002, which is not in the library. |
| High | `logging-monitoring-standard.md:2` | `DUPLICATE_ID` | Id STD-CR-001 is used by 2 documents (cryptography-standard.md, logging-monitoring-standard.md); references are ambiguous. |
| Medium | `acceptable-use-policy.md:1` | `MISSING_SECTION` | No 'Exceptions' section. |
| Medium | `acceptable-use-policy.md:7` | `SELF_APPROVED` | Owner and approver are both 'Head of HR'; approval is not independent. |
| Medium | `acceptable-use-policy.md:30` | `REFERENCE_TO_RETIRED` | Relies on POL-RA-001 (Remote Access Policy), which is retired. |
| Medium | `acceptable-use-policy.md:31` | `PLACEHOLDER_TEXT` | Unfinished text '[Insert helpdesk extension]'. |
| Medium | `access-control-policy.md:12` | `INVALID_CONTROL_REF` | 'A.9.2.3' is not an ISO/IEC 27001:2022 Annex A control (2013 numbering, or a typo?). |
| Medium | `access-control-policy.md:34` | `REFERENCE_TO_RETIRED` | Relies on POL-RA-001 (Remote Access Policy), which is retired. |
| Medium | `glossary.md:29` | `DUPLICATE_TERM` | Glossary defines 'Information Asset' more than once. |
| Medium | `incident-response-policy.md:29` | `CONFLICTING_DEFINITION` | Defines 'Security Incident' differently from the glossary. Here: "Any alert raised by the security monitoring platform." Glossary: "An event that actually or potentially compromises the confidentiality," |
| Medium | `incident-response-policy.md:34` | `BROKEN_ANCHOR` | Link 'escalation matrix' points to section '#escalation-matix', which does not exist in incident-response-policy.md. |
| Medium | `incident-response-policy.md:38` | `STALE_PINNED_REFERENCE` | Cites POL-BC-001 v1.0 but the current version is v1.3. |
| Medium | `third-party-risk-policy.md:1` | `NO_REVISION_HISTORY` | No revision history table; changes to the document cannot be traced (ISO 27001 7.5.3). |
| Medium | `third-party-risk-policy.md:6` | `OWNER_NOT_IN_REGISTER` | Owner 'Vendor Manager' is not a role in the owner register. |
| Low | `access-control-policy.md:31` | `UNDEFINED_TERM` | Acronym 'PAM' is used but not expanded here or defined in the glossary. |
| Low | `access-control-policy.md:66` | `UNDEFINED_TERM` | Acronym 'SLA' is used but not expanded here or defined in the glossary. |
| Low | `business-continuity-policy.md:9` | `REVIEW_DUE_SOON` | Review due 2026-11-20 (in 26 days). |
| Low | `business-continuity-policy.md:54` | `HISTORY_ORDER` | Revision history versions are not in strictly increasing order. |
| Low | `cryptography-standard.md:31` | `UNDEFINED_TERM` | Acronym 'KMS' is used but not expanded here or defined in the glossary. |
| Low | `data-classification-policy.md:1` | `STALE_DRAFT` | Draft not updated since 2026-03-20 (219 days); approve it or withdraw it. |
| Low | `data-classification-policy.md:27` | `PLACEHOLDER_TEXT` | Unfinished text 'TBD'. |
| Low | `data-classification-policy.md:27` | `UNDEFINED_TERM` | Acronym 'FINTRAC' is used but not expanded here or defined in the glossary. |
| Low | `information-security-policy.md:33` | `REFERENCE_TO_DRAFT` | Relies on POL-DC-001 (Data Classification and Handling Policy), which is still a draft. |
| Low | `logging-monitoring-standard.md:28` | `UNDEFINED_TERM` | Acronym 'SIEM' is used but not expanded here or defined in the glossary. |

---
*Generated by policy_linter. Severity reflects audit impact: High = a nonconformity an auditor would likely raise; Medium = weakens the control; Low = hygiene.*

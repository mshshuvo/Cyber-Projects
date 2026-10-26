---
id: POL-AC-001
title: Access Control Policy
version: 2.1
status: approved
owner: Head of IT Operations
approver: CISO
approved_on: 2026-03-14
last_reviewed: 2026-03-14
review_cycle_months: 12
classification: Internal
iso27001: [A.5.15, A.5.18, A.8.2, A.9.2.3]
---

# Access Control Policy

## Purpose

To make sure that access to Information Assets is authorized, limited to business need and
removed promptly when no longer required.

## Scope

All user, service and Privileged Accounts on credit union systems, including core banking,
online banking and cloud services.

## Policy statements

1. Access is requested through the IT service desk and approved by the asset owner.
2. MFA is required for all remote access and for every Privileged Account.
3. Privileged sessions are brokered and recorded by the PAM platform.
4. User access is recertified quarterly for critical systems and semi-annually for all others.
5. Leavers' access is removed within one business day; see the [leaver process](#leaver-process).
6. Remote access must also meet the Remote Access Policy (POL-RA-001).

### Leaver process

HR notifies IT on or before the last working day. IT disables the account the same day and
removes group memberships within one business day.

## Roles and responsibilities

- **Head of IT Operations** owns this policy and runs provisioning.
- **Asset owners** approve access and complete recertifications.
- **CISO** approves this policy and monitors compliance.

## Compliance

Access recertification results are reported to the CISO each quarter.

## Exceptions

Exceptions follow the process in the Information Security Policy (POL-IS-001 v3.0).

## Review

Reviewed annually by the owner.

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2024-03-01 | Head of IT Operations | First issue |
| 2.0 | 2025-03-10 | Head of IT Operations | Quarterly recertification for critical systems |
| 2.1 | 2026-03-14 | Head of IT Operations | Annual review; MFA for all remote access |
| 2.2 | 2026-07-03 | Head of IT Operations | Leaver SLA changed from same day to one business day |

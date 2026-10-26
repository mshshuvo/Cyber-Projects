---
id: POL-IR-001
title: Incident Response Policy
version: 2.0
status: approved
owner: Incident Response Manager
approver: CISO
approved_on: 2026-04-22
last_reviewed: 2026-04-22
review_cycle_months: 12
classification: Internal
iso27001: [A.5.24, A.5.25, A.5.26, A.5.27, A.5.28, A.6.8]
---

# Incident Response Policy

## Purpose

To detect, contain and recover from Security Incidents quickly, and to meet regulatory
reporting duties.

## Scope

All Security Incidents affecting credit union Information Assets or member data, including
those at third parties.

## Definitions

- **Security Incident**: Any alert raised by the security monitoring platform.

## Policy statements

1. All staff report suspected Security Incidents to the service desk immediately.
2. Incidents are triaged and classified within one hour, using the [escalation matrix](#escalation-matix).
3. Material technology or cyber incidents are reported to OSFI within 24 hours.
4. Breaches of security safeguards involving Personal Information are assessed for a real
   risk of significant harm and reported under PIPEDA where required.
5. Recovery follows the Business Continuity Policy (POL-BC-001 v1.0).
6. Vulnerabilities found during an incident are handed to the vulnerability management process (POL-VM-002).

### Escalation matrix

| Severity | Notify | Within |
|---|---|---|
| Critical | CISO, CRO, CEO | 30 minutes |
| High | CISO | 1 hour |
| Medium | Incident Response Manager | 4 hours |

## Roles and responsibilities

- **Incident Response Manager** owns this policy and leads response.
- **CISO** decides on regulatory notification with the CRO.

## Compliance

Every Critical and High incident has a post-incident review within 10 business days.

## Exceptions

None permitted for regulatory reporting timelines.

## Review

Reviewed annually and after every Critical incident.

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2024-04-15 | Incident Response Manager | First issue |
| 2.0 | 2026-04-22 | Incident Response Manager | OSFI 24-hour reporting |

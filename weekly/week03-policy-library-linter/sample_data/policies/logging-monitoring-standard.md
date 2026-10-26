---
id: STD-CR-001
title: Logging and Monitoring Standard
version: 1.1
status: approved
owner: CISO
approver: Chief Risk Officer
approved_on: 2026-04-01
last_reviewed: 2026-04-01
next_review: 2027-04-01
classification: Internal
iso27001: [A.8.15, A.8.16, A.8.17]
---

# Logging and Monitoring Standard

## Purpose

To make sure security events are recorded, retained and reviewed so that Security Incidents
are detected.

## Scope

All production systems, network devices and cloud services.

## Standard

1. Security logs are sent to the SIEM within five minutes.
2. Logs are retained for at least 13 months, with 90 days searchable online.
3. Clocks are synchronized to the approved time source.
4. Alerts are handled under the Incident Response Policy (POL-IR-001 v2.0).

## Roles and responsibilities

- **CISO** owns this standard.
- **Security operations** reviews alerts around the clock.

## Compliance

Log source coverage is reported monthly.

## Exceptions

Exceptions follow the Information Security Policy (POL-IS-001).

## Review

Reviewed annually.

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2025-04-01 | CISO | First issue |
| 1.1 | 2026-04-01 | CISO | 13-month retention |

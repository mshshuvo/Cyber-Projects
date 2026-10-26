---
id: STD-CR-001
title: Cryptography Standard
version: 1.4
status: approved
owner: Security Architect
approver: CISO
approved_on: 2025-06-30
last_reviewed: 2025-06-30
review_cycle_months: 12
classification: Internal
iso27001: [A.8.24]
---

# Cryptography Standard

## Purpose

Defines the approved algorithms, key lengths and key management practices for protecting
credit union information.

## Scope

All systems that encrypt, sign or hash credit union or member data.

## Standard

1. Data in transit uses TLS 1.2 or later; TLS 1.3 is preferred.
2. Data at rest uses AES-256.
3. Card and authentication keys are generated and stored in a Hardware Security Module (HSM).
4. Cloud keys are held in the provider KMS with customer-managed keys and annual rotation.
5. MD5 and SHA-1 must not be used for any security purpose.

## Roles and responsibilities

- **Security Architect** owns this standard and the approved algorithm list.
- **IT Operations** implements key rotation.

## Compliance

Configuration is checked by the quarterly TLS and encryption scan.

## Exceptions

Exceptions follow the Information Security Policy (POL-IS-001).

## Review

Reviewed annually and whenever an algorithm is deprecated.

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2022-05-01 | Security Architect | First issue |
| 1.4 | 2025-06-30 | Security Architect | Removed TLS 1.1; added cloud KMS |

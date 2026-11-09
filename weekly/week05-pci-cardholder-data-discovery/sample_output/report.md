# Cardholder data discovery report

**Scope:** `sample_data/fileshare`  
**As of:** 2026-11-08  
**Standard:** PCI DSS v4.0.1, Requirement 3 (protect stored account data) and 12.5.2 (scope)

## Summary

- Files: 15 on disk, 16 documents scanned (archive members and Office parts included), 96 lines
- Findings: 36  (Critical 12, High 19, Medium 5)  |  suppressed 3  |  coverage gaps 1
- Unique PANs exposed: 14 across 10 locations (all are published test numbers)
- Prohibited SAD hits (3.3.1): 12   Correctly masked PANs seen: 5

> **Sensitive authentication data is stored.** PCI DSS 3.3.1 prohibits storing track data, card verification codes and PINs after authorisation, even encrypted. Treat each Critical location as an incident: contain, find the writing process, securely delete, and assess whether it indicates a compromise.

## Remediation plan by location

| # | Severity | Location | Type | Hits | Unique PANs | Action |
|---|---|---|---|---|---|---|
| 1 | Critical | `finance/chargebacks_2026Q3.csv` | Office document / spreadsheet | 5 CVV, 5 PAN | 5 | Find the business process that needs a spreadsheet of card numbers and replace it with a token or the last four digits. Delete the file and any copies in email and sync folders. |
| 2 | Critical | `app_logs/checkout-api.log` | Application / system log | 2 CVV, 3 PAN | 3 | Stop the leak at source: disable request/response body logging on payment paths and add a PAN/SAD redaction filter to the logger (see `chd_scan redact`). Purge affected logs, including copies in the SIEM and log archive (10.3.x, 3.5.1). |
| 3 | Critical | `pos/store014_terminal_trace.txt` | POS / terminal output | 2 Track, 1 PIN | 2 | Track data or PIN on disk points at a terminal, middleware or debug setting. Engage the POS vendor, confirm P2PE/SRED configuration, and treat as a potential compromise indicator. |
| 4 | Critical | `support/ticket_export_2026-10.json` | Customer support / ticket / email | 1 CVV, 2 PAN | 2 | Customers paste card numbers into free text. Redact in the ticketing system, enable its PAN-masking or DLP feature, and train agents never to request card data by email or chat. |
| 5 | Critical | `app_logs/checkout-api.log.1.gz` | Application / system log | 1 CVV, 1 PAN | 1 | Stop the leak at source: disable request/response body logging on payment paths and add a PAN/SAD redaction filter to the logger (see `chd_scan redact`). Purge affected logs, including copies in the SIEM and log archive (10.3.x, 3.5.1). |
| 6 | High | `pos/offline_queue.db` | Database export / backup | 3 PAN | 3 | Find the source table. Tokenise or encrypt the column at source (3.5.1), purge exports beyond retention (3.2.1), and bring backup media into scope or out of reach. |
| 7 | High | `archive/2024_q4_refunds.zip!refunds_2024q4.csv` | Archive / legacy copy | 2 PAN | 2 | Confirm whether a retention requirement applies (3.2.1). If not, securely delete. If so, move it into the CDE and encrypt it (3.5.1). |
| 8 | High | `legacy/crm_export_2023.csv` | Archive / legacy copy | 2 PAN | 2 | Confirm whether a retention requirement applies (3.2.1). If not, securely delete. If so, move it into the CDE and encrypt it (3.5.1). |
| 9 | High | `hr/corporate_card_request_form.docx` | Office document / spreadsheet | 1 PAN | 1 | Find the business process that needs a spreadsheet of card numbers and replace it with a token or the last four digits. Delete the file and any copies in email and sync folders. |
| 10 | Medium | `db_exports/orders_2025_backup.sql` | Database export / backup | 3 PAN | 3 | Find the source table. Tokenise or encrypt the column at source (3.5.1), purge exports beyond retention (3.2.1), and bring backup media into scope or out of reach. |
| 11 | Medium | `finance/settlement_2026-10.csv` | Office document / spreadsheet | 2 Mask+ | 0 | Find the business process that needs a spreadsheet of card numbers and replace it with a token or the last four digits. Delete the file and any copies in email and sync folders. |

## PCI DSS requirements implicated

| Requirement | Findings | What it requires |
|---|---|---|
| 3.2.1 | 22 | Account data storage kept to a minimum; retention and disposal defined and applied |
| 3.3.1 | 12 | SAD is not stored after authorisation, even if encrypted |
| 3.3.1.1 | 2 | Full track data is not stored after authorisation |
| 3.3.1.2 | 9 | Card verification code is not stored after authorisation |
| 3.3.1.3 | 1 | PIN and PIN block are not stored after authorisation |
| 3.4.1 | 2 | PAN is masked when displayed (BIN and last four at most) |
| 3.5.1 | 22 | PAN is rendered unreadable anywhere it is stored |
| 10.3.x | 7 | Log files are account data locations too: protect them (10.3) and purge clear-text values (3.5.1) |
| 12.5.2 | 22 | PCI DSS scope (all locations of account data) documented and confirmed |

## Findings

Values are masked to BIN and last four (PCI DSS 3.4.1). CVV and PIN values are never recorded, only their length.

| Id | Severity | Type | Location | Masked value | Brand | Confidence | Detail |
|---|---|---|---|---|---|---|---|
| CHD-001 | Critical | Card verification code | `app_logs/checkout-api.log` line 2 | `***` |  | high | value labelled 'cvc' (3 chars) |
| CHD-002 | Critical | Card verification code | `app_logs/checkout-api.log` line 5 | `***` |  | high | value labelled 'cvc' (3 chars) |
| CHD-003 | Critical | Card verification code | `app_logs/checkout-api.log.1.gz` line 1 | `***` |  | high | value labelled 'cvc' (3 chars) |
| CHD-004 | Critical | Card verification code | `finance/chargebacks_2026Q3.csv` line 2 | `***` |  | high | column 'cvv2' (3 chars) |
| CHD-005 | Critical | Card verification code | `finance/chargebacks_2026Q3.csv` line 3 | `***` |  | high | column 'cvv2' (3 chars) |
| CHD-006 | Critical | Card verification code | `finance/chargebacks_2026Q3.csv` line 4 | `****` |  | high | column 'cvv2' (4 chars) |
| CHD-007 | Critical | Card verification code | `finance/chargebacks_2026Q3.csv` line 5 | `***` |  | high | column 'cvv2' (3 chars) |
| CHD-008 | Critical | Card verification code | `finance/chargebacks_2026Q3.csv` line 6 | `***` |  | high | column 'cvv2' (3 chars) |
| CHD-009 | Critical | Track data | `pos/store014_terminal_trace.txt` line 3 | `510510******5100` | Mastercard | high | Track 2 equivalent (PAN, expiry, service code, discretionary data) |
| CHD-010 | Critical | PIN / PIN block | `pos/store014_terminal_trace.txt` line 4 | `****************` |  | high | value labelled 'pin_block' (16 chars) |
| CHD-011 | Critical | Track data | `pos/store014_terminal_trace.txt` line 5 | `401288******1881` | Visa | high | Track 1 (PAN, name, expiry, service code, discretionary data) |
| CHD-012 | Critical | Card verification code | `support/ticket_export_2026-10.json` line 12 | `****` |  | high | value labelled 'security code' (4 chars) |
| CHD-013 | High | Clear-text PAN | `app_logs/checkout-api.log` line 2 | `424242******4242` | Visa | high | stored with SAD in the same record |
| CHD-014 | High | Clear-text PAN | `app_logs/checkout-api.log` line 5 | `222300******3222` | Mastercard | high | stored with SAD in the same record |
| CHD-015 | High | Clear-text PAN | `app_logs/checkout-api.log` line 7 | `353011******0000` | JCB | high |  |
| CHD-016 | High | Clear-text PAN | `app_logs/checkout-api.log.1.gz` line 1 | `400005******5556` | Visa | high | stored with SAD in the same record |
| CHD-017 | High | Clear-text PAN | `archive/2024_q4_refunds.zip!refunds_2024q4.csv` line 2 | `353011******0000` | JCB | high |  |
| CHD-018 | High | Clear-text PAN | `archive/2024_q4_refunds.zip!refunds_2024q4.csv` line 3 | `601111******1117` | Discover | high |  |
| CHD-019 | High | Clear-text PAN | `finance/chargebacks_2026Q3.csv` line 2 | `411111******1111` | Visa | high | stored with SAD in the same record |
| CHD-020 | High | Clear-text PAN | `finance/chargebacks_2026Q3.csv` line 3 | `555555******4444` | Mastercard | high | stored with SAD in the same record |
| CHD-021 | High | Clear-text PAN | `finance/chargebacks_2026Q3.csv` line 4 | `378282*****0005` | American Express | high | stored with SAD in the same record |
| CHD-022 | High | Clear-text PAN | `finance/chargebacks_2026Q3.csv` line 5 | `601111******1117` | Discover | high | stored with SAD in the same record |
| CHD-023 | High | Clear-text PAN | `finance/chargebacks_2026Q3.csv` line 6 | `401288******1881` | Visa | high | stored with SAD in the same record |
| CHD-024 | High | Clear-text PAN | `hr/corporate_card_request_form.docx` line 3 | `510510******5100` | Mastercard | high | grouped |
| CHD-025 | High | Clear-text PAN | `legacy/crm_export_2023.csv` line 2 | `424242******4242` | Visa | high | suppression 'legacy/*' not applied (expired 2026-06-30) |
| CHD-026 | High | Clear-text PAN | `legacy/crm_export_2023.csv` line 3 | `371449*****8431` | American Express | high | suppression 'legacy/*' not applied (expired 2026-06-30) |
| CHD-027 | High | Clear-text PAN | `pos/offline_queue.db` record 1 | `620000******0005` | UnionPay | high |  |
| CHD-028 | High | Clear-text PAN | `pos/offline_queue.db` record 2 | `362272****1667` | Diners Club | high |  |
| CHD-029 | High | Clear-text PAN | `pos/offline_queue.db` record 3 | `371449*****8431` | American Express | high |  |
| CHD-030 | High | Clear-text PAN | `support/ticket_export_2026-10.json` line 6 | `555555******4444` | Mastercard | high | grouped |
| CHD-031 | High | Clear-text PAN | `support/ticket_export_2026-10.json` line 12 | `378282*****0005` | American Express | high | grouped; stored with SAD in the same record |
| CHD-032 | Medium | Clear-text PAN | `db_exports/orders_2025_backup.sql` line 3 | `601100******9424` | Discover | medium |  |
| CHD-033 | Medium | Clear-text PAN | `db_exports/orders_2025_backup.sql` line 4 | `411111******1111` | Visa | medium |  |
| CHD-034 | Medium | Clear-text PAN | `db_exports/orders_2025_backup.sql` line 5 | `510510******5100` | Mastercard | medium | grouped |
| CHD-035 | Medium | Over-exposed masked PAN | `finance/settlement_2026-10.csv` line 5 | `401288******1881` | Visa | high | shows first 10 and last 4 of 16 digits (maximum is first 8 and last 4) |
| CHD-036 | Medium | Over-exposed masked PAN | `finance/settlement_2026-10.csv` line 6 | `601111******1117` | Discover | high | shows first 10 and last 4 of 16 digits (maximum is first 8 and last 4) |

## Suppressed by documented exception

| Location | Type | Masked value | Exception |
|---|---|---|---|
| `qa/fixtures/payment_test_cards.json` line 5 | Clear-text PAN | `411111******1111` | `qa/fixtures/*` |
| `qa/fixtures/payment_test_cards.json` line 9 | Clear-text PAN | `555555******4444` | `qa/fixtures/*` |
| `qa/fixtures/payment_test_cards.json` line 13 | Clear-text PAN | `378282*****0005` | `qa/fixtures/*` |

## Exceptions register and scan coverage

A location the scanner could not read is not a clean location. 12.5.2 requires *all* locations of account data to be known.

| Severity | Code | Subject | Detail |
|---|---|---|---|
| High | SUPPRESSION_EXPIRED | `legacy/*` | Expired 2026-06-30 (131 days ago); 2 finding(s) re-surfaced. Renew with fresh approval or remediate. |
| Low | SUPPRESSION_UNUSED | `tokenization/*` | Matched nothing in this scan; remove it so the register reflects reality. |
| High | SUPPRESSION_INVALID | `reports/*` | Not applied: missing 'approved_by'. |
| High | COVERAGE_GAP | `archive/vendor_handover_2025.zip!handover/customer_cards.xlsx` | encrypted archive member; cannot be inspected. Encrypted is not the same as out of scope: confirm contents and key custody |

## Method

- **PAN:** 13-19 digits (spaces or hyphens allowed as one consistent separator), Luhn-valid, in a published brand IIN range and length, not glued to other letters or digits, not a repeated or sequential number. Confidence is *high* with a card-like label nearby, a card-number column header or SAD on the same line.
- **Track data:** Track 1 (`%B...^NAME^YYMM...`) and Track 2 (`;PAN=YYMM...`) structures with a valid PAN.
- **CVV / PIN:** values next to an explicit label (`cvv2=`, `"cvc":`, `<cvv>`) or in a column with such a header. Ambiguous labels (`cid`, `csc`, `pin`) only count on a line that also holds card data.
- **Masking:** masked PANs showing more than the first 6 (8 for 16+ digit PANs) and last 4 digits.
- Unique PANs are counted with a keyed hash under a per-run random key that is never stored.
- Finding mix this run: Track data 2, Card verification code 9, PIN / PIN block 1, Clear-text PAN 22, Over-exposed masked PAN 2.

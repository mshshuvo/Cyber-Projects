# Week 05: PCI DSS Cardholder Data Discovery Scanner

A defensive "CVV/PAN finder". It scans a file share, export folder or log archive for **stored card numbers** (Luhn- and brand-validated) and **sensitive authentication data** that must never be kept after authorisation: CVV2/CVC2/CID, track data and PIN blocks. Every hit is masked before it reaches a report. The output is a PCI DSS v4.0.1 Requirement 3 remediation plan, organised by location.

It reads plain text, gzip, nested ZIPs, Word/Excel/OpenDocument files and SQLite databases. Anything it cannot open, such as an encrypted ZIP member, is reported as a coverage gap rather than skipped quietly. Standard library only.

## Why this matters

Most merchants and service providers believe card data lives in one place: the payment gateway, the token vault, the CDE database. A discovery scan usually shows otherwise. The data gets copied into ordinary places by ordinary business processes:

- **Debug logging in production.** One `DEBUG` line on the payments path writes the whole request body, including PAN and CVC, to disk, then to the SIEM, then to the log archive. This is one of the most common sources of SAD storage findings.
- **Spreadsheets built for a business reason.** Chargeback teams export the dispute file "with everything", including a `cvv2` column, and save it to the finance share.
- **Customers pasting card numbers into support channels.** Nobody asked for the number, but now it's in the ticketing system and its exports.
- **Pre-tokenisation leftovers.** The SQL backup taken "just before the migration", the 2024 refunds ZIP kept "until after the audit".
- **POS diagnostics.** A vendor support session turns on a raw trace and leaves track data on the lane controller.

Every one of these is a location PCI DSS 12.5.2 says must be in your documented scope. If SAD is involved, it is a 3.3.1 violation that encryption does not fix. Under v4.0.1, entities have to confirm scope at least once every 12 months (every six months for service providers under 12.5.2.1), and data discovery is how you do that with evidence instead of assertions.

## Framework and regulatory mapping

| Area | Reference | How the tool supports it |
|---|---|---|
| PCI DSS v4.0.1 | **3.2.1** retention and disposal of account data | Every clear-text PAN location, classified by type (log, export, archive, ticket) with a retention and disposal action |
| | **3.3.1, 3.3.1.1-3.3.1.3** SAD not stored after authorisation | Critical findings for track 1/2 data, CVV2/CVC2/CID (labelled values and CSV columns) and PIN blocks; documented exceptions can't suppress them |
| | **3.4.1** PAN masked when displayed | Flags masked values showing more than BIN + last four (first 6, or first 8 for PANs of 16+ digits, per PCI SSC FAQ 1091) |
| | **3.5.1, 3.5.1.1** PAN unreadable wherever stored; keyed hashes | Clear-text PAN findings; unique PANs counted with HMAC under a per-run key, never a plain hash |
| | **10.3** protection of audit logs | Log locations get an extra tag and a log-specific fix: stop body logging, add redaction (`chd_scan redact`), purge SIEM copies |
| | **12.5.2 / 12.5.2.1** scope confirmed with all locations of account data | Location inventory, coverage-gap register (unreadable, oversized, encrypted, nested too deep) |
| | **12.10.1** incident response | Track data or PIN on disk is flagged as a potential compromise indicator |
| | **Appendix A3.2.5 / A3.2.5.1** (DESV) data discovery methodology | Repeatable, documented method; `--fail-on` gate for scheduled or CI runs |
| ISO/IEC 27001:2022 | A.5.12 classification, A.5.33 protection of records, A.8.10 information deletion, A.8.11 data masking, A.8.12 data leakage prevention, A.8.15 logging | The scan is evidence for A.8.11/A.8.12 effectiveness and drives A.8.10 deletion |
| NIST CSF 2.0 | ID.AM-07 (inventory of data), PR.DS-01 (data at rest), PR.PS-04 (log records) | Data inventory by location; data-at-rest exposure |
| OSFI B-13 / B-10 | B-13 cyber security domain (data protection controls); B-10 when a third party holds the data | Evidence of data-at-rest discovery for FRFIs and their service providers |
| Card brand programmes | Account data compromise (ADC) investigations | Track data and PIN blocks on disk are the kind of artefacts forensic investigators (PFIs) look for |

## How it works

```
 path ──► extract.py ─────────────────────► detectors.py ──────────────► scanner.py ─────────────────► report.py
          text (BOM-aware), gzip,           per line:                    severity + PCI mapping       console
          ZIP (nested, bomb limits),        PAN (grouping-aware, Luhn,   CSV column pass (cvv2,       report.md
          Office XML (runs rejoined),       IIN brand+length, boundary)  pin, card_number headers)    report.json
          SQLite (row by row),              Track 1 / Track 2            location class → action      findings.csv
          binary → strings                  CVV / PIN (labelled)         suppressions (time-bound)    (all mode 0600)
          gaps: encrypted, too big,         masked PAN over-exposure     keyed-hash unique counts
          too deep, unreadable              → masked Hit objects
```

**PAN detection** has to keep false positives low without missing real numbers:

1. Find runs of digits, optionally grouped by spaces or hyphens (`4111 1111 1111 1111`, `3782-822463-10005`). One consistent separator only.
2. For each group, try every window of whole groups. A window in a standard card layout (4-4-4-4, 4-6-5, ...) beats a longer one, so `4111 1111 1111 1111 123` is read as a PAN followed by a CVV-length number, not as a 19-digit Visa.
3. Keep only 13-19 digits that pass Luhn, sit in a published IIN range with a valid length for that brand, aren't one repeated digit or a straight sequence, and aren't glued to letters, digits or a decimal point (`ORD4111...X`, `3.1415...`).
4. Confidence is **high** when a card-like word (`card`, `pan`, `visa`, `cc_number`, ...) appears within 48 characters before the number, the CSV column header says card number, or SAD is on the same line. Otherwise it's **medium**.

**Sensitive authentication data** is detected broadly, because missing SAD costs far more than a false alarm: `cvv2=`, `"cvc":`, `<cvv>`, `security code:` and CSV columns named `cvv2`, `cvc`, `cid`, `pin_block` and similar. Ambiguous labels (`cid`, `csc`, `pin`) only count when card data is on the same line, so `cid=4821` (customer id) and `push pin: 1234` don't trigger.

**Severity**

| Severity | Rule |
|---|---|
| Critical | Any SAD: track data, CVV, PIN/PIN block (3.3.1). Cannot be suppressed. |
| High | Clear-text PAN with card context, or stored in the same record as SAD |
| Medium | Clear-text PAN without context; masked PAN showing more than BIN + last four |

**Things the tool never does:** write a full PAN, CVV or PIN anywhere (findings record only the length of a CVV or PIN, never the value), emit PAN hashes, follow symlinks, or touch the network. Report files are created with mode 0600 because a list of where card data lives is itself sensitive.

**Published test PANs** (4111 1111 1111 1111 and friends) are *flagged, not ignored*: test data in production is a finding, and real numbers often get pasted right next to them. Exclude QA fixtures with a documented exception, or use `--ignore-test-pans` in a test environment.

### Documented exceptions (`suppressions.json`)

```json
{"suppressions": [
  {"path": "qa/fixtures/*", "kinds": ["PAN"], "reason": "Published test PANs only; env segmented from CDE",
   "approved_by": "ISO / CISO delegate", "ticket": "RISK-2026-031", "expires": "2027-06-30"}
]}
```

An exception needs a path glob, a reason, an approver and an expiry date. The tool audits the register itself:

- **Expired:** findings come back, with a note saying how long ago it expired.
- **Missing approver or expiry:** not applied.
- **Matches nothing:** flagged as unused.
- **Expires within 30 days:** flagged so it can be renewed or remediated.
- **SAD:** never suppressed, whatever the register says.

## Run it

Python 3.10 or later, no dependencies.

```bash
cd weekly/week05-pci-cardholder-data-discovery

# Scan the synthetic file share with its exceptions register
python -m chd_scan scan sample_data/fileshare --suppressions sample_data/suppressions.json \
    --as-of 2026-11-08 --out sample_output

# CI / scheduled gate: exit 2 if anything High or Critical is found
python -m chd_scan scan /srv/exports --fail-on high --out /secure/reports/chd-$(date +%F)

# Use as a log-pipeline redaction filter (stdin -> stdout)
tail -f /var/log/checkout-api.log | python -m chd_scan redact

# Regenerate the synthetic data
python sample_data/generate_sample.py
```

Options: `--exclude GLOB` (repeatable), `--max-mb N` (default 50; bigger files become coverage gaps), `--no-binary`, `--ignore-test-pans`, `--limit N` console rows, `--quiet` to drop the authorised-use notice.

Run the tests (30 tests):

```bash
python -m unittest -v
```

> **Authorised use only.** Scan only systems and data you own or are authorised to assess. The tool reads local paths only and never connects to a network.

## Sample output

The synthetic file share belongs to a fictional Canadian retailer, Northbay Outfitters Ltd. It has 15 files: finance spreadsheets, checkout API logs (one rotated and gzipped), a POS diagnostic trace, a POS SQLite offline queue, a support ticket export, a SQL backup, two ZIP archives (one with an encrypted member), a Word form, QA fixtures, a legacy CRM export, a false-positive bait file and a PNG. **Every card number is a published test PAN.**

```
Cardholder data discovery: sample_data/fileshare  (as of 2026-11-08)
============================================================================================
Files: 15 on disk, 16 documents scanned (archive members and Office parts included), 96 lines
Findings: 36  (Critical 12, High 19, Medium 5)  |  suppressed 3  |  coverage gaps 1
Unique PANs exposed: 14 across 10 locations (all are published test numbers)
Prohibited SAD hits (3.3.1): 12   Correctly masked PANs seen: 5

Locations, worst first
  Sev      Path                                            Hits                    Uniq PAN
  Critical finance/chargebacks_2026Q3.csv                  5 CVV, 5 PAN            5
  Critical app_logs/checkout-api.log                       2 CVV, 3 PAN            3
  Critical pos/store014_terminal_trace.txt                 2 Track, 1 PIN          2
  Critical support/ticket_export_2026-10.json              1 CVV, 2 PAN            2
  Critical app_logs/checkout-api.log.1.gz                  1 CVV, 1 PAN            1
  High     pos/offline_queue.db                            3 PAN                   3
  High     archive/2024_q4_refunds.zip!refunds_2024q4.csv  2 PAN                   2
  High     legacy/crm_export_2023.csv                      2 PAN                   2
  High     hr/corporate_card_request_form.docx             1 PAN                   1
  Medium   db_exports/orders_2025_backup.sql               3 PAN                   3
  Medium   finance/settlement_2026-10.csv                  2 Mask+                 0

Top findings (values masked; CVV/PIN never shown)
  [Critical] CHD-001 CVV   app_logs/checkout-api.log:2                   ***                  value labelled 'cvc' (3 chars)
  [Critical] CHD-003 CVV   app_logs/checkout-api.log.1.gz:1              ***                  value labelled 'cvc' (3 chars)
  [Critical] CHD-004 CVV   finance/chargebacks_2026Q3.csv:2              ***                  column 'cvv2' (3 chars)
  [Critical] CHD-009 Track pos/store014_terminal_trace.txt:3             510510******5100     Track 2 equivalent (PAN, expiry, service code, discretionar…
  [Critical] CHD-010 PIN   pos/store014_terminal_trace.txt:4             ****************     value labelled 'pin_block' (16 chars)
  [Critical] CHD-012 CVV   support/ticket_export_2026-10.json:12         ****                 value labelled 'security code' (4 chars)
  [High    ] CHD-013 PAN   app_logs/checkout-api.log:2                   424242******4242     stored with SAD in the same record
  ...

PCI DSS v4.0.1 requirements implicated
  3.2.1     22  Account data storage kept to a minimum; retention and disposal defined and applied
  3.3.1     12  SAD is not stored after authorisation, even if encrypted
  3.3.1.1    2  Full track data is not stored after authorisation
  3.3.1.2    9  Card verification code is not stored after authorisation
  3.3.1.3    1  PIN and PIN block are not stored after authorisation
  3.4.1      2  PAN is masked when displayed (BIN and last four at most)
  3.5.1     22  PAN is rendered unreadable anywhere it is stored
  10.3.x     7  Log files are account data locations too: protect them (10.3) and purge clear-text values (3.5.1)
  12.5.2    22  PCI DSS scope (all locations of account data) documented and confirmed

Exceptions register and coverage
  [High  ] SUPPRESSION_EXPIRED  legacy/*                                      Expired 2026-06-30 (131 days ago); 2 finding(s) re-surfaced. Renew wi…
  [Low   ] SUPPRESSION_UNUSED   tokenization/*                                Matched nothing in this scan; remove it so the register reflects real…
  [High  ] SUPPRESSION_INVALID  reports/*                                     Not applied: missing 'approved_by'.
  [High  ] COVERAGE_GAP         archive/vendor_handover_2025.zip!handover/c…  encrypted archive member; cannot be inspected. Encrypted is not the s…
```

(Top-findings list trimmed to a few representative rows here; the full console output is in [`sample_output/console.txt`](sample_output/console.txt).)

The redaction filter on the same debug log:

```
$ python -m chd_scan redact sample_data/fileshare/app_logs/checkout-api.log
... DEBUG checkout-api POST /v2/payments body={"order":"NB-120118","card":{"number":"424242******4242","exp":"08/28","cvc":"***"},"amount":72.40}
... ERROR checkout-api tokenisation timeout, falling back to direct auth pan=353011******0000 exp=0529
```

Full results: [`sample_output/report.md`](sample_output/report.md) (remediation plan by location, requirements, every finding, exceptions and coverage), [`sample_output/findings.csv`](sample_output/findings.csv) and [`sample_output/report.json`](sample_output/report.json).

What the sample shows:

- **The rotated log counts too.** `checkout-api.log.1.gz` has the same DEBUG leak as the live log. Fixing the logger without purging rotated files, the SIEM and the log archive leaves the SAD in place.
- **The chargeback spreadsheet is the worst file on the share.** Five PANs, each next to its CVV2. It exists for a legitimate business process, which is why it keeps being recreated. The fix is to change the process (dispute evidence needs the last four digits and an auth code, not the CVV), not just delete the file.
- **A "fallback" path is a leak path.** The `ERROR ... falling back to direct auth pan=...` line shows the tokenisation outage path writing the clear PAN. Error handling paths are often where logging goes wrong.
- **SQLite had to be read row by row.** In a `strings` pass, SQLite packs the lane id, PAN and expiry into one run of digits (`014-0362000000000000052811`), and a careful PAN detector correctly rejects that. Reading the rows finds all three PANs, with the `pan` column name as context.
- **Masking can look compliant and still not be.** `4012888888**1881` and `6011 1111 11** 1117` look masked, but they show ten leading digits. 3.4.1 allows BIN and last four at most.
- **The exceptions register leaks risk too.** The legacy CRM exception expired in June, so its PANs come back. One entry has no approver, so it was never valid. One covers a folder that doesn't exist anymore.
- **The bait file is clean.** Phone numbers, a UPS tracking number, an ISBN, Unix-millisecond timestamps, a Luhn-valid number in no brand range, a Luhn-invalid "card", π, `cid=4821` and `ORD4111111111111111X` produce no findings.

## Limitations

- **Pattern-based, not semantic.** A CVV written as "the code on the back is 731" has no label, so it isn't detected. A PAN split across lines or cells, or written in words, isn't either. Commercial DLP and discovery tools (and the PCI DSS A3 DESV expectations) go further, using exact-data matching against your own tokenised card list.
- **File-level only.** It scans what is mounted as files. Live databases, SaaS ticketing systems, email servers, cloud object storage and memory need their own connectors or exports.
- **Encrypted content is a gap, not a pass.** Password-protected ZIPs, SQLCipher databases and encrypted volumes are reported, not opened. Whether encrypted PAN is in scope depends on key custody (see the PCI SSC guidance on encrypted cardholder data and scope).
- **Legacy formats are not parsed.** That includes `.xls`, `.doc`, PDF and images (PANs in scanned receipts need OCR). Binary files get a strings pass, which catches ASCII only.
- **Excel stores long numbers as floats.** A 16-digit PAN typed into a numeric cell loses its last digit (15 significant digits), so it fails Luhn and is missed. Pattern-based scanners share this blind spot.
- **Brand ranges change.** The IIN table covers the major networks, but new ranges and local schemes (Interac, RuPay, Mir) aren't included. Keep `cards.BRANDS` current.

## Ideas to extend

- Exact data match: load a keyed-hash list of your real tokenised PANs, so hits can be confirmed as "ours" without reading clear text.
- Connectors that stream rows from PostgreSQL/MySQL and objects from S3/Azure Blob through the same detectors, read-only and allowlisted.
- PDF text extraction and OCR for scanned forms and receipts (as optional dependencies).
- Trend mode: diff two `report.json` files to show new, fixed and recurring locations for the quarterly 12.5.2 scope confirmation and the Week 52 KRI dashboard.
- Feed the location inventory into the Week 06 PII discovery data map, so card data and personal data share one register.
- A logging-library plug-in (Python `logging.Filter`) built on `redact_line`, so the leak is fixed where it starts.

---
*All data is synthetic. Northbay Outfitters Ltd., its staff, customers and files are fictional. Every card number is a published test PAN from card-network or payment-processor developer documentation, and every CVV and PIN block is invented. PCI DSS is © PCI Security Standards Council; requirements are cited by number for reference only.*

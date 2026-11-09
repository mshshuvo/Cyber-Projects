# Cyber-Projects

Hands-on cybersecurity and IT risk projects: one launch build on Oct 12, 2026, then one every Sunday for 52 weeks (53 projects in total).

The series runs from governance and audit, through PCI and privacy, vulnerability management and patching, detection and financial crime, to critical infrastructure (OT/ICS), cloud and AI security. Each project is practical, tested and mapped to real frameworks and regulations (ISO/IEC 27001, NIST CSF 2.0, PCI DSS, IEC 62443, OSFI, FINTRAC).

Every project folder includes:
- working Python code with unit tests
- synthetic sample data and real sample output
- a README covering the problem, framework mapping, how to run it, limitations and extensions
- a LinkedIn post draft

See the full plan in [weekly/ROADMAP.md](weekly/ROADMAP.md).

> All tools are defensive and educational. All data is synthetic. Network-facing tools are scope-locked to systems you own or are authorized to test.

## Projects

| Week | Date | Project | Description |
|------|------|---------|-------------|
| 01 | 2026-10-12 | [ISO 27001 SoA Auditor](weekly/week01-iso27001-soa-auditor/) | Cross-checks a Statement of Applicability against Annex A, the risk register and evidence, with clause-referenced findings |
| 02 | 2026-10-18 | [Audit Sampling Calculator & Evidence Tracker](weekly/week02-audit-sampling-calculator/) | Sizes control-test samples with exact attribute-sampling math, draws re-performable hash-ranked samples, checks the population and evaluates the evidence tracker |
| 03 | 2026-10-25 | [Policy Library Linter](weekly/week03-policy-library-linter/) | Lints a Markdown policy library for overdue reviews, vacant owners, unapproved changes, broken cross-references, undefined terms and version drift, with CI and pre-commit support |
| 04 | 2026-11-01 | [Control Crosswalk Engine](weekly/week04-control-crosswalk-engine/) | Tests a control once and shows what its evidence proves across ISO 27001, SOC 2, NIST CSF 2.0 and CIS v8.1, with blast radius of failed evidence, partial-mapping discipline and crosswalk validation |
| 05 | 2026-11-08 | [PCI DSS Cardholder Data Discovery Scanner](weekly/week05-pci-cardholder-data-discovery/) | Finds stored PANs (Luhn and brand validated) and prohibited CVV, track and PIN data across logs, exports, archives, Office files and SQLite, always masked, with a PCI DSS Req. 3 remediation plan and an audited exceptions register |

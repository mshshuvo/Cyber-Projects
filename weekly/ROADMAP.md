# Weekly Series Roadmap (52 weeks)

One project every Sunday at about 10 pm Toronto time, from Nov 1, 2026 to Oct 24, 2027.
The scheduled task builds the first unbuilt row whose date is on or before today. Edit this file to swap or reorder projects; the task always reads the latest version.

**Ground rules:** defensive and educational only. Use synthetic data. Scanners are scope-locked to systems you own or are authorized to test. No exploits, malware or credential harvesting.

## Q1 — Governance, Audit & Compliance

| Week | Date | Folder | Project | What it does |
|---|---|---|---|---|
| 01 | 2026-11-01 | weekly/week01-iso27001-soa-auditor | ISO 27001 Statement of Applicability auditor | Cross-checks an SoA against the risk register and treatment plan; flags excluded controls with no justification, controls marked implemented with no evidence, and risks with no mapped control. |
| 02 | 2026-11-08 | weekly/week02-audit-sampling-calculator | Audit sampling & evidence tracker | Calculates statistical sample sizes for control testing by population and frequency, draws reproducible random samples, and tracks evidence status per sample. |
| 03 | 2026-11-15 | weekly/week03-policy-library-linter | Policy library linter | Scans a folder of Markdown policies for stale review dates, missing owners, broken cross-references, undefined terms and version drift. |
| 04 | 2026-11-22 | weekly/week04-control-crosswalk-engine | Control crosswalk engine | Maps one piece of evidence to ISO 27001, SOC 2, NIST CSF 2.0 and CIS Controls at once, so you test once and satisfy many frameworks. |
| 05 | 2026-11-29 | weekly/week05-pci-cardholder-data-discovery | PCI DSS cardholder data discovery scanner | Defensive 'CVV/PAN finder': scans files and exports for stored card numbers (Luhn-validated) and CVV-like fields that must not be stored after authorization, masks every hit, and produces a PCI DSS Req. 3 remediation report. |
| 06 | 2026-12-06 | weekly/week06-pii-discovery-pipeda | PII discovery for PIPEDA/GDPR | Finds and classifies personal data (SIN-format, emails, phone, DOB) in documents, masks it, and builds a data inventory with retention flags. |
| 07 | 2026-12-13 | weekly/week07-osfi-b10-b13-assessment | OSFI B-10 / B-13 self-assessment toolkit | Canadian FRFI third-party and technology/cyber risk self-assessment with scoring, gaps and an action plan. |
| 08 | 2026-12-20 | weekly/week08-cis-linux-benchmark-checker | CIS Benchmark checker for Linux (read-only) | Runs a curated set of read-only CIS Level 1 checks on a Linux host and outputs pass/fail with remediation guidance. |
| 09 | 2026-12-27 | weekly/week09-config-drift-monitor | Hardening baseline drift monitor | Snapshots host security configuration, diffs against an approved baseline, and reports drift over time. |
| 10 | 2027-01-03 | weekly/week10-audit-finding-writer | Audit finding builder & rater | Turns raw notes into structured findings (condition, criteria, cause, effect, recommendation) with consistent risk ratings and a report. |
| 11 | 2027-01-10 | weekly/week11-bia-rto-rpo-calculator | Business impact analysis & dependency mapper | BIA tool computing RTO/RPO, impact over time, and upstream dependency chains that break recovery targets. |
| 12 | 2027-01-17 | weekly/week12-fair-monte-carlo | FAIR risk quantification simulator | Monte Carlo loss simulation (frequency × magnitude) producing loss exceedance curves and annualized loss in dollars. |
| 13 | 2027-01-24 | weekly/week13-board-cyber-risk-report | Board-level cyber risk report generator | Turns risk, control and incident data into a concise single-file HTML board report with trends and asks. |

## Q2 — Vulnerability Management & Patching

| Week | Date | Folder | Project | What it does |
|---|---|---|---|---|
| 14 | 2027-01-31 | weekly/week14-sbom-vuln-matcher | SBOM generator & vulnerability matcher | Builds a CycloneDX-style SBOM for a Python project and matches components against a vulnerability dataset. |
| 15 | 2027-02-07 | weekly/week15-vuln-ranking-engine | Vulnerability ranking engine | Ranks vulnerabilities using CVSS, exploit likelihood (EPSS-style), CISA KEV status and asset criticality, and explains each rank. |
| 16 | 2027-02-14 | weekly/week16-patch-sla-tracker | Patch SLA & exception tracker | Tracks patch aging against severity SLAs, risk-accepted exceptions with expiry, and produces an aging dashboard. |
| 17 | 2027-02-21 | weekly/week17-patch-impact-harness | Patch impact test harness | Captures pre/post-patch snapshots of services, ports, packages and health checks to detect breakage before rollout. |
| 18 | 2027-02-28 | weekly/week18-scoped-network-discovery | Scope-locked network discovery scanner | Asset and port discovery for your own lab network only: enforced CIDR allowlist, rate limiting, and an inventory report. |
| 19 | 2027-03-07 | weekly/week19-tls-config-grader | TLS configuration grader | Grades your own endpoints' TLS versions, ciphers, certificate expiry and chain issues. |
| 20 | 2027-03-14 | weekly/week20-http-security-headers-auditor | HTTP security headers auditor | Audits your own sites for CSP, HSTS, framing, cookie flags and more, with fix snippets. |
| 21 | 2027-03-21 | weekly/week21-secrets-scanner-precommit | Secrets scanner with pre-commit hook | Detects keys and tokens in repos via patterns and entropy, with a pre-commit hook and allowlisting. |
| 22 | 2027-03-28 | weekly/week22-dockerfile-security-linter | Dockerfile security linter | Flags root users, unpinned images, secrets in layers, ADD vs COPY misuse and missing health checks. |
| 23 | 2027-04-04 | weekly/week23-terraform-policy-checker | Terraform security policy checker | Policy-as-code checks over Terraform plan JSON: encryption, public exposure, logging, tagging. |
| 24 | 2027-04-11 | weekly/week24-nmap-attack-surface-report | Attack surface report from scan results | Parses Nmap XML from authorized scans into a ranked attack-surface report with owners and actions. |
| 25 | 2027-04-18 | weekly/week25-multi-scanner-dedup | Multi-scanner vulnerability correlator | Merges and deduplicates findings from different scanner CSV exports into one normalized backlog. |
| 26 | 2027-04-25 | weekly/week26-remediation-playbook-generator | Remediation playbook generator | Maps top findings to fix steps, owners, verification checks and rollback notes. |

## Q3 — Detection, Response & Financial Crime

| Week | Date | Folder | Project | What it does |
|---|---|---|---|---|
| 27 | 2027-05-02 | weekly/week27-mini-sigma-engine | Mini Sigma-style detection engine | YAML detection rules evaluated over JSON logs, with tests for true and false positives. |
| 28 | 2027-05-09 | weekly/week28-windows-logon-analyzer | Windows logon event analyzer | Analyzes exported 4624/4625/4672 events for spraying, lateral movement patterns and privileged logons. |
| 29 | 2027-05-16 | weekly/week29-dns-dga-tunnel-detector | DNS DGA & tunneling detector | Entropy and n-gram scoring of DNS logs to surface DGA domains and tunneling. |
| 30 | 2027-05-23 | weekly/week30-email-header-forensics | Email header forensic analyzer | Parses headers for SPF/DKIM/DMARC alignment, hop anomalies and spoofing indicators. |
| 31 | 2027-05-30 | weekly/week31-ir-timeline-builder | Incident timeline builder & runbook engine | Merges multi-source logs into one incident timeline and walks a responder through runbook steps. |
| 32 | 2027-06-06 | weekly/week32-ioc-enrichment-pipeline | IOC normalization & enrichment pipeline | Normalizes, deduplicates and ages indicators, and exports STIX-style bundles. |
| 33 | 2027-06-13 | weekly/week33-canary-token-watcher | Canary file & honeytoken watcher | Plants decoy files and credentials in your own environment and alerts on access. |
| 34 | 2027-06-20 | weekly/week34-file-integrity-monitor | File integrity monitor | Hash baselines of critical paths with change alerts and an approved-change workflow. |
| 35 | 2027-06-27 | weekly/week35-ransomware-early-warning | Ransomware early-warning detector | Detects mass renames and high-entropy writes in a monitored folder, with safe simulation for testing. |
| 36 | 2027-07-04 | weekly/week36-card-fraud-anomaly | Card fraud anomaly detector | Velocity, geo-impossibility and merchant-category anomaly scoring on synthetic card transactions. |
| 37 | 2027-07-11 | weekly/week37-aml-mule-ring-graph | AML mule ring detection with graphs | Graph analysis of synthetic transfers to find fan-in/fan-out mule rings and layering chains. |
| 38 | 2027-07-18 | weekly/week38-sanctions-fuzzy-screening | Sanctions screening fuzzy matcher | Fuzzy and transliteration-aware name matching (including South Asian and Arabic name variants) with false-positive tuning. |
| 39 | 2027-07-25 | weekly/week39-kyc-document-consistency | KYC document consistency checker | Cross-checks synthetic KYC records and document metadata for mismatches and tampering indicators. |

## Q4 — Critical Infrastructure, Cloud & AI Security

| Week | Date | Folder | Project | What it does |
|---|---|---|---|---|
| 40 | 2027-08-01 | weekly/week40-modbus-traffic-analyzer | Modbus/TCP traffic analyzer | Parses synthetic Modbus captures to flag unauthorized function codes, writes from unexpected hosts and timing anomalies. |
| 41 | 2027-08-08 | weekly/week41-ot-purdue-zone-checker | OT asset inventory & Purdue zone checker | Builds an OT asset inventory and flags flows that violate Purdue-model zone boundaries. |
| 42 | 2027-08-15 | weekly/week42-iec62443-zone-conduit-gap | IEC 62443 zone & conduit gap tool | Compares target vs achieved security levels per zone and conduit and produces a gap plan. |
| 43 | 2027-08-22 | weekly/week43-ics-alarm-flood-analyzer | ICS alarm flood analyzer | Detects alarm floods, chattering and stale alarms in synthetic SCADA alarm logs (ISA-18.2 style). |
| 44 | 2027-08-29 | weekly/week44-water-utility-ot-assessment | Water utility OT risk assessment | Guided NIST CSF-based OT assessment for a small water utility with prioritized actions. |
| 45 | 2027-09-05 | weekly/week45-aws-iam-overprivilege | Cloud IAM over-privilege analyzer | Analyzes IAM policy JSON for wildcards, privilege-escalation paths and least-privilege suggestions. |
| 46 | 2027-09-12 | weekly/week46-cloud-storage-exposure | Multi-cloud storage exposure checker | Checks sample AWS, Azure and GCP storage configs for public access, missing encryption and missing logging. |
| 47 | 2027-09-19 | weekly/week47-k8s-rbac-risk-mapper | Kubernetes RBAC risk mapper | Maps roles and bindings to find cluster-admin sprawl, secret readers and escalation paths. |
| 48 | 2027-09-26 | weekly/week48-llm-app-security-harness | LLM app security test harness | Defensive test suite for your own local LLM app (e.g., via Ollama): prompt injection, data leakage and jailbreak-resistance checks with scoring. |
| 49 | 2027-10-03 | weekly/week49-ml-model-supply-chain | AI model supply-chain checker | Verifies model file hashes and provenance and scans pickle files for unsafe opcodes before loading. |
| 50 | 2027-10-10 | weekly/week50-iso42001-readiness | ISO/IEC 42001 AI governance readiness tool | AI management system readiness assessment with an AI system inventory and risk scoring. |
| 51 | 2027-10-17 | weekly/week51-kri-trend-dashboard | Security KRI trend dashboard | Aggregates outputs from earlier projects into a KRI trend dashboard with thresholds. |
| 52 | 2027-10-24 | weekly/week52-cyber-risk-command-center | Capstone: Cyber Risk Command Center | One CLI and HTML report tying together the best tools from the series into an end-to-end risk view. |

# Week 03: Policy Library Linter

A command-line linter for a folder of Markdown information-security policies. It reads the whole library at once and reports the defects that auditors find and that document owners rarely notice: **stale review dates, missing or departed owners, broken cross-references, undefined terms and version drift**. Every finding points to a file and line, so it can run in a pull request the same way a code linter does.

## Why this matters

Policies are the first thing an ISO 27001 auditor asks for, and they're where easy nonconformities hide:

- **The review date slipped.** "Reviewed annually" is written in the policy, but the last review was 16 months ago. That is a straight nonconformity against the organisation's own documented requirement (ISO 27001 A.5.1, clause 7.5.2).
- **The owner left.** The policy names a role that is vacant, so nobody is accountable for keeping it current.
- **The text changed after approval.** Someone fixed a "small" detail in July, bumped the revision history to v2.2, and the front page still says v2.1, approved in March. The version in force was never approved.
- **The library doesn't hang together.** The incident policy points to a vulnerability procedure that was never written, relies on a retired remote-access policy, or cites "v1.0" of a continuity policy that is now on v1.3.
- **The same word means two things.** The glossary says a security incident is an event that compromises confidentiality, integrity or availability; the incident policy redefines it as "any alert". That gap shows up in incident metrics and regulatory reporting decisions.
- **Drafts never finish.** "Retention: TBD" sits in a draft for seven months while the approved top-level policy already points to it.

Each of these takes minutes to find with a tool and hours to find by reading. When policies live in Git (more and more of them do), the linter can stop the problem at the pull request.

## Framework and regulatory mapping

| Area | Reference | How the tool supports it |
|---|---|---|
| ISO/IEC 27001:2022 | 5.2 (policy), 5.3 (roles), 7.5.2 (creating and updating: identification, review and approval), 7.5.3 (control of documented information: version control, distribution, obsolete documents) | Required metadata, independent approval, version drift, unapproved changes, retired-document references |
| ISO/IEC 27001:2022 Annex A | A.5.1 Policies for information security ("reviewed at planned intervals and if significant changes occur"); A.5.37 documented operating procedures | Review-cycle checks; validation of mapped control ids against the 93 controls in the 2022 Annex A |
| ISO/IEC 27002:2022 | 5.1 guidance on topic-specific policies, consistency with the top-level policy | Cross-reference integrity and glossary consistency across the library |
| NIST CSF 2.0 | GV.PO-01 (policy established, communicated, enforced), GV.PO-02 (policy reviewed, updated, communicated), GV.RR-02 (roles and accountability) | Currency, ownership and change-control checks |
| OSFI Guideline B-13 | 1.3 technology and cyber risk management framework, including policies, standards and procedures that are kept current | Review calendar and health score as governance evidence |
| OSFI Corporate Governance Guideline | Board and senior management approval of key policies; independent challenge | `SELF_APPROVED` flags owner-approved documents |
| FINTRAC (PCMLTFA regs, s. 156) | Written, up-to-date compliance policies and procedures, approved by a senior officer; two-year effectiveness review | The same linter can run over an AML policy library |
| PCI DSS v4.0.1 | Req. 12.1.1–12.1.2 (policy established, published, reviewed at least once every 12 months); "roles and responsibilities" sub-requirement in each of Req. 1–11 | Review cycle, required sections (Roles and Responsibilities) |
| SOC 2 (TSC 2017, rev. 2022) | CC5.3 (policies and procedures), CC2.2 | Evidence that policies are maintained and consistent |

## What it checks

| Rule | Severity | What it finds |
|---|---|---|
| `NO_FRONT_MATTER`, `MISSING_FIELD` (id, status) | High | A document with no identity or status cannot be controlled |
| `DUPLICATE_ID` | High | Two documents share an id, so every reference to it is ambiguous |
| `MISSING_OWNER`, `MISSING_APPROVER`, `OWNER_VACANT` | High | Nobody accountable, no approval record, or the owning role is vacant (needs `--owners`) |
| `REVIEW_OVERDUE` | High | `last_reviewed` + `review_cycle_months` (or `next_review`) is in the past |
| `VERSION_DRIFT` | High | Front-matter version doesn't match the highest version in the revision history |
| `UNAPPROVED_CHANGE` | High | A revision is dated after `approved_on`: the text in force wasn't approved |
| `BROKEN_REFERENCE`, `BROKEN_LINK` | High | A document id or a relative Markdown link points to nothing |
| `BROKEN_ANCHOR` | Medium | A link to `file.md#section` where that section heading doesn't exist |
| `REFERENCE_TO_RETIRED` | Medium | An approved document relies on a retired one |
| `STALE_PINNED_REFERENCE` | Medium | "POL-BC-001 v1.0" when POL-BC-001 is now v1.3 |
| `SELF_APPROVED` | Medium | Owner and approver are the same; approval isn't independent |
| `OWNER_NOT_IN_REGISTER` | Medium | Owner role isn't in the owner register |
| `CONFLICTING_DEFINITION`, `DUPLICATE_TERM` | Medium | A policy redefines a glossary term; the glossary defines a term twice |
| `INVALID_CONTROL_REF` | Medium | An `iso27001:` mapping that isn't a 2022 Annex A control (often 2013 numbering, e.g. A.9.2.3) |
| `MISSING_SECTION`, `PLACEHOLDER_TEXT` | Medium (approved) / Low (draft) | Required sections absent; "TBD", "[Insert …]", "lorem ipsum" left in |
| `NO_REVISION_HISTORY`, `BAD_FRONT_MATTER`, `BAD_DATE`, `BAD_VERSION`, `BAD_STATUS`, `BAD_REVIEW_CYCLE`, `FUTURE_DATE` | Medium | Document control can't be traced or dates can't be trusted |
| `REVIEW_DUE_SOON` | Low | Review due within `--due-soon-days` (default 45): an early warning for owners |
| `UNDEFINED_TERM` | Low | An acronym that isn't expanded in the document ("Privileged Access Management (PAM)") or defined in the glossary |
| `REFERENCE_TO_DRAFT`, `STALE_DRAFT`, `HISTORY_ORDER`, `DRAFT_VERSION_APPROVED` | Low | Library hygiene |

Retired documents are only checked for identity (id and duplicates). Drafts are not checked for review dates, but are flagged when they stall.

## How it works

```
policies/*.md ──► model.py ──────────────► checks.py ─────────────► report.py
glossary.md       front matter (strict      7 check groups over      console, report.md,
owners.csv        YAML subset), headings,   the whole library:       report.json, GitHub
                  revision table, ids,      governance, currency,    Actions annotations;
                  links, acronyms,          versions, references,    exit 2 on --fail-on
                  local definitions         terms, structure
```

- **Library-wide, not file-by-file.** References, retired targets, pinned versions and duplicate ids can only be judged with the whole library loaded, so the tool parses every file first and then runs the checks.
- **Policy format.** Each policy has a front-matter block and a revision history table:

  ```markdown
  ---
  id: POL-AC-001
  title: Access Control Policy
  version: 2.1
  status: approved            # draft | approved | retired
  owner: Head of IT Operations
  approver: CISO
  approved_on: 2026-03-14
  last_reviewed: 2026-03-14
  review_cycle_months: 12     # or next_review: YYYY-MM-DD
  iso27001: [A.5.15, A.5.18, A.8.2]
  ---
  ...
  ## Revision history
  | Version | Date | Author | Change |
  |---|---|---|---|
  | 2.1 | 2026-03-14 | Head of IT Operations | Annual review |
  ```

  The front-matter parser is a strict subset of YAML, so the tool needs only the standard library and a malformed line is reported, not guessed at.
- **References.** Document ids (`POL-XX-000`, `STD-`, `PRC-`, `GDL-`; change with `--id-pattern`), optionally followed by a pinned version (`v1.2`), and relative Markdown links including `#anchors`, resolved with GitHub's heading-slug rules. Web links are skipped: the tool works offline. Text in code blocks is ignored.
- **Terms.** An acronym is defined if the document expands it once ("Hardware Security Module (HSM)"), lists it in its own Definitions section, or the glossary has it. RFC 2119 keywords (MUST, SHALL, SHOULD) are ignored.
- **Suppressions.** `<!-- policylint-disable UNDEFINED_TERM,PLACEHOLDER_TEXT -->` in a file switches those rules off for that file (`ALL` for every rule). Suppressions are counted in the report, so they stay visible to a reviewer.
- **Health score.** 100 minus a weighted penalty (High 8, Medium 3, Low 1) per document. It's a trend indicator for a KRI, not an audit opinion.

Standard library only. No dependencies. Python 3.10 or later.

## Run it

```bash
cd weekly/week03-policy-library-linter

python -m policy_linter sample_data/policies \
  --owners sample_data/owners.csv \
  --as-of 2026-10-25 \
  --org "Maple Ridge Credit Union (fictional)" \
  --out sample_output
```

`glossary.md` in the library folder is picked up automatically (or pass `--glossary`). Other options:

- `--fail-on high|medium|low` exits with code 2 when a finding is at or above that severity, for CI and pre-commit.
- `--format github` prints GitHub Actions annotations, so findings appear inline on the pull request.
- `--due-soon-days 45`, `--default-cycle 12`, `--sections "Purpose,Scope,..."`, `--ignore-terms "SIEM,KMS"`, `--limit 20`.

Run the tests (32 tests):

```bash
python -m unittest -v
```

### Use it as a gate on a policy repository

GitHub Actions step:

```yaml
- name: Lint policy library
  run: python -m policy_linter policies --owners policies/owners.csv --format github --fail-on high
```

pre-commit (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: local
    hooks:
      - id: policy-linter
        name: policy linter
        entry: python -m policy_linter policies --fail-on high
        language: system
        pass_filenames: false
        files: ^policies/.*\.md$
```

## Sample output

The synthetic library belongs to a fictional credit union: ten documents (eight approved, one draft, one retired), a glossary and an owner register, with defects planted on purpose.

```
Policy library lint  (as of 2026-10-25)
================================================================
Documents: 10  (approved 8, draft 1, retired 1)
Health score: 53/100   Findings: 31  (High 9, Medium 12, Low 10)   Suppressed: 2
Approved documents within review cycle: 88%   Annex A controls mapped: 29/93

  [High  ] access-control-policy.md:4         VERSION_DRIFT           Front matter says v2.1 but the revision history ends at v2.2 (line 66).
  [High  ] access-control-policy.md:66        UNAPPROVED_CHANGE       v2.2 is dated 2026-07-03, after the last approval on 2026-03-14; the text in force has not been approved.
  [High  ] business-continuity-policy.md:28   BROKEN_LINK             Link 'BIA procedure' points to 'procedures/bia-procedure.md', which does not exist.
  [High  ] cryptography-standard.md:2         DUPLICATE_ID            Id STD-CR-001 is used by 2 documents (cryptography-standard.md, logging-monitoring-standard.md); references are ambiguous.
  [High  ] cryptography-standard.md:6         OWNER_VACANT            Owner role 'Security Architect' is vacant; the document is effectively unowned.
  [High  ] cryptography-standard.md:9         REVIEW_OVERDUE          Review was due 2026-06-30 (117 days overdue).
  [High  ] data-classification-policy.md:1    MISSING_OWNER           No owner; nobody is accountable for keeping this document current (ISO 27001 5.3, A.5.1).
  [High  ] incident-response-policy.md:39     BROKEN_REFERENCE        References POL-VM-002, which is not in the library.
  [High  ] logging-monitoring-standard.md:2   DUPLICATE_ID            Id STD-CR-001 is used by 2 documents (cryptography-standard.md, logging-monitoring-standard.md); references are ambiguous.
  [Medium] acceptable-use-policy.md:1         MISSING_SECTION         No 'Exceptions' section.
  ...
  [Low   ] access-control-policy.md:31        UNDEFINED_TERM          Acronym 'PAM' is used but not expanded here or defined in the glossary.
  [Low   ] access-control-policy.md:66        UNDEFINED_TERM          Acronym 'SLA' is used but not expanded here or defined in the glossary.
  [Low   ] business-continuity-policy.md:9    REVIEW_DUE_SOON         Review due 2026-11-20 (in 26 days).
  [Low   ] business-continuity-policy.md:54   HISTORY_ORDER           Revision history versions are not in strictly increasing order.
```

Full results: [`sample_output/report.md`](sample_output/report.md) (summary, findings by rule, review calendar, all findings), [`sample_output/report.json`](sample_output/report.json) and [`sample_output/console.txt`](sample_output/console.txt).

A few of these deserve a comment, because they're the ones that turn into audit findings:

- **Access Control Policy, `VERSION_DRIFT` + `UNAPPROVED_CHANGE`.** The leaver SLA was loosened from "same day" to "one business day" in July, after the March approval. The front page still says v2.1. An auditor testing leavers against the approved policy and one testing against the current text will reach different conclusions.
- **Two documents with id STD-CR-001.** The logging standard was created by copying the cryptography standard and the id was never changed. Every "follows STD-CR-001" in the library is now ambiguous.
- **Cryptography Standard, `OWNER_VACANT` + `REVIEW_OVERDUE`.** These usually come together: the Security Architect role is vacant, so the annual review didn't happen.
- **Incident Response Policy, `CONFLICTING_DEFINITION`.** "Any alert" vs the glossary's CIA-based definition changes how many incidents are counted and which ones are assessed for OSFI reporting.

## Limitations

- **Markdown with front matter only.** Word and PDF policies need converting first (for example with pandoc). The checks don't change.
- **The tool checks that the documentation is controlled, not that the content is right.** It can't tell whether a password rule is sensible or whether a policy meets a regulation's substance.
- **Acronym detection is heuristic.** It looks for runs of two or more capitals; product names in capitals can show up as `UNDEFINED_TERM` (use the glossary, `--ignore-terms` or a suppression). It doesn't detect capitalised *defined terms* used without definition, only conflicting definitions.
- **Approval is read from metadata.** It trusts `approved_on` and `approver`; it can't verify a signature or board minute. Pair it with Git history or your document management system's audit trail.
- **External links aren't checked**, by design: the tool runs offline and touches no network.

## Ideas to extend

- Check that each policy's ISO 27001 mappings agree with the Week 01 SoA (an applicable control with no governing policy is a gap).
- Read approval evidence from signed Git tags or commit trailers, so `UNAPPROVED_CHANGE` is based on the actual approval record.
- Detect capitalised defined terms ("Privileged Account") used but never defined, using noun-phrase extraction.
- Send `REVIEW_DUE_SOON` findings to owners as reminders, and feed the health score into the Week 52 KRI dashboard.
- Readability and length metrics per policy (staff don't follow what they can't read).
- Convert `.docx` policies on the fly with python-docx, as an optional dependency.

---
*All data is synthetic. Maple Ridge Credit Union, its staff ids and its documents are fictional. Standards are cited by clause for reference only.*

Every policy says "reviewed annually." How many actually are?

For week 3 of my 53-project series, I built a linter for policy libraries. It treats a folder of Markdown policies the way a code linter treats source code. It checks the whole library at once and points each finding to a file and line.

Running it on a synthetic credit-union library of 10 documents found 31 issues. The ones that matter most are the ones that become audit findings:

- A policy edited in July with an approval dated March. The front page still showed the old version, so the text in force was never approved.
- Two standards sharing one ID, because one was created by copying the other. Every reference to that ID was ambiguous.
- A standard owned by a vacant role and four months past its review date. In my experience, those two usually go together.
- An incident policy defining "security incident" as "any alert," which contradicts the glossary. That changes what gets counted and what gets assessed for regulatory reporting.

None of these are hard to fix. They're hard to see when you read one policy at a time. If your policies live in Git, a check like this can block the problem at the pull request instead of in the audit report.

Code, sample library and report: https://github.com/mshshuvo/Cyber-Projects/tree/main/weekly/week03-policy-library-linter

#ISO27001 #GRC #InformationSecurity #InternalAudit #PolicyManagement

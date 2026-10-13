94% of controls implemented. Readiness score: 34/100.

That's the result of running a tool I built this week on a sample Statement of Applicability. It's the first of 53 hands-on cybersecurity and IT risk projects I'll be publishing weekly over the next year.

As an ISO 27001 Lead Auditor, I've seen the same pattern many times: the SoA looks healthy on its own, but it falls apart when you hold it up against the risk register and the evidence log.

- A control is marked "not applicable", while the risk treatment plan depends on it.
- A control says "Implemented", backed by evidence that expired months ago.
- A high risk is "mitigated" only by controls that are still at the planned stage.
- Controls disappear in the move from 2013 to 2022 numbering.

So I wrote a Python tool that cross-checks all three sources against the 93 Annex A controls and ties every finding to an ISO/IEC 27001:2022 clause. It can also run in CI, so a broken SoA fails the build before it reaches an auditor.

Coverage tells you how much work got done. Consistency tells you whether it holds up in an audit.

Code, sample data and the full report: https://github.com/mshshuvo/Cyber-Projects/tree/main/weekly/week01-iso27001-soa-auditor

#ISO27001 #GRC #CyberRisk #InformationSecurity #Audit

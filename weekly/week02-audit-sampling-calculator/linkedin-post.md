"We tested 25 items." Why 25?

In a lot of control-testing files I've reviewed, the sample size came from habit rather than from a confidence level and a tolerable deviation rate. So for week 2 of my 53-project series, I built an audit sampling calculator and evidence tracker in Python.

It does four things:

- Sizes samples with exact attribute-sampling math. 95% confidence with a 5% tolerable rate gives the familiar 59, matching the AICPA tables, and it adjusts for small populations.
- Checks the population before sampling: duplicates, out-of-period items, and a record count that doesn't reconcile to the source system. A perfect sample of an incomplete list proves nothing.
- Selects items by SHA-256 hash ranking from a recorded seed, so any reviewer can re-perform the sample, even without my code.
- Evaluates the evidence tracker and flags swapped items, missing evidence references and overdue requests.

In the synthetic change-management test, the tool reached its conclusion at 82% of fieldwork: two exceptions against one allowed. More testing can't rescue that result. The useful move is to stop, report the deficiency and look at compensating controls.

Sampling is where audit conclusions are won or lost.

Code, sample data and working paper: https://github.com/mshshuvo/Cyber-Projects/tree/main/weekly/week02-audit-sampling-calculator

#InternalAudit #ITGC #GRC #ISO27001 #RiskManagement
